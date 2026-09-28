import asyncio
import logging
import os
import re
from pathlib import Path

import dotenv
from quivr_core import Brain
from quivr_core.rag.entities.config import AssistantConfig
from rich.traceback import install as rich_install

ConsoleOutputHandler = logging.StreamHandler()

logger = logging.getLogger("quivr_core")
logger.setLevel(logging.DEBUG)
logger.addHandler(ConsoleOutputHandler)


logger = logging.getLogger("megaparse")
logger.setLevel(logging.DEBUG)
logger.addHandler(ConsoleOutputHandler)


# Install rich's traceback handler to automatically format tracebacks
rich_install()

_ai_dat_sec_023_PII_PATTERNS = [
    # Social Security Number
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), '[REDACTED_SSN]'),
    # Taxpayer Identification Number (EIN)
    (re.compile(r'\b\d{2}-\d{7}\b'), '[REDACTED_TIN]'),
    # Credit Card Number
    (re.compile(r'\b(?:\d[ -]?){13,16}\b'), '[REDACTED_CC]'),
    # Email
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[REDACTED_EMAIL]'),
    # Personal Phone Number
    (re.compile(r'\b(?:\+?\d[\s.\-]?)?(?:\(?\d{2,4}\)?[\s.\-]?){2,5}\d{2,4}\b'), '[REDACTED_PHONE]'),
    # IP Address
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '[REDACTED_IP]'),
    # MAC Address
    (re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), '[REDACTED_MAC]'),
    # Passport Number (generic alphanumeric 6-9 chars)
    (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), '[REDACTED_PASSPORT]'),
    # Driver's License (common US formats)
    (re.compile(r'\b[A-Z]{1,2}\d{5,8}\b'), '[REDACTED_DL]'),
    # Year of Birth (standalone 4-digit year 1900-2099)
    (re.compile(r'\b(19|20)\d{2}\b'), '[REDACTED_YEAR]'),
    # Financial Account Number (8-17 digits)
    (re.compile(r'\b\d{8,17}\b'), '[REDACTED_ACCOUNT]'),
    # Vehicle Identification Number (17 alphanumeric)
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), '[REDACTED_VIN]'),
]


def _ai_dat_sec_023_redact_text(text: str) -> str:
    """Redact PII from a text string using known PII patterns."""
    for pattern, replacement in _ai_dat_sec_023_PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _ai_dat_sec_023_sanitize_files(file_paths):
    """Extract text from PDF files, redact PII, and return sanitized temp file paths."""
    try:
        import pypdf
        _has_pypdf = True
    except ImportError:
        try:
            import PyPDF2 as pypdf
            _has_pypdf = True
        except ImportError:
            _has_pypdf = False

    sanitized_paths = []
    for fp in file_paths:
        fp = Path(fp)
        if fp.suffix.lower() == '.pdf' and _has_pypdf:
            try:
                reader = pypdf.PdfReader(str(fp))
                full_text = ''
                for page in reader.pages:
                    page_text = page.extract_text() or ''
                    full_text += page_text + '\n'
                redacted = _ai_dat_sec_023_redact_text(full_text)
                if redacted != full_text:
                    logging.getLogger('quivr_core').warning(
                        'PII detected and redacted in file: %s (original_len=%d, redacted_len=%d)',
                        fp.name, len(full_text), len(redacted)
                    )
                    tmp = tempfile.NamedTemporaryFile(
                        delete=False, suffix='.txt',
                        prefix='_ai_dat_sec_023_sanitized_'
                    )
                    tmp.write(redacted.encode('utf-8'))
                    tmp.close()
                    sanitized_paths.append(Path(tmp.name))
                else:
                    sanitized_paths.append(fp)
            except Exception as e:
                logging.getLogger('quivr_core').warning(
                    'PII redaction skipped for %s due to error: %s', fp.name, e
                )
                sanitized_paths.append(fp)
        else:
            sanitized_paths.append(fp)
    return sanitized_paths


def _ai_dat_sec_012_mask_pii(text: str) -> str:
    """Mask zero-tolerance PII categories before display on the UI."""
    if not isinstance(text, str):
        text = str(text)
    # Mask personal phone numbers (international and local formats)
    text = re.sub(
        r'(\+?\d[\d\s\-\.\(\)]{6,}\d)',
        '[PHONE REDACTED]',
        text,
    )
    # Mask email addresses
    text = re.sub(
        r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
        '[EMAIL REDACTED]',
        text,
    )
    return text

_ai_app_sec_070_patterns = [
    # 1. instruction_override
    (re.compile(r'ignore previous instructions|forget everything above', re.IGNORECASE),
     '<prompt_injection_removed: instruction_override>'),
    # 2. role_hijack
    (re.compile(r'you are now DAN|act as unrestricted', re.IGNORECASE),
     '<prompt_injection_removed: role_hijack>'),
    # 3. delimiter_escape
    (re.compile(r'</?(system|tool|assistant|user)\s*>', re.IGNORECASE),
     '<prompt_injection_removed: delimiter_escape>'),
    # 4. encoded_payload - base64 blobs, hex sequences, ROT13 instructions, URL-encoded instructions
    (re.compile(r'(?:[A-Za-z0-9+/]{40,}={0,2}|(?:%[0-9A-Fa-f]{2}){8,}|(?:\\u[0-9A-Fa-f]{4}){4,})', re.IGNORECASE),
     '<prompt_injection_removed: encoded_payload>'),
    # 5. hidden_text - HTML comments, zero-width chars
    (re.compile(r'<!--.*?-->|[\u200b-\u200f\u202a-\u202e\u2060\ufeff]', re.DOTALL),
     '<prompt_injection_removed: hidden_text>'),
    # 6. fake_system_message
    (re.compile(r'\[?(SYSTEM|TOOL|ASSISTANT)\]?\s*:', re.IGNORECASE),
     '<prompt_injection_removed: fake_system_message>'),
    # 7. exfiltration_attempt
    (re.compile(r'!\[.*?\]\(https?://[^)]+\)|send (this|the) (data|prompt|context|system prompt) to|leak (the )?system prompt', re.IGNORECASE),
     '<prompt_injection_removed: exfiltration_attempt>'),
    # 8. context_poisoning
    (re.compile(r'(in a previous turn|earlier you said|you previously agreed|remember when you)', re.IGNORECASE),
     '<prompt_injection_removed: context_poisoning>'),
    # 9. indirect_injection
    (re.compile(r'(the (document|file|pdf|data) says? (to|you should)|embedded instruction)', re.IGNORECASE),
     '<prompt_injection_removed: indirect_injection>'),
    # 10. command_injection
    (re.compile(r'(eval\s*\(|exec\s*\(|os\.system\s*\(|subprocess\.|`[^`]+`|\$\([^)]+\))', re.IGNORECASE),
     '<prompt_injection_removed: command_injection>'),
    # 11. split_payload
    (re.compile(r'(part\s*[1-9]\s*of\s*[1-9]|continued (in|on) (next|part))', re.IGNORECASE),
     '<prompt_injection_removed: split_payload>'),
    # 12. jailbreak_attempt
    (re.compile(r'(DAN mode|developer mode|fictional framing|pretend you have no restrictions|jailbreak)', re.IGNORECASE),
     '<prompt_injection_removed: jailbreak_attempt>'),
]


def _ai_app_sec_070_sanitize(text: str) -> str:
    """Neutralize prompt injection patterns in user-supplied text before sending to LLM."""
    for pattern, marker in _ai_app_sec_070_patterns:
        text = pattern.sub(marker, text)
    return text

_ai_app_sec_059_guardrail = lineaje_guardrail()
_ai_app_sec_059_guardrail.enable_policies(["AI_APP_SEC_059.json"])

_AI_APP_SEC_006_DISAPPROVED_PATTERNS = [
    "deepseekchat",
    "deepseekr1distillllama70b",
    "deepseekr1",
    "deepseekreasoner",
    "customllmclient",
    "deepseakchat",
    "openrouter",
    "usdeepseekr1v10",
]


def _ai_app_sec_006_normalize(name: str) -> str:
    """Normalize a model identifier for comparison."""
    return re.sub(r"[\s\-_\.:\u00a0]+", "", name).lower()


def _ai_app_sec_006_check_model(model_name: str) -> None:
    """Raise ValueError if model_name matches a disapproved model."""
    if model_name is None:
        return
    normalized = _ai_app_sec_006_normalize(str(model_name))
    for pattern in _AI_APP_SEC_006_DISAPPROVED_PATTERNS:
        if pattern in normalized:
            raise ValueError(
                f"Model '{model_name}' is on the organization's disapproved list "
                f"and cannot be used."
            )


async def main():
    file_path = [
        Path("data/YamEnterprises_Monotype Fonts Plan License.US.en 04.0 (BLP).pdf")
    ]
    file_path = [
        Path(
            "data/YamEnterprises_Monotype Fonts Plan License.US.en 04.0 (BLP) reduced.pdf"
        )
    ]

    config_file_name = (
        "/Users/jchevall/Coding/quivr/backend/core/tests/rag_config_workflow.yaml"
    )

    assistant_config = AssistantConfig.from_yaml(config_file_name)
    # megaparse_config = find_nested_key(config, "megaparse_config")
    megaparse_config = assistant_config.ingestion_config.parser_config.megaparse_config
    megaparse_config.llama_parse_api_key = os.getenv("LLAMA_PARSE_API_KEY")

    processor_kwargs = {
        "megaparse_config": megaparse_config,
        "splitter_config": assistant_config.ingestion_config.parser_config.splitter_config,
    }

    file_path = _ai_dat_sec_023_sanitize_files(file_path)
    brain = await Brain.afrom_files(
        name="test_brain",
        file_paths=file_path,
        processor_kwargs=processor_kwargs,
    )

    # # Check brain info
    brain.print_info()

    questions = [
        "What is the contact name for Yam Enterprises?",
        "What is the customer phone for Yam Enterprises?",
        "What is the Production Fonts (maximum) for Yam Enterprises?",
        "List the past use font software according to past use term for Yam Enterprises.",
        "How many unique Font Name are there in the Add-On Font Software Section for Yam Enterprises?",
        "What is the maximum number of Production Fonts allowed based on the license usage per term for Yam Enterprises?",
        "What is the number of production fonts licensed by Yam Enterprises? List them one by one.",
        "What is the number of Licensed Monthly Page Views for Yam Enterprises?",
        "What is the monthly licensed impressions (Digital Marketing Communications) for Yam Enterprises?",
        "What is the number of Licensed Applications for Yam Enterprises?",
        "For Yam Enterprises what is the number of applications aggregate Registered users?",
        "What is the number of licensed servers for Yam Enterprises?",
        "When is swap of Production Fonts available in Yam Enterprises?",
        "Who is the primary licensed monotype fonts user for Yam Enterprises?",
        "What is the number of Licensed Commercial Electronic Documents for Yam Enterprises?",
        "How many licensed monotype fonts users can Yam Enterprises have?",
        "How many licensed desktop users can Yam Enterprises have?",
        "Which contract type does Yam Enterprises follow?",
        "What monotype fonts support does Yam Enterprises have?",
        "Which monotype font services onboarding does Yam Enterprises have?",
        "Which Font/User Management does Yam Enterprises have?",
        "What Add-on inventory set did Yam Enterprises pick?",
        "Does Yam Enterprises have Single sign on?",
        "Is there Brand and Licence protection for Yam Enterprises?",
        "Who is the Third Party Payor's contact in Yam Enterprises?",
        "Does Yam Enterprises contract have Company Desktop License?",
        "What is the Number of Swaps Allowed for Yam Enterprises?",
        "When is swap of Production Fonts available in Yam Enterprises?",
    ]

    answers = [
        "Haruko Yamamoto",
        "81 90-1234-5603",
        "300 Production Fonts",
        "Helvetica Regular",
        "7",
        "300 Production Fonts",
        "Yam Enterprises has licensed a total of 105 Production Fonts.",
        "35,000,000",
        "2,500,000",
        "60",
        "40",
        "2",
        "Once per quarter",
        "Haruko Yamamoto",
        "0",
        "100",
        "60",
        "License",
        "Premier",
        "Premier",
        "Premier",
        "Plus",
        "Yes",
        "Yes",
        """
        Name: Yami Enterprises

        Contact: Mei Mei

        Address: 20-22 Tsuki-Tsuki-dori, Tokyo, Japan

        Phone: +81 71-9336-54023

        E-mail: mei.mei@example.com
        """,
        "Yes",
        "One (1) swap per calendar quarter",
        "The swap of Production Fonts will be available one (1) time per calendar quarter by removing Font Software as a Production Font and choosing other Font Software on the Monotype Fonts Platform.",
    ]

    retrieval_config = assistant_config.retrieval_config
    _llm_model = getattr(getattr(retrieval_config, "llm", None), "model", None) or getattr(retrieval_config, "model", None)
    if _llm_model is not None:
        _ai_app_sec_006_check_model(str(_llm_model))
    for i, (question, truth) in enumerate(zip(questions, answers, strict=False)):
        question = _ai_app_sec_059_guardrail.evaluate(question)
        question = _ai_app_sec_070_sanitize(question)
        chunk = brain.ask(question=question, retrieval_config=retrieval_config)
        _ai_dat_sec_012_masked_answer = _ai_dat_sec_012_mask_pii(chunk.answer)
        _ai_dat_sec_012_masked_truth = _ai_dat_sec_012_mask_pii(truth)
        print(
            "\n Question: ", question, "\n Answer: ", _ai_dat_sec_012_masked_answer, "\n Truth: ", _ai_dat_sec_012_masked_truth
        )
        if i == 5:
            break


if __name__ == "__main__":
    dotenv.load_dotenv()

    # Run the main function in the existing event loop
    asyncio.run(main())
