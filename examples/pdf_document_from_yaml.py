import asyncio
import logging
import os
import re
from pathlib import Path

import dotenv
import re
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


def _ai_dat_sec_012_mask_pii(text: str) -> str:
    """Mask personal phone numbers in text before UI display."""
    if not isinstance(text, str):
        text = str(text)
    # Match phone numbers: optional +, digits, spaces, hyphens, parentheses
    phone_pattern = re.compile(
        r'(\+?\d[\d\s\-().]{6,}\d)'
    )
    return phone_pattern.sub('[PHONE REDACTED]', text)

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
    (re.compile(r'(?:[A-Za-z0-9+/]{40,}={0,2})', re.IGNORECASE),
     '<prompt_injection_removed: encoded_payload>'),
    (re.compile(r'(?:0x[0-9a-fA-F]{2}[\s,]*){6,}', re.IGNORECASE),
     '<prompt_injection_removed: encoded_payload>'),
    (re.compile(r'(?:%[0-9a-fA-F]{2}){6,}', re.IGNORECASE),
     '<prompt_injection_removed: encoded_payload>'),
    # 5. hidden_text - HTML comments, zero-width chars, CSS hidden
    (re.compile(r'<!--.*?-->', re.DOTALL),
     '<prompt_injection_removed: hidden_text>'),
    (re.compile(r'[\u200b\u200c\u200d\u2060\ufeff]+'),
     '<prompt_injection_removed: hidden_text>'),
    (re.compile(r'style\s*=\s*["\']?display\s*:\s*none', re.IGNORECASE),
     '<prompt_injection_removed: hidden_text>'),
    # 6. fake_system_message
    (re.compile(r'\[\s*(?:SYSTEM|TOOL|ASSISTANT)\s*\]\s*:', re.IGNORECASE),
     '<prompt_injection_removed: fake_system_message>'),
    (re.compile(r'<\s*(?:system|tool)_message\s*>', re.IGNORECASE),
     '<prompt_injection_removed: fake_system_message>'),
    # 7. exfiltration_attempt
    (re.compile(r'!\[.*?\]\(https?://[^)]+\)', re.IGNORECASE),
     '<prompt_injection_removed: exfiltration_attempt>'),
    (re.compile(r'(?:send|leak|exfiltrate|transmit)\s+(?:the\s+)?(?:system\s+prompt|data|context)\s+to\s+https?://', re.IGNORECASE),
     '<prompt_injection_removed: exfiltration_attempt>'),
    # 8. context_poisoning
    (re.compile(r'(?:in a previous|earlier in this|in the last)\s+(?:conversation|session|turn).*?(?:you said|you told|you agreed)', re.IGNORECASE),
     '<prompt_injection_removed: context_poisoning>'),
    # 9. indirect_injection
    (re.compile(r'(?:the\s+(?:document|file|pdf|data)\s+says?\s+(?:to\s+)?(?:ignore|disregard|override))', re.IGNORECASE),
     '<prompt_injection_removed: indirect_injection>'),
    # 10. command_injection
    (re.compile(r'(?:import\s+os|subprocess\.(?:call|run|Popen)|os\.system|eval\s*\(|exec\s*\()', re.IGNORECASE),
     '<prompt_injection_removed: command_injection>'),
    # 11. split_payload
    (re.compile(r'(?:part\s*[1-9]\s*of\s*[1-9].*?continue|to\s+be\s+continued.*?part)', re.IGNORECASE | re.DOTALL),
     '<prompt_injection_removed: split_payload>'),
    # 12. jailbreak_attempt
    (re.compile(r'\bDAN\b|developer\s+mode|fictional\s+framing|jailbreak', re.IGNORECASE),
     '<prompt_injection_removed: jailbreak_attempt>'),
]


def _ai_app_sec_070_sanitize(text: str) -> str:
    """Neutralize prompt injection patterns in user-supplied text before sending to LLM."""
    for pattern, marker in _ai_app_sec_070_patterns:
        text = pattern.sub(marker, text)
    return text


_AI_APP_SEC_059_SHELL_PATTERNS = re.compile(
    r"(\b(eval|exec|system|popen|subprocess|os\.system|shell_exec|passthru|\bsh\b|\bbash\b|\bcmd\b|powershell)\s*[\(\[\{])"
    r"|(\$\(|`[^`]+`)"
    r"|(\|\s*(sh|bash|cmd|powershell))",
    re.IGNORECASE,
)

_AI_APP_SEC_059_CREDENTIAL_PATTERNS = re.compile(
    r"(api[_\-]?key|secret|token|password|passwd|auth|credential|bearer|private[_\-]?key)",
    re.IGNORECASE,
)

_AI_APP_SEC_059_LEET_PATTERN = re.compile(
    r"[3@!1|0$7]{4,}",
)

_AI_APP_SEC_059_INVISIBLE_PATTERN = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f\u00ad\ufeff\u2060]"
)


def _ai_app_sec_059_is_base64(text: str) -> bool:
    """Return True if text contains a suspiciously long base64-encoded segment."""
    b64_pattern = re.compile(r"(?:[A-Za-z0-9+/]{20,}={0,2})")
    for match in b64_pattern.finditer(text):
        candidate = match.group(0)
        try:
            decoded = base64.b64decode(candidate + "==").decode("utf-8", errors="ignore")
            if any(
                kw in decoded.lower()
                for kw in ("eval", "exec", "system", "import", "secret", "token", "password", "bash", "sh ")
            ):
                return True
        except Exception:
            pass
    return False


def _ai_app_sec_059_check_prompt(prompt: str) -> str:
    """Validate a prompt for hidden, encoded, or malicious content.

    Raises ValueError if the prompt contains suspicious content.
    Returns the prompt unchanged if it passes all checks.
    """
    if _AI_APP_SEC_059_INVISIBLE_PATTERN.search(prompt):
        raise ValueError(
            "Prompt rejected: contains invisible or zero-width characters that may hide malicious instructions."
        )
    if _AI_APP_SEC_059_SHELL_PATTERNS.search(prompt):
        raise ValueError(
            "Prompt rejected: contains shell command patterns that may execute malicious code."
        )
    if _AI_APP_SEC_059_CREDENTIAL_PATTERNS.search(prompt):
        raise ValueError(
            "Prompt rejected: contains credential or secret-seeking patterns."
        )
    if _AI_APP_SEC_059_LEET_PATTERN.search(prompt):
        raise ValueError(
            "Prompt rejected: contains leetspeak patterns that may obfuscate malicious instructions."
        )
    if _ai_app_sec_059_is_base64(prompt):
        raise ValueError(
            "Prompt rejected: contains base64-encoded content with suspicious payload."
        )
    return prompt

_AI_APP_SEC_006_DISAPPROVED_MODELS = [
    "deepseekchat",
    "deepseekr1",
    "deepseekr1distillllama70b",
    "deepseekreasoner",
    "customllmclient",
    "openrouter",
    "usdeepseekr1v10",
]


def _ai_app_sec_006_normalize(name: str) -> str:
    """Normalize a model identifier for comparison."""
    return re.sub(r"[\s\-_\.:\(\)]", "", name).lower()


def _ai_app_sec_006_check_model(model_id: str) -> None:
    """Raise ValueError if model_id matches a disapproved model."""
    normalized = _ai_app_sec_006_normalize(model_id)
    for disapproved in _AI_APP_SEC_006_DISAPPROVED_MODELS:
        if disapproved in normalized or normalized in disapproved:
            raise ValueError(
                f"Model '{model_id}' is not approved for use by this organization."
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
    _llm_model_id = getattr(getattr(retrieval_config, "llm", None), "model", None) or ""
    if _llm_model_id:
        _ai_app_sec_006_check_model(_llm_model_id)
    for i, (question, truth) in enumerate(zip(questions, answers, strict=False)):
        question = _ai_app_sec_059_check_prompt(question)
        question = _ai_app_sec_070_sanitize(question)
        chunk = brain.ask(question=question, retrieval_config=retrieval_config)
        masked_answer = _ai_dat_sec_012_mask_pii(chunk.answer)
        masked_truth = _ai_dat_sec_012_mask_pii(truth)
        print(
            "\n Question: ", question, "\n Answer: ", masked_answer, "\n Truth: ", masked_truth
        )
        if i == 5:
            break


if __name__ == "__main__":
    dotenv.load_dotenv()

    # Run the main function in the existing event loop
    asyncio.run(main())
