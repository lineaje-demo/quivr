import re
import re
import re
import re
import tempfile

import chainlit as cl

# PII redaction patterns for zero-tolerance PII categories
_ai_dat_sec_023_patterns = [
    # Social Security Number
    (re.compile(r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'), '[REDACTED_SSN]'),
    # Taxpayer Identification Number (EIN format)
    (re.compile(r'\b\d{2}-\d{7}\b'), '[REDACTED_TIN]'),
    # Credit Card Number (Visa, MC, Amex, Discover)
    (re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'), '[REDACTED_CC]'),
    # Email address
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[REDACTED_EMAIL]'),
    # Personal Phone Number (US formats)
    (re.compile(r'\b(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b'), '[REDACTED_PHONE]'),
    # IP Address (IPv4)
    (re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'), '[REDACTED_IP]'),
    # MAC Address
    (re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), '[REDACTED_MAC]'),
    # Passport Number (generic: letter(s) followed by digits)
    (re.compile(r'\b[A-Z]{1,2}[0-9]{6,9}\b'), '[REDACTED_PASSPORT]'),
    # Driver's License Number (common US formats)
    (re.compile(r'\b[A-Z]{1,2}\d{5,8}\b'), '[REDACTED_DL]'),
    # Financial Account Number (8-17 digit sequences not already matched)
    (re.compile(r'\b\d{8,17}\b'), '[REDACTED_ACCOUNT]'),
    # Year of Birth (standalone 4-digit year in range 1900-2099)
    (re.compile(r'\b(?:born|dob|date of birth|year of birth)[^\n]{0,30}((?:19|20)\d{2})\b', re.IGNORECASE), '[REDACTED_YOB]'),
    # Vehicle Identification Number (17 chars, no I/O/Q)
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), '[REDACTED_VIN]'),
    # Employee ID / School ID patterns
    (re.compile(r'\b(?:employee|emp|school|student)[\s_\-]?(?:id|ID|#|number)[:\s]+[A-Z0-9\-]{4,20}\b', re.IGNORECASE), '[REDACTED_ID]'),
    # Home Address (street address pattern)
    (re.compile(r'\b\d{1,5}\s+(?:[A-Za-z]+\s){1,4}(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b', re.IGNORECASE), '[REDACTED_ADDRESS]'),
    # Mother's Maiden Name indicator
    (re.compile(r"\b(?:mother'?s?\s+maiden\s+name|maiden\s+name)[:\s]+[A-Za-z\-']+\b", re.IGNORECASE), '[REDACTED_MAIDEN_NAME]'),
    # Birthplace indicator
    (re.compile(r'\b(?:birthplace|place of birth|born in)[:\s]+[A-Za-z\s,]+\b', re.IGNORECASE), '[REDACTED_BIRTHPLACE]'),
    # Ethnicity indicator
    (re.compile(r'\b(?:ethnicity|ethnic origin|race)[:\s]+[A-Za-z\s]+\b', re.IGNORECASE), '[REDACTED_ETHNICITY]'),
    # Sexual Orientation indicator
    (re.compile(r'\b(?:sexual orientation|sexuality)[:\s]+[A-Za-z\s]+\b', re.IGNORECASE), '[REDACTED_SEXUAL_ORIENTATION]'),
    # Medical Records indicator
    (re.compile(r'\b(?:medical record|diagnosis|prescription|patient id)[:\s]+[A-Za-z0-9\s,]+\b', re.IGNORECASE), '[REDACTED_MEDICAL]'),
    # Fine Location (GPS coordinates)
    (re.compile(r'\b[-+]?(?:[1-8]?\d(?:\.\d+)?|90(?:\.0+)?)\s*,\s*[-+]?(?:180(?:\.0+)?|(?:1[0-7]\d|[1-9]?\d)(?:\.\d+)?)\b'), '[REDACTED_LOCATION]'),
]


def _ai_dat_sec_023_redact_pii(text: str) -> str:
    """Redact zero-tolerance PII categories from the given text."""
    for pattern, replacement in _ai_dat_sec_023_patterns:
        text = pattern.sub(replacement, text)
    return text
from quivr_core import Brain
from quivr_core.rag.entities.config import RetrievalConfig


_ai_dat_sec_012_PATTERNS = [
    # Social Security Number
    (re.compile(r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'), '[SSN REDACTED]'),
    # Taxpayer Identification Number (EIN style)
    (re.compile(r'\b\d{2}-\d{7}\b'), '[TIN REDACTED]'),
    # Credit Card Number (Visa, MC, Amex, Discover)
    (re.compile(r'\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b'), '[CC REDACTED]'),
    # Financial Account / generic long numeric account
    (re.compile(r'\b\d{8,17}\b'), '[ACCOUNT REDACTED]'),
    # Email
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[EMAIL REDACTED]'),
    # Personal Phone Number (US and international)
    (re.compile(r'(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b'), '[PHONE REDACTED]'),
    # IP Address (v4)
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '[IP REDACTED]'),
    # MAC Address
    (re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), '[MAC REDACTED]'),
    # Passport Number (generic: letter(s) + digits)
    (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), '[PASSPORT REDACTED]'),
    # Drivers License (common US formats)
    (re.compile(r'\b[A-Z]\d{7}\b|\b\d{3}-\d{3}-\d{3}\b'), '[DL REDACTED]'),
    # Year of Birth (standalone 4-digit year 1900-2009)
    (re.compile(r'\b(?:19|20)\d{2}\b'), '[YOB REDACTED]'),
    # Home Address (number + street)
    (re.compile(r'\b\d{1,5}\s+[A-Za-z0-9 .]{3,30}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b', re.IGNORECASE), '[ADDRESS REDACTED]'),
]


def _ai_dat_sec_012_mask_pii(text: str) -> str:
    """Mask zero-tolerance PII categories before displaying text in the UI."""
    if not text:
        return text
    for pattern, replacement in _ai_dat_sec_012_PATTERNS:
        text = pattern.sub(replacement, text)
    return text

_ai_app_sec_070_patterns = [
    # 1. instruction_override
    (re.compile(r'ignore\s+previous\s+instructions', re.IGNORECASE), '<prompt_injection_removed: instruction_override>'),
    (re.compile(r'forget\s+everything\s+above', re.IGNORECASE), '<prompt_injection_removed: instruction_override>'),
    # 2. role_hijack
    (re.compile(r'you\s+are\s+now\s+DAN', re.IGNORECASE), '<prompt_injection_removed: role_hijack>'),
    (re.compile(r'act\s+as\s+unrestricted', re.IGNORECASE), '<prompt_injection_removed: role_hijack>'),
    # 3. delimiter_escape
    (re.compile(r'</?(system|SYSTEM|tool|TOOL|assistant|ASSISTANT)\s*>', re.IGNORECASE), '<prompt_injection_removed: delimiter_escape>'),
    # 4. encoded_payload
    (re.compile(r'(?:[A-Za-z0-9+/]{20,}={0,2})(?:\s+(?:decode|base64|encoded))', re.IGNORECASE), '<prompt_injection_removed: encoded_payload>'),
    (re.compile(r'\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){4,}', re.IGNORECASE), '<prompt_injection_removed: encoded_payload>'),
    # 5. hidden_text
    (re.compile(r'<!--.*?-->', re.DOTALL), '<prompt_injection_removed: hidden_text>'),
    (re.compile(r'[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad]+'), '<prompt_injection_removed: hidden_text>'),
    # 6. fake_system_message
    (re.compile(r'\[\s*(?:SYSTEM|TOOL|ASSISTANT)\s*\]\s*:', re.IGNORECASE), '<prompt_injection_removed: fake_system_message>'),
    (re.compile(r'<\s*(?:system|tool)_message\s*>', re.IGNORECASE), '<prompt_injection_removed: fake_system_message>'),
    # 7. exfiltration_attempt
    (re.compile(r'!\[.*?\]\(https?://[^)]+\)', re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    (re.compile(r'(?:send|leak|exfiltrate|transmit)\s+(?:the\s+)?(?:system\s+prompt|data|context)\s+to\s+https?://', re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    # 8. context_poisoning
    (re.compile(r'(?:in\s+a\s+previous\s+(?:turn|message)|earlier\s+you\s+(?:said|agreed|confirmed)).*?(?:now|therefore)\s+you\s+(?:must|should|will)', re.IGNORECASE | re.DOTALL), '<prompt_injection_removed: context_poisoning>'),
    # 9. indirect_injection
    (re.compile(r'<!--\s*inject', re.IGNORECASE), '<prompt_injection_removed: indirect_injection>'),
    # 10. command_injection
    (re.compile(r'(?:^|\s)(?:eval|exec|os\.system|subprocess\.(?:call|run|Popen))\s*\(', re.MULTILINE), '<prompt_injection_removed: command_injection>'),
    # 11. split_payload
    (re.compile(r'(?:part\s*1\s*of\s*\d+|continued\s+in\s+next\s+message|split\s+payload)', re.IGNORECASE), '<prompt_injection_removed: split_payload>'),
    # 12. jailbreak_attempt
    (re.compile(r'\bDAN\b'), '<prompt_injection_removed: jailbreak_attempt>'),
    (re.compile(r'developer\s+mode', re.IGNORECASE), '<prompt_injection_removed: jailbreak_attempt>'),
    (re.compile(r'fictional\s+(?:framing|scenario|roleplay)', re.IGNORECASE), '<prompt_injection_removed: jailbreak_attempt>'),
]


def _ai_app_sec_070_sanitize(text: str) -> str:
    """Neutralize prompt injection patterns in untrusted text before sending to LLM."""
    for pattern, marker in _ai_app_sec_070_patterns:
        text = pattern.sub(marker, text)
    return text
from lineaje_guardrail import lineaje_guardrail

_ai_app_sec_059_guardrail = lineaje_guardrail()
_ai_app_sec_059_guardrail.enable_policies(["AI_APP_SEC_059.json"])

_AI_APP_SEC_006_DISAPPROVED_PATTERNS = [
    r"deepseek",
    r"customllmclient",
    r"openrouter",
    r"usdeepseekr1v10",
]


def _ai_app_sec_006_normalize(name: str) -> str:
    """Normalize a model identifier for comparison."""
    return re.sub(r"[\s\-_\.:\"']", "", name).lower()


def _ai_app_sec_006_check_model(model_identifier: str) -> None:
    """Raise ValueError if the model identifier matches a disapproved model."""
    normalized = _ai_app_sec_006_normalize(model_identifier)
    for pattern in _AI_APP_SEC_006_DISAPPROVED_PATTERNS:
        if re.search(pattern, normalized):
            raise ValueError(
                f"Model '{model_identifier}' is not permitted by the organization's model policy."
            )


def _ai_app_sec_006_validate_retrieval_config(retrieval_config: RetrievalConfig) -> None:
    """Check all model references in a RetrievalConfig for disapproved models."""
    try:
        llm_config = retrieval_config.llm
        if llm_config is not None:
            model_name = getattr(llm_config, "model", None) or getattr(llm_config, "model_name", None)
            if model_name:
                _ai_app_sec_006_check_model(str(model_name))
    except AttributeError:
        pass


@cl.on_chat_start
async def on_chat_start():
    files = None

    # Wait for the user to upload a file
    while files is None:
        files = await cl.AskFileMessage(
            content="Please upload a text .txt file to begin!",
            accept=["text/plain"],
            max_size_mb=20,
            timeout=180,
        ).send()

    file = files[0]

    msg = cl.Message(content=f"Processing `{file.name}`...")
    await msg.send()

    with open(file.path, "r", encoding="utf-8") as f:
        text = f.read()
    text = _ai_dat_sec_023_redact_pii(text)
    text = _ai_app_sec_070_sanitize(text)
    text = _ai_app_sec_059_guardrail.evaluate(text)

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=file.name, delete=False
    ) as temp_file:
        temp_file.write(text)
        temp_file.flush()
        temp_file_path = temp_file.name

    brain = Brain.from_files(name="user_brain", file_paths=[temp_file_path])

    # Store the file path in the session
    cl.user_session.set("file_path", temp_file_path)

    # Let the user know that the system is ready
    msg.content = f"Processing `{file.name}` done. You can now ask questions!"
    await msg.update()

    cl.user_session.set("brain", brain)


@cl.on_message
async def main(message: cl.Message):
    brain = cl.user_session.get("brain")  # type: Brain
    path_config = "basic_rag_workflow.yaml"
    retrieval_config = RetrievalConfig.from_yaml(path_config)

    if brain is None:
        await cl.Message(content="Please upload a file first.").send()
        return

    # Prepare the message for streaming
    msg = cl.Message(content="", elements=[])
    await msg.send()

    saved_sources = set()
    saved_sources_complete = []
    elements = []

    # Use the ask_stream method for streaming responses
    _ai_app_sec_006_validate_retrieval_config(retrieval_config)
    _ai_app_sec_059_prompt = _ai_app_sec_059_guardrail.evaluate(message.content)
    async for chunk in brain.ask_streaming(_ai_app_sec_059_prompt, retrieval_config=retrieval_config):
        await msg.stream_token(chunk.answer)
        for source in chunk.metadata.sources:
            if source.page_content not in saved_sources:
                saved_sources.add(source.page_content)
                saved_sources_complete.append(source)
                print(source)
                elements.append(cl.Text(name=source.metadata["original_file_name"], content=_ai_dat_sec_012_mask_pii(source.page_content), display="side"))

    
    await msg.send()
    sources = ""
    for source in saved_sources_complete:
        sources += f"- {source.metadata['original_file_name']}\n"
    msg.elements = elements
    msg.content = _ai_dat_sec_012_mask_pii(msg.content) + f"\n\nSources:\n{sources}"
    await msg.update()