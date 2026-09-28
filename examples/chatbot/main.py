import re
import base64
import re
import re
import re
import re
import tempfile

import chainlit as cl
from quivr_core import Brain
from quivr_core.rag.entities.config import RetrievalConfig

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
    # Personal Phone Number (US and international)
    (re.compile(r'\b(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b'), '[REDACTED_PHONE]'),
    # IP Address (IPv4)
    (re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'), '[REDACTED_IP]'),
    # IP Address (IPv6)
    (re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'), '[REDACTED_IPV6]'),
    # MAC Address
    (re.compile(r'\b(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b'), '[REDACTED_MAC]'),
    # Passport Number (generic: letter(s) followed by digits)
    (re.compile(r'\b[A-Z]{1,2}[0-9]{6,9}\b'), '[REDACTED_PASSPORT]'),
    # Driver's License Number (common US formats)
    (re.compile(r'\b[A-Z]{1,2}\d{5,8}\b'), '[REDACTED_DL]'),
    # Financial Account Number (8-17 digit sequences not already matched)
    (re.compile(r'\b\d{8,17}\b'), '[REDACTED_ACCOUNT]'),
    # Vehicle Identification Number (VIN)
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), '[REDACTED_VIN]'),
    # Year of Birth (standalone 4-digit year in range 1900-2009)
    (re.compile(r'\b(?:19[0-9]{2}|200[0-9])\b'), '[REDACTED_YOB]'),
]


def _ai_dat_sec_023_redact_pii(text: str) -> str:
    """Redact zero-tolerance PII categories from the given text."""
    for pattern, replacement in _ai_dat_sec_023_patterns:
        text = pattern.sub(replacement, text)
    return text

_ai_dat_sec_012_patterns = [
    # Social Security Number
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), '[SSN REDACTED]'),
    # Taxpayer Identification Number (EIN format)
    (re.compile(r'\b\d{2}-\d{7}\b'), '[TIN REDACTED]'),
    # Credit Card Number (major card patterns)
    (re.compile(r'\b(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'), '[CC REDACTED]'),
    # Financial Account Number (generic 8-17 digit)
    (re.compile(r'\b\d{8,17}\b'), '[ACCOUNT REDACTED]'),
    # Email address
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[EMAIL REDACTED]'),
    # Personal Phone Number
    (re.compile(r'\b(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b'), '[PHONE REDACTED]'),
    # Passport Number (generic alphanumeric 6-9 chars)
    (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), '[PASSPORT REDACTED]'),
    # Driver's License (common US formats)
    (re.compile(r'\b[A-Z]{1,2}\d{5,8}\b'), '[DL REDACTED]'),
    # IP Address (IPv4)
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '[IP REDACTED]'),
    # MAC Address
    (re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), '[MAC REDACTED]'),
    # Vehicle Identification Number (VIN)
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), '[VIN REDACTED]'),
    # Year of Birth (standalone 4-digit year 1900-2099 near birth keywords)
    (re.compile(r'(?i)\b(?:born|birth(?:day|date)?|dob|year of birth)[:\s]+(?:in\s+)?((?:19|20)\d{2})\b'), lambda m: m.group(0).replace(m.group(1), '[YOB REDACTED]')),
]


def _ai_dat_sec_012_mask_pii(text: str) -> str:
    """Mask zero-tolerance PII categories in text before UI display."""
    if not text:
        return text
    for pattern, replacement in _ai_dat_sec_012_patterns:
        text = pattern.sub(replacement, text)
    return text

_ai_app_sec_070_patterns = [
    # 1. instruction_override
    (re.compile(
        r'ignore\s+previous\s+instructions|forget\s+everything\s+above',
        re.IGNORECASE),
     '<prompt_injection_removed: instruction_override>'),
    # 2. role_hijack
    (re.compile(
        r'you\s+are\s+now\s+DAN|act\s+as\s+unrestricted',
        re.IGNORECASE),
     '<prompt_injection_removed: role_hijack>'),
    # 3. delimiter_escape - fake </system>, </prompt>, </instruction> tags or injected separators
    (re.compile(
        r'</?\s*(?:system|prompt|instruction|context|human|assistant)\s*>',
        re.IGNORECASE),
     '<prompt_injection_removed: delimiter_escape>'),
    # 4. encoded_payload - base64 blobs, hex sequences, ROT13 cues, URL-encoded instructions
    (re.compile(
        r'(?:[A-Za-z0-9+/]{40,}={0,2})|(?:(?:%[0-9A-Fa-f]{2}){10,})|(?:\\u[0-9A-Fa-f]{4}){5,}',
        re.IGNORECASE),
     '<prompt_injection_removed: encoded_payload>'),
    # 5. hidden_text - HTML comments, zero-width chars, CSS hidden
    (re.compile(
        r'<!--.*?-->|[\u200b-\u200f\u202a-\u202e\ufeff]|style\s*=\s*["\']?display\s*:\s*none',
        re.IGNORECASE | re.DOTALL),
     '<prompt_injection_removed: hidden_text>'),
    # 6. fake_system_message
    (re.compile(
        r'\[\s*(?:system|tool|assistant|function)\s*\]\s*:',
        re.IGNORECASE),
     '<prompt_injection_removed: fake_system_message>'),
    # 7. exfiltration_attempt - markdown image exfil, send/leak data to URLs
    (re.compile(
        r'!\[.*?\]\(https?://[^)]*\?[^)]*\)|(?:send|leak|exfiltrate|transmit)\s+(?:the\s+)?(?:system\s+prompt|data|context)\s+to\s+https?://',
        re.IGNORECASE),
     '<prompt_injection_removed: exfiltration_attempt>'),
    # 8. context_poisoning
    (re.compile(
        r'context\s+poison(?:ing)?|multi[- ]turn\s+manipulat',
        re.IGNORECASE),
     '<prompt_injection_removed: context_poisoning>'),
    # 9. indirect_injection - payloads embedded in metadata/data fields
    (re.compile(
        r'<\s*inject\s*>|\{\{\s*inject\s*\}\}|<!--\s*inject',
        re.IGNORECASE),
     '<prompt_injection_removed: indirect_injection>'),
    # 10. command_injection - shell/code execution attempts
    (re.compile(
        r'(?:^|\s)(?:sudo|rm\s+-rf|chmod|wget|curl|bash|sh|python|perl|ruby|php)\s+',
        re.IGNORECASE | re.MULTILINE),
     '<prompt_injection_removed: command_injection>'),
    # 11. split_payload - fragmented payload markers
    (re.compile(
        r'(?:part\s*\d+\s*of\s*\d+|fragment\s*\d+|continued\s+from\s+previous)',
        re.IGNORECASE),
     '<prompt_injection_removed: split_payload>'),
    # 12. jailbreak_attempt - DAN, developer mode, fictional framing
    (re.compile(
        r'\bDAN\b|developer\s+mode|jailbreak|fictional\s+framing|pretend\s+you\s+(?:have\s+no\s+restrictions|are\s+an?\s+AI\s+without)',
        re.IGNORECASE),
     '<prompt_injection_removed: jailbreak_attempt>'),
]


def _ai_app_sec_070_sanitize(text: str) -> str:
    """Neutralize prompt injection patterns in untrusted text before sending to LLM."""
    for pattern, marker in _ai_app_sec_070_patterns:
        text = pattern.sub(marker, text)
    return text


_ai_app_sec_059_SUSPICIOUS_PATTERNS = [
    # Shell / OS commands
    re.compile(r'(?i)(\b(bash|sh|zsh|cmd|powershell|exec|system|popen|subprocess|os\.system|eval|execve)\s*[\(\[`$])', re.MULTILINE),
    # Binary / null bytes
    re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]'),
    # Base64-encoded blocks (>=40 chars of base64 alphabet)
    re.compile(r'(?:[A-Za-z0-9+/]{40,}={0,2})'),
    # Credential / secret seeking
    re.compile(r'(?i)(api[_\-]?key|secret[_\-]?key|auth[_\-]?token|bearer\s+[A-Za-z0-9\-._~+/]+=*|password\s*=|access[_\-]?token)'),
    # Leetspeak indicators (common substitutions in bulk)
    re.compile(r'(?i)(3x3c|3v4l|sh3ll|c0mm4nd|1nj3ct|pwn|r00t|h4x)'),
    # Invisible / whitespace steganography (many consecutive non-breaking or zero-width spaces)
    re.compile(r'[\u200b\u200c\u200d\u2060\ufeff\u00a0]{3,}'),
    # Prompt injection keywords
    re.compile(r'(?i)(ignore (previous|prior|above|all) instructions|disregard (previous|prior|above|all)|you are now|act as (an? )?(unrestricted|jailbreak|dan)|forget (your|all) (previous )?instructions)'),
]


def _ai_app_sec_059_check_prompt(text: str, label: str = "input") -> str:
    """Scan text for hidden, encoded, or malicious prompt content.

    Raises ValueError if a suspicious pattern is detected.
    Returns the original text unchanged if no issues are found.
    """
    if not isinstance(text, str):
        raise ValueError(f"_ai_app_sec_059_check_prompt: {label} must be a string")

    # Check raw text against all patterns
    for pattern in _ai_app_sec_059_SUSPICIOUS_PATTERNS:
        if pattern.search(text):
            raise ValueError(
                f"Potentially malicious or hidden prompt detected in {label}. "
                "Request blocked for security reasons."
            )

    # Additionally attempt base64 decode and re-scan decoded content
    b64_candidates = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text)
    for candidate in b64_candidates:
        try:
            decoded = base64.b64decode(candidate + '==').decode('utf-8', errors='ignore')
            for pattern in _ai_app_sec_059_SUSPICIOUS_PATTERNS:
                if pattern.search(decoded):
                    raise ValueError(
                        f"Base64-encoded malicious content detected in {label}. "
                        "Request blocked for security reasons."
                    )
        except Exception as exc:
            if isinstance(exc, ValueError):
                raise
            # Decoding failed — not valid base64, skip
            pass

    return text

_AI_APP_SEC_006_DISAPPROVED = [
    "deepseekchat",
    "deepseekr1distillllama70b",
    "deepseekr1",
    "deepseekreasoner",
    "customllmclientnull",
    "deepseekchatnull",
    "openrouternull",
    "usdeepseekr1v10null",
]


def _ai_app_sec_006_normalize(name: str) -> str:
    """Normalize a model identifier for comparison."""
    return re.sub(r"[\s\-_\.:\u0000]", "", name).lower()


def _ai_app_sec_006_check_model(model_id: str) -> None:
    """Raise ValueError if model_id matches a disapproved model."""
    normalized = _ai_app_sec_006_normalize(model_id)
    for disapproved in _AI_APP_SEC_006_DISAPPROVED:
        if disapproved in normalized or normalized in disapproved:
            raise ValueError(
                f"Model '{model_id}' is not permitted by the organization's model policy."
            )


def _ai_app_sec_006_check_config(retrieval_config: RetrievalConfig) -> None:
    """Inspect a RetrievalConfig for disapproved model identifiers."""
    # Walk all string-valued attributes of the config looking for model names
    for attr_name in dir(retrieval_config):
        if attr_name.startswith("_"):
            continue
        try:
            val = getattr(retrieval_config, attr_name)
        except Exception:
            continue
        if isinstance(val, str) and val.strip():
            _ai_app_sec_006_check_model(val)
        elif hasattr(val, "__dict__"):
            for sub_attr in dir(val):
                if sub_attr.startswith("_"):
                    continue
                try:
                    sub_val = getattr(val, sub_attr)
                except Exception:
                    continue
                if isinstance(sub_val, str) and sub_val.strip():
                    _ai_app_sec_006_check_model(sub_val)


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

    _ai_app_sec_059_check_prompt(text, label="uploaded file content")

        text = _ai_dat_sec_023_redact_pii(text)

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=file.name, delete=False
    ) as temp_file:
        temp_file.write(text)
        temp_file.flush()
        temp_file_path = temp_file.name

    _ai_app_sec_006_check_model("user_brain")
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
    _ai_app_sec_006_check_config(retrieval_config)
    _ai_app_sec_059_check_prompt(message.content, label="user message")
    sanitized_message_content = _ai_app_sec_070_sanitize(message.content)
    async for chunk in brain.ask_streaming(sanitized_message_content, retrieval_config=retrieval_config):
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