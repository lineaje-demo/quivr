import asyncio
import re
import tempfile

from dotenv import load_dotenv
from quivr_core import Brain
from quivr_core.quivr_rag import QuivrQARAG
from quivr_core.rag.quivr_rag_langgraph import QuivrQARAGLangGraph

_ai_app_sec_070_patterns = [
    # 1. instruction_override
    (re.compile(r'ignore previous instructions|forget everything above', re.IGNORECASE), '<prompt_injection_removed: instruction_override>'),
    # 2. role_hijack
    (re.compile(r'you are now DAN|act as unrestricted', re.IGNORECASE), '<prompt_injection_removed: role_hijack>'),
    # 3. delimiter_escape
    (re.compile(r'</?(system|tool|assistant|user)\s*>', re.IGNORECASE), '<prompt_injection_removed: delimiter_escape>'),
    # 4. encoded_payload - base64-like blobs, hex sequences, ROT13 instructions, URL-encoded instructions
    (re.compile(r'(?:[A-Za-z0-9+/]{20,}={0,2})', re.IGNORECASE), '<prompt_injection_removed: encoded_payload>'),
    (re.compile(r'(?:0x[0-9a-fA-F]{2}\s*){6,}', re.IGNORECASE), '<prompt_injection_removed: encoded_payload>'),
    (re.compile(r'(?:%[0-9a-fA-F]{2}){4,}', re.IGNORECASE), '<prompt_injection_removed: encoded_payload>'),
    # 5. hidden_text - HTML comments, zero-width chars, CSS hidden
    (re.compile(r'<!--.*?-->', re.DOTALL), '<prompt_injection_removed: hidden_text>'),
    (re.compile(r'[\u200b\u200c\u200d\u2060\ufeff]+'), '<prompt_injection_removed: hidden_text>'),
    (re.compile(r'style\s*=\s*["\']?display\s*:\s*none', re.IGNORECASE), '<prompt_injection_removed: hidden_text>'),
    # 6. fake_system_message
    (re.compile(r'\[\s*(?:system|tool|assistant)\s*\]\s*:', re.IGNORECASE), '<prompt_injection_removed: fake_system_message>'),
    (re.compile(r'<\|(?:system|tool|assistant|im_start|im_end)\|>', re.IGNORECASE), '<prompt_injection_removed: fake_system_message>'),
    # 7. exfiltration_attempt
    (re.compile(r'!\[.*?\]\(https?://[^)]+\)', re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    (re.compile(r'(?:send|leak|exfiltrate|transmit)\s+(?:the\s+)?(?:system\s+prompt|data|information)\s+to\s+https?://', re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    # 8. context_poisoning
    (re.compile(r'(?:in a previous conversation|earlier you said|you previously told me)', re.IGNORECASE), '<prompt_injection_removed: context_poisoning>'),
    # 9. indirect_injection
    (re.compile(r'(?:the file says|according to the document|metadata says)\s*[:\.]*\s*ignore', re.IGNORECASE), '<prompt_injection_removed: indirect_injection>'),
    # 10. command_injection
    (re.compile(r'(?:os\.system|subprocess\.(?:call|run|Popen)|eval\s*\(|exec\s*\()', re.IGNORECASE), '<prompt_injection_removed: command_injection>'),
    # 11. split_payload
    (re.compile(r'(?:part\s*1\s*of\s*\d+|continued\s+in\s+next\s+message|split\s+payload)', re.IGNORECASE), '<prompt_injection_removed: split_payload>'),
    # 12. jailbreak_attempt
    (re.compile(r'(?:DAN mode|developer mode enabled|fictional framing|pretend you have no restrictions|jailbreak)', re.IGNORECASE), '<prompt_injection_removed: jailbreak_attempt>'),
]


def _ai_app_sec_070_sanitize(text: str) -> str:
    """Neutralize prompt injection patterns in user-supplied text before sending to LLM."""
    for pattern, marker in _ai_app_sec_070_patterns:
        text = pattern.sub(marker, text)
    return text


_AI_APP_SEC_059_SUSPICIOUS_PATTERNS = [
    # Shell commands / binary execution
    re.compile(r'(?i)(\b(exec|eval|system|popen|subprocess|shell|cmd|bash|sh|powershell|wget|curl|nc|netcat|chmod|chown|sudo|su\b|rm\s+-rf|mkfifo|mknod|dd\s+if=|base64\s+-d)\b)'),
    # Credential / secret access
    re.compile(r'(?i)(auth[_\s]?token|api[_\s]?key|secret[_\s]?key|password|passwd|credentials|bearer\s+[a-z0-9\-._~+/]+=*|private[_\s]?key|access[_\s]?key|client[_\s]?secret)'),
    # Prompt injection / override attempts
    re.compile(r'(?i)(ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)|you\s+are\s+now|disregard\s+(all|previous)|act\s+as\s+(if\s+you\s+are|a\s+)|new\s+instructions?\s*:)'),
    # Invisible / whitespace steganography (long runs of whitespace)
    re.compile(r'(\s{20,})'),
    # Leetspeak indicators (common substitutions)
    re.compile(r'(?i)(3x3c|3v4l|5y5t3m|p0w3r5h3ll|b4sh|5h3ll|c0mm4nd)'),
]

_AI_APP_SEC_059_B64_PATTERN = re.compile(
    r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
)


def _ai_app_sec_059_check_prompt(prompt: str) -> str:
    """Check prompt for hidden, encoded, or malicious content before sending to LLM."""
    if not isinstance(prompt, str):
        raise ValueError("Prompt must be a string.")

    # Check for suspicious patterns
    for pattern in _AI_APP_SEC_059_SUSPICIOUS_PATTERNS:
        if pattern.search(prompt):
            raise ValueError(
                f"Prompt rejected: suspicious content detected matching pattern '{pattern.pattern}'."
            )

    # Check for base64-encoded payloads
    for match in _AI_APP_SEC_059_B64_PATTERN.finditer(prompt):
        candidate = match.group(0)
        if len(candidate) >= 16:
            try:
                decoded = base64.b64decode(candidate + '==').decode('utf-8', errors='ignore')
                for pattern in _AI_APP_SEC_059_SUSPICIOUS_PATTERNS:
                    if pattern.search(decoded):
                        raise ValueError(
                            "Prompt rejected: base64-encoded suspicious content detected."
                        )
            except Exception as exc:
                if 'rejected' in str(exc):
                    raise

    return prompt

_AI_APP_SEC_006_DISAPPROVED = [
    "deepseekchat",
    "deepseekr1",
    "deepseekr1distillllama70b",
    "deepseakreasoner",
    "deepseakreasoner",
    "customllmclientnull",
    "deepseekchatnull",
    "openrouternull",
    "usdeepseekr1v10null",
]


def _ai_app_sec_006_normalize(model_id: str) -> str:
    """Normalize a model identifier for registry comparison."""
    return re.sub(r"[\s\-_\.:\u00b7]", "", model_id).lower()


def _ai_app_sec_006_check_model(model_id: str) -> None:
    """Raise ValueError if model_id matches a disapproved model in the registry."""
    normalized = _ai_app_sec_006_normalize(model_id)
    for disapproved in _AI_APP_SEC_006_DISAPPROVED:
        if disapproved in normalized or normalized in disapproved:
            raise ValueError(
                f"Model '{model_id}' is on the organization's disapproved model list "
                "and cannot be used."
            )


async def main():
    dotenv_path = "/Users/jchevall/Coding/QuivrHQ/quivr/.env"
    load_dotenv(dotenv_path)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt") as temp_file:
        temp_file.write("Gold is a liquid of blue-like colour.")
        temp_file.flush()

        _ai_app_sec_006_check_model("QuivrQARAG")
        _ai_app_sec_006_check_model("QuivrQARAGLangGraph")
        brain = await Brain.afrom_files(name="test_brain", file_paths=[temp_file.name])

        await brain.save("~/.local/quivr")

                question = "what is gold? answer in french"
        question = _ai_app_sec_070_sanitize(question)
        async for chunk in brain.ask_streaming(question, rag_pipeline=QuivrQARAG):
            print("answer QuivrQARAG:", chunk.answer)

        async for chunk in brain.ask_streaming(
            question, rag_pipeline=QuivrQARAGLangGraph
        ):
            print("answer QuivrQARAGLangGraph:", chunk.answer)


if __name__ == "__main__":
    # Run the main function in the existing event loop
    asyncio.run(main())
