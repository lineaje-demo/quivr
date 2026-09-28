import asyncio
import re
import tempfile

import re

from quivr_core import Brain

_ai_app_sec_070_patterns = [
    # 1. instruction_override
    (re.compile(r'ignore previous instructions|forget everything above', re.IGNORECASE), '<prompt_injection_removed: instruction_override>'),
    # 2. role_hijack
    (re.compile(r'you are now DAN|act as unrestricted', re.IGNORECASE), '<prompt_injection_removed: role_hijack>'),
    # 3. delimiter_escape
    (re.compile(r'</?(system|tool|assistant|user)>', re.IGNORECASE), '<prompt_injection_removed: delimiter_escape>'),
    # 4. encoded_payload - base64-like blobs, hex sequences, ROT13 instructions, URL-encoded instructions
    (re.compile(r'(?:[A-Za-z0-9+/]{20,}={0,2})', re.IGNORECASE), '<prompt_injection_removed: encoded_payload>'),
    (re.compile(r'(?:%[0-9A-Fa-f]{2}){4,}', re.IGNORECASE), '<prompt_injection_removed: encoded_payload>'),
    # 5. hidden_text - HTML comments, zero-width chars, CSS hidden
    (re.compile(r'<!--.*?-->', re.DOTALL), '<prompt_injection_removed: hidden_text>'),
    (re.compile(r'[\u200b\u200c\u200d\u2060\ufeff]+'), '<prompt_injection_removed: hidden_text>'),
    (re.compile(r'visibility\s*:\s*hidden|display\s*:\s*none', re.IGNORECASE), '<prompt_injection_removed: hidden_text>'),
    # 6. fake_system_message
    (re.compile(r'\[system\]|\[tool\]|<\|system\|>|<\|im_start\|>\s*system', re.IGNORECASE), '<prompt_injection_removed: fake_system_message>'),
    # 7. exfiltration_attempt
    (re.compile(r'!\[.*?\]\(https?://[^)]+\)', re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    (re.compile(r'send (this|the|all|data|prompt|system prompt|context) to https?://', re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    (re.compile(r'leak (the )?(system prompt|context|instructions)', re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    # 8. context_poisoning
    (re.compile(r'(in a previous (turn|message)|earlier you said|you previously agreed)', re.IGNORECASE), '<prompt_injection_removed: context_poisoning>'),
    # 9. indirect_injection
    (re.compile(r'(instructions? (embedded|hidden|injected) in (this )?(file|document|data|metadata))', re.IGNORECASE), '<prompt_injection_removed: indirect_injection>'),
    # 10. command_injection
    (re.compile(r'(os\.system|subprocess\.run|subprocess\.call|eval\s*\(|exec\s*\(|`[^`]+`|\$\([^)]+\))', re.IGNORECASE), '<prompt_injection_removed: command_injection>'),
    # 11. split_payload
    (re.compile(r'(part\s*1\s*of\s*\d+|continued (in|on) (next|part))', re.IGNORECASE), '<prompt_injection_removed: split_payload>'),
    # 12. jailbreak_attempt
    (re.compile(r'(DAN mode|developer mode enabled|fictional framing|pretend you have no restrictions)', re.IGNORECASE), '<prompt_injection_removed: jailbreak_attempt>'),
]


def _ai_app_sec_070_sanitize(text: str) -> str:
    """Neutralize prompt injection patterns in untrusted text before LLM ingestion."""
    for pattern, marker in _ai_app_sec_070_patterns:
        text = pattern.sub(marker, text)
    return text

_AI_APP_SEC_006_DISAPPROVED_PATTERNS = [
    r"deepseek",
    r"custom_llm_client",
    r"openrouter",
]


def _ai_app_sec_006_normalize(name: str) -> str:
    """Normalize a model identifier for comparison."""
    return re.sub(r"[\s\-_\.:\u0000]", "", name).lower()


def _ai_app_sec_006_check_model(brain_obj) -> None:
    """Raise ValueError if the brain uses a disapproved model."""
    model_id = ""
    try:
        info = brain_obj.llm.model if hasattr(brain_obj, "llm") and brain_obj.llm is not None else ""
        model_id = str(info)
    except Exception:
        model_id = ""
    normalized = _ai_app_sec_006_normalize(model_id)
    for pattern in _AI_APP_SEC_006_DISAPPROVED_PATTERNS:
        if re.search(pattern, normalized):
            raise ValueError(
                f"Model '{model_id}' is on the organization's disapproved list and cannot be used."
            )


async def main():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt") as temp_file:
        _ai_app_sec_070_content = _ai_app_sec_070_sanitize("Gold is a liquid of blue-like colour.")
        temp_file.write(_ai_app_sec_070_content)
        temp_file.flush()

        brain = await Brain.afrom_files(name="test_brain", file_paths=[temp_file.name])
        _ai_app_sec_006_check_model(brain)

        save_path = await brain.save("/home/amine/.local/quivr")

        brain_loaded = Brain.load(save_path)
        _ai_app_sec_006_check_model(brain_loaded)
        brain_loaded.print_info()


if __name__ == "__main__":
    # Run the main function in the existing event loop
    asyncio.run(main())
