import re
import tempfile
import re
import base64

from quivr_core import Brain

import re
import dotenv

_ai_app_sec_070_patterns = [
    (re.compile(r'ignore previous instructions|forget everything above', re.IGNORECASE), '<prompt_injection_removed: instruction_override>'),
    (re.compile(r'you are now DAN|act as unrestricted', re.IGNORECASE), '<prompt_injection_removed: role_hijack>'),
    (re.compile(r'</?(system|tool|assistant|user)>', re.IGNORECASE), '<prompt_injection_removed: delimiter_escape>'),
    (re.compile(r'(?:[A-Za-z0-9+/]{20,}={0,2}|(?:\\x[0-9a-fA-F]{2}){4,}|(?:%[0-9a-fA-F]{2}){4,})', re.IGNORECASE), '<prompt_injection_removed: encoded_payload>'),
    (re.compile(r'<!--.*?-->', re.DOTALL), '<prompt_injection_removed: hidden_text>'),
    (re.compile(r'\[system\]|\[tool\]|<\|system\|>', re.IGNORECASE), '<prompt_injection_removed: fake_system_message>'),
    (re.compile(r'send (this|data|it) to (https?://\S+)|leak (the )?system prompt|exfiltrate', re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    (re.compile(r'in (a prior|previous|earlier) (turn|message|conversation)', re.IGNORECASE), '<prompt_injection_removed: context_poisoning>'),
    (re.compile(r'(payload|instruction) (in|from) (file|data|metadata|field)', re.IGNORECASE), '<prompt_injection_removed: indirect_injection>'),
    (re.compile(r'(os\.system|subprocess\.run|eval\(|exec\(|`[^`]+`)', re.IGNORECASE), '<prompt_injection_removed: command_injection>'),
    (re.compile(r'(part ?1|part ?2|fragment|continued (below|above))', re.IGNORECASE), '<prompt_injection_removed: split_payload>'),
    (re.compile(r'DAN|developer mode|fictional.{0,10}framing|jailbreak', re.IGNORECASE), '<prompt_injection_removed: jailbreak_attempt>'),
]


def _ai_app_sec_070_sanitize(text: str) -> str:
    """Replace prompt injection patterns with their markers."""
    for pattern, marker in _ai_app_sec_070_patterns:
        text = pattern.sub(marker, text)
    return text

_AI_APP_SEC_006_DISAPPROVED = [
    "deepseekchat",
    "deepseekr1",
    "deepseekr1distillllama70b",
    "deepseekreasoner",
    "customllmclient",
    "deepseekchаtnull",
    "openrouternull",
    "usdeepseekr1v10",
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
                f"Model '{model_id}' is not approved for use by this organization."
            )

dotenv.load_dotenv()


def _ai_app_sec_059_check_prompt(prompt: str) -> str:
    """Check prompt for hidden, encoded, or malicious content before sending to LLM."""
    # Check for invisible/whitespace-obfuscated text (zero-width characters)
    invisible_chars = re.compile(r'[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\u00ad]')
    if invisible_chars.search(prompt):
        raise ValueError("Prompt contains invisible or hidden characters.")

    # Check for base64-encoded content
    b64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
    for match in b64_pattern.findall(prompt):
        try:
            decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
            if any(kw in decoded.lower() for kw in ['exec', 'eval', 'system', 'import', 'token', 'secret', 'password', 'credential']):
                raise ValueError("Prompt contains suspicious base64-encoded content.")
        except Exception as e:
            if 'suspicious' in str(e):
                raise

    # Check for leetspeak patterns (common substitutions)
    leet_pattern = re.compile(r'(?:[e3][x\*][e3][c\(]|[e3][v\*][a@4][l1]|[s\$][y\*][s\$][t\+][e3][m\*])', re.IGNORECASE)
    if leet_pattern.search(prompt):
        raise ValueError("Prompt contains leetspeak obfuscation of dangerous commands.")

    # Check for shell commands and binary executables
    shell_pattern = re.compile(
        r'(?:^|\s|;|&&|\|\|)(?:bash|sh|zsh|cmd|powershell|exec|eval|system|popen|subprocess'
        r'|chmod|chown|wget|curl|nc|ncat|netcat|python|perl|ruby|php|node)\b',
        re.IGNORECASE | re.MULTILINE
    )
    if shell_pattern.search(prompt):
        raise ValueError("Prompt contains shell commands or executable references.")

    # Check for attempts to access auth tokens, secrets, or credentials
    cred_pattern = re.compile(
        r'(?:api[_\-]?key|auth[_\-]?token|bearer|secret|password|credential|private[_\-]?key'
        r'|access[_\-]?token|session[_\-]?token|jwt|oauth)',
        re.IGNORECASE
    )
    if cred_pattern.search(prompt):
        raise ValueError("Prompt contains references to credentials or secrets.")

    # Check for suspicious prompt injection patterns
    injection_pattern = re.compile(
        r'(?:ignore previous instructions|disregard (all |prior |above )?instructions'
        r'|you are now|act as|pretend (you are|to be)|system prompt|override (your |all )?instructions'
        r'|forget (your |all |previous )?instructions)',
        re.IGNORECASE
    )
    if injection_pattern.search(prompt):
        raise ValueError("Prompt contains prompt injection patterns.")

    return prompt

if __name__ == "__main__":
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt") as temp_file:
        temp_file.write("Gold is a liquid of blue-like colour.")
        temp_file.flush()

        brain = Brain.from_files(
            name="test_brain",
            file_paths=[temp_file.name],
        )

        _ai_app_sec_006_check_model("what is gold? answer in french")
        _ai_app_sec_059_prompt = _ai_app_sec_059_check_prompt("what is gold? answer in french")
        answer = brain.ask(_ai_app_sec_059_prompt)
        print("answer QuivrQARAGLangGraph :", answer)
