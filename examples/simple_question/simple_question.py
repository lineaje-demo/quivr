import re
import tempfile
from lineaje_guardrail import lineaje_guardrail, GuardrailBlockedError

_ai_app_sec_059_guardrail = lineaje_guardrail()
_ai_app_sec_059_guardrail.enable_policies(["AI_APP_SEC_059.json"])

from quivr_core import Brain

import re
import dotenv

_ai_app_sec_070_patterns = [
    (re.compile(r'ignore previous instructions|forget everything above', re.IGNORECASE), '<prompt_injection_removed: instruction_override>'),
    (re.compile(r'you are now DAN|act as unrestricted', re.IGNORECASE), '<prompt_injection_removed: role_hijack>'),
    (re.compile(r'</?(system|tool|assistant|user)>', re.IGNORECASE), '<prompt_injection_removed: delimiter_escape>'),
    (re.compile(r'(?:[A-Za-z0-9+/]{20,}={0,2}|(?:\\x[0-9a-fA-F]{2}){4,}|(?:%[0-9a-fA-F]{2}){4,})', re.IGNORECASE), '<prompt_injection_removed: encoded_payload>'),
    (re.compile(r'<!--.*?-->', re.DOTALL), '<prompt_injection_removed: hidden_text>'),
    (re.compile(r'\[system\]|\[tool\]|<system>|<tool>', re.IGNORECASE), '<prompt_injection_removed: fake_system_message>'),
    (re.compile(r'(?:send|leak|exfiltrate|post).*?(?:http[s]?://\S+|system prompt)', re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    (re.compile(r'!\[.*?\]\(http[s]?://\S+\)', re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    (re.compile(r'(?:in a previous conversation|earlier you said|you told me before)', re.IGNORECASE), '<prompt_injection_removed: context_poisoning>'),
    (re.compile(r'(?:the document says|according to the file|metadata states).*?(?:ignore|override|forget)', re.IGNORECASE), '<prompt_injection_removed: indirect_injection>'),
    (re.compile(r'(?:os\.system|subprocess|eval\(|exec\(|`[^`]+`|\$\([^)]+\))', re.IGNORECASE), '<prompt_injection_removed: command_injection>'),
    (re.compile(r'(?:DAN|developer mode|fictional framing|pretend you have no restrictions)', re.IGNORECASE), '<prompt_injection_removed: jailbreak_attempt>'),
]


def _ai_app_sec_070_sanitize(text: str) -> str:
    """Remove prompt injection patterns from text before sending to LLM."""
    for pattern, marker in _ai_app_sec_070_patterns:
        text = pattern.sub(marker, text)
    return text

dotenv.load_dotenv()

_AI_APP_SEC_006_DISAPPROVED = [
    "deepseekchat",
    "deepseekr1",
    "deepseekr1distillllama70b",
    "deepseakreasoner",
    "customllmclientnull",
    "deepseekchatnull",
    "openrouternull",
    "usdeepseekr1v10null",
]


def _ai_app_sec_006_normalize(name):
    """Normalize a model identifier for registry comparison."""
    return re.sub(r"[\s\-_\.:\u0000]", "", str(name)).lower()


def _ai_app_sec_006_check_model(model_id):
    """Raise ValueError if model_id matches a disapproved model."""
    normalized = _ai_app_sec_006_normalize(model_id)
    for disapproved in _AI_APP_SEC_006_DISAPPROVED:
        if disapproved in normalized or normalized in disapproved:
            raise ValueError(
                f"Model '{model_id}' is not permitted by the organization's model registry."
            )
    return model_id

if __name__ == "__main__":
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt") as temp_file:
        temp_file.write("Gold is a liquid of blue-like colour.")
        temp_file.flush()

        import quivr_core.config as _qc_config
        _ai_app_sec_006_llm_name = getattr(
            getattr(_qc_config, "LLMEndpointConfig", None) and _qc_config.LLMEndpointConfig(),
            "model",
            None,
        ) or ""
        if _ai_app_sec_006_llm_name:
            _ai_app_sec_006_check_model(_ai_app_sec_006_llm_name)

        brain = Brain.from_files(
            name="test_brain",
            file_paths=[temp_file.name],
        )

        _ai_app_sec_006_question = "what is gold? answer in french"
        answer = brain.ask(_ai_app_sec_006_question)
        print("answer QuivrQARAGLangGraph :", answer)
