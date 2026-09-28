import re
from lineaje_guardrail import lineaje_guardrail
import re
from langchain_core.embeddings import DeterministicFakeEmbedding
from langchain_core.language_models import FakeListChatModel
from quivr_core import Brain
from quivr_core.rag.entities.config import LLMEndpointConfig
from quivr_core.llm.llm_endpoint import LLMEndpoint
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

_ai_app_sec_059_guardrail = lineaje_guardrail()
_ai_app_sec_059_guardrail.enable_policies(["AI_APP_SEC_059.json"])

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


def _ai_app_sec_006_check_model(model_id: str) -> None:
    """Raise ValueError if model_id matches a disapproved model."""
    normalized = re.sub(r"[\s\-_\.:\u0000]", "", model_id).lower()
    for disapproved in _AI_APP_SEC_006_DISAPPROVED:
        if disapproved in normalized or normalized in disapproved:
            raise ValueError(
                f"Model '{model_id}' is disapproved by the organization's model registry."
            )

_ai_app_sec_070_patterns = [
    # 1. instruction_override
    (re.compile(r'ignore previous instructions|forget everything above', re.IGNORECASE), '<prompt_injection_removed: instruction_override>'),
    # 2. role_hijack
    (re.compile(r'you are now DAN|act as unrestricted', re.IGNORECASE), '<prompt_injection_removed: role_hijack>'),
    # 3. delimiter_escape
    (re.compile(r'</?(system|tool|assistant|user)\s*>', re.IGNORECASE), '<prompt_injection_removed: delimiter_escape>'),
    # 4. encoded_payload - base64-like blobs, hex sequences, ROT13 instructions, URL-encoded instructions
    (re.compile(r'(?:[A-Za-z0-9+/]{20,}={0,2})', re.IGNORECASE), '<prompt_injection_removed: encoded_payload>'),
    (re.compile(r'(?:(?:%[0-9A-Fa-f]{2}){4,})', re.IGNORECASE), '<prompt_injection_removed: encoded_payload>'),
    # 5. hidden_text - HTML comments, zero-width chars, CSS hidden
    (re.compile(r'<!--.*?-->', re.DOTALL), '<prompt_injection_removed: hidden_text>'),
    (re.compile(r'[\u200b\u200c\u200d\u2060\ufeff]+'), '<prompt_injection_removed: hidden_text>'),
    (re.compile(r'style\s*=\s*["\']?display\s*:\s*none', re.IGNORECASE), '<prompt_injection_removed: hidden_text>'),
    # 6. fake_system_message
    (re.compile(r'\[\s*(?:system|tool|assistant)\s*\]\s*:', re.IGNORECASE), '<prompt_injection_removed: fake_system_message>'),
    (re.compile(r'<\s*(?:system|tool)\s*message\s*>', re.IGNORECASE), '<prompt_injection_removed: fake_system_message>'),
    # 7. exfiltration_attempt
    (re.compile(r'!\[.*?\]\(https?://[^)]+\)', re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    (re.compile(r'send\s+(?:the\s+)?(?:data|prompt|system prompt|context)\s+to\s+https?://', re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    (re.compile(r'leak\s+(?:the\s+)?system\s+prompt', re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    # 8. context_poisoning
    (re.compile(r'from now on|in all future responses|for the rest of this conversation', re.IGNORECASE), '<prompt_injection_removed: context_poisoning>'),
    # 9. indirect_injection
    (re.compile(r'the (?:file|document|data|metadata|code comment) (?:says?|instructs?|tells? you)', re.IGNORECASE), '<prompt_injection_removed: indirect_injection>'),
    # 10. command_injection
    (re.compile(r'(?:^|\s)(?:rm\s+-rf|os\.system|subprocess\.(?:call|run|Popen)|eval\(|exec\()', re.IGNORECASE), '<prompt_injection_removed: command_injection>'),
    # 11. split_payload
    (re.compile(r'(?:part\s*1\s*of|continued\s*in\s*next|split\s*payload)', re.IGNORECASE), '<prompt_injection_removed: split_payload>'),
    # 12. jailbreak_attempt
    (re.compile(r'\bDAN\b|developer mode|fictional[- ]framing|jailbreak', re.IGNORECASE), '<prompt_injection_removed: jailbreak_attempt>'),
]


def _ai_app_sec_070_sanitize(text: str) -> str:
    """Neutralize prompt injection patterns in user-supplied text."""
    for pattern, marker in _ai_app_sec_070_patterns:
        text = pattern.sub(marker, text)
    return text


if __name__ == "__main__":
    _ai_app_sec_006_check_model("fake_model")
    brain = Brain.from_files(
        name="test_brain",
        file_paths=["tests/processor/data/dummy.pdf"],
        llm=LLMEndpoint(
            llm=FakeListChatModel(responses=["good"]),
            llm_config=LLMEndpointConfig(model="fake_model", llm_base_url="local"),
        ),
        embedder=DeterministicFakeEmbedding(size=20),
    )
    # Check brain info
    brain.print_info()

    console = Console()
    console.print(Panel.fit("Ask your brain !", style="bold magenta"))

    while True:
        # Get user input
        question = Prompt.ask("[bold cyan]Question[/bold cyan]")

        # Check if user wants to exit
        if question.lower() == "exit":
            console.print(Panel("Goodbye!", style="bold yellow"))
            break

        question = _ai_app_sec_059_guardrail.evaluate(question)
        question = _ai_app_sec_070_sanitize(question)
        answer = brain.ask(question)
        # Print the answer with typing effect
        console.print(f"[bold green]Quivr Assistant[/bold green]: {answer.answer}")

        console.print("-" * console.width)

    brain.print_info()
