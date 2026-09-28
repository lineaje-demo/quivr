import os
import re
from lineaje_guardrail import lineaje_guardrail

_ai_app_sec_059_guardrail = lineaje_guardrail()
_ai_app_sec_059_guardrail.enable_policies(["AI_APP_SEC_059.json"])
import re


def _ai_app_sec_006_normalize(name: str) -> str:
    """Normalize a model identifier for comparison."""
    return re.sub(r'[\s\-_\.:]', '', name).lower()


_AI_APP_SEC_006_DISAPPROVED = [
    'deepseekchat',
    'deepseekr1',
    'deepseekr1distillllama70b',
    'deepseakreasoner',
    'deepseekreasoner',
    'customllmclientnull',
    'deepseekchatnull',
    'opennull',
    'openrouternull',
    'usdeepseekr1v10null',
]


def _ai_app_sec_006_check_model(model: str) -> str:
    """Raise ValueError if model is on the disapproved list, else return model."""
    normalized = _ai_app_sec_006_normalize(model)
    for disapproved in _AI_APP_SEC_006_DISAPPROVED:
        if normalized == disapproved:
            raise ValueError(
                f"Model '{model}' is on the organization's disapproved model list "
                "and cannot be used."
            )
    return model

from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from quivr_core import Brain
from quivr_core.llm.llm_endpoint import LLMEndpoint
from quivr_core.rag.entities.config import LLMEndpointConfig
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

_ai_app_sec_070_patterns = [
    (re.compile(r'(?i)ignore\s+previous\s+instructions|forget\s+everything\s+above'), '<prompt_injection_removed: instruction_override>'),
    (re.compile(r'(?i)you\s+are\s+now\s+DAN|act\s+as\s+unrestricted'), '<prompt_injection_removed: role_hijack>'),
    (re.compile(r'(?i)</?(system|tool|assistant|user)\s*>|\[INST\]|\[/INST\]|<\|im_start\|>|<\|im_end\|>'), '<prompt_injection_removed: delimiter_escape>'),
    (re.compile(r'(?i)(?:[A-Za-z0-9+/]{20,}={0,2}|(?:\\x[0-9a-fA-F]{2}){4,}|(?:%[0-9a-fA-F]{2}){4,}|(?:[0-9a-fA-F]{2}\s*){8,}|(?:\.-\.|-\.\.|\.\.-){6,})'), '<prompt_injection_removed: encoded_payload>'),
    (re.compile(r'(?i)<!--.*?-->|\u200b|\u200c|\u200d|\u2060|\ufeff|display\s*:\s*none|visibility\s*:\s*hidden', re.DOTALL), '<prompt_injection_removed: hidden_text>'),
    (re.compile(r'(?i)\bsystem\s*message\b.*?:|\btool\s*response\b.*?:|\bassistant\s*message\b.*?:'), '<prompt_injection_removed: fake_system_message>'),
    (re.compile(r'(?i)!\[.*?\]\(https?://[^)]+\)|send\s+.{0,40}\s+to\s+https?://|leak\s+.{0,40}\s+(?:system\s+)?prompt|exfiltrate'), '<prompt_injection_removed: exfiltration_attempt>'),
    (re.compile(r'(?i)in\s+(?:a\s+)?previous\s+(?:turn|message|conversation)|remember\s+(?:that\s+)?(?:you\s+)?(?:said|told)|multi.?turn\s+manipulation|context\s+poison'), '<prompt_injection_removed: context_poisoning>'),
    (re.compile(r'(?i)(?:the\s+)?(?:file|document|data|metadata|field|comment)\s+(?:says?|contains?|instructs?)\s+you\s+to'), '<prompt_injection_removed: indirect_injection>'),
    (re.compile(r'(?i)(?:^|\s)(?:sudo\s+|bash\s+|sh\s+|cmd\s+|powershell\s+)?(?:rm\s+-rf|os\.system|subprocess|eval\s*\(|exec\s*\(|__import__|`[^`]+`)'), '<prompt_injection_removed: command_injection>'),
    (re.compile(r'(?i)(?:part\s*[1-9]\s*of\s*[0-9]|continued\s+(?:from|in)\s+(?:next|previous)|split\s+(?:across|over)\s+(?:messages?|turns?))'), '<prompt_injection_removed: split_payload>'),
    (re.compile(r'(?i)\bDAN\b|developer\s+mode|jailbreak|fictional\s+(?:framing|scenario|character)\s+(?:where\s+)?(?:you\s+)?(?:can|must|should)'), '<prompt_injection_removed: jailbreak_attempt>'),
]


def _ai_app_sec_070_sanitize(text: str) -> str:
    """Neutralize prompt injection patterns in user-supplied text."""
    for pattern, marker in _ai_app_sec_070_patterns:
        text = pattern.sub(marker, text)
    return text


if __name__ == "__main__":
    brain = Brain.from_files(
        name="test_brain",
        file_paths=["./tests/processor/pdf/sample.pdf"],
        llm=LLMEndpoint(
            llm_config=LLMEndpointConfig(model=_ai_app_sec_006_check_model("gpt-4o")),
            llm=ChatOpenAI(model=_ai_app_sec_006_check_model("gpt-4o"), api_key=str(os.getenv("OPENAI_API_KEY"))),
        ),
    )
    embedder = embeddings = OpenAIEmbeddings(
        model=_ai_app_sec_006_check_model("text-embedding-3-large"),
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
