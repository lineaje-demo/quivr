import re
import base64
import re
import re
import re
import os
from langchain_core.embeddings import DeterministicFakeEmbedding
from langchain_core.language_models import FakeListChatModel
from quivr_core import Brain
from quivr_core.rag.entities.config import LLMEndpointConfig
from quivr_core.llm.llm_endpoint import LLMEndpoint
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

# PII patterns for zero-tolerance categories
_ai_dat_sec_023_patterns = [
    # Social Security Number
    (re.compile(r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'), 'SSN'),
    # Year of Birth (4-digit year in context)
    (re.compile(r'\b(?:born|birth\s*year|year\s*of\s*birth)[:\s]+\d{4}\b', re.IGNORECASE), 'YearOfBirth'),
    # Birthplace
    (re.compile(r'\b(?:born\s+in|birthplace|place\s+of\s+birth)[:\s]+[A-Za-z ,]+', re.IGNORECASE), 'Birthplace'),
    # Personal Phone Number
    (re.compile(r'\b(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b'), 'PhoneNumber'),
    # Email
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), 'Email'),
    # Mother's Maiden Name
    (re.compile(r"\b(?:mother'?s?\s+maiden\s+name)[:\s]+[A-Za-z]+", re.IGNORECASE), 'MotherMaidenName'),
    # Home Address (basic pattern)
    (re.compile(r'\b\d{1,5}\s+[A-Za-z0-9 .]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b', re.IGNORECASE), 'HomeAddress'),
    # Passport Number
    (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), 'PassportNumber'),
    # Driver's License Number (generic)
    (re.compile(r"\b(?:driver'?s?\s+license|DL)[:\s#]*[A-Z0-9]{5,15}\b", re.IGNORECASE), 'DriversLicense'),
    # Taxpayer Identification Number
    (re.compile(r'\b\d{2}-\d{7}\b'), 'TIN'),
    # Credit Card Number
    (re.compile(r'\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12}|3(?:0[0-5]|[68]\d)\d{11}|(?:2131|1800|35\d{3})\d{11})\b'), 'CreditCard'),
    # Financial Account Number
    (re.compile(r'\b(?:account\s*(?:number|no|#)[:\s]*)[\dX]{6,20}\b', re.IGNORECASE), 'FinancialAccount'),
    # Employee ID
    (re.compile(r'\b(?:employee\s*(?:id|no|number|#)[:\s]*)\w{3,15}\b', re.IGNORECASE), 'EmployeeId'),
    # School ID
    (re.compile(r'\b(?:student\s*(?:id|no|number|#)[:\s]*)\w{3,15}\b', re.IGNORECASE), 'SchoolId'),
    # Vehicle Identification Number
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), 'VIN'),
    # IP Address
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), 'IPAddress'),
    # MAC Address
    (re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), 'MACAddress'),
    # Ethnicity
    (re.compile(r'\b(?:ethnicity|ethnic\s+origin)[:\s]+[A-Za-z ]+', re.IGNORECASE), 'Ethnicity'),
    # Sexual Orientation
    (re.compile(r'\b(?:sexual\s+orientation)[:\s]+[A-Za-z ]+', re.IGNORECASE), 'SexualOrientation'),
]


def _ai_dat_sec_023_extract_text_from_pdf(file_path: str) -> str:
    """Extract plain text from a PDF file using pypdf if available, else read raw bytes as string."""
    try:
        from pypdf import PdfReader  # type: ignore
        reader = PdfReader(file_path)
        return '\n'.join(page.extract_text() or '' for page in reader.pages)
    except ImportError:
        pass
    try:
        import pdfplumber  # type: ignore
        with pdfplumber.open(file_path) as pdf:
            return '\n'.join(page.extract_text() or '' for page in pdf.pages)
    except ImportError:
        pass
    with open(file_path, 'rb') as f:
        return f.read().decode('latin-1', errors='replace')


def _ai_dat_sec_023_check_and_redact_pii(file_paths: list) -> None:
    """Check each file for PII and raise ValueError listing detected PII categories."""
    for path in file_paths:
        if not os.path.isfile(path):
            continue
        text = _ai_dat_sec_023_extract_text_from_pdf(path)
        found = []
        for pattern, label in _ai_dat_sec_023_patterns:
            if pattern.search(text):
                found.append(label)
        if found:
            raise ValueError(
                f"PII detected in '{path}' — categories: {', '.join(found)}. "
                "Please redact PII before uploading."
            )


def _ai_app_sec_059_check_prompt(text: str) -> str:
    """Raise ValueError if the prompt contains hidden, encoded, or malicious content."""
    # 1. Invisible / zero-width characters
    _ai_app_sec_059_invisible = re.compile(
        r'[\u200b\u200c\u200d\u200e\u200f\u00ad\ufeff\u2060]'
    )
    if _ai_app_sec_059_invisible.search(text):
        raise ValueError("Prompt contains invisible/hidden characters.")

    # 2. Base64-encoded payload (long token of base64 chars)
    _ai_app_sec_059_b64 = re.compile(r'(?:[A-Za-z0-9+/]{40,}={0,2})')
    for match in _ai_app_sec_059_b64.findall(text):
        try:
            decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
            if any(kw in decoded.lower() for kw in
                   ['ignore previous', 'system:', 'exec', 'eval', 'token', 'secret',
                    'password', 'credential', '/bin/', 'bash', 'sh -']):
                raise ValueError("Prompt contains suspicious base64-encoded content.")
        except Exception as exc:
            if 'suspicious' in str(exc):
                raise

    # 3. Leetspeak pattern (common substitutions like 3->e, 0->o, 1->i/l)
    _ai_app_sec_059_leet = re.compile(
        r'(?i)(?:[1!][gq][n][0o][r3][e3]|[s$][y][s$][t][e3][m]|[e3][x][e3][c]|[e3][v][4a][l])'
    )
    if _ai_app_sec_059_leet.search(text):
        raise ValueError("Prompt contains leetspeak obfuscation.")

    # 4. Shell commands / binary executables
    _ai_app_sec_059_shell = re.compile(
        r'(?i)(?:\b(?:bash|sh|zsh|cmd|powershell|exec|eval|system|popen|subprocess)\s*[\(\-]'
        r'|/bin/|/usr/bin/|\\\\cmd\\.exe|&&|\|\||;\s*\w+\s*[;&|]|`[^`]+`)'
    )
    if _ai_app_sec_059_shell.search(text):
        raise ValueError("Prompt contains shell commands or binary executable references.")

    # 5. Attempts to access auth tokens, secrets, credentials
    _ai_app_sec_059_secrets = re.compile(
        r'(?i)(?:ignore\s+(?:previous|above|prior)|disregard\s+instructions?'
        r'|you\s+are\s+now|new\s+instructions?|reveal\s+(?:your\s+)?(?:token|secret|key|password|credential)'
        r'|print\s+(?:your\s+)?(?:token|secret|api.?key)|access.?token|bearer\s+[a-z0-9]{8,}'
        r'|authorization:\s*bearer|api[_\-]?key\s*[:=])'
    )
    if _ai_app_sec_059_secrets.search(text):
        raise ValueError("Prompt attempts to access secrets, tokens, or credentials.")

    # 6. Prompt injection keywords
    _ai_app_sec_059_injection = re.compile(
        r'(?i)(?:ignore\s+all\s+(?:previous|prior|above)'
        r'|forget\s+(?:your\s+)?(?:previous|prior|above|instructions?)'
        r'|you\s+must\s+(?:now|instead)'
        r'|act\s+as\s+(?:an?\s+)?(?:unrestricted|jailbreak|dan|evil))'
    )
    if _ai_app_sec_059_injection.search(text):
        raise ValueError("Prompt contains prompt-injection patterns.")

    return text

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


def _ai_app_sec_006_check_model(model_id: str) -> str:
    """Raise ValueError if model_id matches a disapproved model."""
    normalized = re.sub(r"[\s\-_\.:\u0000]", "", model_id).lower()
    for disapproved in _AI_APP_SEC_006_DISAPPROVED:
        if normalized == disapproved:
            raise ValueError(
                f"Model '{model_id}' is disapproved by the organization model registry."
            )
    return model_id

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
    (re.compile(r'[\u200b\u200c\u200d\u200e\u200f\ufeff]'), '<prompt_injection_removed: hidden_text>'),
    (re.compile(r'style\s*=\s*["\']?display\s*:\s*none', re.IGNORECASE), '<prompt_injection_removed: hidden_text>'),
    # 6. fake_system_message
    (re.compile(r'\[\s*(?:system|tool|assistant)\s*\]\s*:', re.IGNORECASE), '<prompt_injection_removed: fake_system_message>'),
    (re.compile(r'<\s*(?:system|tool)\s*message\s*>', re.IGNORECASE), '<prompt_injection_removed: fake_system_message>'),
    # 7. exfiltration_attempt
    (re.compile(r'!\[.*?\]\(https?://[^)]+\)', re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    (re.compile(r'(?:send|leak|exfiltrate|transmit)\s+(?:the\s+)?(?:system\s+prompt|data|information)\s+to\s+https?://', re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    # 8. context_poisoning
    (re.compile(r'(?:in a previous conversation|earlier you said|you previously told me)', re.IGNORECASE), '<prompt_injection_removed: context_poisoning>'),
    # 9. indirect_injection
    (re.compile(r'(?:the file says|according to the document|metadata says)\s*[:\.]*\s*ignore', re.IGNORECASE), '<prompt_injection_removed: indirect_injection>'),
    # 10. command_injection
    (re.compile(r'(?:import os|subprocess\.(?:call|run|Popen)|os\.system|eval\s*\(|exec\s*\()', re.IGNORECASE), '<prompt_injection_removed: command_injection>'),
    # 11. split_payload
    (re.compile(r'(?:part\s*1\s*of\s*\d+|continued\s+in\s+next\s+message|split\s+payload)', re.IGNORECASE), '<prompt_injection_removed: split_payload>'),
    # 12. jailbreak_attempt
    (re.compile(r'(?:DAN mode|developer mode enabled|fictional framing|pretend you have no restrictions|jailbreak)', re.IGNORECASE), '<prompt_injection_removed: jailbreak_attempt>'),
]


def _ai_app_sec_070_sanitize(text: str) -> str:
    """Neutralize prompt injection patterns in user-supplied text."""
    for pattern, marker in _ai_app_sec_070_patterns:
        text = pattern.sub(marker, text)
    return text


if __name__ == "__main__":
    _ai_dat_sec_023_check_and_redact_pii(["tests/processor/data/dummy.pdf"])
    brain = Brain.from_files(
        name="test_brain",
        file_paths=["tests/processor/data/dummy.pdf"],
        llm=LLMEndpoint(
            llm=FakeListChatModel(responses=["good"]),
            llm_config=LLMEndpointConfig(
                model=_ai_app_sec_006_check_model("fake_model"),
                llm_base_url="local",
            ),
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

        try:
            question = _ai_app_sec_059_check_prompt(question)
        except ValueError as _ai_app_sec_059_err:
            console.print(f"[bold red]Blocked:[/bold red] {_ai_app_sec_059_err}")
            continue
        question = _ai_app_sec_070_sanitize(question)
        answer = brain.ask(question)
        # Print the answer with typing effect
        console.print(f"[bold green]Quivr Assistant[/bold green]: {answer.answer}")

        console.print("-" * console.width)

    brain.print_info()
