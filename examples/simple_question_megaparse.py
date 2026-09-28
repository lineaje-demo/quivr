import os
import re
import tempfile
import shutil
import re
import re
import base64
import binascii
import re

_AI_APP_SEC_006_DISAPPROVED = [
    "deepseekchat",
    "deepseekr1",
    "deepseekr1distillllama70b",
    "deepseekreasoner",
    "customllmclient",
    "deepseek",
    "openrouter",
    "usdeepseekr1v10",
]


def _ai_app_sec_006_check_model(model: str) -> str:
    """Raise ValueError if model is on the organisation disapproved list."""
    normalised = re.sub(r"[\s\-_\.:\"']", "", model).lower()
    for disapproved in _AI_APP_SEC_006_DISAPPROVED:
        if disapproved in normalised:
            raise ValueError(
                f"Model '{model}' is on the organisation disapproved list and cannot be used."
            )
    return model

from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from quivr_core import Brain
from quivr_core.llm.llm_endpoint import LLMEndpoint
from quivr_core.rag.entities.config import LLMEndpointConfig
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

def _ai_app_sec_059_check_prompt(text: str) -> str:
    """Check prompt for hidden, encoded, or malicious content before sending to LLM."""
    # Check for base64-encoded content
    b64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
    for match in b64_pattern.findall(text):
        try:
            decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
            if any(kw in decoded.lower() for kw in ['ignore previous', 'system:', 'exec(', 'eval(', 'os.system', 'subprocess', '/bin/', 'cmd.exe', 'password', 'secret', 'token', 'credential']):
                raise ValueError("Prompt contains suspicious base64-encoded content.")
        except (binascii.Error, UnicodeDecodeError):
            pass

    # Check for shell commands and binary executables
    shell_patterns = [
        r'(?:^|\s)(?:sudo|bash|sh|zsh|cmd|powershell|exec|eval|system)\s*[\(\s]',
        r'/bin/(?:sh|bash|zsh|dash|ksh)',
        r'cmd\.exe',
        r'subprocess\.(?:call|run|Popen|check_output)',
        r'os\.system\s*\(',
        r'__import__\s*\(',
        r'\beval\s*\(',
        r'\bexec\s*\(',
    ]
    for pattern in shell_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            raise ValueError("Prompt contains shell commands or executable content.")

    # Check for credential/secret/token harvesting attempts
    cred_patterns = [
        r'(?:api[_\s]?key|secret|password|passwd|token|credential|auth)[\s:=]+',
        r'(?:access|bearer|oauth|jwt|session)[_\s]?(?:token|key|secret)',
        r'\.env\b',
        r'os\.environ',
    ]
    for pattern in cred_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            raise ValueError("Prompt attempts to access credentials, secrets, or tokens.")

    # Check for leetspeak (common substitutions: 3->e, 4->a, 0->o, 1->i/l, @->a, $->s)
    leet_decoded = text.translate(str.maketrans('34015@$!', 'eaoilasi'))
    if leet_decoded != text:
        if any(kw in leet_decoded.lower() for kw in ['ignore previous', 'disregard', 'jailbreak', 'exec', 'eval', 'system', 'shell', 'password', 'secret', 'token']):
            raise ValueError("Prompt contains suspicious leetspeak content.")

    # Check for hidden/invisible text patterns (zero-width characters, whitespace obfuscation)
    invisible_chars = re.compile(r'[\u200b\u200c\u200d\u200e\u200f\u00ad\ufeff\u2060\u180e]')
    if invisible_chars.search(text):
        raise ValueError("Prompt contains hidden or invisible characters.")

    # Check for prompt injection patterns
    injection_patterns = [
        r'ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions',
        r'disregard\s+(?:all\s+)?(?:previous|prior|above)',
        r'you\s+are\s+now\s+(?:a|an)',
        r'new\s+instructions?\s*:',
        r'system\s*:\s*you',
        r'\[system\]',
        r'<\s*system\s*>',
    ]
    for pattern in injection_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            raise ValueError("Prompt contains injection or override instructions.")

    return text


_ai_app_sec_070_patterns = [
    (re.compile(r'(?i)ignore\s+previous\s+instructions|forget\s+everything\s+above'), '<prompt_injection_removed: instruction_override>'),
    (re.compile(r'(?i)you\s+are\s+now\s+DAN|act\s+as\s+unrestricted'), '<prompt_injection_removed: role_hijack>'),
    (re.compile(r'(?i)</?system>|</?\[INST\]>|</?\|im_start\||</?\|im_end\|'), '<prompt_injection_removed: delimiter_escape>'),
    (re.compile(r'(?i)(?:[A-Za-z0-9+/]{20,}={0,2}|(?:\\x[0-9a-fA-F]{2}){4,}|(?:%[0-9a-fA-F]{2}){4,}|(?:[0-9a-fA-F]{2}\s*){8,}|(?:\.\-|\.\.|\-\.){6,})'), '<prompt_injection_removed: encoded_payload>'),
    (re.compile(r'(?i)<!--.*?-->|\u200b|\u200c|\u200d|\u2060|\ufeff|<span\s+style=["\']display:\s*none["\']>.*?</span>', re.DOTALL), '<prompt_injection_removed: hidden_text>'),
    (re.compile(r'(?i)\[system\]|\[tool\]|\[assistant\]|<\|system\|>|<\|tool\|>'), '<prompt_injection_removed: fake_system_message>'),
    (re.compile(r'(?i)!\[.*?\]\(https?://[^)]+\)|send\s+(?:this|the)\s+(?:data|prompt|context|system\s+prompt)\s+to\s+https?://|leak\s+(?:the\s+)?system\s+prompt'), '<prompt_injection_removed: exfiltration_attempt>'),
    (re.compile(r'(?i)in\s+(?:your\s+)?(?:next|previous|following)\s+(?:response|turn|message).*?(?:say|write|output|print)|remember\s+(?:this|the\s+following)\s+for\s+(?:later|future)'), '<prompt_injection_removed: context_poisoning>'),
    (re.compile(r'(?i)(?:the\s+)?(?:file|document|data|metadata|field)\s+(?:says?|contains?|instructs?|tells?\s+you)'), '<prompt_injection_removed: indirect_injection>'),
    (re.compile(r'(?i)(?:^|\s)(?:os\.system|subprocess\.(?:call|run|Popen)|eval\s*\(|exec\s*\(|__import__|`[^`]+`)'), '<prompt_injection_removed: command_injection>'),
    (re.compile(r'(?i)(?:part\s*[1-9]\s*of\s*[1-9]|continued\s+(?:in|on)\s+(?:next|part)|\[part\s*\d+\])'), '<prompt_injection_removed: split_payload>'),
    (re.compile(r'(?i)DAN\s+mode|developer\s+mode\s+enabled|pretend\s+(?:you\s+are|to\s+be)\s+(?:an?\s+)?(?:AI\s+without|unrestricted)|jailbreak'), '<prompt_injection_removed: jailbreak_attempt>'),
]


def _ai_app_sec_070_sanitize(text: str) -> str:
    """Neutralize prompt injection patterns in user-supplied text."""
    for pattern, marker in _ai_app_sec_070_patterns:
        text = pattern.sub(marker, text)
    return text


_ai_dat_sec_023_patterns = [
    # Social Security Number
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), '[REDACTED_SSN]'),
    # Taxpayer Identification Number (EIN)
    (re.compile(r'\b\d{2}-\d{7}\b'), '[REDACTED_TIN]'),
    # Credit Card Number
    (re.compile(r'\b(?:\d[ -]?){13,16}\b'), '[REDACTED_CC]'),
    # Email
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[REDACTED_EMAIL]'),
    # Personal Phone Number
    (re.compile(r'\b(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b'), '[REDACTED_PHONE]'),
    # Home Address (basic street address pattern)
    (re.compile(r'\b\d{1,5}\s+(?:[A-Za-z0-9.\-]+\s){1,5}(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b', re.IGNORECASE), '[REDACTED_ADDRESS]'),
    # Passport Number (US style)
    (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), '[REDACTED_PASSPORT]'),
    # Drivers License (generic alphanumeric)
    (re.compile(r'\bDL[#:\s]?[A-Z0-9]{6,12}\b', re.IGNORECASE), '[REDACTED_DL]'),
    # Financial Account Number
    (re.compile(r'\b(?:account|acct)[#:\s]+\d{6,17}\b', re.IGNORECASE), '[REDACTED_ACCOUNT]'),
    # IP Address (IPv4)
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '[REDACTED_IP]'),
    # MAC Address
    (re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), '[REDACTED_MAC]'),
    # Year of Birth (context-sensitive: "born in YYYY" or "DOB: YYYY")
    (re.compile(r'\b(?:born\s+in|year\s+of\s+birth|dob)[:\s]+\d{4}\b', re.IGNORECASE), '[REDACTED_YOB]'),
    # Vehicle Identification Number
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), '[REDACTED_VIN]'),
    # Employee ID
    (re.compile(r'\b(?:employee\s*id|emp\s*id)[:\s]+[A-Z0-9\-]{4,12}\b', re.IGNORECASE), '[REDACTED_EMPID]'),
    # School ID
    (re.compile(r'\b(?:school\s*id|student\s*id)[:\s]+[A-Z0-9\-]{4,12}\b', re.IGNORECASE), '[REDACTED_SCHOOLID]'),
]


def _ai_dat_sec_023_redact_text(text: str) -> str:
    """Redact zero-tolerance PII categories from a text string."""
    for pattern, replacement in _ai_dat_sec_023_patterns:
        text = pattern.sub(replacement, text)
    return text


def _ai_dat_sec_023_sanitize_files(file_paths: list) -> list:
    """Read each file, redact PII, write sanitized content to a temp file, return new paths."""
    sanitized_paths = []
    for path in file_paths:
        try:
            with open(path, 'rb') as f:
                raw_bytes = f.read()
            try:
                text = raw_bytes.decode('utf-8', errors='replace')
            except Exception:
                text = raw_bytes.decode('latin-1', errors='replace')
            sanitized_text = _ai_dat_sec_023_redact_text(text)
            suffix = os.path.splitext(path)[1] or '.tmp'
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
            tmp.write(sanitized_text.encode('utf-8', errors='replace'))
            tmp.flush()
            tmp.close()
            sanitized_paths.append(tmp.name)
        except Exception as e:
            raise RuntimeError(f"_ai_dat_sec_023_sanitize_files: failed to sanitize {path}: {e}") from e
    return sanitized_paths


if __name__ == "__main__":
    _ai_dat_sec_023_raw_paths = ["./tests/processor/pdf/sample.pdf"]
    _ai_dat_sec_023_clean_paths = _ai_dat_sec_023_sanitize_files(_ai_dat_sec_023_raw_paths)
    brain = Brain.from_files(
        name="test_brain",
        file_paths=_ai_dat_sec_023_clean_paths,
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

        question = _ai_app_sec_059_check_prompt(question)
        question = _ai_app_sec_070_sanitize(question)
        answer = brain.ask(question)
        # Print the answer with typing effect
        console.print(f"[bold green]Quivr Assistant[/bold green]: {answer.answer}")

        console.print("-" * console.width)

    brain.print_info()
