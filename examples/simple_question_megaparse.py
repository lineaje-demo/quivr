import logging
import os
import re

from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from quivr_core import Brain
from quivr_core.llm.llm_endpoint import LLMEndpoint
from quivr_core.rag.entities.config import LLMEndpointConfig
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

logger = logging.getLogger(__name__)

# Patterns that indicate dynamic code execution primitives
_DANGEROUS_PATTERNS = [
    r"\beval\s*\(",                        # Python/JS eval(...)
    r"\bexec\s*\(",                        # Python exec(...)
    r"\bexecfile\s*\(",                    # Python 2 execfile(...)
    r"\bcompile\s*\(",                     # Python compile(...)
    r"\b__import__\s*\(",                  # Python __import__(...)
    r"\bimportlib\.import_module\s*\(",    # importlib dynamic import
    r"subprocess\..*shell\s*=\s*True",     # subprocess with shell=True
    r"\bos\.system\s*\(",                  # os.system(...)
    r"\bos\.popen\s*\(",                   # os.popen(...)
    r"\bpopen\s*\(",                       # popen(...)
    r"\bspawn\s*\(",                       # spawn(...)
    r"\bcall\s*\(.*shell\s*=\s*True",      # call(shell=True)
    r"\bcheck_output\s*\(.*shell\s*=\s*True",  # check_output(shell=True)
    r"\bcheck_call\s*\(.*shell\s*=\s*True",    # check_call(shell=True)
    r"\brun\s*\(.*shell\s*=\s*True",       # run(shell=True)
    r"`[^`]+`",                             # Bash backtick execution
    r"\$\([^)]+\)",                        # Bash $(...) command substitution
    r"\beval\s+[\w$]",                     # Bash eval command
    r"\bsource\s+",                        # Bash source command
    r"\bFunction\s*\(",                    # JS new Function(...)
    r"setTimeout\s*\(\s*['\"].*['\"]\s*,",  # JS setTimeout with string
    r"setInterval\s*\(\s*['\"].*['\"]\s*,", # JS setInterval with string
]

_COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in _DANGEROUS_PATTERNS]


def sanitize_llm_output(text: str) -> str:
    """Remove lines from LLM output that contain dynamic code execution primitives."""
    if not text:
        return text

    sanitized_lines = []
    for line in text.splitlines():
        dangerous = False
        for pattern in _COMPILED_PATTERNS:
            if pattern.search(line):
                logger.warning(
                    "Removed potentially dangerous line from LLM output: %r",
                    line,
                )
                dangerous = True
                break
        if not dangerous:
            sanitized_lines.append(line)

    return "\n".join(sanitized_lines)

if __name__ == "__main__":
    brain = Brain.from_files(
        name="test_brain",
        file_paths=["./tests/processor/pdf/sample.pdf"],
        llm=LLMEndpoint(
            llm_config=LLMEndpointConfig(model="gpt-4o"),
            llm=ChatOpenAI(model="gpt-4o", api_key=str(os.getenv("OPENAI_API_KEY"))),
        ),
    )
    embedder = embeddings = OpenAIEmbeddings(
        model="text-embedding-3-large",
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

        answer = brain.ask(question)
        # Sanitize LLM output: remove lines containing dynamic code execution primitives
        sanitized_answer = sanitize_llm_output(answer.answer)
        # Print the answer with typing effect
        console.print(f"[bold green]Quivr Assistant[/bold green]: {sanitized_answer}")

        console.print("-" * console.width)

    brain.print_info()
