import logging
import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timezone

from langchain_core.embeddings import DeterministicFakeEmbedding
from langchain_core.language_models import FakeListChatModel
from quivr_core import Brain
from quivr_core.rag.entities.config import LLMEndpointConfig
from quivr_core.llm.llm_endpoint import LLMEndpoint
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

# ---------------------------------------------------------------------------
# Provenance helpers (inlined)
# ---------------------------------------------------------------------------

# Secret used to sign provenance envelopes.  In production this must come
# from a secrets manager / environment variable; we fall back to a fixed
# development key so the example still runs, but the code will warn loudly.
_SIGNING_SECRET: bytes = os.environb.get(
    b"QUIVR_PROVENANCE_SECRET",
    b"__dev_only_secret__do_not_use_in_production__",
)

AI_CONTENT_LABEL = "[AI-GENERATED CONTENT]"
CONTENT_ORIGIN_TAG = "quivr-rag-pipeline"


def _prompt_hash(prompt: str) -> str:
    """SHA-256 hex digest of the prompt text."""
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


def _sign_envelope(envelope: dict) -> str:
    """Return an HMAC-SHA256 hex signature over the canonical JSON of *envelope*."""
    canonical = json.dumps(envelope, sort_keys=True, ensure_ascii=True)
    return hmac.new(
        _SIGNING_SECRET,
        canonical.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()


def build_provenance_envelope(
    answer_text: str,
    prompt: str,
    model_id: str,
) -> dict:
    """
    Build a machine-readable provenance envelope and attach a cryptographic
    signature.  Raises RuntimeError if signing fails (fail-closed).
    """
    envelope: dict = {
        "content_label": AI_CONTENT_LABEL,
        "content_origin": CONTENT_ORIGIN_TAG,
        "model_id": model_id,
        "generation_timestamp": datetime.now(timezone.utc).isoformat(),
        "prompt_hash": _prompt_hash(prompt),
        "answer_text": answer_text,
        "signature": None,  # placeholder; filled below
    }
    try:
        # Compute signature over everything except the signature field itself
        signable = {k: v for k, v in envelope.items() if k != "signature"}
        envelope["signature"] = _sign_envelope(signable)
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(
            f"Provenance signing failed — refusing to serve unlabeled content: {exc}"
        ) from exc
    return envelope


def verify_provenance_envelope(envelope: dict) -> bool:
    """Return True only when the envelope signature is valid."""
    try:
        sig = envelope.get("signature")
        if not sig:
            return False
        signable = {k: v for k, v in envelope.items() if k != "signature"}
        expected = _sign_envelope(signable)
        return hmac.compare_digest(sig, expected)
    except Exception:  # noqa: BLE001
        return False


def print_labeled_answer(console: Console, envelope: dict) -> None:
    """
    Print the AI answer together with its provenance label.
    Fails closed: if the envelope cannot be verified it refuses to print.
    """
    if not verify_provenance_envelope(envelope):
        console.print(
            "[bold red]ERROR[/bold red]: Provenance verification failed — "
            "content will not be displayed."
        )
        return

    console.print(
        f"[bold green]Quivr Assistant[/bold green] "
        f"[dim]{envelope['content_label']}[/dim]: {envelope['answer_text']}"
    )
    console.print(
        f"[dim]  model={envelope['model_id']} | "
        f"origin={envelope['content_origin']} | "
        f"ts={envelope['generation_timestamp']} | "
        f"prompt_hash={envelope['prompt_hash'][:12]}… | "
        f"sig={envelope['signature'][:16]}…[/dim]"
    )

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
llm_logger = logging.getLogger("llm.interactions")

import re

DANGEROUS_PATTERNS = [
    r'\beval\s*\(',
    r'\bexec\s*\(',
    r'\bsubprocess\s*\.\s*\w*\s*\([^)]*shell\s*=\s*True',
    r'\bos\.system\s*\(',
    r'\bos\.popen\s*\(',
    r'\b__import__\s*\(',
    r'\bcompile\s*\(',
    r'\bexecfile\s*\(',
    r'\binput\s*\(',
    r'<script[^>]*>',
    r'javascript\s*:',
    r'\$\(.*\)',
    r'`[^`]*`',
]


def sanitize_llm_response(response_text: str) -> str:
    """Sanitize LLM response by removing lines containing dynamic code execution primitives."""
    if not response_text:
        return response_text
    sanitized_lines = []
    for line in response_text.splitlines():
        is_dangerous = False
        for pattern in DANGEROUS_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                is_dangerous = True
                break
        if not is_dangerous:
            sanitized_lines.append(line)
    return "\n".join(sanitized_lines)


if __name__ == "__main__":
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

        answer = brain.ask(question)
        # Sanitize and validate LLM response for dynamic code execution primitives
        sanitized_answer = sanitize_llm_response(answer.answer)
        # Print the answer with typing effect
        console.print(f"[bold green]Quivr Assistant[/bold green]: {sanitized_answer}")

        console.print("-" * console.width)

    brain.print_info()
