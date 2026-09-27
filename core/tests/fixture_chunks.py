import asyncio
import json
import re
from uuid import uuid4

from langchain_core.embeddings import DeterministicFakeEmbedding
from langchain_core.messages.ai import AIMessageChunk
from langchain_core.vectorstores import InMemoryVectorStore
from quivr_core.rag.entities.chat import ChatHistory
from quivr_core.rag.entities.config import LLMEndpointConfig, RetrievalConfig
from quivr_core.llm import LLMEndpoint
from quivr_core.rag.quivr_rag_langgraph import QuivrQARAGLangGraph


# Patterns that indicate dynamic code execution primitives in LLM output
_DANGEROUS_PATTERNS = re.compile(
    r"(?m)^.*"
    r"(?:"
    r"\beval\s*\("
    r"|\bexec\s*\("
    r"|\bexecfile\s*\("
    r"|\bcompile\s*\("
    r"|\b__import__\s*\("
    r"|\bimportlib\.import_module\s*\("
    r"|subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True"
    r"|\bos\.system\s*\("
    r"|\bos\.popen\s*\("
    r"|\$\(.*\)"
    r"|`[^`]+`"
    r"|\beval\b"
    r")"
    r".*$"
)


def sanitize_llm_text(text: str) -> str:
    """Remove lines containing dynamic code execution primitives from LLM output."""
    sanitized = _DANGEROUS_PATTERNS.sub("", text)
    # Clean up any blank lines left by removal
    sanitized = re.sub(r"\n{3,}", "\n\n", sanitized)
    return sanitized


def sanitize_chunk(dict_chunk: dict) -> dict:
    """Sanitize all string values in a chunk dict for dangerous code execution primitives."""
    sanitized = {}
    for k, v in dict_chunk.items():
        if isinstance(v, str):
            sanitized[k] = sanitize_llm_text(v)
        elif isinstance(v, dict):
            # Recursively sanitize nested dicts (e.g. AIMessageChunk.dict())
            sanitized[k] = _sanitize_nested(v)
        else:
            sanitized[k] = v
    return sanitized


def _sanitize_nested(obj):
    """Recursively sanitize nested structures."""
    if isinstance(obj, dict):
        return {k: _sanitize_nested(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_sanitize_nested(item) for item in obj]
    elif isinstance(obj, str):
        return sanitize_llm_text(obj)
    return obj


# Secret key for HMAC signing of provenance metadata.
# In production, load this from a secure secrets manager / environment variable.
_PROVENANCE_SIGNING_KEY: bytes = os.environb.get(
    b"PROVENANCE_SIGNING_KEY",
    secrets.token_bytes(32),  # ephemeral fallback – rotate per deployment
)

MODEL_ORIGIN_TAG = "ai-generated"
CONTENT_LABEL = "SYNTHETIC_AI_CONTENT"


def _sign_provenance(metadata: dict) -> str:
    """Return a hex HMAC-SHA256 signature over the canonical JSON of metadata."""
    canonical = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(_PROVENANCE_SIGNING_KEY, canonical, hashlib.sha256).hexdigest()


def _build_provenance_envelope(
    dict_chunk: dict,
    model_id: str,
    prompt_hash: str,
) -> dict:
    """Wrap an AI-generated chunk in a signed provenance envelope.

    Raises RuntimeError if signing fails so callers can fail closed.
    """
    provenance = {
        "model_id": model_id,
        "generation_timestamp": datetime.now(timezone.utc).isoformat(),
        "prompt_hash": prompt_hash,
        "content_origin": MODEL_ORIGIN_TAG,
        "content_label": CONTENT_LABEL,
    }
    try:
        signature = _sign_provenance(provenance)
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(
            "Provenance signing failed – refusing to emit unsigned AI content."
        ) from exc

    return {
        "provenance": provenance,
        "provenance_signature": signature,
        "payload": dict_chunk,
    }


def _verify_provenance_envelope(envelope: dict) -> bool:
    """Return True only when the envelope's signature is valid."""
    provenance = envelope.get("provenance")
    signature = envelope.get("provenance_signature")
    if not provenance or not signature:
        return False
    expected = _sign_provenance(provenance)
    return hmac.compare_digest(expected, signature)


async def main():
    retrieval_config = RetrievalConfig(llm_config=LLMEndpointConfig(model="gpt-4o"))
    embedder = DeterministicFakeEmbedding(size=20)
    vec = InMemoryVectorStore(embedder)

    llm = LLMEndpoint.from_config(retrieval_config.llm_config)
    chat_history = ChatHistory(uuid4(), uuid4())
    rag_pipeline = QuivrQARAGLangGraph(
        retrieval_config=retrieval_config, llm=llm, vector_store=vec
    )

    conversational_qa_chain = rag_pipeline.build_chain()

    with open("response.jsonl", "w") as f:
        async for event in conversational_qa_chain.astream_events(
            {
                "messages": [
                    ("user", "What is NLP, give a very long detailed answer"),
                ],
                "chat_history": chat_history,
                "custom_personality": None,
            },
            version="v1",
            config={"metadata": {}},
        ):
            kind = event["event"]
            if (
                kind == "on_chat_model_stream"
                and event["metadata"]["langgraph_node"] == "generate"
            ):
                chunk = event["data"]["chunk"]
                dict_chunk = {
                    k: v.dict() if isinstance(v, AIMessageChunk) else v
                    for k, v in chunk.items()
                }
                safe_chunk = sanitize_chunk(dict_chunk)
                f.write(json.dumps(safe_chunk) + "\n")


asyncio.run(main())
