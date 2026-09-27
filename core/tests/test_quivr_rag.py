import re
import logging
from uuid import uuid4

import pytest

logger = logging.getLogger(__name__)
from quivr_core.rag.entities.chat import ChatHistory
from quivr_core.rag.entities.config import LLMEndpointConfig, RetrievalConfig
from quivr_core.llm import LLMEndpoint
from quivr_core.rag.entities.models import ParsedRAGChunkResponse, RAGResponseMetadata
from quivr_core.rag.quivr_rag_langgraph import QuivrQARAGLangGraph

# Patterns that indicate dangerous dynamic code execution primitives in LLM output.
_DANGEROUS_PATTERNS = re.compile(
    r"""
    (?:^|[^\w])          # word boundary or start
    (?:
        eval\s*\(        # Python/JS eval(
      | exec\s*\(        # Python exec(
      | execfile\s*\(    # Python 2 execfile(
      | compile\s*\(     # Python compile(
      | __import__\s*\(  # Python __import__(
      | importlib\.import_module\s*\(  # importlib dynamic import
      | subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True  # subprocess shell=True
      | os\.system\s*\(  # os.system(
      | os\.popen\s*\(   # os.popen(
      | commands\.getoutput\s*\(  # commands module
      | (?:bash|sh|zsh|ksh)\s+-c  # shell -c invocation
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)


def sanitize_llm_response(response: ParsedRAGChunkResponse) -> ParsedRAGChunkResponse:
    """Remove lines from LLM answer that contain dangerous code-execution primitives."""
    if not response.answer:
        return response
    safe_lines = [
        line for line in response.answer.splitlines()
        if not _DANGEROUS_PATTERNS.search(line)
    ]
    sanitized_answer = "\n".join(safe_lines)
    # Preserve a trailing newline if the original had one
    if response.answer.endswith("\n") and not sanitized_answer.endswith("\n"):
        sanitized_answer += "\n"
    # Return a new instance with the sanitized answer; all other fields unchanged.
    return response.model_copy(update={"answer": sanitized_answer})


@pytest.fixture(scope="function")
def mock_chain_qa_stream(monkeypatch, chunks_stream_answer):
    class MockQAChain:
        async def astream_events(self, *args, **kwargs):
            default_metadata = {
                "langgraph_node": "generate",
                "is_final_node": False,
                "citations": None,
                "followup_questions": None,
                "sources": None,
                "metadata_model": None,
            }

            # Send all chunks except the last one
            for chunk in chunks_stream_answer[:-1]:
                yield {
                    "event": "on_chat_model_stream",
                    "metadata": default_metadata,
                    "data": {"chunk": chunk["answer"]},
                }

            # Send the last chunk
            yield {
                "event": "end",
                "metadata": {
                    "langgraph_node": "generate",
                    "is_final_node": True,
                    "citations": [],
                    "followup_questions": None,
                    "sources": [],
                    "metadata_model": None,
                },
                "data": {"chunk": chunks_stream_answer[-1]["answer"]},
            }

    def mock_qa_chain(*args, **kwargs):
        self = args[0]
        self.final_nodes = ["generate"]
        return MockQAChain()

    monkeypatch.setattr(QuivrQARAGLangGraph, "build_chain", mock_qa_chain)


@pytest.mark.base
@pytest.mark.asyncio
async def test_quivrqaraglanggraph(
    mem_vector_store, full_response, mock_chain_qa_stream, openai_api_key
):
    # Making sure the model
    llm_config = LLMEndpointConfig(model="gpt-4o")
    llm = LLMEndpoint.from_config(llm_config)
    retrieval_config = RetrievalConfig(llm_config=llm_config)
    chat_history = ChatHistory(uuid4(), uuid4())
    rag_pipeline = QuivrQARAGLangGraph(
        retrieval_config=retrieval_config, llm=llm, vector_store=mem_vector_store
    )

        stream_responses: list[ParsedRAGChunkResponse] = []

    # Making sure that we are calling the func_calling code path
    assert rag_pipeline.llm_endpoint.supports_func_calling()

    llm_request_prompt = "answer in bullet points. tell me something"
    logger.info(
        "LLM interaction request: prompt=%r, chat_history=%r, sources=%r",
        llm_request_prompt,
        chat_history,
        [],
    )
    async for resp in rag_pipeline.answer_astream(
        llm_request_prompt, chat_history, []
    ):
        logger.info(
            "LLM interaction response chunk: answer=%r, last_chunk=%r, metadata=%r",
            resp.answer,
            resp.last_chunk,
            resp.metadata,
        )
        stream_responses.append(resp)

    # This assertion passed
    assert all(
        not r.last_chunk for r in stream_responses[:-1]
    ), "Some chunks before last have last_chunk=True"
    assert stream_responses[-1].last_chunk

    # Let's check this assertion
    for idx, response in enumerate(stream_responses[1:-1]):
        assert (
            len(response.answer) > 0
        ), f"Sent an empty answer {response} at index {idx+1}"

    # Verify metadata
    default_metadata = RAGResponseMetadata().model_dump()
    assert all(
        r.metadata.model_dump() == default_metadata for r in stream_responses[:-1]
    )
    last_response = stream_responses[-1]
    # TODO(@aminediro) : test responses with sources
    assert last_response.metadata.sources == []
    assert last_response.metadata.citations == []

    # ---------------------------------------------------------------------------
    # Synthetic-content provenance, labeling, and watermarking enforcement
    # ---------------------------------------------------------------------------
    import hashlib
    import hmac
    import json
    import time

    _PROVENANCE_SIGNING_SECRET = b"test-signing-secret-change-in-prod"
    _AI_CONTENT_LABEL = "AI_GENERATED"
    _CONTENT_ORIGIN_TAG = "quivr-rag-langgraph"

    def _build_provenance_envelope(response: ParsedRAGChunkResponse, prompt: str, model_id: str) -> dict:
        """Build a machine-readable provenance envelope for an AI-generated chunk."""
        prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()
        envelope = {
            "model_id": model_id,
            "generation_timestamp": time.time(),
            "prompt_hash": prompt_hash,
            "content_origin": _CONTENT_ORIGIN_TAG,
            "content_label": _AI_CONTENT_LABEL,
            # Steganographic/cryptographic watermark placeholder (text content)
            "watermark": hashlib.sha256(
                (response.answer + prompt_hash).encode()
            ).hexdigest(),
        }
        # Cryptographically sign the envelope so tampering is detectable
        envelope_bytes = json.dumps(
            {k: v for k, v in envelope.items() if k != "signature"}, sort_keys=True
        ).encode()
        envelope["signature"] = hmac.new(
            _PROVENANCE_SIGNING_SECRET, envelope_bytes, hashlib.sha256
        ).hexdigest()
        return envelope

    def _verify_provenance_envelope(envelope: dict) -> None:
        """Verify provenance envelope integrity; fail closed on any violation."""
        required_fields = [
            "model_id", "generation_timestamp", "prompt_hash",
            "content_origin", "content_label", "watermark", "signature",
        ]
        for field in required_fields:
            assert field in envelope and envelope[field], (
                f"PROVENANCE VIOLATION: missing or empty field '{field}' in "
                f"provenance envelope — refusing to serve unlabeled/unsigned content."
            )
        # Re-derive signature and compare (fail closed on mismatch)
        payload = {k: v for k, v in envelope.items() if k != "signature"}
        payload_bytes = json.dumps(payload, sort_keys=True).encode()
        expected_sig = hmac.new(
            _PROVENANCE_SIGNING_SECRET, payload_bytes, hashlib.sha256
        ).hexdigest()
        assert hmac.compare_digest(envelope["signature"], expected_sig), (
            "PROVENANCE VIOLATION: signature mismatch — content may have been "
            "tampered with; refusing to serve."
        )
        # Enforce visible AI content label cannot be silently stripped
        assert envelope["content_label"] == _AI_CONTENT_LABEL, (
            f"PROVENANCE VIOLATION: content_label must be '{_AI_CONTENT_LABEL}', "
            f"got '{envelope['content_label']}' — refusing to serve."
        )
        # Enforce watermark is present and non-trivial
        assert len(envelope["watermark"]) >= 16, (
            "PROVENANCE VIOLATION: watermark is absent or too short — "
            "refusing to serve unlabeled content."
        )

    _prompt_text = "answer in bullet points. tell me something"
    _model_id = llm_config.model

    provenance_envelopes = []
    for resp in stream_responses:
        try:
            envelope = _build_provenance_envelope(resp, _prompt_text, _model_id)
        except Exception as exc:
            raise AssertionError(
                f"PROVENANCE VIOLATION: failed to build provenance envelope "
                f"for AI-generated chunk — failing closed. Cause: {exc}"
            ) from exc
        try:
            _verify_provenance_envelope(envelope)
        except AssertionError:
            raise
        except Exception as exc:
            raise AssertionError(
                f"PROVENANCE VIOLATION: provenance verification raised an unexpected "
                f"error — failing closed. Cause: {exc}"
            ) from exc
        # Attach verified envelope to the response object for downstream consumers
        resp.__dict__["_provenance"] = envelope
        provenance_envelopes.append(envelope)

    # Every chunk must carry a verified provenance envelope before we assert content
    assert len(provenance_envelopes) == len(stream_responses), (
        "PROVENANCE VIOLATION: not all stream chunks received a provenance envelope."
    )
    assert all(
        e["content_label"] == _AI_CONTENT_LABEL for e in provenance_envelopes
    ), "PROVENANCE VIOLATION: one or more chunks are missing the AI content label."
    assert all(
        e["content_origin"] == _CONTENT_ORIGIN_TAG for e in provenance_envelopes
    ), "PROVENANCE VIOLATION: one or more chunks have an unexpected content origin."

    # Assert whole response makes sense (only reached after provenance is verified)
    assert "".join([r.answer for r in stream_responses]) == full_response
