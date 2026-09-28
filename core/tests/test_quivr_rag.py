import re
import base64
import re
import re
from uuid import uuid4

import pytest
from quivr_core.rag.entities.chat import ChatHistory
from quivr_core.rag.entities.config import LLMEndpointConfig, RetrievalConfig
from quivr_core.llm import LLMEndpoint
from quivr_core.rag.entities.models import ParsedRAGChunkResponse, RAGResponseMetadata
from quivr_core.rag.quivr_rag_langgraph import QuivrQARAGLangGraph

_ai_app_sec_070_patterns = [
    (
        re.compile(
            r"ignore previous instructions|forget everything above",
            re.IGNORECASE,
        ),
        "<prompt_injection_removed: instruction_override>",
    ),
    (
        re.compile(
            r"you are now DAN|act as unrestricted",
            re.IGNORECASE,
        ),
        "<prompt_injection_removed: role_hijack>",
    ),
    (
        re.compile(
            r"</?(system|tool|assistant|user)\s*>",
            re.IGNORECASE,
        ),
        "<prompt_injection_removed: delimiter_escape>",
    ),
    (
        re.compile(
            r"(?:[A-Za-z0-9+/]{20,}={0,2}|(?:%[0-9A-Fa-f]{2}){6,}|(?:\\u[0-9A-Fa-f]{4}){4,})",
        ),
        "<prompt_injection_removed: encoded_payload>",
    ),
    (
        re.compile(
            r"<!--.*?-->",
            re.DOTALL,
        ),
        "<prompt_injection_removed: hidden_text>",
    ),
    (
        re.compile(
            r"\[SYSTEM\]|\[TOOL\]|<\|system\|>|<\|im_start\|>system",
            re.IGNORECASE,
        ),
        "<prompt_injection_removed: fake_system_message>",
    ),
    (
        re.compile(
            r"!\[.*?\]\(https?://[^)]+\)|send.*?to.*?https?://|leak.*?system prompt|exfiltrate",
            re.IGNORECASE,
        ),
        "<prompt_injection_removed: exfiltration_attempt>",
    ),
    (
        re.compile(
            r"in your next response|from now on you will|remember this for later turns",
            re.IGNORECASE,
        ),
        "<prompt_injection_removed: context_poisoning>",
    ),
    (
        re.compile(
            r"the (document|file|data|metadata) says? (to|you should|ignore)",
            re.IGNORECASE,
        ),
        "<prompt_injection_removed: indirect_injection>",
    ),
    (
        re.compile(
            r"(?:os\.system|subprocess\.(?:call|run|Popen)|eval\s*\(|exec\s*\()",
        ),
        "<prompt_injection_removed: command_injection>",
    ),
    (
        re.compile(
            r"(?:ignore|disregard).{0,40}(?:above|previous|prior).{0,40}(?:and|then|now)",
            re.IGNORECASE,
        ),
        "<prompt_injection_removed: split_payload>",
    ),
    (
        re.compile(
            r"DAN mode|developer mode enabled|fictional framing|pretend you have no restrictions",
            re.IGNORECASE,
        ),
        "<prompt_injection_removed: jailbreak_attempt>",
    ),
]


def _ai_app_sec_070_sanitize(text: str) -> str:
    """Neutralize prompt injection patterns in user-supplied text."""
    for pattern, marker in _ai_app_sec_070_patterns:
        text = pattern.sub(marker, text)
    return text


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


def _ai_app_sec_006_normalize(name: str) -> str:
    return re.sub(r'[\s\-_\.:]', '', name).lower()


_AI_APP_SEC_006_DISAPPROVED = [
    'deepseekchat',
    'deepseekr1',
    'deepseekr1distillllama70b',
    'deepseekreasoner',
    'customllmclientnull',
    'deepseekchatnull',
    'opennull',
    'usdeepseekr1v10null',
]


def _ai_app_sec_006_check_model(model: str) -> str:
    normalized = _ai_app_sec_006_normalize(model)
    for disapproved in _AI_APP_SEC_006_DISAPPROVED:
        if normalized == disapproved:
            raise ValueError(
                f"Model '{model}' is disapproved by the organization's model registry."
            )
    return model


def _ai_app_sec_059_check_prompt(prompt: str) -> str:
    """Check prompt for hidden, encoded, or malicious content before sending to LLM."""
    # Check for base64-encoded content
    b64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
    for match in b64_pattern.findall(prompt):
        try:
            decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
            if any(kw in decoded.lower() for kw in ['exec', 'eval', 'system', 'import', 'token', 'secret', 'password', 'credential']):
                raise ValueError(f"Potentially malicious base64-encoded content detected in prompt.")
        except Exception as e:
            if 'malicious' in str(e):
                raise
    # Check for shell commands / binary executables
    shell_pattern = re.compile(
        r'(\b(exec|eval|system|popen|subprocess|os\.system|sh\s+-c|bash\s+-c|cmd\.exe|powershell)\b'
        r'|\$\(|`[^`]+`|\x00|\\x[0-9a-fA-F]{2})',
        re.IGNORECASE
    )
    if shell_pattern.search(prompt):
        raise ValueError("Prompt contains shell commands or binary executable patterns.")
    # Check for credential/secret access attempts
    cred_pattern = re.compile(
        r'(auth[_\s]?token|api[_\s]?key|secret[_\s]?key|password|credential|bearer\s+[A-Za-z0-9\-._~+/]+=*)',
        re.IGNORECASE
    )
    if cred_pattern.search(prompt):
        raise ValueError("Prompt contains suspicious credential or secret access patterns.")
    # Check for leetspeak obfuscation (e.g. 3x3c, 3v4l)
    leet_pattern = re.compile(r'[3@][xX][3@][cC]|[3@][vV][4@][lL]', re.IGNORECASE)
    if leet_pattern.search(prompt):
        raise ValueError("Prompt contains leetspeak-obfuscated command patterns.")
    # Check for invisible/whitespace-hidden text (zero-width chars)
    invisible_pattern = re.compile(r'[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad]')
    if invisible_pattern.search(prompt):
        raise ValueError("Prompt contains invisible or zero-width characters.")
    return prompt


@pytest.mark.base
@pytest.mark.asyncio
async def test_quivrqaraglanggraph(
    mem_vector_store, full_response, mock_chain_qa_stream, openai_api_key
):
    # Making sure the model
    _ai_app_sec_006_check_model("gpt-4o")
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
    _ai_app_sec_059_user_prompt = _ai_app_sec_059_check_prompt("answer in bullet points. tell me something")
        _ai_app_sec_070_query = _ai_app_sec_070_sanitize(
        "answer in bullet points. tell me something"
    )
    async for resp in rag_pipeline.answer_astream(
        _ai_app_sec_070_query, chat_history, []
    ):
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

    # Assert whole response makes sense
    assert "".join([r.answer for r in stream_responses]) == full_response
