import re
from dataclasses import asdict
from uuid import uuid4
from lineaje_guardrail import lineaje_guardrail, GuardrailBlockedError

_ai_app_sec_059_guardrail = lineaje_guardrail()
_ai_app_sec_059_guardrail.enable_policies(["AI_APP_SEC_059.json"])

import pytest
from langchain_core.documents import Document
from langchain_core.embeddings import Embeddings
from quivr_core.brain import Brain
from quivr_core.rag.entities.chat import ChatHistory
from quivr_core.llm import LLMEndpoint
from quivr_core.storage.local_storage import TransparentStorage

_ai_app_sec_070_patterns = [
    # 1. instruction_override
    (re.compile(r'ignore previous instructions|forget everything above', re.IGNORECASE),
     '<prompt_injection_removed: instruction_override>'),
    # 2. role_hijack
    (re.compile(r'you are now DAN|act as unrestricted', re.IGNORECASE),
     '<prompt_injection_removed: role_hijack>'),
    # 3. delimiter_escape
    (re.compile(r'</?(system|tool|assistant|user)\s*>', re.IGNORECASE),
     '<prompt_injection_removed: delimiter_escape>'),
    # 4. encoded_payload
    (re.compile(
        r'(?:[A-Za-z0-9+/]{20,}={0,2}|'
        r'(?:\\x[0-9a-fA-F]{2}){4,}|'
        r'(?:%[0-9a-fA-F]{2}){4,}|'
        r'(?:[0-9a-fA-F]{2}\s){6,}|'
        r'(?:\.-\.|-\.\.|\.\.-){4,})',
        re.IGNORECASE),
     '<prompt_injection_removed: encoded_payload>'),
    # 5. hidden_text
    (re.compile(r'<!--.*?-->|\u200b|\u200c|\u200d|\u2060|\ufeff|'
                r'style\s*=\s*["\']?display\s*:\s*none', re.IGNORECASE | re.DOTALL),
     '<prompt_injection_removed: hidden_text>'),
    # 6. fake_system_message
    (re.compile(r'\[\s*(?:SYSTEM|TOOL|ASSISTANT)\s*\]|'
                r'<\s*(?:system|tool)\s*>',
                re.IGNORECASE),
     '<prompt_injection_removed: fake_system_message>'),
    # 7. exfiltration_attempt
    (re.compile(
        r'!\[.*?\]\(https?://[^)]+\)|'
        r'send\s+(?:this|the|all|data|prompt|system)\s+(?:data|info|prompt|to)\s+https?://|'
        r'leak\s+(?:the\s+)?system\s+prompt',
        re.IGNORECASE),
     '<prompt_injection_removed: exfiltration_attempt>'),
    # 8. context_poisoning
    (re.compile(r'in\s+(?:a\s+)?previous\s+(?:turn|message|conversation)\s+(?:you\s+)?(?:said|agreed|told)',
                re.IGNORECASE),
     '<prompt_injection_removed: context_poisoning>'),
    # 9. indirect_injection
    (re.compile(r'(?:the\s+)?(?:file|document|data|metadata|field)\s+(?:says?|contains?|instructs?)\s+you\s+to',
                re.IGNORECASE),
     '<prompt_injection_removed: indirect_injection>'),
    # 10. command_injection
    (re.compile(r'(?:^|\s)(?:eval|exec|os\.system|subprocess\.(?:call|run|Popen))\s*\(',
                re.IGNORECASE | re.MULTILINE),
     '<prompt_injection_removed: command_injection>'),
    # 11. split_payload
    (re.compile(r'(?:part\s*[12]\s*of\s*[12]|continued\s+from\s+(?:above|previous))',
                re.IGNORECASE),
     '<prompt_injection_removed: split_payload>'),
    # 12. jailbreak_attempt
    (re.compile(r'\bDAN\b|developer\s+mode|fictional\s+framing|jailbreak',
                re.IGNORECASE),
     '<prompt_injection_removed: jailbreak_attempt>'),
]


def _ai_app_sec_070_sanitize(text: str) -> str:
    """Replace known prompt-injection patterns with their markers."""
    for pattern, marker in _ai_app_sec_070_patterns:
        text = pattern.sub(marker, text)
    return text
import re as _re

_AI_APP_SEC_006_DISAPPROVED = [
    "deepseekchat",
    "deepseekr1",
    "deepseekr1distillllama70b",
    "deepseekreasoner",
    "customllmclientnull",
    "deepseekchatnull",
    "openrouternull",
    "usdeepseekr1v10null",
]


def _ai_app_sec_006_normalize(name: str) -> str:
    return _re.sub(r"[\s\-_\.:\u0000]", "", name).lower()


def _ai_app_sec_006_check_model(llm) -> None:
    """Raise ValueError if the LLM uses a disapproved model."""
    try:
        model_id = llm.llm.model_name if hasattr(llm.llm, "model_name") else str(llm)
    except Exception:
        model_id = str(llm)
    normalized = _ai_app_sec_006_normalize(model_id)
    for disapproved in _AI_APP_SEC_006_DISAPPROVED:
        if disapproved in normalized or normalized in disapproved:
            raise ValueError(
                f"Model '{model_id}' is on the organization's disapproved list and cannot be used."
            )


@pytest.mark.base
def test_brain_empty_files_no_vectordb(fake_llm, embedder):
    _ai_app_sec_006_check_model(fake_llm)
    # Testing no files
    with pytest.raises(ValueError):
        Brain.from_files(
            name="test_brain",
            file_paths=[],
            llm=fake_llm,
            embedder=embedder,
        )


def test_brain_empty_files(fake_llm, embedder, mem_vector_store):
    _ai_app_sec_006_check_model(fake_llm)
    brain = Brain.from_files(
        name="test_brain",
        file_paths=[],
        llm=fake_llm,
        embedder=embedder,
        vector_db=mem_vector_store,
    )
    assert brain


@pytest.mark.asyncio
async def test_brain_from_files_success(
    fake_llm: LLMEndpoint, embedder, temp_data_file, mem_vector_store
):
    _ai_app_sec_006_check_model(fake_llm)
    brain = await Brain.afrom_files(
        name="test_brain",
        file_paths=[temp_data_file],
        embedder=embedder,
        llm=fake_llm,
        vector_db=mem_vector_store,
    )
    assert brain.name == "test_brain"
    assert len(brain.chat_history) == 0
    assert brain.llm == fake_llm
    assert brain.vector_db.embeddings == embedder
    assert isinstance(brain.default_chat, ChatHistory)
    assert len(brain.default_chat) == 0

    # storage
    assert isinstance(brain.storage, TransparentStorage)
    assert len(await brain.storage.get_files()) == 1


@pytest.mark.asyncio
async def test_brain_from_langchain_docs(embedder, fake_llm, mem_vector_store):
    _ai_app_sec_006_check_model(fake_llm)
    chunk = Document("content_1", metadata={"id": uuid4()})
    brain = await Brain.afrom_langchain_documents(
        name="test",
        llm=fake_llm,
        langchain_documents=[chunk],
        embedder=embedder,
        vector_db=mem_vector_store,
    )
    # No appended files
    assert len(await brain.storage.get_files()) == 0
    assert len(brain.chat_history) == 0


@pytest.mark.base
@pytest.mark.asyncio
async def test_brain_search(
    embedder: Embeddings,
):
    chunk1 = Document("content_1", metadata={"id": uuid4()})
    chunk2 = Document("content_2", metadata={"id": uuid4()})
    brain = await Brain.afrom_langchain_documents(
        name="test", langchain_documents=[chunk1, chunk2], embedder=embedder
    )

    k = 2
    result = await brain.asearch(_ai_app_sec_070_sanitize("content_1"), n_results=k)

    assert len(result) == k
    assert result[0].chunk == chunk1
    assert result[1].chunk == chunk2
    assert result[0].distance == 0
    assert result[1].distance > result[0].distance


@pytest.mark.asyncio
async def test_brain_get_history(
    fake_llm: LLMEndpoint, embedder, temp_data_file, mem_vector_store
):
    _ai_app_sec_006_check_model(fake_llm)
    brain = await Brain.afrom_files(
        name="test_brain",
        file_paths=[temp_data_file],
        embedder=embedder,
        llm=fake_llm,
        vector_db=mem_vector_store,
    )

    _ai_app_sec_059_q1 = _ai_app_sec_059_guardrail.evaluate("question")
    await brain.aask(_ai_app_sec_059_q1)
    _ai_app_sec_059_q2 = _ai_app_sec_059_guardrail.evaluate("question")
    await brain.aask(_ai_app_sec_059_q2)

    assert len(brain.default_chat) == 4


@pytest.mark.base
@pytest.mark.asyncio
async def test_brain_ask_streaming(
    fake_llm: LLMEndpoint, embedder, temp_data_file, answers
):
    _ai_app_sec_006_check_model(fake_llm)
    brain = await Brain.afrom_files(
        name="test_brain", file_paths=[temp_data_file], embedder=embedder, llm=fake_llm
    )

    response = ""
    _ai_app_sec_059_sq = _ai_app_sec_059_guardrail.evaluate("question")
    async for chunk in brain.ask_streaming(_ai_app_sec_059_sq):
        response += chunk.answer

    assert response == answers[1]


def test_brain_info_empty(fake_llm: LLMEndpoint, embedder, mem_vector_store):
    _ai_app_sec_006_check_model(fake_llm)
    storage = TransparentStorage()
    id = uuid4()
    brain = Brain(
        name="test",
        id=id,
        llm=fake_llm,
        embedder=embedder,
        storage=storage,
        vector_db=mem_vector_store,
    )

    assert asdict(brain.info()) == {
        "brain_id": id,
        "brain_name": "test",
        "files_info": asdict(storage.info()),
        "chats_info": {
            "nb_chats": 1,  # start with a default chat
            "current_default_chat": brain.default_chat.id,
            "current_chat_history_length": 0,
        },
        "llm_info": asdict(fake_llm.info()),
    }
