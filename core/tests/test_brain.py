import re
from dataclasses import asdict
from uuid import uuid4
import base64
import re

import pytest


def _ai_app_sec_059_check_prompt(prompt: str) -> str:
    """Check a prompt string for hidden, encoded, or malicious content.

    Raises ValueError if suspicious content is detected.
    Returns the original prompt if it passes all checks.
    """
    if not isinstance(prompt, str):
        raise ValueError("Prompt must be a string.")

    # Check for invisible/whitespace-only content or zero-width characters
    invisible_chars = re.compile(r'[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad]')
    if invisible_chars.search(prompt):
        raise ValueError("Prompt contains invisible/hidden characters.")

    # Check for base64-encoded content (long base64 blobs)
    b64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{40,}={0,2})')
    for match in b64_pattern.findall(prompt):
        try:
            decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
            shell_in_decoded = re.search(
                r'(eval|exec|system|subprocess|os\.system|base64|/bin/|/etc/passwd|curl |wget |chmod |rm -|sudo |sh -c)',
                decoded, re.IGNORECASE
            )
            if shell_in_decoded:
                raise ValueError("Prompt contains base64-encoded shell/malicious command.")
        except Exception as exc:
            if 'base64-encoded' in str(exc):
                raise

    # Check for shell commands and binary executable patterns
    shell_pattern = re.compile(
        r'(\beval\s*\(|\bexec\s*\(|os\.system\s*\(|subprocess\.|/bin/sh|/bin/bash'
        r'|\bchmod\b|\brm\s+-|\bsudo\b|\bwget\b|\bcurl\b|\bnc\b|\bnetcat\b'
        r'|\$\(|`[^`]+`|\bpython\s+-c\b|\bperl\s+-e\b|\bruby\s+-e\b)',
        re.IGNORECASE
    )
    if shell_pattern.search(prompt):
        raise ValueError("Prompt contains shell commands or binary executable patterns.")

    # Check for credential/secret/token harvesting attempts
    cred_pattern = re.compile(
        r'(api[_\s-]?key|secret[_\s-]?key|auth[_\s-]?token|bearer\s+token'
        r'|password|passwd|credentials|private[_\s-]?key|access[_\s-]?token'
        r'|\.env\b|/etc/shadow|/etc/passwd)',
        re.IGNORECASE
    )
    if cred_pattern.search(prompt):
        raise ValueError("Prompt contains credential/secret harvesting patterns.")

    # Check for leetspeak obfuscation of dangerous words
    leet_map = str.maketrans('013457@$', 'oieatsas')
    normalized = prompt.lower().translate(leet_map)
    leet_danger = re.compile(
        r'\b(exec|eval|system|shell|passwd|rootkit|exploit|payload|malware|backdoor)\b'
    )
    if leet_danger.search(normalized):
        raise ValueError("Prompt contains leetspeak-obfuscated dangerous content.")

    return prompt
from langchain_core.documents import Document
from langchain_core.embeddings import Embeddings
from quivr_core.brain import Brain
from quivr_core.rag.entities.chat import ChatHistory
from quivr_core.llm import LLMEndpoint
import re

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


def _ai_app_sec_006_check_llm(llm):
    """Raise ValueError if the LLM uses a disapproved model."""
    model_id = ""
    try:
        info = llm.info()
        model_id = str(getattr(info, "model", "") or "")
    except Exception:
        pass
    normalized = re.sub(r"[\s\-_\.:\"']", "", model_id).lower()
    for disapproved in _AI_APP_SEC_006_DISAPPROVED:
        if disapproved in normalized:
            raise ValueError(
                f"LLM model '{model_id}' is on the organization's disapproved list."
            )
    return llm
from quivr_core.storage.local_storage import TransparentStorage

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
            r"\[\s*(?:system|tool)\s*\].*",
            re.IGNORECASE,
        ),
        "<prompt_injection_removed: fake_system_message>",
    ),
    (
        re.compile(
            r"!\[.*?\]\(https?://[^)]+\)|send.*?to\s+https?://\S+|leak.*?system prompt",
            re.IGNORECASE,
        ),
        "<prompt_injection_removed: exfiltration_attempt>",
    ),
    (
        re.compile(
            r"in a previous conversation|as we discussed earlier|building on what you said",
            re.IGNORECASE,
        ),
        "<prompt_injection_removed: context_poisoning>",
    ),
    (
        re.compile(
            r"the file (says|contains|instructs)|metadata says|hidden in (the )?(file|data|field)",
            re.IGNORECASE,
        ),
        "<prompt_injection_removed: indirect_injection>",
    ),
    (
        re.compile(
            r"`[^`]*`|\$\([^)]*\)|os\.system\s*\(|subprocess\.(run|call|Popen)\s*\(",
            re.IGNORECASE,
        ),
        "<prompt_injection_removed: command_injection>",
    ),
    (
        re.compile(
            r"(part\s*1\s*of|continued\s*in\s*part|split\s*payload)",
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


@pytest.mark.base
def test_brain_empty_files_no_vectordb(fake_llm, embedder):
    # Testing no files
    _ai_app_sec_006_check_llm(fake_llm)
    with pytest.raises(ValueError):
        Brain.from_files(
            name="test_brain",
            file_paths=[],
            llm=fake_llm,
            embedder=embedder,
        )


def test_brain_empty_files(fake_llm, embedder, mem_vector_store):
    _ai_app_sec_006_check_llm(fake_llm)
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
    _ai_app_sec_006_check_llm(fake_llm)
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
    _ai_app_sec_006_check_llm(fake_llm)
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
    result = await brain.asearch(_ai_app_sec_059_check_prompt("content_1"), n_results=k)

    assert len(result) == k
    assert result[0].chunk == chunk1
    assert result[1].chunk == chunk2
    assert result[0].distance == 0
    assert result[1].distance > result[0].distance


@pytest.mark.asyncio
async def test_brain_get_history(
    fake_llm: LLMEndpoint, embedder, temp_data_file, mem_vector_store
):
    _ai_app_sec_006_check_llm(fake_llm)
    brain = await Brain.afrom_files(
        name="test_brain",
        file_paths=[temp_data_file],
        embedder=embedder,
        llm=fake_llm,
        vector_db=mem_vector_store,
    )

    _q1 = _ai_app_sec_059_check_prompt("question")
    await brain.aask(_q1)
    _q2 = _ai_app_sec_059_check_prompt("question")
    await brain.aask(_q2)

    assert len(brain.default_chat) == 4


@pytest.mark.base
@pytest.mark.asyncio
async def test_brain_ask_streaming(
    fake_llm: LLMEndpoint, embedder, temp_data_file, answers
):
    _ai_app_sec_006_check_llm(fake_llm)
    brain = await Brain.afrom_files(
        name="test_brain", file_paths=[temp_data_file], embedder=embedder, llm=fake_llm
    )

    response = ""
    async for chunk in brain.ask_streaming(_ai_app_sec_059_check_prompt("question")):
        response += chunk.answer

    assert response == answers[1]


def test_brain_info_empty(fake_llm: LLMEndpoint, embedder, mem_vector_store):
    _ai_app_sec_006_check_llm(fake_llm)
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
