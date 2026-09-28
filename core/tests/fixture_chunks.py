import asyncio
import base64
import json
import re
from uuid import uuid4

from langchain_core.embeddings import DeterministicFakeEmbedding
from langchain_core.messages.ai import AIMessageChunk
from langchain_core.vectorstores import InMemoryVectorStore
from quivr_core.rag.entities.chat import ChatHistory
from quivr_core.rag.entities.config import LLMEndpointConfig, RetrievalConfig
import re as _re

_AI_APP_SEC_006_DISAPPROVED = [
    "deepseekchat",
    "deepseekr1",
    "deepseekr1distillllama70b",
    "deepseekreasoner",
    "customllmclient",
    "openrouter",
    "usdeepseekr1v10",
]


def _ai_app_sec_006_check_model(model: str) -> str:
    """Raise ValueError if model is on the disapproved list."""
    normalized = _re.sub(r"[\s\-_\.:\u0000]", "", model).lower()
    for disapproved in _AI_APP_SEC_006_DISAPPROVED:
        if normalized == disapproved:
            raise ValueError(
                f"Model '{model}' is on the organization's disapproved list and cannot be used."
            )
    return model
from quivr_core.llm import LLMEndpoint
from quivr_core.rag.quivr_rag_langgraph import QuivrQARAGLangGraph


def _ai_app_sec_059_check_prompt(text: str) -> str:
    """Raise ValueError if the prompt contains hidden, encoded, or malicious content."""
    # Check for base64-encoded content
    b64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
    for match in b64_pattern.findall(text):
        try:
            decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
            if any(kw in decoded.lower() for kw in ['exec', 'eval', 'import', 'system', 'shell', 'token', 'secret', 'password', 'credential']):
                raise ValueError("Prompt contains suspicious base64-encoded content.")
        except Exception as exc:
            if 'suspicious' in str(exc):
                raise
    # Check for shell commands / binary executables
    shell_pattern = re.compile(
        r'(\b(exec|eval|system|popen|subprocess|bash|sh|cmd|powershell|wget|curl|chmod|chown|rm\s+-rf|dd\s+if=|nc\s+|ncat\s+|netcat\s+)\b'
        r'|\$\(|`[^`]+`|;\s*\w+\s*\()',
        re.IGNORECASE
    )
    if shell_pattern.search(text):
        raise ValueError("Prompt contains shell commands or executable patterns.")
    # Check for credential/secret access attempts
    cred_pattern = re.compile(
        r'(auth[_\s]?token|api[_\s]?key|secret[_\s]?key|password|bearer\s+[A-Za-z0-9\-._~+/]+=*'
        r'|access[_\s]?token|private[_\s]?key|credentials)',
        re.IGNORECASE
    )
    if cred_pattern.search(text):
        raise ValueError("Prompt attempts to access credentials or secrets.")
    # Check for leetspeak obfuscation (common substitutions like 3->e, 0->o, 1->i/l)
    leet_pattern = re.compile(r'(?:[3@][xX][3e][cC]|[3@][vV][4@][lL]|[5s][yY][5s][tT][3e][mM])', re.IGNORECASE)
    if leet_pattern.search(text):
        raise ValueError("Prompt contains leetspeak-obfuscated commands.")
    # Check for invisible / whitespace-hidden text (zero-width characters)
    invisible_pattern = re.compile(r'[\u200b\u200c\u200d\u2060\ufeff\u00ad]')
    if invisible_pattern.search(text):
        raise ValueError("Prompt contains invisible or zero-width characters.")
    return text


_ai_app_sec_070_patterns = [
    (re.compile(r'ignore previous instructions|forget everything above', re.IGNORECASE), '<prompt_injection_removed: instruction_override>'),
    (re.compile(r'you are now DAN|act as unrestricted', re.IGNORECASE), '<prompt_injection_removed: role_hijack>'),
    (re.compile(r'</?(system|tool|assistant|user)>', re.IGNORECASE), '<prompt_injection_removed: delimiter_escape>'),
    (re.compile(r'(?:[A-Za-z0-9+/]{20,}={0,2}|(?:\\x[0-9a-fA-F]{2}){4,}|(?:%[0-9a-fA-F]{2}){4,}|(?:[0-9a-fA-F]{2}\s){6,})', re.IGNORECASE), '<prompt_injection_removed: encoded_payload>'),
    (re.compile(r'<!--.*?-->|\u200b|\u200c|\u200d|\u2060|\ufeff|<[^>]+style\s*=\s*["\'][^"\'>]*display\s*:\s*none', re.IGNORECASE | re.DOTALL), '<prompt_injection_removed: hidden_text>'),
    (re.compile(r'\[system\]|\[tool\]|<\|system\|>|<\|im_start\|>\s*system', re.IGNORECASE), '<prompt_injection_removed: fake_system_message>'),
    (re.compile(r'!\[.*?\]\(https?://[^)]+\)|send.*?to\s+https?://|leak.*?system prompt|exfiltrate', re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    (re.compile(r'in your (next|previous|following) (response|message|turn)|remember (for|in) (all|future|subsequent)', re.IGNORECASE), '<prompt_injection_removed: context_poisoning>'),
    (re.compile(r'(payload|instruction|command)\s+(in|from|via)\s+(file|data|field|metadata|comment)', re.IGNORECASE), '<prompt_injection_removed: indirect_injection>'),
    (re.compile(r'(?:^|\s)(?:rm\s+-rf|os\.system|subprocess|eval\(|exec\(|__import__|`[^`]+`)', re.IGNORECASE), '<prompt_injection_removed: command_injection>'),
    (re.compile(r'(part|fragment)\s*\d+\s*of\s*\d+|continued (in|on) (next|part)', re.IGNORECASE), '<prompt_injection_removed: split_payload>'),
    (re.compile(r'DAN|developer mode|jailbreak|fictional framing|pretend you have no restrictions|as an AI without (restrictions|guidelines)', re.IGNORECASE), '<prompt_injection_removed: jailbreak_attempt>'),
]


def _ai_app_sec_070_sanitize(text: str) -> str:
    """Sanitize user input to remove prompt injection attempts."""
    if not isinstance(text, str):
        return text
    for pattern, marker in _ai_app_sec_070_patterns:
        text = pattern.sub(marker, text)
    return text


async def main():
    _ai_app_sec_006_check_model("gpt-4o")
    retrieval_config = RetrievalConfig(llm_config=LLMEndpointConfig(model="gpt-4o"))
    embedder = DeterministicFakeEmbedding(size=20)
    vec = InMemoryVectorStore(embedder)

    llm = LLMEndpoint.from_config(retrieval_config.llm_config)
    chat_history = ChatHistory(uuid4(), uuid4())
    rag_pipeline = QuivrQARAGLangGraph(
        retrieval_config=retrieval_config, llm=llm, vector_store=vec
    )

    conversational_qa_chain = rag_pipeline.build_chain()

    _user_message = "What is NLP, give a very long detailed answer"
    _ai_app_sec_059_check_prompt(_user_message)

        _ai_app_sec_070_user_message = _ai_app_sec_070_sanitize("What is NLP, give a very long detailed answer")
    with open("response.jsonl", "w") as f:
        async for event in conversational_qa_chain.astream_events(
            {
                "messages": [
                    ("user", _ai_app_sec_070_user_message),
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
                f.write(json.dumps(dict_chunk) + "\n")


asyncio.run(main())
