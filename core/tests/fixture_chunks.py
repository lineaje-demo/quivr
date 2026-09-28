import asyncio
import json
import re
from uuid import uuid4
from lineaje_guardrail import lineaje_guardrail

_ai_app_sec_059_guardrail = lineaje_guardrail()
_ai_app_sec_059_guardrail.enable_policies(["AI_APP_SEC_059.json"])

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
    normalized = _re.sub(r"[\s\-_\.:\u0000-\u001f]", "", model).lower()
    if normalized in _AI_APP_SEC_006_DISAPPROVED:
        raise ValueError(
            f"Model '{model}' is on the organization's disapproved list and cannot be used."
        )
    return model
from quivr_core.llm import LLMEndpoint
from quivr_core.rag.quivr_rag_langgraph import QuivrQARAGLangGraph


_ai_app_sec_070_patterns = [
    (re.compile(r'ignore previous instructions|forget everything above', re.IGNORECASE), '<prompt_injection_removed: instruction_override>'),
    (re.compile(r'you are now DAN|act as unrestricted', re.IGNORECASE), '<prompt_injection_removed: role_hijack>'),
    (re.compile(r'</?(system|tool|assistant|user)\s*>', re.IGNORECASE), '<prompt_injection_removed: delimiter_escape>'),
    (re.compile(r'(?:[A-Za-z0-9+/]{20,}={0,2}|\\u[0-9a-fA-F]{4}|%[0-9a-fA-F]{2}(?:%[0-9a-fA-F]{2}){4,}|(?:[0-9a-fA-F]{2}\s){8,})', re.IGNORECASE), '<prompt_injection_removed: encoded_payload>'),
    (re.compile(r'<!--.*?-->|\u200b|\u200c|\u200d|\u2060|\ufeff|display\s*:\s*none', re.IGNORECASE | re.DOTALL), '<prompt_injection_removed: hidden_text>'),
    (re.compile(r'\[system\]|\[tool\]|<\|system\|>|<\|im_start\|>\s*system', re.IGNORECASE), '<prompt_injection_removed: fake_system_message>'),
    (re.compile(r'!\[.*?\]\(https?://[^)]+\)|send (this|the|all|data|prompt|system) (to|at) https?://\S+|leak (the )?system prompt', re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    (re.compile(r'in (previous|earlier|prior) (turns?|messages?|context)|remember (from|that) (earlier|before|previously)', re.IGNORECASE), '<prompt_injection_removed: context_poisoning>'),
    (re.compile(r'(instructions?|payload|prompt)\s+(in|from|inside)\s+(file|data|field|metadata|comment)', re.IGNORECASE), '<prompt_injection_removed: indirect_injection>'),
    (re.compile(r'`{0,3}\s*(bash|sh|python|cmd|powershell|exec|eval|os\.system|subprocess)\s*[(`]', re.IGNORECASE), '<prompt_injection_removed: command_injection>'),
    (re.compile(r'(part|fragment|chunk|piece)\s*\d+\s*of\s*\d+', re.IGNORECASE), '<prompt_injection_removed: split_payload>'),
    (re.compile(r'DAN|developer mode|jailbreak|fictional framing|pretend (you are|to be) (an? )?(unrestricted|unfiltered|evil|malicious)', re.IGNORECASE), '<prompt_injection_removed: jailbreak_attempt>'),
]


def _ai_app_sec_070_sanitize(text: str) -> str:
    """Neutralize prompt injection patterns in user-supplied text."""
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

    _ai_app_sec_059_payload = {
        "messages": [
            ("user", "What is NLP, give a very long detailed answer"),
        ],
        "chat_history": chat_history,
        "custom_personality": None,
    }
    _ai_app_sec_059_payload = _ai_app_sec_059_guardrail.evaluate(_ai_app_sec_059_payload)
    with open("response.jsonl", "w") as f:
        async for event in conversational_qa_chain.astream_events(
            _ai_app_sec_059_payload,
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
