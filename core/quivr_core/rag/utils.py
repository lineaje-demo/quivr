import logging
import re
from typing import Any, Dict, List, Tuple, no_type_check

from lineaje_guardrail import lineaje_guardrail

_ai_app_sec_059_guardrail = lineaje_guardrail()
_ai_app_sec_059_guardrail.enable_policies(["AI_APP_SEC_059.json"])

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
from langchain_core.messages.ai import AIMessageChunk
from langchain_core.prompts import format_document
from langfuse.callback import CallbackHandler

from quivr_core.rag.entities.config import WorkflowConfig
from quivr_core.rag.entities.models import (
    ChatLLMMetadata,
    ParsedRAGResponse,
    QuivrKnowledge,
    RAGResponseMetadata,
    RawRAGResponse,
)
from quivr_core.rag.prompts import TemplatePromptName, custom_prompts

# TODO(@aminediro): define a types packages where we clearly define IO types
# This should be used for serialization/deseriallization later


logger = logging.getLogger("quivr_core")

_ai_app_sec_070_patterns: List[Tuple[re.Pattern, str]] = [
    # 1. instruction_override
    (re.compile(
        r'ignore\s+(?:all\s+)?previous\s+instructions|forget\s+everything\s+above',
        re.IGNORECASE), '<prompt_injection_removed: instruction_override>'),
    # 2. role_hijack
    (re.compile(
        r'you\s+are\s+now\s+DAN|act\s+as\s+(?:an?\s+)?unrestricted',
        re.IGNORECASE), '<prompt_injection_removed: role_hijack>'),
    # 3. delimiter_escape - fake </system>, </user>, </assistant> tags or injected separators
    (re.compile(
        r'</\s*(?:system|user|assistant|prompt|context|instruction)\s*>|<\s*(?:system|user|assistant|prompt|context|instruction)\s*>',
        re.IGNORECASE), '<prompt_injection_removed: delimiter_escape>'),
    # 4. encoded_payload - base64 blobs, hex sequences, ROT13 cues, URL-encoded instructions
    (re.compile(
        r'(?:base64|hex|rot13|leetspeak|morse|url.?encod)\s*(?:decode|encode|:)',
        re.IGNORECASE), '<prompt_injection_removed: encoded_payload>'),
    # 5. hidden_text - HTML comments, zero-width chars, CSS hidden
    (re.compile(
        r'<!--.*?-->|[\u200b-\u200f\u202a-\u202e\u2060\ufeff]|display\s*:\s*none',
        re.IGNORECASE | re.DOTALL), '<prompt_injection_removed: hidden_text>'),
    # 6. fake_system_message
    (re.compile(
        r'\[\s*(?:system|tool|assistant)\s*\]|<<\s*(?:system|tool)\s*>>|<\|\s*(?:system|tool)\s*\|>',
        re.IGNORECASE), '<prompt_injection_removed: fake_system_message>'),
    # 7. exfiltration_attempt - markdown image exfil, send/leak data to URLs
    (re.compile(
        r'!\[.*?\]\(https?://[^)]*\?[^)]*\)|(?:send|leak|exfiltrate|transmit)\s+(?:the\s+)?(?:system\s+prompt|data|context)\s+to\s+https?://',
        re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    # 8. context_poisoning
    (re.compile(
        r'context\s+poison(?:ing)?|multi.?turn\s+manipulat',
        re.IGNORECASE), '<prompt_injection_removed: context_poisoning>'),
    # 9. indirect_injection - payloads in metadata/data fields
    (re.compile(
        r'indirect\s+injection|payload\s+in\s+(?:file|data|metadata)',
        re.IGNORECASE), '<prompt_injection_removed: indirect_injection>'),
    # 10. command_injection - shell/code execution
    (re.compile(
        r'(?:^|\s)(?:eval|exec|os\.system|subprocess\.(?:call|run|Popen)|shell=True)\s*\(',
        re.IGNORECASE | re.MULTILINE), '<prompt_injection_removed: command_injection>'),
    # 11. split_payload - fragmented instructions
    (re.compile(
        r'(?:split|fragment(?:ed)?)\s+payload|continue\s+(?:the\s+)?(?:previous\s+)?instruction',
        re.IGNORECASE), '<prompt_injection_removed: split_payload>'),
    # 12. jailbreak_attempt - DAN, developer mode, fictional framing
    (re.compile(
        r'\bDAN\b|developer\s+mode\s+enabled|fictional\s+(?:framing|scenario)\s+(?:to\s+)?bypass|jailbreak',
        re.IGNORECASE), '<prompt_injection_removed: jailbreak_attempt>'),
]


def _ai_app_sec_070_sanitize(text: str) -> str:
    """Neutralize prompt injection patterns in user-supplied text before LLM handoff."""
    for pattern, marker in _ai_app_sec_070_patterns:
        text = pattern.sub(marker, text)
    return text

_AI_APP_SEC_006_DISAPPROVED_PATTERNS: list[str] = [
    "deepseekr1distillama70b",
    "deepseekr1",
    "deepseekreasoner",
    "deepseek",
    "customllmclient",
    "openrouter",
    "usdeepseekr1v10",
]


def _ai_app_sec_006_normalize(name: str) -> str:
    """Normalize a model name for registry comparison."""
    import re
    return re.sub(r"[\s\-_\.:\u0000]", "", name).lower()


def _ai_app_sec_006_check_model(model_name: str) -> None:
    """Raise ValueError if model_name matches a disapproved model."""
    normalized = _ai_app_sec_006_normalize(model_name)
    for pattern in _AI_APP_SEC_006_DISAPPROVED_PATTERNS:
        if pattern in normalized:
            raise ValueError(
                f"Model '{model_name}' is not permitted by the organization's model registry."
            )


def model_supports_function_calling(model_name: str):
    _ai_app_sec_006_check_model(model_name)
    models_not_supporting_function_calls: list[str] = ["llama2", "test", "ollama3"]

    return model_name not in models_not_supporting_function_calls


def format_history_to_openai_mesages(
    tuple_history: List[Tuple[str, str]], system_message: str, question: str
) -> List[BaseMessage]:
    """Format the chat history into a list of Base Messages"""
    messages = []
    messages.append(SystemMessage(content=system_message))
        for human, ai in tuple_history:
        messages.append(HumanMessage(content=_ai_app_sec_070_sanitize(human)))
        messages.append(AIMessage(content=ai))
    messages.append(HumanMessage(content=_ai_app_sec_070_sanitize(question)))
    return messages


def cited_answer_filter(tool):
    return tool["name"] == "cited_answer"


def get_chunk_metadata(
    msg: AIMessageChunk, sources: list[Any] | None = None
) -> RAGResponseMetadata:
    metadata = {"sources": sources or []}

    if not msg.tool_calls:
        return RAGResponseMetadata(**metadata, metadata_model=None)

    all_citations = []
    all_followup_questions = []

    for tool_call in msg.tool_calls:
        if tool_call.get("name") == "cited_answer" and "args" in tool_call:
            args = tool_call["args"]
            all_citations.extend(args.get("citations", []))
            all_followup_questions.extend(args.get("followup_questions", []))

    metadata["citations"] = all_citations
    metadata["followup_questions"] = all_followup_questions[:3]  # Limit to 3

    return RAGResponseMetadata(**metadata, metadata_model=None)


def get_prev_message_str(msg: AIMessageChunk) -> str:
    if msg.tool_calls:
        cited_answer = next(x for x in msg.tool_calls if cited_answer_filter(x))
        if "args" in cited_answer and "answer" in cited_answer["args"]:
            return cited_answer["args"]["answer"]
    return ""


# TODO: CONVOLUTED LOGIC !
# TODO(@aminediro): redo this
@no_type_check
def parse_chunk_response(
    rolling_msg: AIMessageChunk,
    raw_chunk: AIMessageChunk,
    supports_func_calling: bool,
    previous_content: str = "",
) -> Tuple[AIMessageChunk, str, str]:
    """Parse a chunk response
    Args:
        rolling_msg: The accumulated message so far
        raw_chunk: The new chunk to add
        supports_func_calling: Whether function calling is supported
        previous_content: The previous content string
    Returns:
        Tuple of (updated rolling message, new content only, full content)
    """
    rolling_msg += raw_chunk

    tool_calls = rolling_msg.tool_calls

    if not supports_func_calling or not tool_calls:
        new_content = raw_chunk.content  # Just the new chunk's content
        full_content = rolling_msg.content  # The full accumulated content
        return rolling_msg, new_content, full_content

    current_answers = get_answers_from_tool_calls(tool_calls)
    full_answer = "\n\n".join(current_answers)
    if not full_answer:
        full_answer = previous_content

    new_content = full_answer[len(previous_content) :]

    return rolling_msg, new_content, full_answer


def get_answers_from_tool_calls(tool_calls):
    answers = []
    for tool_call in tool_calls:
        if tool_call.get("name") == "cited_answer":
            args = tool_call.get("args", {})
            if isinstance(args, dict):
                answers.append(args.get("answer", ""))
            else:
                logger.warning(f"Expected dict for tool_call args, got {type(args)}")
    return answers


@no_type_check
def parse_response(raw_response: RawRAGResponse, model_name: str) -> ParsedRAGResponse:
    answers = []
    sources = raw_response["docs"] if "docs" in raw_response else []

    metadata = RAGResponseMetadata(
        sources=sources, metadata_model=ChatLLMMetadata(name=model_name)
    )

    if (
        model_supports_function_calling(model_name)
        and "tool_calls" in raw_response["answer"]
        and raw_response["answer"].tool_calls
    ):
        all_citations = []
        all_followup_questions = []
        for tool_call in raw_response["answer"].tool_calls:
            if "args" in tool_call:
                args = tool_call["args"]
                if "citations" in args:
                    all_citations.extend(args["citations"])
                if "followup_questions" in args:
                    all_followup_questions.extend(args["followup_questions"])
                if "answer" in args:
                    answers.append(args["answer"])
        metadata.citations = all_citations
        metadata.followup_questions = all_followup_questions
    else:
        answers.append(raw_response["answer"].content)

    answer_str = "\n".join(answers)
    parsed_response = ParsedRAGResponse(answer=answer_str, metadata=metadata)
    return parsed_response


def combine_documents(
    docs,
    document_prompt=custom_prompts[TemplatePromptName.DEFAULT_DOCUMENT_PROMPT],
    document_separator="\n\n",
):
    # for each docs, add an index in the metadata to be able to cite the sources
    for doc, index in zip(docs, range(len(docs)), strict=False):
        doc.metadata["index"] = index
    doc_strings = [format_document(doc, document_prompt) for doc in docs]
    return document_separator.join(doc_strings)


def format_file_list(
    list_files_array: list[QuivrKnowledge], max_files: int = 20
) -> str:
    list_files = [file.file_name or file.url for file in list_files_array]
    files: list[str] = list(filter(lambda n: n is not None, list_files))  # type: ignore
    files = files[:max_files]

    files_str = "\n".join(files) if list_files_array else "None"
    return files_str


def collect_tools(workflow_config: WorkflowConfig):
    validated_tools = "Available tools which can be activated:\n"
    for i, tool in enumerate(workflow_config.validated_tools):
        validated_tools += f"Tool {i+1} name: {tool.name}\n"
        validated_tools += f"Tool {i+1} description: {tool.description}\n\n"

    activated_tools = "Activated tools which can be deactivated:\n"
    for i, tool in enumerate(workflow_config.activated_tools):
        activated_tools += f"Tool {i+1} name: {tool.name}\n"
        activated_tools += f"Tool {i+1} description: {tool.description}\n\n"

    return validated_tools, activated_tools


def format_dict(kv: Dict[str, str]) -> str:
    return "\n".join([f"{k}: {v}" for k, v in kv.items() if v is not None and v != ""])


class LangfuseService:
    def __init__(self):
        self.langfuse_handler = CallbackHandler()

    def get_handler(self):
        return self.langfuse_handler
