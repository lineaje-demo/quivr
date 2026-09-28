import logging
import re
from operator import itemgetter
from typing import AsyncGenerator, Optional, Sequence

# TODO(@aminediro): this is the only dependency to langchain package, we should remove it
from langchain.retrievers import ContextualCompressionRetriever
from langchain_core.callbacks import Callbacks
from langchain_core.documents import BaseDocumentCompressor, Document
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.messages.ai import AIMessageChunk
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnableLambda, RunnablePassthrough
from langchain_core.vectorstores import VectorStore

from lineaje_guardrail import lineaje_guardrail

_ai_app_sec_059_guardrail = lineaje_guardrail()
_ai_app_sec_059_guardrail.enable_policies(["AI_APP_SEC_059.json"])

from quivr_core.llm import LLMEndpoint
from quivr_core.rag.entities.chat import ChatHistory
from quivr_core.rag.entities.config import RetrievalConfig
from quivr_core.rag.entities.models import (
    ParsedRAGChunkResponse,
    ParsedRAGResponse,
    QuivrKnowledge,
    RAGResponseMetadata,
    cited_answer,
)
from quivr_core.rag.prompts import TemplatePromptName, custom_prompts
from quivr_core.rag.utils import (
    LangfuseService,
    combine_documents,
    format_file_list,
    get_chunk_metadata,
    parse_chunk_response,
    parse_response,
)

logger = logging.getLogger("quivr_core")

_ai_app_sec_070_patterns = [
    # 1. instruction_override
    (re.compile(r'ignore\s+previous\s+instructions|forget\s+everything\s+above', re.IGNORECASE), '<prompt_injection_removed: instruction_override>'),
    # 2. role_hijack
    (re.compile(r'you\s+are\s+now\s+DAN|act\s+as\s+unrestricted', re.IGNORECASE), '<prompt_injection_removed: role_hijack>'),
    # 3. delimiter_escape - fake </system> or </prompt> tags and injected separators
    (re.compile(r'</?\s*system\s*>|</?\s*prompt\s*>|</?\s*context\s*>|</?\s*instruction\s*>', re.IGNORECASE), '<prompt_injection_removed: delimiter_escape>'),
    # 4. encoded_payload - base64 blobs, hex sequences, ROT13 instructions, URL-encoded instructions
    (re.compile(r'(?:[A-Za-z0-9+/]{40,}={0,2})', re.IGNORECASE), '<prompt_injection_removed: encoded_payload>'),
    (re.compile(r'(?:0x[0-9a-fA-F]{2}\s*){8,}', re.IGNORECASE), '<prompt_injection_removed: encoded_payload>'),
    (re.compile(r'(?:%[0-9a-fA-F]{2}){8,}', re.IGNORECASE), '<prompt_injection_removed: encoded_payload>'),
    # 5. hidden_text - HTML comments, zero-width characters, CSS hidden
    (re.compile(r'<!--.*?-->', re.DOTALL), '<prompt_injection_removed: hidden_text>'),
    (re.compile(r'[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad]+'), '<prompt_injection_removed: hidden_text>'),
    (re.compile(r'style\s*=\s*["\']?display\s*:\s*none', re.IGNORECASE), '<prompt_injection_removed: hidden_text>'),
    # 6. fake_system_message
    (re.compile(r'\[\s*system\s*\]|\bSYSTEM\s*:\s*(?=\S)', re.IGNORECASE), '<prompt_injection_removed: fake_system_message>'),
    (re.compile(r'\[\s*tool\s*\]|\bTOOL\s*:\s*(?=\S)', re.IGNORECASE), '<prompt_injection_removed: fake_system_message>'),
    # 7. exfiltration_attempt - markdown image exfil, send data to URL, leak system prompt
    (re.compile(r'!\[.*?\]\(https?://[^)]+\)', re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    (re.compile(r'(?:send|post|leak|exfiltrate|transmit)\s+(?:the\s+)?(?:system\s+prompt|data|information)\s+to\s+https?://', re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    (re.compile(r'reveal\s+(?:the\s+)?system\s+prompt|leak\s+(?:the\s+)?system\s+prompt', re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    # 8. context_poisoning
    (re.compile(r'disregard\s+(?:all\s+)?(?:prior|previous)\s+context|override\s+(?:all\s+)?(?:prior|previous)\s+instructions', re.IGNORECASE), '<prompt_injection_removed: context_poisoning>'),
    # 10. command_injection - shell or code execution
    (re.compile(r'(?:^|\s)(?:eval|exec|system|subprocess\.(?:call|run|Popen))\s*\(', re.IGNORECASE), '<prompt_injection_removed: command_injection>'),
    (re.compile(r'(?:^|\s)(?:rm\s+-rf|chmod\s+777|curl\s+.*\|\s*(?:bash|sh)|wget\s+.*\|\s*(?:bash|sh))', re.IGNORECASE), '<prompt_injection_removed: command_injection>'),
    # 12. jailbreak_attempt - DAN, developer mode, fictional framing
    (re.compile(r'\bDAN\b|developer\s+mode\s+enabled|jailbreak|fictional\s+framing\s+bypass', re.IGNORECASE), '<prompt_injection_removed: jailbreak_attempt>'),
]


def _ai_app_sec_070_sanitize(text: str) -> str:
    """Neutralize prompt injection patterns in user-supplied text."""
    for pattern, marker in _ai_app_sec_070_patterns:
        text = pattern.sub(marker, text)
    return text

_AI_APP_SEC_006_DISAPPROVED_MODELS = [
    "deepseekchat",
    "deepseekr1",
    "deepseekr1distillllama70b",
    "deepseekreasoner",
    "customllmclient",
    "openrouter",
    "usdeepseekr1v10",
]


def _ai_app_sec_006_normalize(model_id: str) -> str:
    """Normalize a model identifier for comparison."""
    import re
    return re.sub(r"[\s\-_\.:\u0000-\u001f]", "", model_id).lower()


def _ai_app_sec_006_check_model(llm_endpoint: "LLMEndpoint") -> None:
    """Raise ValueError if the LLMEndpoint uses a disapproved model."""
    try:
        model_id = llm_endpoint.llm_config.model or ""
    except AttributeError:
        model_id = ""
    normalized = _ai_app_sec_006_normalize(model_id)
    for disapproved in _AI_APP_SEC_006_DISAPPROVED_MODELS:
        if disapproved in normalized or normalized in disapproved and normalized:
            raise ValueError(
                f"Model '{model_id}' is not approved for use by this organization."
            )
langfuse_service = LangfuseService()
langfuse_handler = langfuse_service.get_handler()


class IdempotentCompressor(BaseDocumentCompressor):
    def compress_documents(
        self,
        documents: Sequence[Document],
        query: str,
        callbacks: Optional[Callbacks] = None,
    ) -> Sequence[Document]:
        return documents


class QuivrQARAG:
    """
    QuivrQA RAG is a class that provides a RAG interface to the QuivrQA system.
    """

    def __init__(
        self,
        *,
        retrieval_config: RetrievalConfig,
        llm: LLMEndpoint,
        vector_store: VectorStore,
        reranker: BaseDocumentCompressor | None = None,
    ):
        _ai_app_sec_006_check_model(llm)
        self.retrieval_config = retrieval_config
        self.vector_store = vector_store
        self.llm_endpoint = llm
        self.reranker = reranker if reranker is not None else IdempotentCompressor()

    @property
    def retriever(self):
        """
        Retriever is a function that retrieves the documents from the vector store.
        """
        return self.vector_store.as_retriever()

    def filter_history(
        self,
        chat_history: ChatHistory,
    ):
        """
        Filter out the chat history to only include the messages that are relevant to the current question

        Takes in a chat_history= [HumanMessage(content='Qui est Chloé ? '), AIMessage(content="Chloé est une salariée travaillant pour l'entreprise Quivr en tant qu'AI Engineer, sous la direction de son supérieur hiérarchique, Stanislas Girard."), HumanMessage(content='Dis moi en plus sur elle'), AIMessage(content=''), HumanMessage(content='Dis moi en plus sur elle'), AIMessage(content="Désolé, je n'ai pas d'autres informations sur Chloé à partir des fichiers fournis.")]
        Returns a filtered chat_history with in priority: first max_tokens, then max_history where a Human message and an AI message count as one pair
        a token is 4 characters
        """
        total_tokens = 0
        total_pairs = 0
        filtered_chat_history: list[AIMessage | HumanMessage] = []
        for human_message, ai_message in chat_history.iter_pairs():
            # TODO: replace with tiktoken
            message_tokens = (len(human_message.content) + len(ai_message.content)) // 4
            if (
                total_tokens + message_tokens
                > self.retrieval_config.llm_config.max_output_tokens
                or total_pairs >= self.retrieval_config.max_history
            ):
                break
            filtered_chat_history.append(human_message)
            filtered_chat_history.append(ai_message)
            total_tokens += message_tokens
            total_pairs += 1

        return filtered_chat_history[::-1]

    def build_chain(self, files: str):
        """
        Builds the chain for the QuivrQA RAG.
        """
        compression_retriever = ContextualCompressionRetriever(
            base_compressor=self.reranker, base_retriever=self.retriever
        )

        loaded_memory = RunnablePassthrough.assign(
            chat_history=RunnableLambda(
                lambda x: self.filter_history(x["chat_history"]),
            ),
            question=lambda x: x["question"],
        )

        standalone_question = {
            "standalone_question": {
                "question": lambda x: x["question"],
                "chat_history": itemgetter("chat_history"),
            }
            | custom_prompts[TemplatePromptName.DEFAULT_DOCUMENT_PROMPT]
            | self.llm_endpoint._llm
            | StrOutputParser(),
        }

        # Now we retrieve the documents
        retrieved_documents = {
            "docs": itemgetter("standalone_question") | compression_retriever,
            "question": lambda x: x["standalone_question"],
            "custom_instructions": lambda x: self.retrieval_config.prompt,
        }

        final_inputs = {
            "context": lambda x: combine_documents(x["docs"]),
            "question": itemgetter("question"),
            "custom_instructions": itemgetter("custom_instructions"),
            "files": lambda _: files,  # TODO: shouldn't be here
        }

        # Bind the llm to cited_answer if model supports it
        llm = self.llm_endpoint._llm
        if self.llm_endpoint.supports_func_calling():
            llm = self.llm_endpoint._llm.bind_tools(
                [cited_answer],
                tool_choice="any",
            )

        answer = {
            "answer": final_inputs
            | custom_prompts[TemplatePromptName.RAG_ANSWER_PROMPT]
            | llm,
            "docs": itemgetter("docs"),
        }

        return loaded_memory | standalone_question | retrieved_documents | answer

    def answer(
        self,
        question: str,
        history: ChatHistory,
        list_files: list[QuivrKnowledge],
        metadata: dict[str, str] = {},
    ) -> ParsedRAGResponse:
        """
        Answers a question using the QuivrQA RAG synchronously.
        """
        question = _ai_app_sec_059_guardrail.evaluate(question)
        concat_list_files = format_file_list(
            list_files, self.retrieval_config.max_files
        )
        conversational_qa_chain = self.build_chain(concat_list_files)
        question = _ai_app_sec_070_sanitize(question)
        raw_llm_response = conversational_qa_chain.invoke(
            {
                "question": question,
                "chat_history": history,
                "custom_instructions": (self.retrieval_config.prompt),
            },
            config={"metadata": metadata, "callbacks": [langfuse_handler]},
        )
        response = parse_response(
            raw_llm_response, self.retrieval_config.llm_config.model
        )
        return response

    async def answer_astream(
        self,
        question: str,
        history: ChatHistory,
        list_files: list[QuivrKnowledge],
        metadata: dict[str, str] = {},
    ) -> AsyncGenerator[ParsedRAGChunkResponse, ParsedRAGChunkResponse]:
        """
        Answers a question using the QuivrQA RAG asynchronously.
        """
        question = _ai_app_sec_059_guardrail.evaluate(question)
        concat_list_files = format_file_list(
            list_files, self.retrieval_config.max_files
        )
        conversational_qa_chain = self.build_chain(concat_list_files)

        rolling_message = AIMessageChunk(content="")
        sources = []
        prev_answer = ""
        chunk_id = 0

        question = _ai_app_sec_070_sanitize(question)
        async for chunk in conversational_qa_chain.astream(
            {
                "question": question,
                "chat_history": history,
                "custom_personality": (self.retrieval_config.prompt),
            },
            config={"metadata": metadata, "callbacks": [langfuse_handler]},
        ):
            # Could receive this anywhere so we need to save it for the last chunk
            if "docs" in chunk:
                sources = chunk["docs"] if "docs" in chunk else []

            if "answer" in chunk:
                rolling_message, answer_str = parse_chunk_response(
                    rolling_message,
                    chunk,
                    self.llm_endpoint.supports_func_calling(),
                )

                if len(answer_str) > 0:
                    if self.llm_endpoint.supports_func_calling():
                        diff_answer = answer_str[len(prev_answer) :]
                        if len(diff_answer) > 0:
                            parsed_chunk = ParsedRAGChunkResponse(
                                answer=diff_answer,
                                metadata=RAGResponseMetadata(),
                            )
                            prev_answer += diff_answer

                            logger.debug(
                                f"answer_astream func_calling=True question={question} rolling_msg={rolling_message} chunk_id={chunk_id}, chunk={parsed_chunk}"
                            )
                            yield parsed_chunk
                    else:
                        parsed_chunk = ParsedRAGChunkResponse(
                            answer=answer_str,
                            metadata=RAGResponseMetadata(),
                        )
                        logger.debug(
                            f"answer_astream func_calling=False question={question} rolling_msg={rolling_message} chunk_id={chunk_id}, chunk={parsed_chunk}"
                        )
                        yield parsed_chunk

                    chunk_id += 1

        # Last chunk provides metadata
        last_chunk = ParsedRAGChunkResponse(
            answer="",
            metadata=get_chunk_metadata(rolling_message, sources),
            last_chunk=True,
        )
        logger.debug(
            f"answer_astream last_chunk={last_chunk} question={question} rolling_msg={rolling_message} chunk_id={chunk_id}"
        )
        yield last_chunk
