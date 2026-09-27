import logging
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

# Patterns for dynamic code execution primitives that must be removed from LLM output
import re

_DANGEROUS_PATTERNS = re.compile(
    r"(?m)^.*"
    r"(?:"
    r"\beval\s*\("
    r"|\bexec\s*\("
    r"|\bexecfile\s*\("
    r"|\bcompile\s*\("
    r"|\b__import__\s*\("
    r"|subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True"
    r"|os\.system\s*\("
    r"|os\.popen\s*\("
    r"|commands\.getoutput\s*\("
    r"|\beval\b"
    r"|\$\(.*\)"
    r"|`[^`]*`"
    r"|\beval\s+"
    r").*$",
    re.IGNORECASE,
)


def sanitize_llm_output(text: str) -> str:
    """Remove lines containing dynamic code execution primitives from LLM output.

    Checks for and removes lines containing:
    - Python eval(), exec(), execfile(), compile(), __import__()
    - subprocess calls with shell=True
    - os.system(), os.popen()
    - JavaScript eval
    - Bash command substitution: $(...) and backtick execution
    - Bash eval builtin
    """
    if not text:
        return text
    sanitized = _DANGEROUS_PATTERNS.sub("", text)
    # Clean up any double blank lines introduced by removal
    sanitized = re.sub(r"\n{3,}", "\n\n", sanitized)
    if sanitized != text:
        logger.warning(
            "sanitize_llm_output: removed one or more lines containing "
            "dynamic code execution primitives from LLM response."
        )
    return sanitized
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

        Takes in a chat_history= [HumanMessage(content='Qui est REDACTED ? '), AIMessage(content="REDACTED est une salariée travaillant pour l'entreprise Quivr en tant qu'AI Engineer, sous la direction de son supérieur hiérarchique, REDACTED."), HumanMessage(content='Dis moi en plus sur elle'), AIMessage(content=''), HumanMessage(content='Dis moi en plus sur elle'), AIMessage(content="Désolé, je n'ai pas d'autres informations sur REDACTED à partir des fichiers fournis.")]
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
        concat_list_files = format_file_list(
            list_files, self.retrieval_config.max_files
        )
        conversational_qa_chain = self.build_chain(concat_list_files)

        # --- Provenance helpers (fail-closed) ---
        import hashlib, hmac, os, time, json

        _PROVENANCE_SECRET = os.environ.get("QUIVR_PROVENANCE_SECRET", "")
        if not _PROVENANCE_SECRET:
            raise RuntimeError(
                "QUIVR_PROVENANCE_SECRET env var is not set; "
                "cannot sign AI-generated content provenance. Refusing to serve."
            )

        _prompt_hash = hashlib.sha256(
            (question or "").encode("utf-8")
        ).hexdigest()

        _model_id = getattr(
            getattr(self, "llm_endpoint", None), "model", "unknown-model"
        )

        def _build_provenance(chunk_index: int, is_last: bool) -> dict:
            """Build and cryptographically sign a provenance envelope."""
            envelope = {
                "origin": "ai-generated",
                "content_label": "SYNTHETIC_AI_CONTENT",
                "model_id": _model_id,
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "prompt_hash": _prompt_hash,
                "chunk_index": chunk_index,
                "is_last_chunk": is_last,
            }
            payload = json.dumps(envelope, sort_keys=True).encode("utf-8")
            signature = hmac.new(
                _PROVENANCE_SECRET.encode("utf-8"), payload, hashlib.sha256
            ).hexdigest()
            envelope["provenance_signature"] = signature
            return envelope

        def _attach_provenance(
            parsed: "ParsedRAGChunkResponse", chunk_index: int, is_last: bool
        ) -> "ParsedRAGChunkResponse":
            """Attach provenance envelope to a chunk; fail closed on error."""
            try:
                provenance = _build_provenance(chunk_index, is_last)
            except Exception as exc:
                raise RuntimeError(
                    f"Provenance signing failed for chunk {chunk_index}: {exc}; "
                    "refusing to serve unsigned AI-generated content."
                ) from exc
            # Store provenance on the metadata object so it travels with the chunk
            if hasattr(parsed.metadata, "provenance"):
                parsed.metadata.provenance = provenance  # type: ignore[attr-defined]
            else:
                # Fallback: attach as a dynamic attribute so consumers can inspect it
                object.__setattr__(parsed, "provenance", provenance)
            return parsed
        # --- end provenance helpers ---
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
        concat_list_files = format_file_list(
            list_files, self.retrieval_config.max_files
        )
        conversational_qa_chain = self.build_chain(concat_list_files)

        rolling_message = AIMessageChunk(content="")
        sources = []
        prev_answer = ""
        chunk_id = 0

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
                            answer=sanitize_llm_output(diff_answer),
                            metadata=RAGResponseMetadata(),
                        ),
                            )
                            prev_answer += diff_answer

                            parsed_chunk = _attach_provenance(
                                parsed_chunk, chunk_id, is_last=False
                            )
                            logger.debug(
                                f"answer_astream func_calling=True question={question} rolling_msg={rolling_message} chunk_id={chunk_id}, chunk={parsed_chunk}"
                            )
                            yield parsed_chunk
                    else:
                        parsed_chunk = ParsedRAGChunkResponse(
                            answer=sanitize_llm_output(answer_str),
                            metadata=RAGResponseMetadata(),
                        )
                        parsed_chunk = _attach_provenance(
                            parsed_chunk, chunk_id, is_last=False
                        )
                        logger.debug(
                            f"answer_astream func_calling=False question={question} rolling_msg={rolling_message} chunk_id={chunk_id}, chunk={parsed_chunk}"
                        )
                        yield parsed_chunk

                    full_response_chunks.append(answer_str)
                    chunk_id += 1

        # Log the full LLM interaction (request + complete response)
        logger.info(
            "LLM interaction response",
            extra={
                "event": "llm_response",
                "question": question,
                "model": self.llm_endpoint.llm.model_name
                if hasattr(self.llm_endpoint.llm, "model_name")
                else str(self.llm_endpoint.llm),
                "full_response": "".join(full_response_chunks),
                "chunk_count": chunk_id,
                "sources_count": len(sources),
            },
        )

        # Last chunk provides metadata
        last_chunk = ParsedRAGChunkResponse(
            answer="",
            metadata=get_chunk_metadata(rolling_message, sources),
            last_chunk=True,
        )
        last_chunk = _attach_provenance(last_chunk, chunk_id, is_last=True)
        logger.debug(
            f"answer_astream last_chunk={last_chunk} question={question} rolling_msg={rolling_message} chunk_id={chunk_id}"
        )
        yield last_chunk
