import logging
import os

from langchain_core.documents import Document
from langchain_core.embeddings import Embeddings
from langchain_core.vectorstores import VectorStore
from pydantic import SecretStr

from quivr_core.rag.entities.config import (
    OPENROUTER_BASE_URL,
    DefaultModelSuppliers,
    LLMEndpointConfig,
    use_openrouter,
)
from quivr_core.llm import LLMEndpoint

logger = logging.getLogger("quivr_core")


async def build_default_vectordb(
    docs: list[Document], embedder: Embeddings
) -> VectorStore:
    try:
        from langchain_community.vectorstores import FAISS

        logger.debug("Using Faiss-CPU as vector store.")
        # TODO(@aminediro) : embedding call is usually not concurrent for all documents but waits
        if len(docs) > 0:
            vector_db = await FAISS.afrom_documents(documents=docs, embedding=embedder)
            return vector_db
        else:
            raise ValueError("can't initialize brain without documents")

    except ImportError as e:
        raise ImportError(
            "Please provide a valid vector store or install quivr-core['base'] package for using the default one."
        ) from e


def default_embedder() -> Embeddings:
    try:
        from langchain_openai import OpenAIEmbeddings

        logger.debug("Loaded OpenAIEmbeddings as default LLM for brain")
        if use_openrouter():
            # check_embedding_ctx_length=False: send raw text, OpenRouter does not take tiktoken ids
            return OpenAIEmbeddings(
                model=os.getenv(
                    "OPENROUTER_EMBEDDING_MODEL", "openai/text-embedding-3-small"
                ),
                base_url=OPENROUTER_BASE_URL,
                api_key=SecretStr(os.environ["OPENROUTER_API_KEY"]),
                check_embedding_ctx_length=False,
            )
        embedder = OpenAIEmbeddings()
        return embedder
    except ImportError as e:
        raise ImportError(
            "Please provide a valid Embedder or install quivr-core['base'] package for using the defaultone."
        ) from e


def default_llm() -> LLMEndpoint:
    try:
        logger.debug("Loaded ChatOpenAI as default LLM for brain")
        if use_openrouter():
            # supplier/model come from OPENROUTER_API_KEY / OPENROUTER_MODEL
            config = LLMEndpointConfig()
        else:
            config = LLMEndpointConfig(
                supplier=DefaultModelSuppliers.OPENAI, model="gpt-4o"
            )
        llm = LLMEndpoint.from_config(config)
        return llm

    except ImportError as e:
        raise ImportError(
            "Please provide a valid BaseLLM or install quivr-core['base'] package"
        ) from e
