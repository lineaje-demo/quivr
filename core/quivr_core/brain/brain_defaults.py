import logging

from langchain_core.documents import Document
from langchain_core.embeddings import Embeddings
from langchain_core.vectorstores import VectorStore

from quivr_core.rag.entities.config import DefaultModelSuppliers, LLMEndpointConfig
from quivr_core.llm import LLMEndpoint

logger = logging.getLogger("quivr_core")

_AI_APP_SEC_006_DISAPPROVED = [
    "deepseekchat",
    "deepseekr1",
    "deepseekr1distillllama70b",
    "deepseekreasoner",
    "customllmclient",
    "openrouter",
    "usdeepseekr1v10",
]


def _ai_app_sec_006_normalize(name: str) -> str:
    import re
    return re.sub(r"[\s\-_\.:\u0000]", "", name).lower()


def _ai_app_sec_006_check_model(model_id: str) -> None:
    normalized = _ai_app_sec_006_normalize(model_id)
    for disapproved in _AI_APP_SEC_006_DISAPPROVED:
        if disapproved in normalized or normalized in disapproved:
            raise ValueError(
                f"Model '{model_id}' is disapproved by the organization's model registry and cannot be used."
            )


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
        _ai_app_sec_006_check_model("OpenAIEmbeddings")
        embedder = OpenAIEmbeddings()
        return embedder
    except ImportError as e:
        raise ImportError(
            "Please provide a valid Embedder or install quivr-core['base'] package for using the defaultone."
        ) from e


def default_llm() -> LLMEndpoint:
    try:
        logger.debug("Loaded ChatOpenAI as default LLM for brain")
        _ai_app_sec_006_check_model("gpt-4o")
        llm = LLMEndpoint.from_config(
            LLMEndpointConfig(supplier=DefaultModelSuppliers.OPENAI, model="gpt-4o")
        )
        return llm

    except ImportError as e:
        raise ImportError(
            "Please provide a valid BaseLLM or install quivr-core['base'] package"
        ) from e
