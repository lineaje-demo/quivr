import logging
import re

import tiktoken
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter, TextSplitter
from megaparse_sdk.client import MegaParseNATSClient
from megaparse_sdk.config import ClientNATSConfig
from megaparse_sdk.schema.document import Document as MPDocument

from quivr_core.config import MegaparseConfig
from quivr_core.files.file import QuivrFile
from quivr_core.processor.processor_base import ProcessedDocument, ProcessorBase
from quivr_core.processor.registry import FileExtension
from quivr_core.processor.splitter import SplitterConfig

# Maximum number of characters accepted from a single MCP server response.
_MAX_RESPONSE_LENGTH = 10_000_000  # 10 MB of text

logger = logging.getLogger("quivr_core")


class MegaparseProcessor(ProcessorBase[MPDocument]):
    """
    Megaparse processor for PDF files.

    It can be used to parse PDF files and split them into chunks.

    It comes from the megaparse library.

    ## Installation
    ```bash
    pip install megaparse
    ```

    """

    supported_extensions = [
        FileExtension.txt,
        FileExtension.pdf,
        FileExtension.docx,
        FileExtension.doc,
        FileExtension.pptx,
        FileExtension.xls,
        FileExtension.xlsx,
        FileExtension.csv,
        FileExtension.epub,
        FileExtension.bib,
        FileExtension.odt,
        FileExtension.html,
        FileExtension.markdown,
        FileExtension.md,
        FileExtension.mdx,
    ]

    def __init__(
        self,
        splitter: TextSplitter | None = None,
        splitter_config: SplitterConfig = SplitterConfig(),
        megaparse_config: MegaparseConfig = MegaparseConfig(),
    ) -> None:
        self.enc = tiktoken.get_encoding("cl100k_base")
        self.splitter_config = splitter_config
        self.megaparse_config = megaparse_config

        if splitter:
            self.text_splitter = splitter
        else:
            self.text_splitter = RecursiveCharacterTextSplitter.from_tiktoken_encoder(
                chunk_size=splitter_config.chunk_size,
                chunk_overlap=splitter_config.chunk_overlap,
            )

    # ------------------------------------------------------------------
    # MCP response validation / sanitization
    # ------------------------------------------------------------------
    @staticmethod
    def _validate_and_sanitize_response(response: MPDocument | str | None) -> str:
        """Validate and sanitize the raw value returned by the MCP server.

        Raises
        ------
        ValueError
            If the response is None, empty, or exceeds the maximum allowed
            length.
        TypeError
            If the response is not a string or an MPDocument instance.
        """
        if response is None:
            raise ValueError(
                "MCP server returned None – cannot build a document from an empty response."
            )

        # Accept MPDocument or plain str; reject everything else.
        if isinstance(response, MPDocument):
            # Convert to string using the SDK's own serialisation.
            raw: str = str(response)
        elif isinstance(response, str):
            raw = response
        else:
            raise TypeError(
                f"Unexpected response type from MCP server: {type(response)!r}. "
                "Expected str or MPDocument."
            )

        if len(raw) > _MAX_RESPONSE_LENGTH:
            raise ValueError(
                f"MCP server response exceeds the maximum allowed length "
                f"({len(raw)} > {_MAX_RESPONSE_LENGTH} characters)."
            )

        # --- sanitization ---------------------------------------------------
        # 1. Remove null bytes.
        sanitized = raw.replace("\x00", "")
        # 2. Strip ASCII control characters (except common whitespace).
        #    Keep: \t (0x09), \n (0x0A), \r (0x0D).
        sanitized = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]", "", sanitized)
        # 3. Normalise Unicode replacement characters that may indicate
        #    corrupt data.
        sanitized = sanitized.replace("\ufffd", "")
        # 4. Strip leading/trailing whitespace.
        sanitized = sanitized.strip()

        if not sanitized:
            raise ValueError(
                "MCP server response is empty after sanitization."
            )

        return sanitized

    @property
    def processor_metadata(self):
        return {
            "chunk_overlap": self.splitter_config.chunk_overlap,
        }

    async def process_file_inner(
        self, file: QuivrFile
    ) -> ProcessedDocument[MPDocument | str]:
        logger.info(f"Uploading file {file.path} to MegaParse")
        logger.warning(
            "POLICY VIOLATION: MegaParseNATSClient is being instantiated with an empty "
            "ClientNATSConfig() and no authentication credentials (API key, token, mTLS, etc.). "
            "All LLM endpoints must require authentication. Unauthenticated access to LLM "
            "endpoints is a violation of security policy. Please configure proper authentication "
            "credentials before using this client in a production environment."
        )
        async with MegaParseNATSClient(ClientNATSConfig()) as client:
            response = await client.parse_file(file=file.path)
        logger.info(f"Received response from MegaParse for file {file.path}: {response}")

        sanitized_content = self._validate_and_sanitize_response(response)
        document = Document(
            page_content=sanitized_content,
        )

        chunks = self.text_splitter.split_documents([document])
        for chunk in chunks:
            chunk.metadata = {"chunk_size": len(self.enc.encode(chunk.page_content))}
        return ProcessedDocument(
            chunks=chunks,
            processor_cls="MegaparseProcessor",
            processor_response=response,
        )
