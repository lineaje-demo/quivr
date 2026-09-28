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

logger = logging.getLogger("quivr_core")

_ai_dat_sec_023_PII_PATTERNS = [
    # Social Security Number
    (re.compile(r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'), '[REDACTED_SSN]'),
    # Taxpayer Identification Number (EIN format)
    (re.compile(r'\b\d{2}-\d{7}\b'), '[REDACTED_TIN]'),
    # Credit Card Number (Visa, MC, Amex, Discover)
    (re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'), '[REDACTED_CC]'),
    # Email address
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[REDACTED_EMAIL]'),
    # Personal Phone Number (US and international)
    (re.compile(r'\b(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b'), '[REDACTED_PHONE]'),
    # IP Address (v4)
    (re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'), '[REDACTED_IP]'),
    # MAC Address
    (re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), '[REDACTED_MAC]'),
    # Passport Number (generic: letter(s) + digits)
    (re.compile(r'\b[A-Z]{1,2}[0-9]{6,9}\b'), '[REDACTED_PASSPORT]'),
    # US Driver License (common formats)
    (re.compile(r'\b[A-Z]{1,2}\d{5,8}\b'), '[REDACTED_DL]'),
    # Vehicle Identification Number (VIN)
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), '[REDACTED_VIN]'),
    # Financial Account Number (8-17 digits)
    (re.compile(r'\b\d{8,17}\b'), '[REDACTED_ACCOUNT]'),
    # Year of Birth (standalone 4-digit year 1900-2099 near keywords)
    (re.compile(r'(?i)(?:born|birth(?:day|date)?|dob|year of birth)[^\n]{0,30}((?:19|20)\d{2})'), '[REDACTED_YOB]'),
    # Home Address (street address pattern)
    (re.compile(r'\b\d{1,5}\s+(?:[A-Za-z]+\s){1,4}(?:St(?:reet)?|Ave(?:nue)?|Blvd|Rd|Road|Dr(?:ive)?|Ln|Lane|Ct|Court|Pl|Place|Way|Terr(?:ace)?|Cir(?:cle)?)\b'), '[REDACTED_ADDRESS]'),
    # Ethnicity keywords
    (re.compile(r'(?i)\bethnicity\s*:\s*[A-Za-z\s]+'), '[REDACTED_ETHNICITY]'),
    # Sexual Orientation keywords
    (re.compile(r'(?i)\bsexual orientation\s*:\s*[A-Za-z\s]+'), '[REDACTED_ORIENTATION]'),
    # Medical Record Number
    (re.compile(r'(?i)\b(?:mrn|medical record(?:\s+number)?|patient id)\s*[:#]?\s*[A-Z0-9\-]{4,20}\b'), '[REDACTED_MRN]'),
    # Employee ID
    (re.compile(r'(?i)\b(?:employee\s+id|emp\s*id)\s*[:#]?\s*[A-Z0-9\-]{3,15}\b'), '[REDACTED_EMP_ID]'),
    # School ID
    (re.compile(r'(?i)\b(?:school\s+id|student\s+id)\s*[:#]?\s*[A-Z0-9\-]{3,15}\b'), '[REDACTED_SCHOOL_ID]'),
    # Birthplace (near keyword)
    (re.compile(r'(?i)(?:birthplace|place of birth|born in)[^\n]{0,60}'), '[REDACTED_BIRTHPLACE]'),
    # Mother's Maiden Name
    (re.compile(r"(?i)(?:mother(?:'s)?\s+maiden\s+name)[^\n]{0,60}"), '[REDACTED_MAIDEN_NAME]'),
    # Fine Location (GPS coordinates)
    (re.compile(r'\b[-+]?(?:[1-8]?\d(?:\.\d+)?|90(?:\.0+)?)\s*,\s*[-+]?(?:180(?:\.0+)?|(?:1[0-7]\d|[1-9]?\d)(?:\.\d+)?)\b'), '[REDACTED_LOCATION]'),
]


def _ai_dat_sec_023_redact_pii(text: str) -> str:
    """Redact zero-tolerance PII categories from the given text."""
    for pattern, replacement in _ai_dat_sec_023_PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


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

    @property
    def processor_metadata(self):
        return {
            "chunk_overlap": self.splitter_config.chunk_overlap,
        }

    async def process_file_inner(
        self, file: QuivrFile
    ) -> ProcessedDocument[MPDocument | str]:
        logger.info(f"Uploading file {file.path} to MegaParse")
        async with MegaParseNATSClient(ClientNATSConfig()) as client:
            response = await client.parse_file(file=file.path)

        redacted_content = _ai_dat_sec_023_redact_pii(str(response))
        document = Document(
            page_content=redacted_content,
        )

        chunks = self.text_splitter.split_documents([document])
        for chunk in chunks:
            chunk.metadata = {"chunk_size": len(self.enc.encode(chunk.page_content))}
        return ProcessedDocument(
            chunks=chunks,
            processor_cls="MegaparseProcessor",
            processor_response=response,
        )
