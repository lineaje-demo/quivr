import re
from typing import Any

import aiofiles
from langchain_core.documents import Document

from quivr_core.files.file import QuivrFile
from quivr_core.processor.processor_base import ProcessedDocument, ProcessorBase
from quivr_core.processor.registry import FileExtension
from quivr_core.processor.splitter import SplitterConfig


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
    # IP Address (IPv4)
    (re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'), '[REDACTED_IP]'),
    # MAC Address
    (re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), '[REDACTED_MAC]'),
    # Passport Number (generic: letter(s) followed by digits)
    (re.compile(r'\b[A-Z]{1,2}[0-9]{6,9}\b'), '[REDACTED_PASSPORT]'),
    # Driver's License Number (common US formats)
    (re.compile(r'\b[A-Z]{1,2}\d{5,8}\b'), '[REDACTED_DL]'),
    # Vehicle Identification Number (VIN)
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), '[REDACTED_VIN]'),
    # Year of Birth (standalone 4-digit year 1900-2099 near birth keywords)
    (re.compile(r'(?i)(?:born|birth(?:day|date|year)?|dob|date of birth)[^\n]{0,30}((?:19|20)\d{2})'), '[REDACTED_YOB]'),
    # Home Address (street address pattern)
    (re.compile(r'\b\d{1,5}\s+(?:[A-Za-z0-9.\-]+\s){1,4}(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl|Circle|Cir)\b', re.IGNORECASE), '[REDACTED_ADDRESS]'),
    # Financial Account Number (generic: 8-17 digit sequences near account keywords)
    (re.compile(r'(?i)(?:account|acct|iban)[^\n]{0,20}\b(\d{8,17})\b'), '[REDACTED_ACCOUNT]'),
    # Employee ID / School ID
    (re.compile(r'(?i)(?:employee|emp|school|student)\s*(?:id|#|number|no\.?)[^\n]{0,10}([A-Z0-9\-]{4,12})'), '[REDACTED_ID]'),
    # Ethnicity keywords
    (re.compile(r'(?i)\bethnicity\s*[:\-]?\s*[A-Za-z\s]{2,30}'), '[REDACTED_ETHNICITY]'),
    # Sexual Orientation keywords
    (re.compile(r'(?i)\bsexual\s+orientation\s*[:\-]?\s*[A-Za-z\s]{2,30}'), '[REDACTED_SEXUAL_ORIENTATION]'),
    # Birthplace
    (re.compile(r'(?i)(?:birthplace|place of birth|born in)[^\n]{0,50}'), '[REDACTED_BIRTHPLACE]'),
    # Mother's Maiden Name
    (re.compile(r"(?i)(?:mother'?s?\s+maiden\s+name)[^\n]{0,50}"), '[REDACTED_MAIDEN_NAME]'),
]


def _ai_dat_sec_023_redact_pii(text: str) -> str:
    """Redact zero-tolerance PII categories from the given text."""
    for pattern, replacement in _ai_dat_sec_023_PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def recursive_character_splitter(
    doc: Document, chunk_size: int, chunk_overlap: int
) -> list[Document]:
    assert chunk_overlap < chunk_size, "chunk_overlap is greater than chunk_size"

    if len(doc.page_content) <= chunk_size:
        return [doc]

    chunk = Document(page_content=doc.page_content[:chunk_size], metadata=doc.metadata)
    remaining = Document(
        page_content=doc.page_content[chunk_size - chunk_overlap :],
        metadata=doc.metadata,
    )

    return [chunk] + recursive_character_splitter(remaining, chunk_size, chunk_overlap)


class SimpleTxtProcessor(ProcessorBase):
    """
    SimpleTxtProcessor is a class that implements the ProcessorBase interface.
    It is used to process the files with the Simple Txt parser.
    """

    supported_extensions = [FileExtension.txt]

    def __init__(
        self, splitter_config: SplitterConfig = SplitterConfig(), **kwargs
    ) -> None:
        super().__init__(**kwargs)
        self.splitter_config = splitter_config

    @property
    def processor_metadata(self) -> dict[str, Any]:
        return {
            "processor_cls": "SimpleTxtProcessor",
            "splitter": self.splitter_config.model_dump(),
        }

    async def process_file_inner(self, file: QuivrFile) -> ProcessedDocument[str]:
        async with aiofiles.open(file.path, mode="r") as f:
            content = await f.read()
            content = _ai_dat_sec_023_redact_pii(content)

        doc = Document(page_content=content)

        docs = recursive_character_splitter(
            doc, self.splitter_config.chunk_size, self.splitter_config.chunk_overlap
        )

        return ProcessedDocument(
            chunks=docs, processor_cls="SimpleTxtProcessor", processor_response=content
        )
