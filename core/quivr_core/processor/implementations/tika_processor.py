import logging
import os
import re
from typing import AsyncIterable

import httpx
import tiktoken
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter, TextSplitter

from quivr_core.files.file import QuivrFile
from quivr_core.processor.processor_base import ProcessedDocument, ProcessorBase
from quivr_core.processor.registry import FileExtension
from quivr_core.processor.splitter import SplitterConfig

logger = logging.getLogger("quivr_core")

# PII patterns for zero-tolerance categories
_ai_dat_sec_023_patterns = [
    # Social Security Number
    (re.compile(r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'), '[REDACTED_SSN]'),
    # Taxpayer Identification Number (EIN format)
    (re.compile(r'\b\d{2}-\d{7}\b'), '[REDACTED_TIN]'),
    # Credit Card Number (Visa, MC, Amex, Discover)
    (re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'), '[REDACTED_CC]'),
    # Financial Account Number (generic 8-17 digit)
    (re.compile(r'\b[0-9]{8,17}\b'), '[REDACTED_ACCOUNT]'),
    # Passport Number (US-style)
    (re.compile(r'\b[A-Z]{1,2}[0-9]{6,9}\b'), '[REDACTED_PASSPORT]'),
    # Driver's License Number (common US formats)
    (re.compile(r'\b[A-Z]{1,2}\d{5,8}\b'), '[REDACTED_DL]'),
    # Vehicle Identification Number
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), '[REDACTED_VIN]'),
    # IP Address (IPv4)
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '[REDACTED_IP]'),
    # IP Address (IPv6)
    (re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'), '[REDACTED_IPV6]'),
    # MAC Address
    (re.compile(r'\b(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b'), '[REDACTED_MAC]'),
    # Email Address
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[REDACTED_EMAIL]'),
    # Personal Phone Number
    (re.compile(r'\b(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b'), '[REDACTED_PHONE]'),
    # Year of Birth (standalone 4-digit year 1900-2099 near birth keywords)
    (re.compile(r'(?i)(?:born|birth(?:day|date|year)?|dob|date of birth)[^\n]{0,30}((?:19|20)\d{2})'), '[REDACTED_YOB]'),
    # Home Address (street address pattern)
    (re.compile(r'\b\d{1,5}\s+(?:[A-Za-z]+\s){1,4}(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl|Circle|Cir)\b', re.IGNORECASE), '[REDACTED_ADDRESS]'),
    # Fine Location (GPS coordinates)
    (re.compile(r'\b[-+]?(?:[1-8]?\d(?:\.\d+)?|90(?:\.0+)?)\s*,\s*[-+]?(?:180(?:\.0+)?|(?:1[0-7]\d|[1-9]?\d)(?:\.\d+)?)\b'), '[REDACTED_LOCATION]'),
    # Medical Record Number
    (re.compile(r'(?i)(?:mrn|medical record(?:\s+number)?|patient\s+id)[^\n]{0,20}([A-Z0-9\-]{5,20})'), '[REDACTED_MRN]'),
    # Employee ID
    (re.compile(r'(?i)(?:employee\s+id|emp\s*id|staff\s+id)[^\n]{0,20}([A-Z0-9\-]{3,15})'), '[REDACTED_EMPID]'),
    # School ID
    (re.compile(r'(?i)(?:school\s+id|student\s+id|student\s+number)[^\n]{0,20}([A-Z0-9\-]{3,15})'), '[REDACTED_SCHOOLID]'),
    # Ethnicity
    (re.compile(r'(?i)\b(?:ethnicity|ethnic\s+origin|race)\s*[:=]\s*[A-Za-z\s]{2,30}'), '[REDACTED_ETHNICITY]'),
    # Sexual Orientation
    (re.compile(r'(?i)\b(?:sexual\s+orientation|sexuality)\s*[:=]\s*[A-Za-z\s]{2,30}'), '[REDACTED_ORIENTATION]'),
]


def _ai_dat_sec_023_redact_pii(text: str) -> str:
    """Redact zero-tolerance PII categories from the given text."""
    for pattern, replacement in _ai_dat_sec_023_patterns:
        text = pattern.sub(replacement, text)
    return text


class TikaProcessor(ProcessorBase):
    """
    TikaProcessor is a class that implements the ProcessorBase interface.
    It is used to process the files with the Tika server.

    To run it with docker you can do:
    ```bash
    docker run -d -p 9998:9998 apache/tika
    ```
    """

    supported_extensions = [FileExtension.pdf]

    def __init__(
        self,
        tika_url: str = os.getenv("TIKA_SERVER_URL", "http://localhost:9998/tika"),
        splitter: TextSplitter | None = None,
        splitter_config: SplitterConfig = SplitterConfig(),
        timeout: float = 5.0,
        max_retries: int = 3,
    ) -> None:
        self.tika_url = tika_url
        self.max_retries = max_retries
        self._client = httpx.AsyncClient(timeout=timeout)

        self.enc = tiktoken.get_encoding("cl100k_base")
        self.splitter_config = splitter_config

        if splitter:
            self.text_splitter = splitter
        else:
            self.text_splitter = RecursiveCharacterTextSplitter.from_tiktoken_encoder(
                chunk_size=splitter_config.chunk_size,
                chunk_overlap=splitter_config.chunk_overlap,
            )

    async def _send_parse_tika(self, f: AsyncIterable[bytes]) -> str:
        retry = 0
        headers = {"Accept": "text/plain"}
        while retry < self.max_retries:
            try:
                resp = await self._client.put(self.tika_url, headers=headers, content=f)
                resp.raise_for_status()
                return resp.content.decode("utf-8")
            except Exception as e:
                retry += 1
                logger.debug(f"tika url error :{e}. retrying for the {retry} time...")
        raise RuntimeError("can't send parse request to tika server")

    @property
    def processor_metadata(self):
        return {
            "chunk_overlap": self.splitter_config.chunk_overlap,
        }

    async def process_file_inner(self, file: QuivrFile) -> ProcessedDocument[None]:
        async with file.open() as f:
            txt = await self._send_parse_tika(f)
        txt = _ai_dat_sec_023_redact_pii(txt)
        document = Document(page_content=txt)
        docs = self.text_splitter.split_documents([document])
        for doc in docs:
            doc.metadata = {"chunk_size": len(self.enc.encode(doc.page_content))}

        return ProcessedDocument(
            chunks=docs, processor_cls="TikaProcessor", processor_response=None
        )
