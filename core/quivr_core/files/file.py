import hashlib
import re
import mimetypes
import os
import warnings
from contextlib import asynccontextmanager
from enum import Enum
from pathlib import Path
from typing import Any, AsyncGenerator, AsyncIterable, Self
from uuid import UUID, uuid4

import aiofiles
from openai import BaseModel

# PII patterns for zero-tolerance categories
_ai_dat_sec_023_patterns = [
    # Social Security Number
    (re.compile(r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'), '[REDACTED_SSN]'),
    # Taxpayer Identification Number (EIN format)
    (re.compile(r'\b\d{2}-\d{7}\b'), '[REDACTED_TIN]'),
    # Credit Card Number (Visa, MC, Amex, Discover)
    (re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'), '[REDACTED_CC]'),
    # Financial Account Number (generic 8-17 digit)
    (re.compile(r'\bACCT\s*#?\s*\d{8,17}\b', re.IGNORECASE), '[REDACTED_FINANCIAL_ACCOUNT]'),
    # Passport Number (US format)
    (re.compile(r'\b[A-Z]{1,2}[0-9]{6,9}\b'), '[REDACTED_PASSPORT]'),
    # Driver License Number (generic alphanumeric 6-15)
    (re.compile(r'\bDL\s*#?\s*[A-Z0-9]{6,15}\b', re.IGNORECASE), '[REDACTED_DL]'),
    # Vehicle Identification Number
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), '[REDACTED_VIN]'),
    # IP Address (v4)
    (re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'), '[REDACTED_IP]'),
    # MAC Address
    (re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), '[REDACTED_MAC]'),
    # Email
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[REDACTED_EMAIL]'),
    # Personal Phone Number
    (re.compile(r'\b(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b'), '[REDACTED_PHONE]'),
    # Year of Birth (context-based)
    (re.compile(r'\b(?:born|dob|date of birth|birth year)[:\s]+(?:19|20)\d{2}\b', re.IGNORECASE), '[REDACTED_YOB]'),
    # Home Address (street address pattern)
    (re.compile(r'\b\d{1,5}\s+[A-Za-z0-9\s]{3,30}(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b', re.IGNORECASE), '[REDACTED_ADDRESS]'),
    # Employee ID
    (re.compile(r'\b(?:EMP|EMPLOYEE)\s*#?\s*[A-Z0-9]{4,12}\b', re.IGNORECASE), '[REDACTED_EMPLOYEE_ID]'),
    # School ID
    (re.compile(r'\b(?:STUDENT|SCHOOL)\s*ID\s*#?\s*[A-Z0-9]{4,12}\b', re.IGNORECASE), '[REDACTED_SCHOOL_ID]'),
    # Mother's Maiden Name (context-based)
    (re.compile(r"\b(?:mother'?s?\s+maiden\s+name)[:\s]+[A-Za-z\-']{2,30}\b", re.IGNORECASE), '[REDACTED_MAIDEN_NAME]'),
    # Birthplace (context-based)
    (re.compile(r'\b(?:birthplace|place of birth|born in)[:\s]+[A-Za-z\s,]{2,50}\b', re.IGNORECASE), '[REDACTED_BIRTHPLACE]'),
    # Ethnicity (context-based)
    (re.compile(r'\b(?:ethnicity|ethnic origin|race)[:\s]+[A-Za-z\s]{2,30}\b', re.IGNORECASE), '[REDACTED_ETHNICITY]'),
    # Sexual Orientation (context-based)
    (re.compile(r'\b(?:sexual orientation|sexuality)[:\s]+[A-Za-z\s]{2,30}\b', re.IGNORECASE), '[REDACTED_SEXUAL_ORIENTATION]'),
]


def _ai_dat_sec_023_redact_pii(content: bytes) -> bytes:
    """Detect and redact PII from file content bytes."""
    try:
        text = content.decode('utf-8', errors='replace')
    except Exception:
        return content
    for pattern, replacement in _ai_dat_sec_023_patterns:
        text = pattern.sub(replacement, text)
    return text.encode('utf-8', errors='replace')


class QuivrFileSerialized(BaseModel):
    id: UUID
    brain_id: UUID
    path: Path
    original_filename: str
    file_size: int | None
    file_extension: str
    file_sha1: str
    additional_metadata: dict[str, Any]


class FileExtension(str, Enum):
    txt = ".txt"
    pdf = ".pdf"
    csv = ".csv"
    doc = ".doc"
    docx = ".docx"
    pptx = ".pptx"
    xls = ".xls"
    xlsx = ".xlsx"
    md = ".md"
    mdx = ".mdx"
    markdown = ".markdown"
    bib = ".bib"
    epub = ".epub"
    html = ".html"
    odt = ".odt"
    py = ".py"
    ipynb = ".ipynb"
    m4a = ".m4a"
    mp3 = ".mp3"
    webm = ".webm"
    mp4 = ".mp4"
    mpga = ".mpga"
    wav = ".wav"
    mpeg = ".mpeg"


def get_file_extension(file_path: Path) -> FileExtension | str:
    try:
        mime_type, _ = mimetypes.guess_type(file_path.name)
        if mime_type:
            mime_ext = mimetypes.guess_extension(mime_type)
            if mime_ext:
                return FileExtension(mime_ext)
        return FileExtension(file_path.suffix)
    except ValueError:
        warnings.warn(
            f"File {file_path.name} extension isn't recognized. Make sure you have registered a parser for {file_path.suffix}",
            stacklevel=2,
        )
        return file_path.suffix


async def load_qfile(brain_id: UUID, path: str | Path):
    if not isinstance(path, Path):
        path = Path(path)

    if not path.exists():
        raise FileExistsError(f"file {path} doesn't exist")

    file_size = os.stat(path).st_size

    async with aiofiles.open(path, mode="rb") as f:
        raw_content = await f.read()
    redacted_content = _ai_dat_sec_023_redact_pii(raw_content)
    async with aiofiles.open(path, mode="wb") as f:
        await f.write(redacted_content)
    file_sha1 = hashlib.sha1(redacted_content).hexdigest()

    try:
        # NOTE: when loading from existing storage, file name will be uuid
        id = UUID(path.name)
    except ValueError:
        id = uuid4()

    return QuivrFile(
        id=id,
        brain_id=brain_id,
        path=path,
        original_filename=path.name,
        file_extension=get_file_extension(path),
        file_size=file_size,
        file_sha1=file_sha1,
    )


class QuivrFile:
    __slots__ = [
        "id",
        "brain_id",
        "path",
        "original_filename",
        "file_size",
        "file_extension",
        "file_sha1",
        "additional_metadata",
    ]

    def __init__(
        self,
        id: UUID,
        original_filename: str,
        path: Path,
        file_sha1: str,
        file_extension: FileExtension | str,
        brain_id: UUID | None = None,
        file_size: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.id = id
        self.brain_id = brain_id
        self.path = path
        self.original_filename = original_filename
        self.file_size = file_size
        self.file_extension = file_extension
        self.file_sha1 = file_sha1
        self.additional_metadata = metadata if metadata else {}

    def __repr__(self) -> str:
        return f"QuivrFile-{self.id} original_filename:{self.original_filename}"

    @asynccontextmanager
    async def open(self) -> AsyncGenerator[AsyncIterable[bytes], None]:
        # TODO(@aminediro) : match on path type
        f = await aiofiles.open(self.path, mode="rb")
        try:
            yield f
        finally:
            await f.close()

    @property
    def metadata(self) -> dict[str, Any]:
        return {
            "qfile_id": self.id,
            "qfile_path": self.path,
            "original_file_name": self.original_filename,
            "file_sha1": self.file_sha1,
            "file_size": self.file_size,
            **self.additional_metadata,
        }

    def serialize(self) -> QuivrFileSerialized:
        return QuivrFileSerialized(
            id=self.id,
            brain_id=self.brain_id,
            path=self.path.absolute(),
            original_filename=self.original_filename,
            file_size=self.file_size,
            file_extension=self.file_extension,
            file_sha1=self.file_sha1,
            additional_metadata=self.additional_metadata,
        )

    @classmethod
    def deserialize(cls, serialized: QuivrFileSerialized) -> Self:
        return cls(
            id=serialized.id,
            brain_id=serialized.brain_id,
            path=serialized.path,
            original_filename=serialized.original_filename,
            file_size=serialized.file_size,
            file_extension=serialized.file_extension,
            file_sha1=serialized.file_sha1,
            metadata=serialized.additional_metadata,
        )
