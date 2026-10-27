# Copyright (c) Lineaje, Inc. All rights reserved.
# Lineaje UnifAI guardrail  version=2.0.0-alpha
def _lineaje_load_gr_client():
    """Lineaje-added: load gr_stub_client.py (missing / broken: a pass-through client)."""
    import sys, importlib.util as u, pathlib
    n = "_lineaje_gr_stub_client"
    if n in sys.modules: return sys.modules[n]
    try:
        h = pathlib.Path(__file__).resolve().parent
        s = u.spec_from_file_location(n, next(p for p in (d / "gr_stub_client.py" for d in [h, *h.parents][:8]) if p.is_file()))
        m = sys.modules[n] = u.module_from_spec(s); s.loader.exec_module(m); return m
    except Exception:
        sys.modules.pop(n, None); return __import__('types').SimpleNamespace(STUB_API=999999, GuardrailUnavailableError=type('GuardrailUnavailableError', (PermissionError,), {}), SiteDescriptor=lambda *a, **k: None, new_interaction_id=lambda *a, **k: None, enforce=lambda _s, _p, *a, **k: _p, enforce_request=lambda _s, _p, *a, **k: _p, enforce_reply=lambda _s, _p, *a, **k: _p)

import hashlib
import mimetypes
import os
import warnings
from contextlib import asynccontextmanager
from enum import Enum
from pathlib import Path
from typing import Any, AsyncGenerator, AsyncIterable
from uuid import UUID, uuid4

import aiofiles


class FileExtension(str, Enum):
    txt = ".txt"
    pdf = ".pdf"
    docx = ".docx"


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
        file_sha1 = hashlib.sha1(await f.read()).hexdigest()

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
    ]

    def __init__(
        self,
        id: UUID,
        original_filename: str,
        path: Path,
        brain_id: UUID,
        file_sha1: str,
        file_extension: FileExtension | str,
        file_size: int | None = None,
    ) -> None:
        self.id = id
        self.brain_id = brain_id
        self.path = path
        self.original_filename = original_filename
        self.file_size = file_size
        self.file_extension = file_extension
        self.file_sha1 = file_sha1

    @asynccontextmanager
    async def open(self) -> AsyncGenerator[AsyncIterable[bytes], None]:
        # TODO(@aminediro) : match on path type
        f = await aiofiles.open(self.path, mode="rb")
        # LINEAJE: runtime guardrail checks `f` as it flows from file storage to the agent (in QuivrFile.open).
        #   Detected: this statement moves data from file storage to the agent with no runtime policy check (detection confidence: medium).
        #   Decision: the Guardrail evaluates AI_APP_SEC_070, AI_DAT_SEC_023, AI_DAT_SEC_024; sensitive values in `f` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:a0981e69d2f31936333289aa3433ba710153de1b8ebb4c61943617f7775da1bb'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:a0981e69d2f31936333289aa3433ba710153de1b8ebb4c61943617f7775da1bb', phase='file_upload', boundary={'source': 'file_upload', 'sink': 'agent_context'}, fail_mode='BLOCK', source_type='file_storage', destination_type='agent', components={'invocation': {'file': 'core/quivr_core/storage/file.py', 'line': 97, 'function': 'QuivrFile.open'}, 'file': 'core/quivr_core/storage/file.py', 'line': 97, 'function': 'open', 'agent_name': 'QuivrFile', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
        try:
            f = _gr_client.enforce(_gr_site, f, content_type='application/json')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            raise
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
            "file_md4": self.file_sha1,
            "file_size": self.file_size,
        }
