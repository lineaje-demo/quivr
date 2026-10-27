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

import logging
from abc import ABC, abstractmethod
from importlib.metadata import PackageNotFoundError, version
from typing import Any, Generic, List, TypeVar

from attr import dataclass
from langchain_core.documents import Document

from quivr_core.files.file import FileExtension, QuivrFile
from quivr_core.language.utils import detect_language

logger = logging.getLogger("quivr_core")


R = TypeVar("R", covariant=True)


@dataclass
class ProcessedDocument(Generic[R]):
    chunks: List[Document]
    processor_cls: str
    processor_response: R


# TODO: processors should be cached somewhere ?
# The processor should be cached by processor type
# The cache should use a single
class ProcessorBase(ABC, Generic[R]):
    supported_extensions: list[FileExtension | str]

    def check_supported(self, file: QuivrFile) -> None:
        if file.file_extension not in self.supported_extensions:
            raise ValueError(f"can't process a file of type {file.file_extension}")

    @property
    @abstractmethod
    def processor_metadata(self) -> dict[str, Any]:
        raise NotImplementedError

    async def process_file(self, file: QuivrFile) -> ProcessedDocument[R]:
        _lineaje_payload = f"Processing file {file}"
        # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in ProcessorBase.process_file).
        #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:8b74c8b50692a02c7980bd108bbeab948e28fa6426968c54f77324f72d05489f'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:8b74c8b50692a02c7980bd108bbeab948e28fa6426968c54f77324f72d05489f', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'invocation': {'file': 'core/quivr_core/processor/processor_base.py', 'line': 41, 'function': 'ProcessorBase.process_file'}, 'file': 'core/quivr_core/processor/processor_base.py', 'line': 41, 'function': 'process_file', 'agent_name': 'ProcessorBase', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
        try:
            _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        logger.debug(_lineaje_payload)
        self.check_supported(file)
        docs = await self.process_file_inner(file)
        try:
            qvr_version = version("quivr-core")
        except PackageNotFoundError:
            qvr_version = "dev"

        for idx, doc in enumerate(docs.chunks, start=1):
            if "original_file_name" in doc.metadata:
                doc.page_content = f"Filename: {doc.metadata['original_file_name']} Content: {doc.page_content}"
            doc.page_content = doc.page_content.replace("\u0000", "")
            doc.page_content = doc.page_content.encode("utf-8", "replace").decode(
                "utf-8"
            )
            doc.metadata = {
                "chunk_index": idx,
                "quivr_core_version": qvr_version,
                "language": detect_language(
                    text=doc.page_content.replace("\\n", " ").replace("\n", " "),
                    low_memory=True,
                ).value,
                **file.metadata,
                **doc.metadata,
                **self.processor_metadata,
            }
        # LINEAJE: runtime guardrail checks `docs` as it flows from the agent to the user interface, before it leaves the application (in ProcessorBase.process_file).
        #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `docs` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:309ff589e93aa7b43f80a42c5dbea3abd3bdbeceec1908c295eb6917739fc7e3'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:309ff589e93aa7b43f80a42c5dbea3abd3bdbeceec1908c295eb6917739fc7e3', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'invocation': {'file': 'core/quivr_core/processor/processor_base.py', 'line': 67, 'function': 'ProcessorBase.process_file'}, 'file': 'core/quivr_core/processor/processor_base.py', 'line': 67, 'function': 'process_file', 'agent_name': 'ProcessorBase', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
        try:
            docs = _gr_client.enforce(_gr_site, docs, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        return docs

    @abstractmethod
    async def process_file_inner(self, file: QuivrFile) -> ProcessedDocument[R]:
        raise NotImplementedError
