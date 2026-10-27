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
import os
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
                # LINEAJE: runtime guardrail checks `resp` as it flows from an external API to the agent, after the tool returns (in TikaProcessor._send_parse_tika).
                #   Detected: this statement moves data from an external API to the agent with no runtime policy check (detection confidence: low).
                #   Decision: the Guardrail evaluates the policies enabled for this boundary; sensitive values in `resp` are masked in place; a policy violation is logged and the call continues (fail_mode=ALLOW_WITH_AUDIT). If the Guardrail is unreachable, the call continues unchanged.
                #   Do not remove without review. site_id='site:sha256:4b831e98cf2fe5db3bbeac68440e0b35a72bcfce54e2546662bd648247e58c98'
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:4b831e98cf2fe5db3bbeac68440e0b35a72bcfce54e2546662bd648247e58c98', phase='post_tool', boundary={'source': 'external_endpoint', 'sink': 'agent_message'}, fail_mode='ALLOW_WITH_AUDIT', source_type='api', destination_type='agent', components={'invocation': {'file': 'core/quivr_core/processor/implementations/tika_processor.py', 'line': 59, 'function': 'TikaProcessor._send_parse_tika'}, 'file': 'core/quivr_core/processor/implementations/tika_processor.py', 'line': 59, 'function': '_send_parse_tika', 'agent_name': 'TikaProcessor', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
                try:
                    resp = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, resp, content_type='application/json', variable_name='resp', source_file=__file__, before_line=59))
                except _gr_client.GuardrailUnavailableError:
                    pass
                resp.raise_for_status()
                return resp.content.decode("utf-8")
            except Exception as e:
                retry += 1
                _lineaje_payload = f"tika url error :{e}. retrying for the {retry} time..."
                # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in TikaProcessor._send_parse_tika).
                #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
                #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
                #   Do not remove without review. site_id='site:sha256:e3278ed8e92ec19109ebb88abd25cf53e9a09b1aa296607cf60a51ff95bec7c4'
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:e3278ed8e92ec19109ebb88abd25cf53e9a09b1aa296607cf60a51ff95bec7c4', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'invocation': {'file': 'core/quivr_core/processor/implementations/tika_processor.py', 'line': 64, 'function': 'TikaProcessor._send_parse_tika'}, 'file': 'core/quivr_core/processor/implementations/tika_processor.py', 'line': 64, 'function': '_send_parse_tika', 'agent_name': 'TikaProcessor', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
                try:
                    _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
                except _gr_client.GuardrailUnavailableError:
                    pass
                except PermissionError:
                    pass
                logger.debug(_lineaje_payload)
        raise RuntimeError("can't send parse request to tika server")

    @property
    def processor_metadata(self):
        return {
            "chunk_overlap": self.splitter_config.chunk_overlap,
        }

    async def process_file_inner(self, file: QuivrFile) -> ProcessedDocument[None]:
        async with file.open() as f:
            txt = await self._send_parse_tika(f)
        document = Document(page_content=txt)
        _lineaje_payload = [document]
        # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from rag source to the RAG pipeline, before the tool runs (in TikaProcessor.process_file_inner).
        #   Detected: this statement moves data from rag source to the RAG pipeline with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates the policies enabled for this boundary; sensitive values in `_lineaje_payload` are masked in place; a policy violation is logged and the call continues (fail_mode=ALLOW_WITH_AUDIT). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:4e8c14e61065c77f2c38f662eb118dfaadd5912ae64c1e97d453f884442b8029'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:4e8c14e61065c77f2c38f662eb118dfaadd5912ae64c1e97d453f884442b8029', phase='pre_tool', boundary={'source': 'rag_source', 'sink': 'rag_pipeline'}, fail_mode='ALLOW_WITH_AUDIT', source_type='rag_source', destination_type='rag_pipeline', components={'invocation': {'file': 'core/quivr_core/processor/implementations/tika_processor.py', 'line': 77, 'function': 'TikaProcessor.process_file_inner'}, 'file': 'core/quivr_core/processor/implementations/tika_processor.py', 'line': 77, 'function': 'process_file_inner', 'agent_name': 'TikaProcessor', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
        try:
            _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json', variable_name='_lineaje_payload', source_file=__file__, before_line=77))
        except _gr_client.GuardrailUnavailableError:
            pass
        docs = self.text_splitter.split_documents(_lineaje_payload)
        for doc in docs:
            doc.metadata = {"chunk_size": len(self.enc.encode(doc.page_content))}

        return ProcessedDocument(
            chunks=docs, processor_cls="TikaProcessor", processor_response=None
        )
