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
from typing import Any, List, Type, TypeVar

import tiktoken
from langchain_community.document_loaders import (
    BibtexLoader,
    CSVLoader,
    Docx2txtLoader,
    NotebookLoader,
    PythonLoader,
    UnstructuredEPubLoader,
    UnstructuredExcelLoader,
    UnstructuredHTMLLoader,
    UnstructuredMarkdownLoader,
    UnstructuredODTLoader,
    UnstructuredPDFLoader,
    UnstructuredPowerPointLoader,
)
from langchain_community.document_loaders.base import BaseLoader
from langchain_community.document_loaders.text import TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter, TextSplitter

from quivr_core.files.file import FileExtension, QuivrFile
from quivr_core.processor.processor_base import ProcessedDocument, ProcessorBase
from quivr_core.processor.splitter import SplitterConfig

logger = logging.getLogger("quivr_core")

P = TypeVar("P", bound=BaseLoader)


class ProcessorInit(ProcessorBase):
    def __init__(self, *args, **loader_kwargs) -> None:
        pass


# FIXME(@aminediro):
# dynamically creates Processor classes. Maybe redo this for finer control over instanciation
# processor classes are opaque as we don't know what params they would have -> not easy to have lsp completion
def _build_processor(
    cls_name: str, load_cls: Type[P], cls_extensions: List[FileExtension | str]
) -> Type[ProcessorInit]:
    enc = tiktoken.get_encoding("cl100k_base")

    class _Processor(ProcessorBase):
        supported_extensions = cls_extensions

        def __init__(
            self,
            splitter: TextSplitter | None = None,
            splitter_config: SplitterConfig = SplitterConfig(),
            **loader_kwargs: dict[str, Any],
        ) -> None:
            self.loader_cls = load_cls
            self.loader_kwargs = loader_kwargs

            self.splitter_config = splitter_config

            if splitter:
                self.text_splitter = splitter
            else:
                self.text_splitter = (
                    RecursiveCharacterTextSplitter.from_tiktoken_encoder(
                        chunk_size=splitter_config.chunk_size,
                        chunk_overlap=splitter_config.chunk_overlap,
                    )
                )

        @property
        def processor_metadata(self) -> dict[str, Any]:
            return {
                "processor_cls": self.loader_cls.__name__,
                "splitter": self.splitter_config.model_dump(),
            }

        async def process_file_inner(self, file: QuivrFile) -> ProcessedDocument[None]:
            if hasattr(self.loader_cls, "__init__"):
                # NOTE: mypy can't correctly type this as BaseLoader doesn't have a constructor method
                loader = self.loader_cls(file_path=str(file.path), **self.loader_kwargs)  # type: ignore
            else:
                loader = self.loader_cls()

            documents = await loader.aload()
            # LINEAJE: runtime guardrail checks `documents` as it flows from a data source to the RAG pipeline, after the tool returns (in _Processor.process_file_inner).
            #   Detected: this statement moves data from a data source to the RAG pipeline with no runtime policy check (detection confidence: medium).
            #   Decision: the Guardrail evaluates the policies enabled for this boundary; sensitive values in `documents` are masked in place; a policy violation is logged and the call continues (fail_mode=ALLOW_WITH_AUDIT). If the Guardrail is unreachable, the call continues unchanged.
            #   Do not remove without review. site_id='site:sha256:a5f887ffe4da94aa65d3319ab85bdaa8200d18c4c01e32584dc8ad2b74ee95f2'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:a5f887ffe4da94aa65d3319ab85bdaa8200d18c4c01e32584dc8ad2b74ee95f2', phase='post_tool', boundary={'source': 'data_source', 'sink': 'rag_pipeline'}, fail_mode='ALLOW_WITH_AUDIT', source_type='data_source', destination_type='rag_pipeline', components={'invocation': {'file': 'core/quivr_core/processor/implementations/default.py', 'line': 83, 'function': '_build_processor._Processor.process_file_inner'}, 'file': 'core/quivr_core/processor/implementations/default.py', 'line': 83, 'function': 'process_file_inner', 'agent_name': '_Processor', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
            try:
                documents = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, documents, content_type='application/json', variable_name='documents', source_file=__file__, before_line=83))
            except _gr_client.GuardrailUnavailableError:
                pass
            # LINEAJE: runtime guardrail checks `documents` as it flows from rag source to the RAG pipeline, before the tool runs (in _Processor.process_file_inner).
            #   Detected: this statement moves data from rag source to the RAG pipeline with no runtime policy check (detection confidence: high).
            #   Decision: the Guardrail evaluates the policies enabled for this boundary; sensitive values in `documents` are masked in place; a policy violation is logged and the call continues (fail_mode=ALLOW_WITH_AUDIT). If the Guardrail is unreachable, the call continues unchanged.
            #   Do not remove without review. site_id='site:sha256:a5617df644ac78b4dab04687a216e2f9102f871c8b553f2e65bf8e2b8438b71a'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:a5617df644ac78b4dab04687a216e2f9102f871c8b553f2e65bf8e2b8438b71a', phase='pre_tool', boundary={'source': 'rag_source', 'sink': 'rag_pipeline'}, fail_mode='ALLOW_WITH_AUDIT', source_type='rag_source', destination_type='rag_pipeline', components={'invocation': {'file': 'core/quivr_core/processor/implementations/default.py', 'line': 84, 'function': '_build_processor._Processor.process_file_inner'}, 'file': 'core/quivr_core/processor/implementations/default.py', 'line': 84, 'function': 'process_file_inner', 'agent_name': '_Processor', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
            try:
                documents = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, documents, content_type='application/json', variable_name='documents', source_file=__file__, before_line=84))
            except _gr_client.GuardrailUnavailableError:
                pass
            docs = self.text_splitter.split_documents(documents)

            for doc in docs:
                # TODO: This metadata info should be typed
                doc.metadata = {"chunk_size": len(enc.encode(doc.page_content))}

            return ProcessedDocument(
                chunks=docs, processor_cls=cls_name, processor_response=None
            )

    return type(cls_name, (ProcessorInit,), dict(_Processor.__dict__))


CSVProcessor = _build_processor("CSVProcessor", CSVLoader, [FileExtension.csv])
TikTokenTxtProcessor = _build_processor(
    "TikTokenTxtProcessor", TextLoader, [FileExtension.txt]
)
DOCXProcessor = _build_processor(
    "DOCXProcessor", Docx2txtLoader, [FileExtension.docx, FileExtension.doc]
)
XLSXProcessor = _build_processor(
    "XLSXProcessor", UnstructuredExcelLoader, [FileExtension.xlsx, FileExtension.xls]
)
PPTProcessor = _build_processor(
    "PPTProcessor", UnstructuredPowerPointLoader, [FileExtension.pptx]
)
MarkdownProcessor = _build_processor(
    "MarkdownProcessor",
    UnstructuredMarkdownLoader,
    [FileExtension.md, FileExtension.mdx, FileExtension.markdown],
)
EpubProcessor = _build_processor(
    "EpubProcessor", UnstructuredEPubLoader, [FileExtension.epub]
)
BibTexProcessor = _build_processor("BibTexProcessor", BibtexLoader, [FileExtension.bib])
ODTProcessor = _build_processor(
    "ODTProcessor", UnstructuredODTLoader, [FileExtension.odt]
)
HTMLProcessor = _build_processor(
    "HTMLProcessor", UnstructuredHTMLLoader, [FileExtension.html]
)
PythonProcessor = _build_processor("PythonProcessor", PythonLoader, [FileExtension.py])
NotebookProcessor = _build_processor(
    "NotebookProcessor", NotebookLoader, [FileExtension.ipynb]
)
UnstructuredPDFProcessor = _build_processor(
    "UnstructuredPDFProcessor", UnstructuredPDFLoader, [FileExtension.pdf]
)
