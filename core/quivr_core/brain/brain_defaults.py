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

from langchain_core.documents import Document
from langchain_core.embeddings import Embeddings
from langchain_core.vectorstores import VectorStore
from pydantic import SecretStr

from quivr_core.rag.entities.config import (
    OPENROUTER_BASE_URL,
    DefaultModelSuppliers,
    LLMEndpointConfig,
    use_openrouter,
)
from quivr_core.llm import LLMEndpoint

logger = logging.getLogger("quivr_core")


async def build_default_vectordb(
    docs: list[Document], embedder: Embeddings
) -> VectorStore:
    try:
        from langchain_community.vectorstores import FAISS

        _lineaje_payload = "Using Faiss-CPU as vector store."
        # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in build_default_vectordb).
        #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:ba792bd0925958e73e6ea89d5585d9fc6bf2715b0ee284741ee705e0f40d950d'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:ba792bd0925958e73e6ea89d5585d9fc6bf2715b0ee284741ee705e0f40d950d', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'invocation': {'file': 'core/quivr_core/brain/brain_defaults.py', 'line': 26, 'function': 'build_default_vectordb'}, 'file': 'core/quivr_core/brain/brain_defaults.py', 'line': 26, 'function': 'build_default_vectordb', 'agent_name': 'build_default_vectordb', 'agent_name_source': 'inferred_from_function', 'not_on_graph': True})
        try:
            _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        logger.debug(_lineaje_payload)
        # TODO(@aminediro) : embedding call is usually not concurrent for all documents but waits
        if len(docs) > 0:
            try:
                _lineaje_obs = _lineaje_load_gr_client()
                _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:7bb3374b7061f01eca23480705e7c261df346fed563532ef05ad338949fc0e2e', phase='', boundary={}, fail_mode='ALLOW', source_type='rag_pipeline', destination_type='vector_store', components={'file': 'core/quivr_core/brain/brain_defaults.py', 'line': 29, 'function': 'build_default_vectordb', 'agent_name': 'build_default_vectordb', 'agent_name_source': 'inferred_from_function', 'call_target': 'FAISS.afrom_documents', 'not_on_graph': True}, observe_only=True)
                await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'vectorstore_upsert'}, content_type='application/json'))
            except Exception:
                pass
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

        _lineaje_payload = "Loaded OpenAIEmbeddings as default LLM for brain"
        # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in default_embedder).
        #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:7bd8e5bc4c69956c57ff51b20344d0c95ca79656a45699a275bcd335b7723f93'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:7bd8e5bc4c69956c57ff51b20344d0c95ca79656a45699a275bcd335b7723f93', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'invocation': {'file': 'core/quivr_core/brain/brain_defaults.py', 'line': 44, 'function': 'default_embedder'}, 'file': 'core/quivr_core/brain/brain_defaults.py', 'line': 44, 'function': 'default_embedder', 'agent_name': 'default_embedder', 'agent_name_source': 'inferred_from_function', 'not_on_graph': True})
        try:
            _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        logger.debug(_lineaje_payload)
        if use_openrouter():
            # check_embedding_ctx_length=False: send raw text, OpenRouter does not take tiktoken ids
            _lineaje_model = (os.getenv(
                    "OPENROUTER_EMBEDDING_MODEL", "openai/text-embedding-3-small"
                ))
            # LINEAJE: runtime guardrail checks the model this client is built with as it flows from the agent to the LLM, before it is sent to the model (in default_embedder).
            #   Detected: this statement moves data from the agent to the LLM with no runtime policy check (detection confidence: medium).
            #   Decision: the Guardrail evaluates AI_AGENT_ACTIVITY_LOG, AI_APP_SEC_006, AI_APP_SEC_028, AI_APP_SEC_070 (+1 more); a model that is not approved is refused before the client is built (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
            #   Do not remove without review. site_id='site:sha256:590e99e2cf4378a7f9f9dea0d0b99663f1effdd2b5252cf544cb67e45424f382'
            _lineaje_model_evidence = {'model': _lineaje_model, 'client': 'OpenAIEmbeddings', 'provider': 'openai', 'model_source': 'call_kwarg', 'project': 'tree'}
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:590e99e2cf4378a7f9f9dea0d0b99663f1effdd2b5252cf544cb67e45424f382', phase='pre_model', boundary={'source': 'agent_config', 'sink': 'model'}, fail_mode='BLOCK', source_type='agent', destination_type='llm', components={'destination': {'entity_type': 'llm', 'name': 'text-embedding-3-small', 'version': '', 'provider': 'openai'}, 'invocation': {'file': 'core/quivr_core/brain/brain_defaults.py', 'function': 'default_embedder', 'line': 47}, 'file': 'core/quivr_core/brain/brain_defaults.py', 'line': 47, 'function': 'default_embedder', 'agent_name': 'default_embedder', 'agent_name_source': 'inferred_from_function', 'boundary_id': 'bnd:b4d17a669bd4103f'})
            try:
                _lineaje_model_evidence = _gr_client.enforce(_gr_site, _lineaje_model_evidence, content_type='application/json')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                raise
            return OpenAIEmbeddings(
                model=_lineaje_model,
                base_url=OPENROUTER_BASE_URL,
                api_key=SecretStr(os.environ["OPENROUTER_API_KEY"]),
                check_embedding_ctx_length=False,
            )
        embedder = OpenAIEmbeddings()
        return embedder
    except ImportError as e:
        raise ImportError(
            "Please provide a valid Embedder or install quivr-core['base'] package for using the defaultone."
        ) from e


def default_llm() -> LLMEndpoint:
    try:
        _lineaje_payload = "Loaded ChatOpenAI as default LLM for brain"
        # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in default_llm).
        #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:fc1ca1cbca32e603d83f0e29d694b1a00b4e75224afb48363546d7a2ab13791d'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:fc1ca1cbca32e603d83f0e29d694b1a00b4e75224afb48363546d7a2ab13791d', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'invocation': {'file': 'core/quivr_core/brain/brain_defaults.py', 'line': 65, 'function': 'default_llm'}, 'file': 'core/quivr_core/brain/brain_defaults.py', 'line': 65, 'function': 'default_llm', 'agent_name': 'default_llm', 'agent_name_source': 'inferred_from_function', 'not_on_graph': True})
        try:
            _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        logger.debug(_lineaje_payload)
        if use_openrouter():
            # supplier/model come from OPENROUTER_API_KEY / OPENROUTER_MODEL
            config = LLMEndpointConfig()
        else:
            config = LLMEndpointConfig(
                supplier=DefaultModelSuppliers.OPENAI, model="gpt-4o"
            )
        llm = LLMEndpoint.from_config(config)
        return llm

    except ImportError as e:
        raise ImportError(
            "Please provide a valid BaseLLM or install quivr-core['base'] package"
        ) from e
