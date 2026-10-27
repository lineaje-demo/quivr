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
import re
from enum import Enum
from typing import Any, Dict, Hashable, List, Optional, Type, Union
from uuid import UUID

from langchain_core.prompts.base import BasePromptTemplate
from langchain_core.tools import BaseTool
from langgraph.graph import END, START
from pydantic import BaseModel
from rapidfuzz import fuzz, process

from quivr_core.base_config import QuivrBaseConfig
from quivr_core.config import MegaparseConfig
from quivr_core.llm_tools.llm_tools import TOOLS_CATEGORIES, TOOLS_LISTS, LLMToolFactory
from quivr_core.processor.splitter import SplitterConfig

logger = logging.getLogger("quivr_core")
MIN_CONTEXT_TOKENS = 4096
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


def use_openrouter() -> bool:
    """Default to OpenRouter when only OPENROUTER_API_KEY is set."""
    return bool(os.getenv("OPENROUTER_API_KEY")) and not os.getenv("OPENAI_API_KEY")
MIN_OUTPUT_TOKENS = 4096


def normalize_to_env_variable_name(name: str) -> str:
    # Replace any character that is not a letter, digit, or underscore with an underscore
    env_variable_name = re.sub(r"[^A-Za-z0-9_]", "_", name).upper()

    # Check if the normalized name starts with a digit
    if env_variable_name[0].isdigit():
        raise ValueError(
            f"Invalid environment variable name '{env_variable_name}': Cannot start with a digit."
        )

    # LINEAJE: runtime guardrail checks `env_variable_name` as it flows from the agent to the user interface, before it leaves the application (in normalize_to_env_variable_name).
    #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: high).
    #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `env_variable_name` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
    #   Do not remove without review. site_id='site:sha256:5a4544a021080faffea34593751a0b469cb330bffd05f849f5d0770c4bf98686'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:5a4544a021080faffea34593751a0b469cb330bffd05f849f5d0770c4bf98686', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'invocation': {'file': 'core/quivr_core/config.py', 'line': 40, 'function': 'normalize_to_env_variable_name'}, 'file': 'core/quivr_core/config.py', 'line': 40, 'function': 'normalize_to_env_variable_name', 'agent_name': 'normalize_to_env_variable_name', 'agent_name_source': 'inferred_from_function', 'not_on_graph': True})
    try:
        env_variable_name = _gr_client.enforce(_gr_site, env_variable_name, content_type='text/plain')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    return env_variable_name


class SpecialEdges(str, Enum):
    start = "START"
    end = "END"


class BrainConfig(QuivrBaseConfig):
    brain_id: UUID | None = None
    name: str

    @property
    def id(self) -> UUID | None:
        return self.brain_id


class DefaultWebSearchTool(str, Enum):
    TAVILY = "tavily"


class DefaultRerankers(str, Enum):
    COHERE = "cohere"
    JINA = "jina"
    # MIXEDBREAD = "mixedbread-ai"

    @property
    def default_model(self) -> str:
        # Mapping of suppliers to their default models
        return {
            self.COHERE: "rerank-v3.5",
            self.JINA: "jina-reranker-v2-base-multilingual",
            # self.MIXEDBREAD: "rmxbai-rerank-large-v1",
        }[self]


class DefaultModelSuppliers(str, Enum):
    OPENAI = "openai"
    AZURE = "azure"
    ANTHROPIC = "anthropic"
    META = "meta"
    MISTRAL = "mistral"
    GROQ = "groq"
    GEMINI = "gemini"
    OPENROUTER = "openrouter"


class LLMConfig(QuivrBaseConfig):
    max_context_tokens: int | None = None
    max_output_tokens: int | None = None
    tokenizer_hub: str | None = None


class LLMModelConfig:
    _model_defaults: Dict[DefaultModelSuppliers, Dict[str, LLMConfig]] = {
        DefaultModelSuppliers.OPENAI: {
            "gpt-4.1": LLMConfig(
                max_context_tokens=1047576,
                max_output_tokens=32768,
                tokenizer_hub="Quivr/gpt-4o",
            ),
            "gpt-4o": LLMConfig(
                max_context_tokens=128000,
                max_output_tokens=16384,
                tokenizer_hub="Quivr/gpt-4o",
            ),
            "gpt-4o-mini": LLMConfig(
                max_context_tokens=128000,
                max_output_tokens=16384,
                tokenizer_hub="Quivr/gpt-4o",
            ),
            "o3-mini": LLMConfig(
                max_context_tokens=200000,
                max_output_tokens=100000,
                tokenizer_hub="Quivr/gpt-4o",
            ),
            "o4-mini": LLMConfig(
                max_context_tokens=200000,
                max_output_tokens=100000,
                tokenizer_hub="Quivr/gpt-4o",
            ),
            "o1-mini": LLMConfig(
                max_context_tokens=128000,
                max_output_tokens=65536,
                tokenizer_hub="Quivr/gpt-4o",
            ),
            "o1-preview": LLMConfig(
                max_context_tokens=128000,
                max_output_tokens=32768,
                tokenizer_hub="Quivr/gpt-4o",
            ),
            "o1": LLMConfig(
                max_context_tokens=200000,
                max_output_tokens=100000,
                tokenizer_hub="Quivr/gpt-4o",
            ),
            "gpt-4-turbo": LLMConfig(
                max_context_tokens=128000,
                max_output_tokens=4096,
                tokenizer_hub="Quivr/gpt-4",
            ),
            "gpt-4": LLMConfig(
                max_context_tokens=8192,
                max_output_tokens=8192,
                tokenizer_hub="Quivr/gpt-4",
            ),
            "gpt-3.5-turbo": LLMConfig(
                max_context_tokens=16385,
                max_output_tokens=4096,
                tokenizer_hub="Quivr/gpt-3.5-turbo",
            ),
            "text-embedding-3-large": LLMConfig(
                max_context_tokens=8191, tokenizer_hub="Quivr/text-embedding-ada-002"
            ),
            "text-embedding-3-small": LLMConfig(
                max_context_tokens=8191, tokenizer_hub="Quivr/text-embedding-ada-002"
            ),
            "text-embedding-ada-002": LLMConfig(
                max_context_tokens=8191, tokenizer_hub="Quivr/text-embedding-ada-002"
            ),
        },
        DefaultModelSuppliers.ANTHROPIC: {
            "claude-opus-4": LLMConfig(
                max_context_tokens=200000,
                max_output_tokens=8192,
                tokenizer_hub="Quivr/claude-tokenizer",
            ),
            "claude-sonnet-4": LLMConfig(
                max_context_tokens=200000,
                max_output_tokens=8192,
                tokenizer_hub="Quivr/claude-tokenizer",
            ),
            "claude-3-7-sonnet": LLMConfig(
                max_context_tokens=200000,
                max_output_tokens=8192,
                tokenizer_hub="Quivr/claude-tokenizer",
            ),
            "claude-3-5-sonnet": LLMConfig(
                max_context_tokens=200000,
                max_output_tokens=8192,
                tokenizer_hub="Quivr/claude-tokenizer",
            ),
            "claude-3-opus": LLMConfig(
                max_context_tokens=200000,
                max_output_tokens=4096,
                tokenizer_hub="Quivr/claude-tokenizer",
            ),
            "claude-3-sonnet": LLMConfig(
                max_context_tokens=200000,
                max_output_tokens=4096,
                tokenizer_hub="Quivr/claude-tokenizer",
            ),
            "claude-3-haiku": LLMConfig(
                max_context_tokens=200000,
                max_output_tokens=4096,
                tokenizer_hub="Quivr/claude-tokenizer",
            ),
            "claude-2-1": LLMConfig(
                max_context_tokens=200000,
                max_output_tokens=4096,
                tokenizer_hub="Quivr/claude-tokenizer",
            ),
            "claude-2-0": LLMConfig(
                max_context_tokens=100000,
                max_output_tokens=4096,
                tokenizer_hub="Quivr/claude-tokenizer",
            ),
            "claude-instant-1-2": LLMConfig(
                max_context_tokens=100000,
                max_output_tokens=4096,
                tokenizer_hub="Quivr/claude-tokenizer",
            ),
        },
        # Unclear for LLAMA models...
        # see https://huggingface.co/meta-llama/Llama-3.1-405B-Instruct/discussions/6
        DefaultModelSuppliers.META: {
            "llama-3.1": LLMConfig(
                max_context_tokens=128000,
                max_output_tokens=4096,
                tokenizer_hub="Quivr/Meta-Llama-3.1-Tokenizer",
            ),
            "llama-3": LLMConfig(
                max_context_tokens=8192,
                max_output_tokens=2048,
                tokenizer_hub="Quivr/llama3-tokenizer-new",
            ),
            "code-llama": LLMConfig(
                max_context_tokens=16384, tokenizer_hub="Quivr/llama-code-tokenizer"
            ),
        },
        DefaultModelSuppliers.GROQ: {
            "llama-3.3-70b": LLMConfig(
                max_context_tokens=128000,
                max_output_tokens=32768,
                tokenizer_hub="Quivr/Meta-Llama-3.1-Tokenizer",
            ),
            "llama-3.1-70b": LLMConfig(
                max_context_tokens=128000,
                max_output_tokens=32768,
                tokenizer_hub="Quivr/Meta-Llama-3.1-Tokenizer",
            ),
            "llama-3": LLMConfig(
                max_context_tokens=8192, tokenizer_hub="Quivr/llama3-tokenizer-new"
            ),
            "code-llama": LLMConfig(
                max_context_tokens=16384, tokenizer_hub="Quivr/llama-code-tokenizer"
            ),
            "deepseek-r1-distill-llama-70b": LLMConfig(
                max_context_tokens=128000,
                max_output_tokens=32768,
                tokenizer_hub="Quivr/Meta-Llama-3.1-Tokenizer",
            ),
            "meta-llama/llama-4-maverick-17b-128e-instruct": LLMConfig(
                max_context_tokens=128000,
                max_output_tokens=32768,
                tokenizer_hub="Quivr/Meta-Llama-3.1-Tokenizer",
            ),
        },
        DefaultModelSuppliers.MISTRAL: {
            "mistral-large": LLMConfig(
                max_context_tokens=128000,
                max_output_tokens=4096,
                tokenizer_hub="Quivr/mistral-tokenizer-v3",
            ),
            "mistral-small": LLMConfig(
                max_context_tokens=128000,
                max_output_tokens=4096,
                tokenizer_hub="Quivr/mistral-tokenizer-v3",
            ),
            "mistral-nemo": LLMConfig(
                max_context_tokens=128000,
                max_output_tokens=4096,
                tokenizer_hub="Quivr/Mistral-Nemo-Instruct-Tokenizer",
            ),
            "codestral": LLMConfig(
                max_context_tokens=32000, tokenizer_hub="Quivr/mistral-tokenizer-v3"
            ),
        },
        DefaultModelSuppliers.GEMINI: {
            "gemini-2.5": LLMConfig(
                max_context_tokens=128000,
                max_output_tokens=4096,
                tokenizer_hub="Quivr/gemini-tokenizer",
            ),
        },
    }

    @classmethod
    def get_supplier_by_model_name(cls, model: str) -> DefaultModelSuppliers | None:
        # Iterate over the suppliers and their models
        for supplier, models in cls._model_defaults.items():
            # Check if the model name or a base part of the model name is in the supplier's models
            for base_model_name in models:
                if model.startswith(base_model_name):
                    return supplier
        # Return None if no supplier matches the model name
        return None

    @classmethod
    def get_llm_model_config(
        cls, supplier: DefaultModelSuppliers, model_name: str
    ) -> Optional[LLMConfig]:
        """Retrieve the LLMConfig (context and tokenizer_hub) for a given supplier and model."""
        supplier_defaults = cls._model_defaults.get(supplier)
        if not supplier_defaults:
            return None

        # Use startswith logic for matching model names
        for key, config in supplier_defaults.items():
            if model_name.startswith(key):
                return config

        return None


class LLMEndpointConfig(QuivrBaseConfig):
    supplier: DefaultModelSuppliers = DefaultModelSuppliers.OPENAI
    model: str = "gpt-4o"
    tokenizer_hub: str | None = None
    llm_base_url: str | None = None
    env_variable_name: str | None = None
    llm_api_key: str | None = None
    max_context_tokens: int = 20000
    max_output_tokens: int = 4096
    temperature: float = 0.3
    streaming: bool = True
    prompt: BasePromptTemplate | None = None

    _FALLBACK_TOKENIZER = "cl100k_base"

    def __hash__(self):
        return hash(
            (
                self.supplier,
                self.model,
                self.tokenizer_hub,
                self.llm_base_url,
                self.env_variable_name,
                self.llm_api_key,
                self.max_context_tokens,
                self.max_output_tokens,
                self.temperature,
                self.streaming,
                repr(self.prompt) if self.prompt is not None else None,
            )
        )

    @property
    def fallback_tokenizer(self) -> str:
        return self._FALLBACK_TOKENIZER

    def __init__(self, **data):
        if "supplier" not in data and use_openrouter():
            data["supplier"] = DefaultModelSuppliers.OPENROUTER
            data.setdefault("model", os.getenv("OPENROUTER_MODEL", "openai/gpt-4o"))
        super().__init__(**data)
        # OpenRouter is OpenAI-compatible: served through ChatOpenAI at its own base URL
        if self.supplier == DefaultModelSuppliers.OPENROUTER and not self.llm_base_url:
            self.llm_base_url = OPENROUTER_BASE_URL
        self.set_llm_model_config()
        self.set_api_key()

    def set_api_key(self, force_reset: bool = False):
        if not self.supplier:
            return

        # Check if the corresponding API key environment variable is set
        if force_reset or not self.env_variable_name:
            self.env_variable_name = (
                f"{normalize_to_env_variable_name(self.supplier)}_API_KEY"
            )

        if not self.llm_api_key or force_reset:
            self.llm_api_key = os.getenv(self.env_variable_name)

        if not self.llm_api_key:
            _lineaje_payload = f"The API key for supplier '{self.supplier}' is not set. "
            # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in LLMEndpointConfig.set_api_key).
            #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
            #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
            #   Do not remove without review. site_id='site:sha256:46e9d008ab39a416a9388f1c257be503e1dba1ec9353492fb90b8fe97356bc47'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:46e9d008ab39a416a9388f1c257be503e1dba1ec9353492fb90b8fe97356bc47', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'invocation': {'file': 'core/quivr_core/config.py', 'line': 376, 'function': 'LLMEndpointConfig.set_api_key'}, 'file': 'core/quivr_core/config.py', 'line': 376, 'function': 'set_api_key', 'agent_name': 'LLMEndpointConfig', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
            try:
                _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            logger.warning(_lineaje_payload)
            _lineaje_payload = f"Please set the environment variable: '{self.env_variable_name}'. "
            # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in LLMEndpointConfig.set_api_key).
            #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
            #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
            #   Do not remove without review. site_id='site:sha256:31bb0fb6ed4760e573873dbada8df46fd4d3f37f87b156dec642302cf3fa5712'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:31bb0fb6ed4760e573873dbada8df46fd4d3f37f87b156dec642302cf3fa5712', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'invocation': {'file': 'core/quivr_core/config.py', 'line': 377, 'function': 'LLMEndpointConfig.set_api_key'}, 'file': 'core/quivr_core/config.py', 'line': 377, 'function': 'set_api_key', 'agent_name': 'LLMEndpointConfig', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
            try:
                _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            logger.warning(
                _lineaje_payload
            )

    def set_llm_model_config(self):
        # Automatically set context_length and tokenizer_hub based on the supplier and model
        llm_model_config = LLMModelConfig.get_llm_model_config(
            self.supplier, self.model
        )
        if llm_model_config:
            if llm_model_config.max_context_tokens:
                _max_context_tokens = (
                    llm_model_config.max_context_tokens
                    - llm_model_config.max_output_tokens
                    if llm_model_config.max_output_tokens
                    else llm_model_config.max_context_tokens
                )
                if self.max_context_tokens > _max_context_tokens:
                    _lineaje_payload = f"Lowering max_context_tokens from {self.max_context_tokens} to {_max_context_tokens}"
                    # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in LLMEndpointConfig.set_llm_model_config).
                    #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
                    #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
                    #   Do not remove without review. site_id='site:sha256:2f2210efe7cb375260c70bf6b84bc1bb9c13a72f6aafcd5981f21375adb53980'
                    _gr_client = _lineaje_load_gr_client()
                    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:2f2210efe7cb375260c70bf6b84bc1bb9c13a72f6aafcd5981f21375adb53980', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'invocation': {'file': 'core/quivr_core/config.py', 'line': 395, 'function': 'LLMEndpointConfig.set_llm_model_config'}, 'file': 'core/quivr_core/config.py', 'line': 395, 'function': 'set_llm_model_config', 'agent_name': 'LLMEndpointConfig', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
                    try:
                        _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
                    except _gr_client.GuardrailUnavailableError:
                        pass
                    except PermissionError:
                        pass
                    logger.warning(
                        _lineaje_payload
                    )
                    self.max_context_tokens = _max_context_tokens

                if self.max_context_tokens < MIN_CONTEXT_TOKENS:
                    _lineaje_payload = f"max_context_tokens is too low: {self.max_context_tokens}. "
                    # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in LLMEndpointConfig.set_llm_model_config).
                    #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
                    #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
                    #   Do not remove without review. site_id='site:sha256:b1e1dc95b79d76e1554f981ec0882b281aee053dcb1d09135ce554153d942e22'
                    _gr_client = _lineaje_load_gr_client()
                    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:b1e1dc95b79d76e1554f981ec0882b281aee053dcb1d09135ce554153d942e22', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'invocation': {'file': 'core/quivr_core/config.py', 'line': 401, 'function': 'LLMEndpointConfig.set_llm_model_config'}, 'file': 'core/quivr_core/config.py', 'line': 401, 'function': 'set_llm_model_config', 'agent_name': 'LLMEndpointConfig', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
                    try:
                        _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
                    except _gr_client.GuardrailUnavailableError:
                        pass
                    except PermissionError:
                        pass
                    logger.error(
                        _lineaje_payload
                    )
                    raise ValueError(
                        f"max_context_tokens is too low: {self.max_context_tokens}. "
                    )
            if llm_model_config.max_output_tokens:
                if self.max_output_tokens > llm_model_config.max_output_tokens:
                    _lineaje_payload = f"Lowering max_output_tokens from {self.max_output_tokens} to {llm_model_config.max_output_tokens}"
                    # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in LLMEndpointConfig.set_llm_model_config).
                    #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
                    #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
                    #   Do not remove without review. site_id='site:sha256:aa94c8bbb91e16d633b6a1817ed90c85815564bf6f50bfbf572d9b859190b4be'
                    _gr_client = _lineaje_load_gr_client()
                    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:aa94c8bbb91e16d633b6a1817ed90c85815564bf6f50bfbf572d9b859190b4be', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'invocation': {'file': 'core/quivr_core/config.py', 'line': 409, 'function': 'LLMEndpointConfig.set_llm_model_config'}, 'file': 'core/quivr_core/config.py', 'line': 409, 'function': 'set_llm_model_config', 'agent_name': 'LLMEndpointConfig', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
                    try:
                        _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
                    except _gr_client.GuardrailUnavailableError:
                        pass
                    except PermissionError:
                        pass
                    logger.warning(
                        _lineaje_payload
                    )
                    self.max_output_tokens = llm_model_config.max_output_tokens

                if self.max_output_tokens < MIN_OUTPUT_TOKENS:
                    _lineaje_payload = f"max_output_tokens is too low: {self.max_output_tokens}. "
                    # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in LLMEndpointConfig.set_llm_model_config).
                    #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
                    #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
                    #   Do not remove without review. site_id='site:sha256:30d4dd17e25bf20db5a56bbc108dba16ecf944fcbef4eb4820a589f733d923ea'
                    _gr_client = _lineaje_load_gr_client()
                    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:30d4dd17e25bf20db5a56bbc108dba16ecf944fcbef4eb4820a589f733d923ea', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'invocation': {'file': 'core/quivr_core/config.py', 'line': 415, 'function': 'LLMEndpointConfig.set_llm_model_config'}, 'file': 'core/quivr_core/config.py', 'line': 415, 'function': 'set_llm_model_config', 'agent_name': 'LLMEndpointConfig', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
                    try:
                        _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
                    except _gr_client.GuardrailUnavailableError:
                        pass
                    except PermissionError:
                        pass
                    logger.error(
                        _lineaje_payload
                    )
                    raise ValueError(
                        f"max_output_tokens is too low: {self.max_output_tokens}. "
                    )

            self.tokenizer_hub = llm_model_config.tokenizer_hub

    def set_llm_model(self, model: str):
        supplier = LLMModelConfig.get_supplier_by_model_name(model)
        if supplier is None:
            raise ValueError(
                f"Cannot find the corresponding supplier for model {model}"
            )
        self.supplier = supplier
        self.model = model

        self.set_llm_model_config()
        self.set_api_key(force_reset=True)

    def set_from_sqlmodel(self, sqlmodel: BaseModel, mapping: Dict[str, str]):
        """
        Set attributes in LLMEndpointConfig from Model attributes using a field mapping.

        :param model_instance: An instance of the Model class.
        :param mapping: A dictionary that maps Model fields to LLMEndpointConfig fields.
                        Example: {"max_input": "max_input_tokens", "env_variable_name": "env_variable_name"}
        """
        for model_field, llm_field in mapping.items():
            if hasattr(sqlmodel, model_field) and hasattr(self, llm_field):
                setattr(self, llm_field, getattr(sqlmodel, model_field))
            else:
                raise AttributeError(
                    f"Invalid mapping: {model_field} or {llm_field} does not exist."
                )


# Cannot use Pydantic v2 field_validator because of conflicts with pydantic v1 still in use in LangChain
class RerankerConfig(QuivrBaseConfig):
    supplier: DefaultRerankers | None = None
    model: str | None = None
    top_n: int = 5  # Number of chunks returned by the re-ranker
    api_key: str | None = None
    relevance_score_threshold: float | None = None
    relevance_score_key: str = "relevance_score"

    def __init__(self, **data):
        super().__init__(**data)  # Call Pydantic's BaseModel init
        self.validate_model()  # Automatically call external validation

    def validate_model(self):
        # If model is not provided, get default model based on supplier
        if self.model is None and self.supplier is not None:
            self.model = self.supplier.default_model

        # Check if the corresponding API key environment variable is set
        if self.supplier:
            api_key_var = f"{normalize_to_env_variable_name(self.supplier)}_API_KEY"
            self.api_key = os.getenv(api_key_var)

            if self.api_key is None:
                raise ValueError(
                    f"The API key for supplier '{self.supplier}' is not set. "
                    f"Please set the environment variable: {api_key_var}"
                )


class ConditionalEdgeConfig(QuivrBaseConfig):
    routing_function: str
    conditions: Union[list, Dict[Hashable, str]]

    def __init__(self, **data):
        super().__init__(**data)
        self.resolve_special_edges()

    def resolve_special_edges(self):
        """Replace SpecialEdges enum values with their corresponding langgraph values."""

        if isinstance(self.conditions, dict):
            # If conditions is a dictionary, iterate through the key-value pairs
            for key, value in self.conditions.items():
                if value == SpecialEdges.end:
                    self.conditions[key] = END
                elif value == SpecialEdges.start:
                    self.conditions[key] = START
        elif isinstance(self.conditions, list):
            # If conditions is a list, iterate through the values
            for index, value in enumerate(self.conditions):
                if value == SpecialEdges.end:
                    self.conditions[index] = END
                elif value == SpecialEdges.start:
                    self.conditions[index] = START


class NodeConfig(QuivrBaseConfig):
    name: str
    description: str | None = None
    edges: List[str] | None = None
    conditional_edge: ConditionalEdgeConfig | None = None
    tools: List[Dict[str, Any]] | None = None
    instantiated_tools: List[BaseTool | Type] | None = None

    def __init__(self, **data):
        super().__init__(**data)
        self._instantiate_tools()
        self.resolve_special_edges_in_name_and_edges()

    def resolve_special_edges_in_name_and_edges(self):
        """Replace SpecialEdges enum values in name and edges with corresponding langgraph values."""
        if self.name == SpecialEdges.start:
            self.name = START
        elif self.name == SpecialEdges.end:
            self.name = END

        if self.edges:
            for i, edge in enumerate(self.edges):
                if edge == SpecialEdges.start:
                    self.edges[i] = START
                elif edge == SpecialEdges.end:
                    self.edges[i] = END

    def _instantiate_tools(self):
        """Instantiate tools based on the configuration."""
        if self.tools:
            self.instantiated_tools = [
                LLMToolFactory.create_tool(tool_config.pop("name"), tool_config)
                for tool_config in self.tools
            ]


class DefaultWorkflow(str, Enum):
    RAG = "rag"

    @property
    def nodes(self) -> List[NodeConfig]:
        # Mapping of workflow types to their default node configurations
        workflows = {
            self.RAG: [
                NodeConfig(name=START, edges=["filter_history"]),
                NodeConfig(name="filter_history", edges=["rewrite"]),
                NodeConfig(name="rewrite", edges=["retrieve"]),
                NodeConfig(name="retrieve", edges=["generate_rag"]),
                NodeConfig(name="generate_rag", edges=[END]),
            ]
        }
        return workflows[self]


class WorkflowConfig(QuivrBaseConfig):
    name: str | None = None
    nodes: List[NodeConfig] = []
    available_tools: List[str] | None = None
    validated_tools: List[BaseTool | Type] = []
    activated_tools: List[BaseTool | Type] = []

    def __init__(self, **data):
        super().__init__(**data)
        self.check_first_node_is_start()
        self.validate_available_tools()

    def check_first_node_is_start(self):
        if self.nodes and self.nodes[0].name != START:
            raise ValueError(f"The first node should be a {SpecialEdges.start} node")

    def get_node_tools(self, node_name: str) -> List[Any]:
        """Get tools for a specific node."""
        for node in self.nodes:
            if node.name == node_name and node.instantiated_tools:
                return node.instantiated_tools
        return []

    def validate_available_tools(self):
        if self.available_tools:
            valid_tools = list(TOOLS_CATEGORIES.keys()) + list(TOOLS_LISTS.keys())
            for tool in self.available_tools:
                if tool.lower() in valid_tools:
                    self.validated_tools.append(
                        LLMToolFactory.create_tool(tool, {}).tool
                    )
                else:
                    matches = process.extractOne(
                        tool.lower(), valid_tools, scorer=fuzz.WRatio
                    )
                    if matches:
                        raise ValueError(
                            f"Tool {tool} is not a valid ToolsCategory or ToolsList. Did you mean {matches[0]}?"
                        )
                    else:
                        raise ValueError(
                            f"Tool {tool} is not a valid ToolsCategory or ToolsList"
                        )


class RetrievalConfig(QuivrBaseConfig):
    reranker_config: RerankerConfig = RerankerConfig()
    llm_config: LLMEndpointConfig = LLMEndpointConfig()
    max_history: int = 10
    max_files: int = 20
    k: int = 40  # Number of chunks returned by the retriever
    prompt: str | None = None
    workflow_config: WorkflowConfig = WorkflowConfig(nodes=DefaultWorkflow.RAG.nodes)

    def __init__(self, **data):
        super().__init__(**data)
        self.llm_config.set_api_key(force_reset=True)


class ParserConfig(QuivrBaseConfig):
    splitter_config: SplitterConfig = SplitterConfig()
    megaparse_config: MegaparseConfig = MegaparseConfig()


class IngestionConfig(QuivrBaseConfig):
    parser_config: ParserConfig = ParserConfig()


class AssistantConfig(QuivrBaseConfig):
    retrieval_config: RetrievalConfig = RetrievalConfig()
    ingestion_config: IngestionConfig = IngestionConfig()
