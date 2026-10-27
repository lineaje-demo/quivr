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

from enum import Enum

import yaml
from pydantic import BaseModel


class ParserType(str, Enum):
    """Parser type enumeration."""

    UNSTRUCTURED = "unstructured"
    LLAMA_PARSER = "llama_parser"
    MEGAPARSE_VISION = "megaparse_vision"


class StrategyEnum(str, Enum):
    """Method to use for the conversion"""

    FAST = "fast"
    AUTO = "auto"
    HI_RES = "hi_res"


class MegaparseBaseConfig(BaseModel):
    @classmethod
    def from_yaml(cls, file_path: str):
        # Load the YAML file
        with open(file_path, "r") as stream:
            # LINEAJE: runtime guardrail checks `stream` as it flows from file storage to the agent (in MegaparseBaseConfig.from_yaml).
            #   Detected: this statement moves data from file storage to the agent with no runtime policy check (detection confidence: medium).
            #   Decision: the Guardrail evaluates AI_APP_SEC_070, AI_DAT_SEC_023, AI_DAT_SEC_024; sensitive values in `stream` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
            #   Do not remove without review. site_id='site:sha256:0d3d581f13550527b7eadfbbff8d7c4d535245da29a6606e02fb61051fc3c1a5'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:0d3d581f13550527b7eadfbbff8d7c4d535245da29a6606e02fb61051fc3c1a5', phase='file_upload', boundary={'source': 'file_upload', 'sink': 'agent_context'}, fail_mode='BLOCK', source_type='file_storage', destination_type='agent', components={'invocation': {'file': 'core/quivr_core/config.py', 'line': 28, 'function': 'MegaparseBaseConfig.from_yaml'}, 'file': 'core/quivr_core/config.py', 'line': 28, 'function': 'from_yaml', 'agent_name': 'MegaparseBaseConfig', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
            try:
                stream = _gr_client.enforce(_gr_site, stream, content_type='application/json')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                raise
            config_data = yaml.safe_load(stream)

        # Instantiate the class using the YAML data
        return cls(**config_data)


class MegaparseConfig(MegaparseBaseConfig):
    method: ParserType = ParserType.UNSTRUCTURED
    strategy: StrategyEnum = StrategyEnum.FAST
    check_table: bool = False
    parsing_instruction: str | None = None
    model_name: str = "gpt-4o"
