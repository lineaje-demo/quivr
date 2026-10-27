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

from quivr_core.base_config import QuivrBaseConfig
from typing import Callable
from langchain_core.tools import BaseTool
from typing import Dict, Any


class ToolsCategory(QuivrBaseConfig):
    name: str
    description: str
    tools: list
    default_tool: str | None = None
    create_tool: Callable

    def __init__(self, **data):
        super().__init__(**data)
        self.name = self.name.lower()


class ToolWrapper:
    def __init__(self, tool: BaseTool, format_input: Callable, format_output: Callable):
        self.tool = tool
        self.format_input = format_input
        self.format_output = format_output


class ToolRegistry:
    def __init__(self):
        self._registry = {}

    def register_tool(self, tool_name: str, create_func: Callable):
        self._registry[tool_name] = create_func

    def create_tool(self, tool_name: str, config: Dict[str, Any]) -> ToolWrapper:
        if tool_name not in self._registry:
            raise ValueError(f"Tool {tool_name} is not supported.")
        # LINEAJE: runtime guardrail checks `config` as it flows from the agent to system, at a security decision (in ToolRegistry.create_tool).
        #   Detected: this statement moves data from the agent to system with no runtime policy check (detection confidence: medium).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_029; sensitive values in `config` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:f1d23665eec048b7fa208365156b6f43ac41ae3a5b68b839c462ca82be88873b'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:f1d23665eec048b7fa208365156b6f43ac41ae3a5b68b839c462ca82be88873b', phase='security_decision', boundary={'source': 'agent_message', 'sink': 'agent_message'}, fail_mode='BLOCK', source_type='agent', destination_type='system', components={'invocation': {'file': 'core/quivr_core/llm_tools/entity.py', 'line': 36, 'function': 'ToolRegistry.create_tool'}, 'file': 'core/quivr_core/llm_tools/entity.py', 'line': 36, 'function': 'create_tool', 'agent_name': 'ToolRegistry', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
        try:
            config = _gr_client.enforce(_gr_site, config, content_type='application/json', variable_name='config', source_file=__file__, before_line=36)
        except _gr_client.GuardrailUnavailableError:
            pass
        return self._registry[tool_name](config)
