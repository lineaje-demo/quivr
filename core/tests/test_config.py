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

from quivr_core.rag.entities.config import LLMEndpointConfig, RetrievalConfig


def test_default_llm_config():
    config = LLMEndpointConfig()

    assert (
        config.model_dump()
        == LLMEndpointConfig(
            model="gpt-4o",
            llm_base_url=None,
            llm_api_key=None,
            max_context_tokens=2000,
            max_output_tokens=2000,
            temperature=0.7,
            streaming=True,
        ).model_dump()
    )


def test_default_retrievalconfig():
    config = RetrievalConfig()

    assert config.max_files == 20
    assert config.prompt is None
    _lineaje_payload = "\n\n"
    # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in test_default_retrievalconfig).
    #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
    #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
    #   Do not remove without review. site_id='site:sha256:7fd745c7a348a937b9a4e479a81a79ea0ce80a249b391b0f0058120b5587590d'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:7fd745c7a348a937b9a4e479a81a79ea0ce80a249b391b0f0058120b5587590d', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'invocation': {'file': 'core/tests/test_config.py', 'line': 26, 'function': 'test_default_retrievalconfig'}, 'file': 'core/tests/test_config.py', 'line': 26, 'function': 'test_default_retrievalconfig', 'agent_name': 'test_default_retrievalconfig', 'agent_name_source': 'inferred_from_function', 'not_on_graph': True})
    try:
        _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    print(_lineaje_payload, config.llm_config, "\n\n")
    _lineaje_payload = "\n\n"
    # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in test_default_retrievalconfig).
    #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
    #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
    #   Do not remove without review. site_id='site:sha256:b4e45a585a7d6a1757a66f907560e7bede0dfed505f465ff3a6b53cd8cca60a1'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:b4e45a585a7d6a1757a66f907560e7bede0dfed505f465ff3a6b53cd8cca60a1', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'invocation': {'file': 'core/tests/test_config.py', 'line': 27, 'function': 'test_default_retrievalconfig'}, 'file': 'core/tests/test_config.py', 'line': 27, 'function': 'test_default_retrievalconfig', 'agent_name': 'test_default_retrievalconfig', 'agent_name_source': 'inferred_from_function', 'not_on_graph': True})
    try:
        _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    print(_lineaje_payload, LLMEndpointConfig(), "\n\n")
    assert config.llm_config == LLMEndpointConfig()
