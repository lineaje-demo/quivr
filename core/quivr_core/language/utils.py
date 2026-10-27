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

from ftlangdetect import detect
from quivr_core.language.models import Language


def detect_language(text: str, low_memory: bool = True) -> Language:
    detected_lang = detect(text=text, low_memory=low_memory)
    try:
        detected_language = Language(detected_lang["lang"])
    except ValueError:
        return Language.UNKNOWN

    # LINEAJE: runtime guardrail checks `detected_language` as it flows from the agent to the user interface, before it leaves the application (in detect_language).
    #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: high).
    #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `detected_language` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
    #   Do not remove without review. site_id='site:sha256:2eb834d84b66b5dea3146460df3759ec7a53523d8cda9a06a88801d315042aad'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:2eb834d84b66b5dea3146460df3759ec7a53523d8cda9a06a88801d315042aad', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'invocation': {'file': 'core/quivr_core/language/utils.py', 'line': 12, 'function': 'detect_language'}, 'file': 'core/quivr_core/language/utils.py', 'line': 12, 'function': 'detect_language', 'agent_name': 'detect_language', 'agent_name_source': 'inferred_from_function', 'not_on_graph': True})
    try:
        detected_language = _gr_client.enforce(_gr_site, detected_language, content_type='text/plain')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    return detected_language
