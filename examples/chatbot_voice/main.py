# Copyright (c) Lineaje, Inc. All rights reserved.
# gr_check() POSTs to GR_SERVICE_URL+/enforce; fail-open unless GRBlockedError.
class GRBlockedError(Exception):
    def __init__(self, policy_id, reason):
        self.policy_id, self.reason = policy_id, reason
        super().__init__("Guardrail block for policy %r: %s" % (policy_id, reason))

def gr_check(data, source_type, destination_type, tenant_id="", timeout=5.0, **context):
    import json as _j, logging as _lg, os as _os, urllib.error as _ue, urllib.request as _ur
    _log = _lg.getLogger("lineaje.gr_client")
    hop_label = source_type + "->" + destination_type
    # A genuine policy block stops later checks in the same request context only
    # (a contextvar, not process-wide) so one blocked call never breaks the next request.
    _latch = getattr(gr_check, "_latch", None)
    if _latch is None:
        import contextvars as _cv
        _latch = gr_check._latch = _cv.ContextVar("lineaje_gr_blocked", default=None)
    _obs = bool(context.get("observe_only"))  # a log-only call never enforces, so a block neither skips nor sets it
    _prior = None if _obs else _latch.get()
    if _prior:
        _log.warning("gr_client[%s]: skipping POST /enforce — request already blocked (%s)", hop_label, _prior[1])
        try:  # still tell the Guardrail the activity happened (no data, no policy)
            import sys as _s
            _m = _s.modules.get("_lineaje_gr_stub_client")
            if _m is not None and hasattr(_m, "_report_skipped_after_block"):
                _f = getattr(_m.SiteDescriptor, "__dataclass_fields__", {})
                _m._report_skipped_after_block(_m.SiteDescriptor(site_id=context.get("site_id") or "", source_type=source_type, destination_type=destination_type, **{k: context[k] for k in ("components", "interaction_id") if context.get(k) and k in _f}), tenant_id or _os.environ.get("GR_TENANT_ID", ""))
        except Exception:
            pass
        raise GRBlockedError(_prior[0], _prior[1])
    def _blk(o):
        if isinstance(o, dict):
            return any(_blk(o.get(k)) for k in ("skill_path", "skill_file", "path", "file_path", "data", "skill_manifest_path"))
        s = str(o or "")
        b = s.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if b.endswith(".md.blocked"): return True
        try:
            if b in ("skill.md", "skills.md") and _os.path.isfile(str(o) + ".blocked"): return True
        except Exception:
            pass
        return False
    if _blk(data) or _blk(context):
        _log.warning("gr_client[%s]: quarantined skill (*.blocked) — not loaded, GR not called", hop_label)
        _latch.set(("blocked_manifest", "quarantined skill must not be read, downloaded, or loaded"))
        raise GRBlockedError("blocked_manifest", "quarantined skill must not be read, downloaded, or loaded")
    def _stub_client():
        # gr_stub_client.py (shipped next to instrumented files) loads .env, exchanges
        # the refresh token, and re-registers the site on unknown_site /
        # candidate_policies_mismatch — prefer it over the bare POST below.
        import sys as _s, importlib.util as _ilu
        from pathlib import Path as _P
        n = "_lineaje_gr_stub_client"
        if n in _s.modules: return _s.modules[n]
        if getattr(gr_check, "_no_stub_client", False): return None
        try:
            h = _P(__file__).resolve().parent
            c = next((d / "gr_stub_client.py" for d in [h, *h.parents][:8] if (d / "gr_stub_client.py").is_file()), None)
            if c is not None:
                spec = _ilu.spec_from_file_location(n, c)
                _s.modules[n] = m = _ilu.module_from_spec(spec)
                spec.loader.exec_module(m)
                if hasattr(m, "check") and hasattr(m, "SiteDescriptor"): return m
                _s.modules.pop(n, None)
        except Exception as exc:
            _s.modules.pop(n, None)
            _log.warning("gr_client[%s]: gr_stub_client.py not loadable (%s) — using inline client", hop_label, exc)
        gr_check._no_stub_client = True
        return None
    def _block(policy_id, reason):
        _log.warning("gr_client[%s]: BLOCKED by policy=%s — %s", hop_label, policy_id, reason)
        if _os.environ.get("GR_BLOCK_MODE", "enforce").lower() == "audit":
            return data
        if not _obs: _latch.set((policy_id, reason))
        raise GRBlockedError(policy_id, reason)
    tid = tenant_id or _os.environ.get("GR_TENANT_ID", "")
    _sc = _stub_client()
    if _sc is not None:
        try:
            _cp = [p if isinstance(p, dict) else {"policy_id": p} for p in (context.get("candidate_policies") or [])]
            _kw = {k: context[k] for k in ("components", "interaction_id", "observe_only") if context.get(k) and k in getattr(_sc.SiteDescriptor, "__dataclass_fields__", {})}
            _site = _sc.SiteDescriptor(site_id=context.get("site_id") or "", candidate_policies=_cp, fail_mode="BLOCK", source_type=source_type, destination_type=destination_type, **_kw)
            _d = _sc.check(_site, data, tenant_id=tid, timeout=timeout)
        except Exception as exc:
            _log.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
            return data
        if _d.blocked and not getattr(_d, "infra_failure", False):
            _acts = _d.actions_applied or []
            _pid = (_acts[0].get("policy_id") if _acts and isinstance(_acts[0], dict) else "") or "unknown"
            return _block(_pid, _d.warning or "Request denied by policy enforcement.")
        if _d.blocked:
            _log.warning("gr_client[%s]: GR service unavailable (%s) — failing open", hop_label, _d.warning)
            return data
        return data if _d.payload is None else _d.payload
    url = _os.environ.get("GR_SERVICE_URL", "")
    if not url:
        return data
    # Refresh token first: the GR service exchanges it for the access JWT it
    # calls the Data Service policy API with; a lineaje_pat_ PAT only
    # identifies the caller and cannot be exchanged.
    bearer = _os.environ.get("GR_BEARER_TOKEN") or _os.environ.get("LINEAJE_REFRESH_TOKEN") or _os.environ.get("LINEAJE_PAT_TOKEN") or _os.environ.get("LINEAJE_PAT", "")
    params_key = "out_params" if destination_type == "agent" else "in_params"
    def _gr_js(o):
        # JSON form of non-JSON payloads (LangChain Document, pydantic models, ...).
        if hasattr(o, "page_content"):
            return {"page_content": o.page_content, "metadata": getattr(o, "metadata", None) or {}}
        for _m in ("model_dump", "dict", "to_dict"):
            _f = getattr(o, _m, None)
            if callable(_f):
                try:
                    return _f()
                except Exception:
                    pass
        if isinstance(o, (set, tuple)):
            return list(o)
        return str(o)
    def _gr_back(orig, new):
        # Map the (possibly masked) JSON back onto the caller's own objects.
        if new == _j.loads(_j.dumps(orig, default=_gr_js)):
            return orig
        if isinstance(orig, (list, tuple)) and isinstance(new, list) and len(orig) == len(new):
            _out = [_gr_back(a, b) for a, b in zip(orig, new)]
            return tuple(_out) if isinstance(orig, tuple) else _out
        if hasattr(orig, "page_content") and isinstance(new, dict) and "page_content" in new:
            import copy as _cp
            _c = _cp.copy(orig)
            _c.page_content = new["page_content"]
            if isinstance(new.get("metadata"), dict) and hasattr(_c, "metadata"):
                _c.metadata = new["metadata"]
            return _c
        if orig is None or isinstance(orig, (str, int, float, bool, dict, list)):
            return new
        _log.warning("gr_client[%s]: masked result cannot be applied to %s — returning original", hop_label, type(orig).__name__)
        return orig
    _base = url.rstrip("/")
    if _base.lower().endswith("/enforce"): _base = _base[: -len("/enforce")].rstrip("/")
    def _post(body):
        headers = {"Content-Type": "application/json"}
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        req = _ur.Request(_base + "/enforce", data=_j.dumps(body, default=_gr_js).encode(), headers=headers, method="POST")
        with _ur.urlopen(req, timeout=timeout) as resp:
            return _j.loads(resp.read())
    try:
        _sent = _j.loads(_j.dumps(data, default=_gr_js))
        body = {"source_type": source_type, "destination_type": destination_type, params_key: {"data": _sent}}
        for _k, _v in context.items():
            if _v:
                body[_k] = _v
        if tid:
            body["tenant_id"] = tid
    except Exception as exc:
        _log.warning("gr_client[%s]: payload not serializable (%s) — failing open", hop_label, exc)
        return data
    result = None
    for _attempt in (0, 1):
        try:
            result = _post(body)
            break
        except Exception as exc:
            if isinstance(exc, _ue.HTTPError) and exc.code == 403:
                try: detail = _j.loads(exc.read()).get("detail", {})
                except Exception: detail = {}
                if not isinstance(detail, dict): detail = {"message": str(detail)}
                blocked_by = detail.get("blocked_by") or []
                if blocked_by or detail.get("error") == "request_blocked":
                    _pid = (blocked_by[0].get("policy_id") if isinstance(blocked_by[0], dict) else "") if blocked_by else ""
                    return _block(_pid or "unknown", detail.get("message", "Request denied by policy enforcement."))
                if _attempt == 0 and (body.get("site_id") or body.get("candidate_policies")):
                    # unknown_site / candidate_policies_mismatch: a site-manifest
                    # problem, not a policy verdict — re-evaluate without site scoping.
                    _log.warning("gr_client[%s]: %s — retrying without site_id", hop_label, detail.get("error") or detail.get("message") or "403")
                    body = {k: v for k, v in body.items() if k not in ("site_id", "candidate_policies")}
                    continue
            _log.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
            return data
    if not isinstance(result, dict):
        return data
    if result.get("status") == "escalate":
        _log.warning("gr_client[%s]: escalation flagged — passing through for human review", hop_label)
    if not isinstance(result.get("result"), dict) or "data" not in result["result"]:
        return data
    return _gr_back(data, result["result"]["data"])
import tempfile
import os
import chainlit as cl
from quivr_core import Brain
from quivr_core.rag.entities.config import RetrievalConfig
from openai import AsyncOpenAI
from chainlit.element import Element

from io import BytesIO


@cl.on_chat_start
async def on_chat_start():
    files = None

    # Wait for the user to upload a file
    while files is None:
        files = await cl.AskFileMessage(
            content="Please upload a text .txt file to begin!",
            accept=["text/plain"],
            max_size_mb=20,
            timeout=180,
        ).send()

    file = files[0]

    msg = cl.Message(content=f"Processing `{file.name}`...")
    try:
        import asyncio as _gr_asyncio
        await _gr_asyncio.to_thread(gr_check, {"activity": "agent_to_ui"}, "agent", "user_interface", observe_only=True, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], site_id='site:sha256:52280b0f611dee50ca42179bd727f7e3b7632e9b1f34afc50f9c5a28f5872559', components={'identity': {'app': {'name': 'quivr', 'version': 'main', 'purl': 'pkg:github/lineaje-demo/quivr@main?commit-id=cb72bb5e125b56bc68c0a6ef2b473794a944ef53&commit-time=2026-09-27%2000%3A34%3A20%20%2B0000&build_file=core/pyproject.toml&repo_strategy=single-repo'}}, 'invocation': {'file': 'examples/chatbot_voice/main.py', 'line': 28, 'function': 'on_chat_start'}, 'file': 'examples/chatbot_voice/main.py', 'line': 28, 'function': 'on_chat_start', 'agent_name': 'on_chat_start', 'agent_name_source': 'inferred_from_function', 'call_target': 'msg.send'})
    except Exception:
        pass
    await msg.send()

    with open(file.path, "r", encoding="utf-8") as f:
        text = f.read()
        try:
            import asyncio as _gr_asyncio
            text = await _gr_asyncio.to_thread(gr_check, text, "file_storage", "agent", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_VULN_SEC_005', 'AI_AGENT_ACTIVITY_LOG'], site_id='site:sha256:5dcb48adf715bd1cb5edf530b217e9d36dc184b1c16c01cf47b3ad3cf826b551', components={'identity': {'app': {'name': 'quivr', 'version': 'main', 'purl': 'pkg:github/lineaje-demo/quivr@main?commit-id=cb72bb5e125b56bc68c0a6ef2b473794a944ef53&commit-time=2026-09-27%2000%3A34%3A20%20%2B0000&build_file=core/pyproject.toml&repo_strategy=single-repo'}}, 'invocation': {'file': 'examples/chatbot_voice/main.py', 'line': 31, 'function': 'on_chat_start'}, 'file': 'examples/chatbot_voice/main.py', 'line': 31, 'function': 'on_chat_start', 'agent_name': 'on_chat_start', 'agent_name_source': 'inferred_from_function', 'call_target': 'f.read'})
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            text = text
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'file_storage->agent' — passing data through unchecked")

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=file.name, delete=False
    ) as temp_file:
        try:
            import asyncio as _gr_asyncio
            text = await _gr_asyncio.to_thread(gr_check, text, "agent", "file", candidate_policies=['AI_DAT_SEC_025', 'AI_AGENT_ACTIVITY_LOG'], site_id='site:sha256:0e739d447d774db8760c09bde05d45eee5171316b3c3533d18ed42a01865b2df', components={'identity': {'app': {'name': 'quivr', 'version': 'main', 'purl': 'pkg:github/lineaje-demo/quivr@main?commit-id=cb72bb5e125b56bc68c0a6ef2b473794a944ef53&commit-time=2026-09-27%2000%3A34%3A20%20%2B0000&build_file=core/pyproject.toml&repo_strategy=single-repo'}}, 'invocation': {'file': '/tmp/lineaje-efs/vdna_6dXylGIYVjVO6Lkf/SPDXRef-DOCUMENT-vdna_6dXylGIYVjVO6Lkf-2133358-2135906/20261015_220147_830758_8c45f16937d5/source_code/examples/chatbot_voice/main.py', 'line': 36, 'function': 'on_chat_start'}, 'file': '/tmp/lineaje-efs/vdna_6dXylGIYVjVO6Lkf/SPDXRef-DOCUMENT-vdna_6dXylGIYVjVO6Lkf-2133358-2135906/20261015_220147_830758_8c45f16937d5/source_code/examples/chatbot_voice/main.py', 'line': 36, 'function': 'on_chat_start', 'agent_name': 'on_chat_start', 'agent_name_source': 'inferred_from_function', 'call_target': 'temp_file.write'})
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            text = text
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->file' — passing data through unchecked")
        temp_file.write(text)
        temp_file.flush()
        temp_file_path = temp_file.name

    brain = Brain.from_files(name="user_brain", file_paths=[temp_file_path])
    try:
        import asyncio as _gr_asyncio
        brain = await _gr_asyncio.to_thread(gr_check, brain, "file_storage", "agent", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_VULN_SEC_005', 'AI_AGENT_ACTIVITY_LOG'], site_id='site:sha256:1e30d90a8737ce3e457dcadfb0042a85270157e8c10c0251d4d5acb5ef9feca8', components={'identity': {'app': {'name': 'quivr', 'version': 'main', 'purl': 'pkg:github/lineaje-demo/quivr@main?commit-id=cb72bb5e125b56bc68c0a6ef2b473794a944ef53&commit-time=2026-09-27%2000%3A34%3A20%20%2B0000&build_file=core/pyproject.toml&repo_strategy=single-repo'}}, 'invocation': {'file': '/tmp/lineaje-efs/vdna_6dXylGIYVjVO6Lkf/SPDXRef-DOCUMENT-vdna_6dXylGIYVjVO6Lkf-2133358-2135906/20261015_220147_830758_8c45f16937d5/source_code/examples/chatbot_voice/main.py', 'line': 40, 'function': 'on_chat_start'}, 'file': '/tmp/lineaje-efs/vdna_6dXylGIYVjVO6Lkf/SPDXRef-DOCUMENT-vdna_6dXylGIYVjVO6Lkf-2133358-2135906/20261015_220147_830758_8c45f16937d5/source_code/examples/chatbot_voice/main.py', 'line': 40, 'function': 'on_chat_start', 'agent_name': 'on_chat_start', 'agent_name_source': 'inferred_from_function', 'call_target': 'Brain.from_files'})
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        brain = brain
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'file_storage->agent' — passing data through unchecked")

    # Store the file path in the session
    cl.user_session.set("file_path", temp_file_path)

    # Let the user know that the system is ready
    msg.content = f"Processing `{file.name}` done. You can now ask questions!"
    try:
        import asyncio as _gr_asyncio
        await _gr_asyncio.to_thread(gr_check, {"activity": "agent_to_ui"}, "agent", "user_interface", observe_only=True, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], site_id='site:sha256:8496b2d5bed0d5874cc85f6fd51abdf11e632ad38fec9ff46c0130d229fee747', components={'identity': {'app': {'name': 'quivr', 'version': 'main', 'purl': 'pkg:github/lineaje-demo/quivr@main?commit-id=cb72bb5e125b56bc68c0a6ef2b473794a944ef53&commit-time=2026-09-27%2000%3A34%3A20%20%2B0000&build_file=core/pyproject.toml&repo_strategy=single-repo'}}, 'invocation': {'file': 'examples/chatbot_voice/main.py', 'line': 47, 'function': 'on_chat_start'}, 'file': 'examples/chatbot_voice/main.py', 'line': 47, 'function': 'on_chat_start', 'agent_name': 'on_chat_start', 'agent_name_source': 'inferred_from_function', 'call_target': 'msg.update'})
    except Exception:
        pass
    await msg.update()

    cl.user_session.set("brain", brain)


@cl.on_message
async def main(message: cl.Message):

    try:
        import asyncio as _gr_asyncio
        await _gr_asyncio.to_thread(gr_check, {"activity": "ui_to_agent"}, "user_interface", "agent", observe_only=True, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], site_id='site:sha256:cddc7efd43b077742283fb6dcc6f3777630bb8866394ddb459ddd1d6bf5f2be3', components={'identity': {'app': {'name': 'quivr', 'version': 'main', 'purl': 'pkg:github/lineaje-demo/quivr@main?commit-id=cb72bb5e125b56bc68c0a6ef2b473794a944ef53&commit-time=2026-09-27%2000%3A34%3A20%20%2B0000&build_file=core/pyproject.toml&repo_strategy=single-repo'}}, 'invocation': {'file': 'examples/chatbot_voice/main.py', 'line': 55, 'function': 'main'}, 'file': 'examples/chatbot_voice/main.py', 'line': 55, 'function': 'main', 'agent_name': 'main', 'agent_name_source': 'inferred_from_function', 'call_target': 'cl.TaskList'})
    except Exception:
        pass
    task_list = cl.TaskList(name="State")
    task_list.status = "Running..."

    think = cl.Task(title="Thinking", status=cl.TaskStatus.RUNNING)
    await task_list.add_task(think)

    tts = cl.Task(title="Text to speech")
    await task_list.add_task(tts)

    await task_list.send()

    brain = cl.user_session.get("brain")  # type: Brain
    path_config = "basic_rag_workflow.yaml"
    retrieval_config = RetrievalConfig.from_yaml(path_config)

    if brain is None:
        await cl.Message(content="Please upload a file first.").send()
        return

    # Prepare the message for streaming
    msg = cl.Message(content="", elements=[], author="Quivr", type="assistant_message")
    try:
        import asyncio as _gr_asyncio
        await _gr_asyncio.to_thread(gr_check, {"activity": "agent_to_ui"}, "agent", "user_interface", observe_only=True, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], site_id='site:sha256:b4f505a126ee0cf2f2c2f5f56312299141d6a2edb5b92aa51b8733866bfbb20b', components={'identity': {'app': {'name': 'quivr', 'version': 'main', 'purl': 'pkg:github/lineaje-demo/quivr@main?commit-id=cb72bb5e125b56bc68c0a6ef2b473794a944ef53&commit-time=2026-09-27%2000%3A34%3A20%20%2B0000&build_file=core/pyproject.toml&repo_strategy=single-repo'}}, 'invocation': {'file': 'examples/chatbot_voice/main.py', 'line': 76, 'function': 'main'}, 'file': 'examples/chatbot_voice/main.py', 'line': 76, 'function': 'main', 'agent_name': 'main', 'agent_name_source': 'inferred_from_function', 'call_target': 'msg.send'})
    except Exception:
        pass
    await msg.send()

    saved_sources = set()
    saved_sources_complete = []
    elements = []

    # Use the ask_stream method for streaming responses
    _lineaje_payload = message.content
    try:
        import asyncio as _gr_asyncio
        _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "llm", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005', 'AI_AGENT_ACTIVITY_LOG'], site_id='site:sha256:798859f9d953004e7ec3e9096f20a9c8b56cdd6ff6f9ce2df6bf07f0b0038322', components={'destination': {'entity_type': 'llm', 'name': 'whisper-1', 'version': '', 'provider': 'openai'}, 'identity': {'app': {'name': 'quivr', 'version': 'main', 'purl': 'pkg:github/lineaje-demo/quivr@main?commit-id=cb72bb5e125b56bc68c0a6ef2b473794a944ef53&commit-time=2026-09-27%2000%3A34%3A20%20%2B0000&build_file=core/pyproject.toml&repo_strategy=single-repo'}, 'destination': {'entity_type': 'aimodel', 'name': 'Whisper', 'version': '1', 'purl': 'pkg:aimodel/Whisper@1'}}, 'invocation': {'file': '/tmp/lineaje-efs/vdna_6dXylGIYVjVO6Lkf/SPDXRef-DOCUMENT-vdna_6dXylGIYVjVO6Lkf-2133358-2135906/20261015_220147_830758_8c45f16937d5/source_code/examples/chatbot_voice/main.py', 'line': 83, 'function': 'main'}, 'file': '/tmp/lineaje-efs/vdna_6dXylGIYVjVO6Lkf/SPDXRef-DOCUMENT-vdna_6dXylGIYVjVO6Lkf-2133358-2135906/20261015_220147_830758_8c45f16937d5/source_code/examples/chatbot_voice/main.py', 'line': 83, 'function': 'main', 'agent_name': 'main', 'agent_name_source': 'inferred_from_function', 'call_target': 'brain.ask_streaming'})
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        _lineaje_payload = _lineaje_payload
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->llm' — passing data through unchecked")
    async for chunk in brain.ask_streaming(message.content, retrieval_config=retrieval_config):
        try:
            import asyncio as _gr_asyncio
            await _gr_asyncio.to_thread(gr_check, {"activity": "agent_to_ui"}, "agent", "user_interface", observe_only=True, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], site_id='site:sha256:b4f505a126ee0cf2f2c2f5f56312299141d6a2edb5b92aa51b8733866bfbb20b', components={'identity': {'app': {'name': 'quivr', 'version': 'main', 'purl': 'pkg:github/lineaje-demo/quivr@main?commit-id=cb72bb5e125b56bc68c0a6ef2b473794a944ef53&commit-time=2026-09-27%2000%3A34%3A20%20%2B0000&build_file=core/pyproject.toml&repo_strategy=single-repo'}}, 'invocation': {'file': 'examples/chatbot_voice/main.py', 'line': 84, 'function': 'main'}, 'file': 'examples/chatbot_voice/main.py', 'line': 84, 'function': 'main', 'agent_name': 'main', 'agent_name_source': 'inferred_from_function', 'call_target': 'msg.stream_token'})
        except Exception:
            pass
        _lineaje_payload = chunk.answer
        try:
            import asyncio as _gr_asyncio
            _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005', 'AI_AGENT_ACTIVITY_LOG'], site_id='site:sha256:4e8a8dba98ed9ecc8d6793fce785e9ec0adca53737e579e949a35fe20f0c4f4f', components={'identity': {'app': {'name': 'quivr', 'version': 'main', 'purl': 'pkg:github/lineaje-demo/quivr@main?commit-id=cb72bb5e125b56bc68c0a6ef2b473794a944ef53&commit-time=2026-09-27%2000%3A34%3A20%20%2B0000&build_file=core/pyproject.toml&repo_strategy=single-repo'}}, 'invocation': {'file': 'examples/chatbot_voice/main.py', 'line': 84, 'function': 'main'}, 'file': 'examples/chatbot_voice/main.py', 'line': 84, 'function': 'main', 'agent_name': 'main', 'agent_name_source': 'inferred_from_function', 'call_target': 'msg.stream_token'})
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        await msg.stream_token(chunk.answer)
        for source in chunk.metadata.sources:
            if source.page_content not in saved_sources:
                saved_sources.add(source.page_content)
                saved_sources_complete.append(source)
                try:
                    import asyncio as _gr_asyncio
                    source = await _gr_asyncio.to_thread(gr_check, source, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005', 'AI_AGENT_ACTIVITY_LOG'], site_id='site:sha256:22f161ed56d256f46ba6b12c58f23d6595554b68757ad08ea3edb162e5c592eb', components={'identity': {'app': {'name': 'quivr', 'version': 'main', 'purl': 'pkg:github/lineaje-demo/quivr@main?commit-id=cb72bb5e125b56bc68c0a6ef2b473794a944ef53&commit-time=2026-09-27%2000%3A34%3A20%20%2B0000&build_file=core/pyproject.toml&repo_strategy=single-repo'}}, 'invocation': {'file': 'examples/chatbot_voice/main.py', 'line': 89, 'function': 'main'}, 'file': 'examples/chatbot_voice/main.py', 'line': 89, 'function': 'main', 'agent_name': 'main', 'agent_name_source': 'inferred_from_function', 'call_target': 'print'})
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError": raise
                    source = source
                    __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
                print(source)
                _lineaje_content = source.page_content
                try:
                    import asyncio as _gr_asyncio
                    _lineaje_content = await _gr_asyncio.to_thread(gr_check, _lineaje_content, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005', 'AI_AGENT_ACTIVITY_LOG'], site_id='site:sha256:48d5f4d6f0d4ae4562d2349c86b66daec93f1a9320211091d26e25d699941cf0', components={'identity': {'app': {'name': 'quivr', 'version': 'main', 'purl': 'pkg:github/lineaje-demo/quivr@main?commit-id=cb72bb5e125b56bc68c0a6ef2b473794a944ef53&commit-time=2026-09-27%2000%3A34%3A20%20%2B0000&build_file=core/pyproject.toml&repo_strategy=single-repo'}}, 'invocation': {'file': 'examples/chatbot_voice/main.py', 'line': 90, 'function': 'main'}, 'file': 'examples/chatbot_voice/main.py', 'line': 90, 'function': 'main', 'agent_name': 'main', 'agent_name_source': 'inferred_from_function', 'call_target': 'cl.Text'})
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError": raise
                    _lineaje_content = _lineaje_content
                    __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
                elements.append(cl.Text(name=source.metadata["original_file_name"], content=source.page_content, display="side"))
    try:
        import asyncio as _gr_asyncio
        await _gr_asyncio.to_thread(gr_check, {"activity": "llm_to_agent"}, "llm", "agent", observe_only=True, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], site_id='site:sha256:dc164d98f27c80927e47436db75e4f4049f7cb6050a8bb8c49c6f24eea1c24ef', components={'destination': {'entity_type': 'llm', 'name': 'whisper-1', 'version': '', 'provider': 'openai'}, 'identity': {'app': {'name': 'quivr', 'version': 'main', 'purl': 'pkg:github/lineaje-demo/quivr@main?commit-id=cb72bb5e125b56bc68c0a6ef2b473794a944ef53&commit-time=2026-09-27%2000%3A34%3A20%20%2B0000&build_file=core/pyproject.toml&repo_strategy=single-repo'}, 'destination': {'entity_type': 'aimodel', 'name': 'Whisper', 'version': '1', 'purl': 'pkg:aimodel/Whisper@1'}}, 'invocation': {'file': 'examples/chatbot_voice/main.py', 'line': 83, 'function': 'main'}, 'file': 'examples/chatbot_voice/main.py', 'line': 83, 'function': 'main', 'agent_name': 'main', 'agent_name_source': 'inferred_from_function', 'call_target': 'brain.ask_streaming'}, interaction_id=locals().get('_lineaje_interaction_id'))
    except Exception:
        pass
    
    think.status = cl.TaskStatus.DONE
    tts.status = cl.TaskStatus.RUNNING
    await task_list.update()
    
    audio_file = await text_to_speech(msg.content)
    try:
        import asyncio as _gr_asyncio
        audio_file = await _gr_asyncio.to_thread(gr_check, audio_file, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005', 'AI_AGENT_ACTIVITY_LOG'], site_id='site:sha256:cee5da66cbc65c1fe8cf556ca4ee1333e5838cc0b90efb93b3f3cd571c828f75', components={'identity': {'app': {'name': 'quivr', 'version': 'main', 'purl': 'pkg:github/lineaje-demo/quivr@main?commit-id=cb72bb5e125b56bc68c0a6ef2b473794a944ef53&commit-time=2026-09-27%2000%3A34%3A20%20%2B0000&build_file=core/pyproject.toml&repo_strategy=single-repo'}}, 'invocation': {'file': 'examples/chatbot_voice/main.py', 'line': 97, 'function': 'main'}, 'file': 'examples/chatbot_voice/main.py', 'line': 97, 'function': 'main', 'agent_name': 'main', 'agent_name_source': 'inferred_from_function', 'call_target': 'cl.Audio'})
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        audio_file = audio_file
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
    elements.append(cl.Audio(content=audio_file, auto_play=True, mime="audio/mpeg"))

    sources = ""
    for source in saved_sources_complete:
        sources += f"- {source.metadata['original_file_name']}\n"
    msg.elements = elements
    msg.content = msg.content + f"\n\nSources:\n{sources}"
    try:
        import asyncio as _gr_asyncio
        await _gr_asyncio.to_thread(gr_check, {"activity": "agent_to_ui"}, "agent", "user_interface", observe_only=True, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], site_id='site:sha256:833c5289f9126dbe7dc55fac0d4845d44ad5d549dd0327fcd16eba4963f57e6e', components={'identity': {'app': {'name': 'quivr', 'version': 'main', 'purl': 'pkg:github/lineaje-demo/quivr@main?commit-id=cb72bb5e125b56bc68c0a6ef2b473794a944ef53&commit-time=2026-09-27%2000%3A34%3A20%20%2B0000&build_file=core/pyproject.toml&repo_strategy=single-repo'}}, 'invocation': {'file': 'examples/chatbot_voice/main.py', 'line': 104, 'function': 'main'}, 'file': 'examples/chatbot_voice/main.py', 'line': 104, 'function': 'main', 'agent_name': 'main', 'agent_name_source': 'inferred_from_function', 'call_target': 'msg.update'})
    except Exception:
        pass
    await msg.update()

    tts.status = cl.TaskStatus.DONE
    task_list.status = "Done"
    await task_list.update()
    await cl.sleep(1)
    await task_list.remove()

async_openai_client = AsyncOpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

@cl.step(type="tool", name="Speech to text")
async def speech_to_text(audio_file):
    try:
        import asyncio as _gr_asyncio
        await _gr_asyncio.to_thread(gr_check, {"activity": "agent_to_llm"}, "agent", "llm", observe_only=True, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], site_id='site:sha256:bb03ffc6e114833c0026d46159936c3c2e0cce678472a394bb9c8ee1e2b9baa5', components={'destination': {'entity_type': 'llm', 'name': 'whisper-1', 'version': '', 'provider': 'openai'}, 'identity': {'app': {'name': 'quivr', 'version': 'main', 'purl': 'pkg:github/lineaje-demo/quivr@main?commit-id=cb72bb5e125b56bc68c0a6ef2b473794a944ef53&commit-time=2026-09-27%2000%3A34%3A20%20%2B0000&build_file=core/pyproject.toml&repo_strategy=single-repo'}, 'destination': {'entity_type': 'aimodel', 'name': 'Whisper', 'version': '1', 'purl': 'pkg:aimodel/Whisper@1'}}, 'invocation': {'file': 'examples/chatbot_voice/main.py', 'line': 116, 'function': 'speech_to_text'}, 'file': 'examples/chatbot_voice/main.py', 'line': 116, 'function': 'speech_to_text', 'agent_name': 'speech_to_text', 'agent_name_source': 'inferred_from_function', 'call_target': 'async_openai_client.audio.transcriptions.create', 'model': 'whisper-1'})
    except Exception:
        pass
    response = await async_openai_client.audio.transcriptions.create(
        model="whisper-1", file=audio_file
    )

    try:
        import asyncio as _gr_asyncio
        await _gr_asyncio.to_thread(gr_check, {"activity": "data_outbound"}, "agent", "external", observe_only=True, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], site_id='site:sha256:29757472e981a949829c51c1ac91ab0c9dac697a17e265114bdf4549301c21ce', components={'identity': {'app': {'name': 'quivr', 'version': 'main', 'purl': 'pkg:github/lineaje-demo/quivr@main?commit-id=cb72bb5e125b56bc68c0a6ef2b473794a944ef53&commit-time=2026-09-27%2000%3A34%3A20%20%2B0000&build_file=core/pyproject.toml&repo_strategy=single-repo'}}, 'invocation': {'file': 'examples/chatbot_voice/main.py', 'line': 120, 'function': 'speech_to_text'}, 'file': 'examples/chatbot_voice/main.py', 'line': 120, 'function': 'speech_to_text', 'agent_name': 'speech_to_text', 'agent_name_source': 'inferred_from_function', 'site_kind': 'return'})
    except Exception:
        pass
    return response.text

@cl.step(type="tool", name="Text to speech")
async def text_to_speech(text):
    try:
        import asyncio as _gr_asyncio
        text = await _gr_asyncio.to_thread(gr_check, text, "agent", "llm", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005', 'AI_AGENT_ACTIVITY_LOG'], site_id='site:sha256:07809ccd6fa42d122d87893b0572b0273341b71b2841a420d4c21b3a72608c0f', components={'destination': {'entity_type': 'llm', 'name': 'whisper-1', 'version': '', 'provider': 'openai'}, 'identity': {'app': {'name': 'quivr', 'version': 'main', 'purl': 'pkg:github/lineaje-demo/quivr@main?commit-id=cb72bb5e125b56bc68c0a6ef2b473794a944ef53&commit-time=2026-09-27%2000%3A34%3A20%20%2B0000&build_file=core/pyproject.toml&repo_strategy=single-repo'}, 'destination': {'entity_type': 'aimodel', 'name': 'Whisper', 'version': '1', 'purl': 'pkg:aimodel/Whisper@1'}}, 'invocation': {'file': '/tmp/lineaje-efs/vdna_6dXylGIYVjVO6Lkf/SPDXRef-DOCUMENT-vdna_6dXylGIYVjVO6Lkf-2133358-2135906/20261015_220147_830758_8c45f16937d5/source_code/examples/chatbot_voice/main.py', 'line': 124, 'function': 'text_to_speech'}, 'file': '/tmp/lineaje-efs/vdna_6dXylGIYVjVO6Lkf/SPDXRef-DOCUMENT-vdna_6dXylGIYVjVO6Lkf-2133358-2135906/20261015_220147_830758_8c45f16937d5/source_code/examples/chatbot_voice/main.py', 'line': 124, 'function': 'text_to_speech', 'agent_name': 'text_to_speech', 'agent_name_source': 'inferred_from_function', 'call_target': 'async_openai_client.audio.speech.create', 'model': 'tts-1'})
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        text = text
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->llm' — passing data through unchecked")
    response = await async_openai_client.audio.speech.create(
        model="tts-1", voice="alloy", input=text
    )
    try:
        import asyncio as _gr_asyncio
        await _gr_asyncio.to_thread(gr_check, {"activity": "llm_to_agent"}, "llm", "agent", observe_only=True, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], site_id='site:sha256:6f44cd4ba705092240290236c40288e69288256066aa4d147bb9703c5d291073', components={'destination': {'entity_type': 'llm', 'name': 'whisper-1', 'version': '', 'provider': 'openai'}, 'identity': {'app': {'name': 'quivr', 'version': 'main', 'purl': 'pkg:github/lineaje-demo/quivr@main?commit-id=cb72bb5e125b56bc68c0a6ef2b473794a944ef53&commit-time=2026-09-27%2000%3A34%3A20%20%2B0000&build_file=core/pyproject.toml&repo_strategy=single-repo'}, 'destination': {'entity_type': 'aimodel', 'name': 'Whisper', 'version': '1', 'purl': 'pkg:aimodel/Whisper@1'}}, 'invocation': {'file': 'examples/chatbot_voice/main.py', 'line': 124, 'function': 'text_to_speech'}, 'file': 'examples/chatbot_voice/main.py', 'line': 124, 'function': 'text_to_speech', 'agent_name': 'text_to_speech', 'agent_name_source': 'inferred_from_function', 'call_target': 'async_openai_client.audio.speech.create'}, interaction_id=locals().get('_lineaje_interaction_id'))
    except Exception:
        pass

    try:
        import asyncio as _gr_asyncio
        await _gr_asyncio.to_thread(gr_check, {"activity": "data_outbound"}, "agent", "external", observe_only=True, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], site_id='site:sha256:b6c56923d0a7efa40a23768ad46e916120dad68a59c1e6996bd879d755731a16', components={'identity': {'app': {'name': 'quivr', 'version': 'main', 'purl': 'pkg:github/lineaje-demo/quivr@main?commit-id=cb72bb5e125b56bc68c0a6ef2b473794a944ef53&commit-time=2026-09-27%2000%3A34%3A20%20%2B0000&build_file=core/pyproject.toml&repo_strategy=single-repo'}}, 'invocation': {'file': 'examples/chatbot_voice/main.py', 'line': 128, 'function': 'text_to_speech'}, 'file': 'examples/chatbot_voice/main.py', 'line': 128, 'function': 'text_to_speech', 'agent_name': 'text_to_speech', 'agent_name_source': 'inferred_from_function', 'site_kind': 'return'})
    except Exception:
        pass
    return response.content


@cl.on_audio_chunk
async def on_audio_chunk(chunk: cl.AudioChunk):
    if chunk.isStart:
        buffer = BytesIO()
        # This is required for whisper to recognize the file type
        buffer.name = f"input_audio.{chunk.mimeType.split('/')[1]}"
        # Initialize the session for a new audio stream
        cl.user_session.set("audio_buffer", buffer)
        cl.user_session.set("audio_mime_type", chunk.mimeType)

    # Write the chunks to a buffer and transcribe the whole audio at the end
    cl.user_session.get("audio_buffer").write(chunk.data)


@cl.on_audio_end
async def on_audio_end(elements: list[Element]):
    # Get the audio buffer from the session
    task_list = cl.TaskList(name="State")
    task_list.status = "Running..."

    stt = cl.Task(title="Speech to text", status=cl.TaskStatus.RUNNING)
    await task_list.add_task(stt)

    await task_list.send()

    audio_buffer: BytesIO = cl.user_session.get("audio_buffer")
    audio_buffer.seek(0)  # Move the file pointer to the beginning
    audio_file = audio_buffer.read()
    audio_mime_type: str = cl.user_session.get("audio_mime_type")

    try:
        import asyncio as _gr_asyncio
        audio_file = await _gr_asyncio.to_thread(gr_check, audio_file, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005', 'AI_AGENT_ACTIVITY_LOG'], site_id='site:sha256:2805003565327a138a7c08f472b57293d7f69f58a5ad50827a44127dd508043d', components={'identity': {'app': {'name': 'quivr', 'version': 'main', 'purl': 'pkg:github/lineaje-demo/quivr@main?commit-id=cb72bb5e125b56bc68c0a6ef2b473794a944ef53&commit-time=2026-09-27%2000%3A34%3A20%20%2B0000&build_file=core/pyproject.toml&repo_strategy=single-repo'}}, 'invocation': {'file': 'examples/chatbot_voice/main.py', 'line': 161, 'function': 'on_audio_end'}, 'file': 'examples/chatbot_voice/main.py', 'line': 161, 'function': 'on_audio_end', 'agent_name': 'on_audio_end', 'agent_name_source': 'inferred_from_function', 'call_target': 'cl.Audio'})
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        audio_file = audio_file
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
    input_audio_el = cl.Audio(
        mime=audio_mime_type, content=audio_file, name=audio_buffer.name
    )
    try:
        import asyncio as _gr_asyncio
        await _gr_asyncio.to_thread(gr_check, {"activity": "agent_to_ui"}, "agent", "user_interface", observe_only=True, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], site_id='site:sha256:9c4e4ee3002e065f7d70fb3350c2f21ef30906185696fb711bbf3674284a2e42', components={'identity': {'app': {'name': 'quivr', 'version': 'main', 'purl': 'pkg:github/lineaje-demo/quivr@main?commit-id=cb72bb5e125b56bc68c0a6ef2b473794a944ef53&commit-time=2026-09-27%2000%3A34%3A20%20%2B0000&build_file=core/pyproject.toml&repo_strategy=single-repo'}}, 'invocation': {'file': 'examples/chatbot_voice/main.py', 'line': 164, 'function': 'on_audio_end'}, 'file': 'examples/chatbot_voice/main.py', 'line': 164, 'function': 'on_audio_end', 'agent_name': 'on_audio_end', 'agent_name_source': 'inferred_from_function', 'call_target': "cl.Message(author='You', type='user_message', content='', elements=[input_audio_"})
    except Exception:
        pass
    await cl.Message(
        author="You",
        type="user_message",
        content="",
        elements=[input_audio_el, *elements],
    ).send()

    whisper_input = (audio_buffer.name, audio_file, audio_mime_type)
    transcription = await speech_to_text(whisper_input)
    try:
        import asyncio as _gr_asyncio
        transcription = await _gr_asyncio.to_thread(gr_check, transcription, "file_storage", "agent", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_VULN_SEC_005', 'AI_AGENT_ACTIVITY_LOG'], site_id='site:sha256:8ce05e9707f5aa394d17e37033f2b99d8daa52a00440991eac243ca2e19887cb', components={'identity': {'app': {'name': 'quivr', 'version': 'main', 'purl': 'pkg:github/lineaje-demo/quivr@main?commit-id=cb72bb5e125b56bc68c0a6ef2b473794a944ef53&commit-time=2026-09-27%2000%3A34%3A20%20%2B0000&build_file=core/pyproject.toml&repo_strategy=single-repo'}}, 'invocation': {'file': '/tmp/lineaje-efs/vdna_6dXylGIYVjVO6Lkf/SPDXRef-DOCUMENT-vdna_6dXylGIYVjVO6Lkf-2133358-2135906/20261015_220147_830758_8c45f16937d5/source_code/examples/chatbot_voice/main.py', 'line': 172, 'function': 'on_audio_end'}, 'file': '/tmp/lineaje-efs/vdna_6dXylGIYVjVO6Lkf/SPDXRef-DOCUMENT-vdna_6dXylGIYVjVO6Lkf-2133358-2135906/20261015_220147_830758_8c45f16937d5/source_code/examples/chatbot_voice/main.py', 'line': 172, 'function': 'on_audio_end', 'agent_name': 'on_audio_end', 'agent_name_source': 'inferred_from_function', 'call_target': 'speech_to_text'})
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        transcription = transcription
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'file_storage->agent' — passing data through unchecked")

    msg = cl.Message(author="You", content=transcription, elements=elements)

    stt.status = cl.TaskStatus.DONE
    task_list.status = "Done"
    await task_list.update()
    await cl.sleep(1)
    await task_list.remove()

    await main(message=msg)
