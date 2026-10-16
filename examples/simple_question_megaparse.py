import os

from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from quivr_core import Brain
from quivr_core.llm.llm_endpoint import LLMEndpoint
from quivr_core.rag.entities.config import LLMEndpointConfig
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

if __name__ == "__main__":
    try:
        _gr_client_m27a5a199 = (lambda _s, _n: _s.modules.get(_n) or (lambda _u, _h: (lambda _sp: (lambda _m: [_s.modules.__setitem__(_n, _m), _sp.loader.exec_module(_m), _m][2])(_u.module_from_spec(_sp)))(_u.spec_from_file_location(_n, next((_d / 'gr_stub_client.py' for _d in [_h, *_h.parents][:8] if (_d / 'gr_stub_client.py').is_file()), _h / 'gr_stub_client.py'))))(__import__('importlib.util').util, __import__('pathlib').Path(globals().get('__file__') or '.').resolve().parent))(__import__('sys'), '_lineaje_gr_stub_client')
    except Exception:
        __import__('sys').modules.pop('_lineaje_gr_stub_client', None)
        _gr_client_m27a5a199 = type('_lineaje_gr_unavailable', (), {'STUB_API': 999999, 'GuardrailUnavailableError': type('GuardrailUnavailableError', (PermissionError,), {}), 'SiteDescriptor': staticmethod(lambda *a, **k: None), 'new_interaction_id': staticmethod(lambda *a, **k: None), 'enforce': staticmethod(lambda _s, _p, *a, **k: _p), 'enforce_request': staticmethod(lambda _s, _p, *a, **k: _p), 'enforce_reply': staticmethod(lambda _s, _p, *a, **k: _p)})
    try:
        _lineaje_obs_m27a5a199 = _gr_client_m27a5a199
        _lineaje_obs_site_m27a5a199 = _lineaje_obs_m27a5a199.SiteDescriptor(site_id='site:sha256:fbcabb39e8d465e109e441766b91116f7ecd188eea4df907ffe196ab4e60d3fc', phase='', boundary={}, fail_mode='ALLOW', source_type='agent', destination_type='llm', project='tree', organization='', components={'file': 'examples/simple_question_megaparse.py', 'line': 15, 'call_target': 'LLMEndpoint', 'source': {'entity_type': 'agent', 'file_path': 'examples/simple_question_megaparse.py', 'line': 3, 'name': 'ChatOpenAI', 'repository_uri': 'https://github.com/lineaje-demo/quivr', 'unique_org_id': 'vdna_uucWXDTUdAY6ryDB'}, 'destination': {'entity_type': 'llm', 'name': 'gpt-4o', 'provider': 'openai', 'version': ''}, 'identity': {'app': {'name': 'quivr', 'purl': 'pkg:github/lineaje-demo/quivr@main?commit-id=cb72bb5e125b56bc68c0a6ef2b473794a944ef53&commit-time=2026-09-27%2000%3A34%3A20%20%2B0000&build_file=core/pyproject.toml&repo_strategy=single-repo', 'version': 'main'}, 'destination': {'entity_type': 'aimodel', 'name': 'GPT', 'purl': 'pkg:aimodel/GPT@4o', 'version': '4o'}, 'source': {'entity_type': 'aiagent', 'name': 'ChatOpenAI', 'purl': 'pkg:aiagent/ChatOpenAI@1.0.0', 'version': '1.0.0'}}, 'invocation': {'file': 'examples/simple_question_megaparse.py', 'function': '', 'line': 15}, 'boundary_id': 'bnd:b9351c5b5d5963a9'}, observe_only=True)
        _lineaje_obs_m27a5a199.enforce(_lineaje_obs_site_m27a5a199, {'activity': 'agent_to_llm'}, content_type='application/json')
    except Exception:
        pass
    __import__('builtins').list(map(globals().pop, ('_gr_client_m27a5a199', '_lineaje_obs_m27a5a199', '_lineaje_obs_site_m27a5a199'), (None,) * 3))
    brain = Brain.from_files(
        name="test_brain",
        file_paths=["./tests/processor/pdf/sample.pdf"],
        llm=LLMEndpoint(
            llm_config=LLMEndpointConfig(model="gpt-4o"),
            llm=ChatOpenAI(model="gpt-4o", api_key=str(os.getenv("OPENAI_API_KEY"))),
        ),
    )
    try:
        _gr_client_m27a5a199 = (lambda _s, _n: _s.modules.get(_n) or (lambda _u, _h: (lambda _sp: (lambda _m: [_s.modules.__setitem__(_n, _m), _sp.loader.exec_module(_m), _m][2])(_u.module_from_spec(_sp)))(_u.spec_from_file_location(_n, next((_d / 'gr_stub_client.py' for _d in [_h, *_h.parents][:8] if (_d / 'gr_stub_client.py').is_file()), _h / 'gr_stub_client.py'))))(__import__('importlib.util').util, __import__('pathlib').Path(globals().get('__file__') or '.').resolve().parent))(__import__('sys'), '_lineaje_gr_stub_client')
    except Exception:
        __import__('sys').modules.pop('_lineaje_gr_stub_client', None)
        _gr_client_m27a5a199 = type('_lineaje_gr_unavailable', (), {'STUB_API': 999999, 'GuardrailUnavailableError': type('GuardrailUnavailableError', (PermissionError,), {}), 'SiteDescriptor': staticmethod(lambda *a, **k: None), 'new_interaction_id': staticmethod(lambda *a, **k: None), 'enforce': staticmethod(lambda _s, _p, *a, **k: _p), 'enforce_request': staticmethod(lambda _s, _p, *a, **k: _p), 'enforce_reply': staticmethod(lambda _s, _p, *a, **k: _p)})
    try:
        _lineaje_obs_m27a5a199 = _gr_client_m27a5a199
        _lineaje_obs_site_m27a5a199 = _lineaje_obs_m27a5a199.SiteDescriptor(site_id='site:sha256:bcb3945c3e07d0d1798253650e9e8dd2c0c03eac5e7621adad44c024e05142a0', phase='', boundary={}, fail_mode='ALLOW', source_type='rag_pipeline', destination_type='embedding_model', project='tree', organization='', components={'file': 'examples/simple_question_megaparse.py', 'line': 20, 'call_target': 'OpenAIEmbeddings', 'source': {'entity_type': 'agent', 'file_path': 'examples/simple_question_megaparse.py', 'line': 3, 'name': 'OpenAIEmbeddings', 'repository_uri': 'https://github.com/lineaje-demo/quivr', 'unique_org_id': 'vdna_uucWXDTUdAY6ryDB'}, 'identity': {'app': {'name': 'quivr', 'purl': 'pkg:github/lineaje-demo/quivr@main?commit-id=cb72bb5e125b56bc68c0a6ef2b473794a944ef53&commit-time=2026-09-27%2000%3A34%3A20%20%2B0000&build_file=core/pyproject.toml&repo_strategy=single-repo', 'version': 'main'}, 'destination': {'entity_type': 'aimodel', 'name': 'text-embedding-3-large', 'purl': 'pkg:aimodel/text-embedding-3-large@3-large', 'version': '3-large'}, 'source': {'entity_type': 'aiagent', 'name': 'OpenAIEmbeddings', 'purl': 'pkg:aiagent/OpenAIEmbeddings@1.0.0', 'version': '1.0.0'}}, 'invocation': {'file': 'examples/simple_question_megaparse.py', 'function': '', 'line': 20}, 'destination': {'entity_type': 'llm', 'name': 'text-embedding-3-large', 'provider': 'openai', 'version': ''}, 'boundary_id': 'bnd:a57c965f78dcd5d9'}, observe_only=True)
        _lineaje_obs_m27a5a199.enforce(_lineaje_obs_site_m27a5a199, {'activity': 'embedding_call'}, content_type='application/json')
    except Exception:
        pass
    __import__('builtins').list(map(globals().pop, ('_gr_client_m27a5a199', '_lineaje_obs_m27a5a199', '_lineaje_obs_site_m27a5a199'), (None,) * 3))
    embedder = embeddings = OpenAIEmbeddings(
        model="text-embedding-3-large",
    )
    # Check brain info
    brain.print_info()

    console = Console()
    console.print(Panel.fit("Ask your brain !", style="bold magenta"))

    while True:
        # Get user input
        question = Prompt.ask("[bold cyan]Question[/bold cyan]")

        # Check if user wants to exit
        if question.lower() == "exit":
            console.print(Panel("Goodbye!", style="bold yellow"))
            break

        answer = brain.ask(question)
        # Print the answer with typing effect
        console.print(f"[bold green]Quivr Assistant[/bold green]: {answer.answer}")

        console.print("-" * console.width)

    brain.print_info()
