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

from dataclasses import dataclass
from uuid import UUID

from rich.tree import Tree


@dataclass
class ChatHistoryInfo:
    nb_chats: int
    current_default_chat: UUID
    current_chat_history_length: int

    def add_to_tree(self, chats_tree: Tree):
        chats_tree.add(f"Number of Chats: [bold]{self.nb_chats}[/bold]")
        chats_tree.add(
            f"Current Default Chat: [bold magenta]{self.current_default_chat}[/bold magenta]"
        )
        chats_tree.add(
            f"Current Chat History Length: [bold]{self.current_chat_history_length}[/bold]"
        )


@dataclass
class LLMInfo:
    model: str
    llm_base_url: str
    temperature: float
    max_tokens: int
    supports_function_calling: int

    def add_to_tree(self, llm_tree: Tree):
        llm_tree.add(f"Model: [italic]{self.model}[/italic]")
        llm_tree.add(f"Base URL: [underline]{self.llm_base_url}[/underline]")
        llm_tree.add(f"Temperature: [bold]{self.temperature}[/bold]")
        llm_tree.add(f"Max Tokens: [bold]{self.max_tokens}[/bold]")
        func_call_color = "green" if self.supports_function_calling else "red"
        llm_tree.add(
            f"Supports Function Calling: [bold {func_call_color}]{self.supports_function_calling}[/bold {func_call_color}]"
        )


@dataclass
class StorageInfo:
    storage_type: str
    n_files: int

    def add_to_tree(self, files_tree: Tree):
        files_tree.add(f"Storage Type: [italic]{self.storage_type}[/italic]")
        files_tree.add(f"Number of Files: [bold]{self.n_files}[/bold]")


@dataclass
class BrainInfo:
    brain_id: UUID
    brain_name: str
    chats_info: ChatHistoryInfo
    llm_info: LLMInfo
    files_info: StorageInfo | None = None

    def to_tree(self):
        tree = Tree("📊 Brain Information")
        tree.add(f"🆔 ID: [bold cyan]{self.brain_id}[/bold cyan]")
        tree.add(f"🧠 Brain Name: [bold green]{self.brain_name}[/bold green]")

        if self.files_info:
            files_tree = tree.add("📁 Files")
            self.files_info.add_to_tree(files_tree)

        chats_tree = tree.add("💬 Chats")
        self.chats_info.add_to_tree(chats_tree)

        llm_tree = tree.add("🤖 LLM")
        self.llm_info.add_to_tree(llm_tree)
        # LINEAJE: runtime guardrail checks `tree` as it flows from the agent to the user interface, before it leaves the application (in BrainInfo.to_tree).
        #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `tree` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:a62e2789723c9834440bac4997fbedb45cd9274e87129b445cc07cb5bbe0193e'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:a62e2789723c9834440bac4997fbedb45cd9274e87129b445cc07cb5bbe0193e', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'invocation': {'file': 'core/quivr_core/brain/info.py', 'line': 74, 'function': 'BrainInfo.to_tree'}, 'file': 'core/quivr_core/brain/info.py', 'line': 74, 'function': 'to_tree', 'agent_name': 'BrainInfo', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
        try:
            tree = _gr_client.enforce(_gr_site, tree, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        return tree
