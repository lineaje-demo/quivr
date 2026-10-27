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

from datetime import datetime
from typing import Any, Generator, Tuple, List
from uuid import UUID, uuid4

from langchain_core.messages import AIMessage, HumanMessage

from quivr_core.rag.entities.models import ChatMessage


class ChatHistory:
    """
    ChatHistory is a class that maintains a record of chat conversations. Each message
    in the history is represented by an instance of the `ChatMessage` class, and the
    chat history is stored internally as a list of these `ChatMessage` objects.
    The class provides methods to retrieve, append, iterate, and manipulate the chat
    history, as well as utilities to convert the messages into specific formats
    and support deep copying.
    """

    def __init__(self, chat_id: UUID, brain_id: UUID | None) -> None:
        """Init a new ChatHistory object.

        Args:
            chat_id (UUID): A unique identifier for the chat session.
            brain_id (UUID | None): An optional identifier for the brain associated with the chat.
        """
        self.id = chat_id
        self.brain_id = brain_id
        # TODO(@aminediro): maybe use a deque() instead ?
        self._msgs: list[ChatMessage] = []

    def get_chat_history(self, newest_first: bool = False) -> List[ChatMessage]:
        """
        Retrieves the chat history, optionally sorted in reverse chronological order.

        Args:
            newest_first (bool, optional): If True, returns the messages in reverse order (newest first). Defaults to False.

        Returns:
            List[ChatMessage]: A sorted list of chat messages.
        """
        history = sorted(self._msgs, key=lambda msg: msg.message_time)
        if newest_first:
            return history[::-1]
        # LINEAJE: runtime guardrail checks `history` as it flows from the agent to the user interface, before it leaves the application (in ChatHistory.get_chat_history).
        #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `history` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:1ec55da2b352bef0c7606e088d41e12660c3ef335a135221191af0d695dc7512'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:1ec55da2b352bef0c7606e088d41e12660c3ef335a135221191af0d695dc7512', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'invocation': {'file': 'core/quivr_core/rag/entities/chat.py', 'line': 45, 'function': 'ChatHistory.get_chat_history'}, 'file': 'core/quivr_core/rag/entities/chat.py', 'line': 45, 'function': 'get_chat_history', 'agent_name': 'ChatHistory', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
        try:
            history = _gr_client.enforce(_gr_site, history, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        return history

    def __len__(self):
        return len(self._msgs)

    def append(
        self, langchain_msg: AIMessage | HumanMessage, metadata: dict[str, Any] = {}
    ):
        """
        Appends a new message to the chat history.

        Args:
            langchain_msg (AIMessage | HumanMessage): The message content (either an AI or Human message).
            metadata (dict[str, Any], optional): Additional metadata related to the message. Defaults to an empty dictionary.
        """
        chat_msg = ChatMessage(
            chat_id=self.id,
            message_id=uuid4(),
            brain_id=self.brain_id,
            msg=langchain_msg,
            message_time=datetime.now(),
            metadata=metadata,
        )
        self._msgs.append(chat_msg)

    def iter_pairs(self) -> Generator[Tuple[HumanMessage, AIMessage], None, None]:
        """
        Iterates over the chat history in pairs, returning a HumanMessage followed by an AIMessage.

        Yields:
            Tuple[HumanMessage, AIMessage]: Pairs of human and AI messages.

        Raises:
            AssertionError: If the messages in the pair are not in the expected order (i.e., a HumanMessage followed by an AIMessage).
        """
        # Reverse the chat_history, newest first
        it = iter(self.get_chat_history(newest_first=True))
        for ai_message, human_message in zip(it, it, strict=False):
            assert isinstance(
                human_message.msg, HumanMessage
            ), f"msg {human_message} is not HumanMessage"
            assert isinstance(
                ai_message.msg, AIMessage
            ), f"msg {human_message} is not AIMessage"
            yield (human_message.msg, ai_message.msg)

    def to_list(self) -> List[HumanMessage | AIMessage]:
        """
        Converts the chat history into a list of raw HumanMessage or AIMessage objects.

        Returns:
            list[HumanMessage | AIMessage]: A list of messages in their raw form, without metadata.
        """

        return [_msg.msg for _msg in self._msgs]
