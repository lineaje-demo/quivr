import logging
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from typing import Any, Generator, Tuple, List
from uuid import UUID, uuid4

from langchain_core.messages import AIMessage, HumanMessage

from quivr_core.rag.entities.models import ChatMessage

# ---------------------------------------------------------------------------
# Provenance helpers
# ---------------------------------------------------------------------------

# Secret used to HMAC-sign provenance metadata.  In production this should be
# injected via a secrets manager; the env-var fallback keeps tests runnable.
_PROVENANCE_SECRET: bytes = os.environ.get(
    "QUIVR_PROVENANCE_SECRET", "change-me-in-production"
).encode()

_AI_CONTENT_LABEL = "[AI-GENERATED CONTENT]"
_CONTENT_ORIGIN_TAG = "quivr-rag-pipeline"


def _sign_provenance(metadata: dict) -> str:
    """Return an HMAC-SHA256 hex digest over the canonical JSON of *metadata*."""
    canonical = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(_PROVENANCE_SECRET, canonical, hashlib.sha256).hexdigest()


def _attach_provenance(msg: AIMessage, chat_message: "ChatMessage") -> AIMessage:
    """Return a *new* AIMessage with provenance metadata attached.

    Raises RuntimeError (fail-closed) if labeling or signing fails for any
    reason so that unsigned / unlabeled content is never silently returned.
    """
    try:
        # 1. Build machine-readable provenance metadata.
        raw_content = msg.content if isinstance(msg.content, str) else json.dumps(msg.content)
        prompt_hash = hashlib.sha256(raw_content.encode()).hexdigest()

        provenance: dict[str, Any] = {
            "content_origin": _CONTENT_ORIGIN_TAG,
            "model_id": (msg.response_metadata or {}).get("model_name", "unknown"),
            "generation_timestamp": datetime.now(timezone.utc).isoformat(),
            "prompt_hash": prompt_hash,
            "message_id": str(chat_message.message_id),
            "chat_id": str(chat_message.chat_id),
        }

        # 2. Cryptographically sign the provenance block.
        provenance["signature"] = _sign_provenance(
            {k: v for k, v in provenance.items() if k != "signature"}
        )

        # 3. Attach a visible AI-content label to the message content.
        labeled_content = (
            f"{_AI_CONTENT_LABEL}\n{raw_content}"
            if isinstance(msg.content, str)
            else msg.content  # non-text content keeps original structure
        )

        # 4. Merge provenance into additional_kwargs so it travels with the
        #    message through any downstream serialisation.
        new_additional_kwargs = dict(msg.additional_kwargs)
        new_additional_kwargs["provenance"] = provenance

        labeled_msg = AIMessage(
            content=labeled_content,
            additional_kwargs=new_additional_kwargs,
            response_metadata=dict(msg.response_metadata or {}),
            id=msg.id,
        )
        return labeled_msg
    except Exception as exc:  # fail-closed
        raise RuntimeError(
            "Provenance labeling/signing failed; refusing to return unlabeled "
            f"AI-generated content. Underlying error: {exc}"
        ) from exc

logger = logging.getLogger(__name__)


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
        message_id = uuid4()
        message_time = datetime.now()
        msg_type = "AIMessage" if isinstance(langchain_msg, AIMessage) else "HumanMessage"
        logger.info(
            "LLM interaction recorded",
            extra={
                "chat_id": str(self.id),
                "brain_id": str(self.brain_id),
                "message_id": str(message_id),
                "message_type": msg_type,
                "message_content": langchain_msg.content,
                "message_time": message_time.isoformat(),
                "metadata": metadata,
            },
        )
        chat_msg = ChatMessage(
            chat_id=self.id,
            message_id=message_id,
            brain_id=self.brain_id,
            msg=langchain_msg,
            message_time=message_time,
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

        result: List[HumanMessage | AIMessage] = []
        for _msg in self._msgs:
            if isinstance(_msg.msg, AIMessage):
                # Attach provenance, label, and signature; fail-closed on error.
                result.append(_attach_provenance(_msg.msg, _msg))
            else:
                result.append(_msg.msg)
        return result
