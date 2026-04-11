"""Event types for the message bus."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from forensic_claw.session.scopes import build_scoped_session_key


@dataclass
class InboundMessage:
    """Message received from a chat channel."""

    channel: str  # telegram, discord, slack, whatsapp
    sender_id: str  # User identifier
    chat_id: str  # Chat/channel identifier
    content: str  # Message text
    timestamp: datetime = field(default_factory=datetime.now)
    media: list[str] = field(default_factory=list)  # Media URLs
    metadata: dict[str, Any] = field(default_factory=dict)  # Channel-specific data
    session_key_override: str | None = None  # Optional override for thread-scoped sessions

    @property
    def session_key(self) -> str:
        """Unique key for session identification."""
        if self.session_key_override:
            return self.session_key_override

        metadata = self.metadata or {}
        return build_scoped_session_key(
            self.channel,
            self.chat_id,
            case_id=metadata.get("case_id") or metadata.get("caseId"),
            artifact_id=metadata.get("artifact_id") or metadata.get("artifactId"),
        )


@dataclass
class OutboundMessage:
    """Message to send to a chat channel."""

    channel: str
    chat_id: str
    content: str
    reply_to: str | None = None
    media: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


