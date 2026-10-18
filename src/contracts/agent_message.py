"""AgentMessage contract."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class AgentMessage:
    """Message exchanged between orchestrator and agents."""

    sender_agent_id: str
    receiver_agent_id: str
    payload: Any
    privilege_level: int
    metadata: dict[str, Any] = field(default_factory=dict)
    trace_id: str = field(default_factory=lambda: str(uuid4()))
    message_id: str = field(default_factory=lambda: str(uuid4()))
    parent_message_id: str | None = None
    hop: int = 0
    scenario_id: str | None = None
    created_at: str = field(default_factory=utc_now_iso)

    def __post_init__(self) -> None:
        if not self.sender_agent_id.strip():
            raise ValueError("sender_agent_id must be a non-empty string.")
        if not self.receiver_agent_id.strip():
            raise ValueError("receiver_agent_id must be a non-empty string.")
        if not 1 <= self.privilege_level <= 5:
            raise ValueError("privilege_level must be in range [1, 5].")
        if self.hop < 0:
            raise ValueError("hop must be >= 0.")
        if not self.trace_id.strip():
            raise ValueError("trace_id must be a non-empty string.")
        if not self.message_id.strip():
            raise ValueError("message_id must be a non-empty string.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "message_id": self.message_id,
            "trace_id": self.trace_id,
            "sender_agent_id": self.sender_agent_id,
            "receiver_agent_id": self.receiver_agent_id,
            "parent_message_id": self.parent_message_id,
            "payload": self.payload,
            "privilege_level": self.privilege_level,
            "hop": self.hop,
            "scenario_id": self.scenario_id,
            "created_at": self.created_at,
            "metadata": dict(self.metadata),
        }
