"""TraceEvent contract."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class TraceEvent:
    """Structured trace event for propagation analysis."""

    event_type: str
    trace_id: str
    event_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: str = field(default_factory=_utc_now_iso)
    sender_agent_id: str | None = None
    receiver_agent_id: str | None = None
    message_id: str | None = None
    parent_message_id: str | None = None
    scenario_id: str | None = None
    chunk_id: str | None = None
    decision: str | None = None
    payload_hash: str | None = None
    hop: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.event_type.strip():
            raise ValueError("event_type must be a non-empty string.")
        if not self.trace_id.strip():
            raise ValueError("trace_id must be a non-empty string.")
        if self.hop is not None and self.hop < 0:
            raise ValueError("hop must be >= 0 when provided.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "trace_id": self.trace_id,
            "event_type": self.event_type,
            "sender_agent_id": self.sender_agent_id,
            "receiver_agent_id": self.receiver_agent_id,
            "message_id": self.message_id,
            "parent_message_id": self.parent_message_id,
            "scenario_id": self.scenario_id,
            "chunk_id": self.chunk_id,
            "decision": self.decision,
            "payload_hash": self.payload_hash,
            "hop": self.hop,
            "metadata": dict(self.metadata),
        }
