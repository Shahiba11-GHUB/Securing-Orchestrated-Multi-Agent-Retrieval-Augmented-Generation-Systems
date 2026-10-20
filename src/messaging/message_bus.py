"""Message bus implementation for agent communication."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Callable
from typing import Any

from src.contracts import AgentMessage, TraceEvent
from src.messaging.event_logger import EventLogger
from src.messaging.propagation_tracker import PropagationTracker

Subscriber = Callable[[AgentMessage], None]


class MessageBus:
    """In-memory FIFO message bus for orchestrator/agent communication."""

    def __init__(
        self,
        *,
        event_logger: EventLogger | None = None,
        propagation_tracker: PropagationTracker | None = None,
    ) -> None:
        self._queues: dict[str, list[AgentMessage]] = defaultdict(list)
        self._subscribers: dict[str, list[Subscriber]] = defaultdict(list)
        self._history: list[AgentMessage] = []
        self._event_logger = event_logger
        self._propagation_tracker = propagation_tracker

    def send(self, message: AgentMessage) -> None:
        if not isinstance(message, AgentMessage):
            raise TypeError("message must be an AgentMessage instance.")

        self._queues[message.receiver_agent_id].append(message)
        self._history.append(message)
        trace_event = self._build_trace_event(message)
        if self._propagation_tracker is not None:
            self._propagation_tracker.record(trace_event)
        if self._event_logger is not None:
            self._event_logger.log(trace_event)

        for subscriber in self._subscribers[message.receiver_agent_id]:
            subscriber(message)

    def register_subscriber(self, agent_id: str, callback: Subscriber) -> None:
        if not isinstance(agent_id, str) or not agent_id.strip():
            raise ValueError("agent_id must be a non-empty string.")
        if not callable(callback):
            raise TypeError("callback must be callable.")
        self._subscribers[agent_id].append(callback)

    def receive_for(self, agent_id: str, *, limit: int | None = None) -> list[AgentMessage]:
        if not isinstance(agent_id, str) or not agent_id.strip():
            raise ValueError("agent_id must be a non-empty string.")
        if limit is not None and limit < 1:
            raise ValueError("limit must be >= 1 when provided.")

        queue = self._queues[agent_id]
        if limit is None:
            messages = list(queue)
            queue.clear()
            return messages

        messages = queue[:limit]
        del queue[:limit]
        return messages

    def peek_for(self, agent_id: str, *, limit: int | None = None) -> list[AgentMessage]:
        if not isinstance(agent_id, str) or not agent_id.strip():
            raise ValueError("agent_id must be a non-empty string.")
        if limit is not None and limit < 1:
            raise ValueError("limit must be >= 1 when provided.")

        queue = self._queues[agent_id]
        return list(queue) if limit is None else list(queue[:limit])

    def has_messages(self, agent_id: str) -> bool:
        if not isinstance(agent_id, str) or not agent_id.strip():
            raise ValueError("agent_id must be a non-empty string.")
        return len(self._queues[agent_id]) > 0

    def history(self, *, trace_id: str | None = None) -> list[AgentMessage]:
        if trace_id is None:
            return list(self._history)
        return [msg for msg in self._history if msg.trace_id == trace_id]

    @staticmethod
    def _hash_payload(payload: Any) -> str:
        payload_bytes = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(payload_bytes).hexdigest()

    def _build_trace_event(self, message: AgentMessage) -> TraceEvent:
        decision: str | None = None
        if isinstance(message.metadata.get("policy_action"), str):
            decision = message.metadata["policy_action"]
        elif isinstance(message.payload, dict) and isinstance(message.payload.get("status"), str):
            decision = message.payload["status"]

        return TraceEvent(
            event_type="message_sent",
            trace_id=message.trace_id,
            sender_agent_id=message.sender_agent_id,
            receiver_agent_id=message.receiver_agent_id,
            message_id=message.message_id,
            parent_message_id=message.parent_message_id,
            scenario_id=message.scenario_id,
            hop=message.hop,
            decision=decision,
            payload_hash=self._hash_payload(message.payload),
            metadata=dict(message.metadata),
        )
