"""Message bus implementation for agent communication."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable

from src.contracts import AgentMessage

Subscriber = Callable[[AgentMessage], None]


class MessageBus:
    """In-memory FIFO message bus for orchestrator/agent communication."""

    def __init__(self) -> None:
        self._queues: dict[str, list[AgentMessage]] = defaultdict(list)
        self._subscribers: dict[str, list[Subscriber]] = defaultdict(list)
        self._history: list[AgentMessage] = []

    def send(self, message: AgentMessage) -> None:
        if not isinstance(message, AgentMessage):
            raise TypeError("message must be an AgentMessage instance.")

        self._queues[message.receiver_agent_id].append(message)
        self._history.append(message)

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
