"""Abstract base agent and lifecycle hooks."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any
from uuid import uuid4

from src.contracts import AgentMessage
from src.messaging.message_bus import MessageBus


class BaseAgent(ABC):
    """Base class for all orchestrator agents."""

    def __init__(
        self,
        *,
        agent_id: str,
        role: str,
        privilege_level: int,
        bus: MessageBus | None = None,
    ) -> None:
        if not agent_id.strip():
            raise ValueError("agent_id must be a non-empty string.")
        if not role.strip():
            raise ValueError("role must be a non-empty string.")
        if not 1 <= privilege_level <= 5:
            raise ValueError("privilege_level must be in range [1, 5].")
        self.agent_id = agent_id
        self.role = role
        self.privilege_level = privilege_level
        self.local_context: list[dict[str, Any]] = []
        self._bus = bus

    @property
    def bus(self) -> MessageBus:
        if self._bus is None:
            raise RuntimeError("Message bus is not bound for this agent.")
        return self._bus

    def bind_bus(self, bus: MessageBus) -> None:
        self._bus = bus

    def record_local_context(self, entry: dict[str, Any]) -> None:
        if not isinstance(entry, dict):
            raise TypeError("local context entry must be a dictionary.")
        self.local_context.append(entry)

    def create_message(
        self,
        *,
        receiver_agent_id: str,
        payload: Any,
        trace_id: str | None = None,
        parent_message_id: str | None = None,
        hop: int = 0,
        scenario_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AgentMessage:
        return AgentMessage(
            sender_agent_id=self.agent_id,
            receiver_agent_id=receiver_agent_id,
            payload=payload,
            privilege_level=self.privilege_level,
            trace_id=trace_id if trace_id is not None else str(uuid4()),
            parent_message_id=parent_message_id,
            hop=hop,
            scenario_id=scenario_id,
            metadata=dict(metadata or {}),
        )

    def send_message(self, message: AgentMessage) -> None:
        self.bus.send(message)

    def poll_messages(self, *, limit: int | None = None) -> list[AgentMessage]:
        return self.bus.receive_for(self.agent_id, limit=limit)

    @abstractmethod
    def handle_message(self, message: AgentMessage) -> AgentMessage | list[AgentMessage] | None:
        """Process an inbound message and optionally return outbound messages."""

    def process_next(self) -> list[AgentMessage]:
        inbound = self.poll_messages(limit=1)
        if not inbound:
            return []

        message = inbound[0]
        result = self.handle_message(message)
        if result is None:
            return []
        if isinstance(result, AgentMessage):
            self.send_message(result)
            return [result]

        outbound: list[AgentMessage] = []
        for item in result:
            if not isinstance(item, AgentMessage):
                raise TypeError("handle_message returned a non-AgentMessage item.")
            self.send_message(item)
            outbound.append(item)
        return outbound
