"""Security agent implementation."""

from __future__ import annotations

from src.adapters.security_port import SecurityPort
from src.agents.base_agent import BaseAgent
from src.contracts import AgentMessage, DocumentChunk


class SecurityAgent(BaseAgent):
    """Agent that classifies chunks and emits security verdicts."""

    def __init__(
        self,
        *,
        agent_id: str,
        role: str,
        privilege_level: int,
        security_adapter: SecurityPort,
        next_agent_id: str,
    ) -> None:
        super().__init__(agent_id=agent_id, role=role, privilege_level=privilege_level)
        self._security_adapter = security_adapter
        self._next_agent_id = next_agent_id

    def handle_message(self, message: AgentMessage) -> AgentMessage:
        payload = message.payload
        if not isinstance(payload, dict):
            raise ValueError("SecurityAgent expects dict payload with chunks.")

        query = payload.get("query")
        case_id = payload.get("case_id")
        chunks = payload.get("chunks")

        if not isinstance(query, str) or not query.strip():
            raise ValueError("SecurityAgent payload must include a non-empty 'query'.")
        if not isinstance(chunks, list) or any(not isinstance(item, DocumentChunk) for item in chunks):
            raise ValueError("SecurityAgent payload must include 'chunks' as list[DocumentChunk].")

        verdicts = self._security_adapter.screen_chunks(chunks, request_id=message.message_id)
        self.record_local_context(
            {
                "event": "screened",
                "query": query,
                "case_id": case_id,
                "chunk_count": len(chunks),
                "verdict_count": len(verdicts),
            }
        )

        return self.create_message(
            receiver_agent_id=self._next_agent_id,
            payload={"query": query, "case_id": case_id, "chunks": chunks, "verdicts": verdicts},
            trace_id=message.trace_id,
            parent_message_id=message.message_id,
            hop=message.hop + 1,
            scenario_id=message.scenario_id,
            metadata={
                "route": f"{self.agent_id}->{self._next_agent_id}",
                "verdict_count": len(verdicts),
            },
        )
