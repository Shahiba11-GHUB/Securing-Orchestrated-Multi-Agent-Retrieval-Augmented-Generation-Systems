"""Retrieval agent implementation."""

from __future__ import annotations

from src.adapters.retriever_port import RetrieverPort
from src.agents.base_agent import BaseAgent
from src.contracts import AgentMessage


class RetrievalAgent(BaseAgent):
    """Agent that fetches document chunks for a user query."""

    def __init__(
        self,
        *,
        agent_id: str,
        role: str,
        privilege_level: int,
        retriever: RetrieverPort,
        next_agent_id: str,
    ) -> None:
        super().__init__(agent_id=agent_id, role=role, privilege_level=privilege_level)
        self._retriever = retriever
        self._next_agent_id = next_agent_id

    def handle_message(self, message: AgentMessage) -> AgentMessage:
        payload = message.payload
        if not isinstance(payload, dict):
            raise ValueError("RetrievalAgent expects dict payload with query metadata.")

        query = payload.get("query")
        case_id = payload.get("case_id")
        top_k = payload.get("top_k")
        options = payload.get("retrieval_options")

        if not isinstance(query, str) or not query.strip():
            raise ValueError("RetrievalAgent payload must include a non-empty 'query'.")

        chunks = self._retriever.retrieve(
            query=query,
            case_id=case_id if isinstance(case_id, str) else None,
            request_id=message.message_id,
            top_k=top_k if isinstance(top_k, int) else None,
            options=options if isinstance(options, dict) else None,
        )
        self.record_local_context(
            {"event": "retrieved", "query": query, "case_id": case_id, "chunk_count": len(chunks)}
        )

        return self.create_message(
            receiver_agent_id=self._next_agent_id,
            payload={"query": query, "case_id": case_id, "chunks": chunks},
            trace_id=message.trace_id,
            parent_message_id=message.message_id,
            hop=message.hop + 1,
            scenario_id=message.scenario_id,
            metadata={"route": f"{self.agent_id}->{self._next_agent_id}", "chunk_count": len(chunks)},
        )
