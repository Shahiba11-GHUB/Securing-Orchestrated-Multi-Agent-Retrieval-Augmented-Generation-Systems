"""Main orchestration execution loop."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4

from src.adapters.retriever_port import RetrieverPort
from src.adapters.security_port import SecurityPort
from src.agents.action_agent import ActionAgent
from src.agents.retrieval_agent import RetrievalAgent
from src.agents.security_agent import SecurityAgent
from src.contracts import AgentMessage
from src.messaging.message_bus import MessageBus
from src.orchestrator.router import OrchestratorRoutes


@dataclass(slots=True)
class OrchestrationResult:
    trace_id: str
    final_message: AgentMessage
    history: list[AgentMessage]


class OrchestratorEngine:
    """Minimal orchestrator engine for retrieval -> security -> action flow."""

    def __init__(
        self,
        *,
        retriever: RetrieverPort,
        security_adapter: SecurityPort,
        routes: OrchestratorRoutes | None = None,
    ) -> None:
        self.routes = routes or OrchestratorRoutes()
        self.bus = MessageBus()

        self.retrieval_agent = RetrievalAgent(
            agent_id=self.routes.retrieval_agent_id,
            role="retrieval",
            privilege_level=2,
            retriever=retriever,
            next_agent_id=self.routes.security_agent_id,
        )
        self.security_agent = SecurityAgent(
            agent_id=self.routes.security_agent_id,
            role="security",
            privilege_level=3,
            security_adapter=security_adapter,
            next_agent_id=self.routes.action_agent_id,
        )
        self.action_agent = ActionAgent(
            agent_id=self.routes.action_agent_id,
            role="action",
            privilege_level=5,
            next_agent_id=self.routes.orchestrator_id,
        )
        self.retrieval_agent.bind_bus(self.bus)
        self.security_agent.bind_bus(self.bus)
        self.action_agent.bind_bus(self.bus)

    def process_query(
        self,
        *,
        query: str,
        case_id: str | None = None,
        top_k: int | None = None,
        scenario_id: str | None = None,
    ) -> OrchestrationResult:
        if not isinstance(query, str) or not query.strip():
            raise ValueError("query must be a non-empty string.")

        trace_id = str(uuid4())
        initial = AgentMessage(
            sender_agent_id=self.routes.orchestrator_id,
            receiver_agent_id=self.routes.retrieval_agent_id,
            payload={
                "query": query,
                "case_id": case_id,
                "top_k": top_k,
            },
            privilege_level=5,
            trace_id=trace_id,
            hop=0,
            scenario_id=scenario_id,
            metadata={"route": "orchestrator->retrieval"},
        )
        self.bus.send(initial)

        self.retrieval_agent.process_next()
        self.security_agent.process_next()
        self.action_agent.process_next()

        final_messages = self.bus.receive_for(self.routes.orchestrator_id)
        if not final_messages:
            raise RuntimeError("No final response produced by action agent.")
        final_message = final_messages[-1]
        history = self.bus.history(trace_id=trace_id)
        return OrchestrationResult(trace_id=trace_id, final_message=final_message, history=history)
