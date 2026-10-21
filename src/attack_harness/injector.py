"""Indirect prompt-injection payload insertion utilities."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4

from src.contracts import AgentMessage
from src.orchestrator.router import OrchestratorRoutes


@dataclass(frozen=True, slots=True)
class InjectorEnvelope:
    """Container for generated probe message metadata."""

    trace_id: str
    message: AgentMessage


def build_privilege_escalation_probe(
    *,
    routes: OrchestratorRoutes,
    query: str,
    scenario_id: str,
    source_privilege_level: int,
) -> InjectorEnvelope:
    """Create a direct low-privilege message targeting the action agent."""

    if not isinstance(query, str) or not query.strip():
        raise ValueError("query must be a non-empty string.")
    if not 1 <= source_privilege_level <= 5:
        raise ValueError("source_privilege_level must be in range [1, 5].")

    trace_id = str(uuid4())
    message = AgentMessage(
        sender_agent_id="probe-low-privilege-agent",
        receiver_agent_id=routes.action_agent_id,
        payload={"query": query, "case_id": None, "chunks": [], "verdicts": []},
        privilege_level=source_privilege_level,
        trace_id=trace_id,
        hop=0,
        scenario_id=scenario_id,
        metadata={"route": "probe->action", "probe_type": "privilege_escalation"},
    )
    return InjectorEnvelope(trace_id=trace_id, message=message)
