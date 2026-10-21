"""Routing logic for inter-agent handoff."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Stage = Literal["retrieval", "security", "action", "orchestrator"]


@dataclass(frozen=True, slots=True)
class OrchestratorRoutes:
    retrieval_agent_id: str = "retrieval-agent"
    security_agent_id: str = "security-agent"
    action_agent_id: str = "action-agent"
    orchestrator_id: str = "orchestrator"

    def next_agent_for(self, stage: Stage) -> str:
        if stage == "retrieval":
            return self.retrieval_agent_id
        if stage == "security":
            return self.security_agent_id
        if stage == "action":
            return self.action_agent_id
        return self.orchestrator_id
