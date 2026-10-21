"""Action agent implementation."""

from __future__ import annotations

from src.agents.base_agent import BaseAgent
from src.contracts import AgentMessage, DocumentChunk, SecurityVerdict
from src.orchestrator.policy import SecurityPolicy
from src.orchestrator.privilege import PrivilegeEscalationGuard


class ActionAgent(BaseAgent):
    """Agent that gates final action based on security verdicts."""

    def __init__(
        self,
        *,
        agent_id: str,
        role: str,
        privilege_level: int,
        next_agent_id: str,
        policy: SecurityPolicy | None = None,
        privilege_guard: PrivilegeEscalationGuard | None = None,
    ) -> None:
        super().__init__(agent_id=agent_id, role=role, privilege_level=privilege_level)
        self._next_agent_id = next_agent_id
        self._policy = policy or SecurityPolicy()
        self._privilege_guard = privilege_guard or PrivilegeEscalationGuard()

    def handle_message(self, message: AgentMessage) -> AgentMessage:
        payload = message.payload
        if not isinstance(payload, dict):
            raise ValueError("ActionAgent expects dict payload with chunks and verdicts.")

        query = payload.get("query")
        case_id = payload.get("case_id")
        chunks = payload.get("chunks")
        verdicts = payload.get("verdicts")

        if not isinstance(query, str) or not query.strip():
            raise ValueError("ActionAgent payload must include a non-empty 'query'.")
        if not isinstance(chunks, list) or any(not isinstance(item, DocumentChunk) for item in chunks):
            raise ValueError("ActionAgent payload must include 'chunks' as list[DocumentChunk].")
        if not isinstance(verdicts, list) or any(
            not isinstance(item, SecurityVerdict) for item in verdicts
        ):
            raise ValueError("ActionAgent payload must include 'verdicts' as list[SecurityVerdict].")
        if len(chunks) != len(verdicts):
            raise ValueError("ActionAgent requires one verdict per input chunk.")

        privilege_check = self._privilege_guard.check_transition(
            message=message,
            target_privilege=self.privilege_level,
            verdicts=verdicts,
        )
        policy_decision = self._policy.evaluate(verdicts, privilege_check=privilege_check)

        status = "allow" if policy_decision.action == "allow" else "blocked"
        summary = {
            "status": status,
            "policy_action": policy_decision.action,
            "policy_reason": policy_decision.reason,
            "query": query,
            "case_id": case_id,
            "allowed_chunks": policy_decision.allowed_chunks,
            "blocked_or_quarantined_chunks": (
                policy_decision.blocked_chunks + policy_decision.quarantined_chunks
            ),
            "actions": [v.action for v in verdicts],
        }
        if policy_decision.metadata:
            summary["policy_metadata"] = dict(policy_decision.metadata)

        self.record_local_context({"event": "action_decision", **summary})

        return self.create_message(
            receiver_agent_id=self._next_agent_id,
            payload=summary,
            trace_id=message.trace_id,
            parent_message_id=message.message_id,
            hop=message.hop + 1,
            scenario_id=message.scenario_id,
            metadata={
                "route": f"{self.agent_id}->{self._next_agent_id}",
                "status": status,
                "policy_action": policy_decision.action,
            },
        )
