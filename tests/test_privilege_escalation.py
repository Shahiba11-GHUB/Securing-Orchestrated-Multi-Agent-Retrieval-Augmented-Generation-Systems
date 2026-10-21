from typing import Literal

from src.contracts import AgentMessage, SecurityVerdict
from src.orchestrator.privilege import PrivilegeEscalationGuard


def _message(*, privilege_level: int) -> AgentMessage:
    return AgentMessage(
        sender_agent_id="source-agent",
        receiver_agent_id="target-agent",
        payload={"query": "test"},
        privilege_level=privilege_level,
        trace_id="trace-1",
        message_id=f"msg-{privilege_level}",
    )


def _verdict(decision: Literal["allow", "quarantine", "block"]) -> SecurityVerdict:
    return SecurityVerdict(
        chunk_id="chunk-1",
        decision=decision,
        risk_score=0.8 if decision != "allow" else 0.1,
        is_suspicious=decision != "allow",
        reason=f"decision={decision}",
    )


def test_clean_low_to_high_escalation_is_allowed() -> None:
    guard = PrivilegeEscalationGuard()

    result = guard.check_transition(
        message=_message(privilege_level=2),
        target_privilege=5,
        verdicts=[_verdict("allow")],
    )

    assert result.is_allowed is True
    assert result.decision == "allow"
    assert result.escalation_step == 3


def test_suspicious_low_to_high_escalation_is_blocked() -> None:
    guard = PrivilegeEscalationGuard()

    result = guard.check_transition(
        message=_message(privilege_level=2),
        target_privilege=5,
        verdicts=[_verdict("quarantine")],
    )

    assert result.is_allowed is False
    assert result.decision == "block"


def test_large_unreviewed_escalation_is_quarantined() -> None:
    guard = PrivilegeEscalationGuard(max_unreviewed_escalation_step=1)

    result = guard.check_transition(
        message=_message(privilege_level=2),
        target_privilege=5,
        verdicts=None,
    )

    assert result.is_allowed is False
    assert result.decision == "quarantine"
