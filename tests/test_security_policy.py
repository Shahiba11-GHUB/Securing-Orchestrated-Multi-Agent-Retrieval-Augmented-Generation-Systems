from typing import Literal

from src.contracts import SecurityVerdict
from src.orchestrator.policy import SecurityPolicy
from src.orchestrator.privilege import PrivilegeCheckResult


def _verdict(decision: Literal["allow", "quarantine", "block"]) -> SecurityVerdict:
    return SecurityVerdict(
        chunk_id=f"chunk-{decision}",
        decision=decision,
        risk_score=0.2 if decision == "allow" else 0.8,
        is_suspicious=decision != "allow",
        reason=f"{decision} by test",
    )


def test_policy_allows_when_all_verdicts_allow() -> None:
    policy = SecurityPolicy()

    decision = policy.evaluate([_verdict("allow"), _verdict("allow")])

    assert decision.action == "allow"
    assert decision.allowed_chunks == 2
    assert decision.blocked_chunks == 0
    assert decision.quarantined_chunks == 0


def test_policy_quarantines_when_any_verdict_is_quarantine() -> None:
    policy = SecurityPolicy()

    decision = policy.evaluate([_verdict("allow"), _verdict("quarantine")])

    assert decision.action == "quarantine"
    assert decision.allowed_chunks == 1
    assert decision.quarantined_chunks == 1


def test_policy_uses_privilege_denial_over_verdicts() -> None:
    policy = SecurityPolicy()
    privilege_result = PrivilegeCheckResult(
        is_allowed=False,
        decision="block",
        reason="Escalation denied by test guard.",
        source_privilege=2,
        target_privilege=5,
        escalation_step=3,
    )

    decision = policy.evaluate([_verdict("allow")], privilege_check=privilege_result)

    assert decision.action == "block"
    assert decision.reason == "Escalation denied by test guard."
    assert decision.metadata["source_privilege"] == 2
    assert decision.metadata["target_privilege"] == 5
