"""Security and routing policy evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.contracts import SecurityDecision, SecurityVerdict
from src.orchestrator.privilege import PrivilegeCheckResult


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """Normalized policy decision for downstream routing/action."""

    action: SecurityDecision
    reason: str
    allowed_chunks: int
    quarantined_chunks: int
    blocked_chunks: int
    metadata: dict[str, Any]


class SecurityPolicy:
    """Evaluates security verdicts and privilege checks into one action."""

    def evaluate(
        self,
        verdicts: list[SecurityVerdict],
        *,
        privilege_check: PrivilegeCheckResult | None = None,
    ) -> PolicyDecision:
        if any(not isinstance(item, SecurityVerdict) for item in verdicts):
            raise ValueError("verdicts must be list[SecurityVerdict].")

        blocked = sum(1 for item in verdicts if item.action == "block")
        quarantined = sum(1 for item in verdicts if item.action == "quarantine")
        allowed = sum(1 for item in verdicts if item.action == "allow")

        if privilege_check is not None and not privilege_check.is_allowed:
            decision = privilege_check.decision
            if decision == "allow":
                raise ValueError("Invalid privilege check result: denied transition cannot allow.")
            return PolicyDecision(
                action=decision,
                reason=privilege_check.reason,
                allowed_chunks=allowed,
                quarantined_chunks=quarantined,
                blocked_chunks=blocked,
                metadata={
                    "source_privilege": privilege_check.source_privilege,
                    "target_privilege": privilege_check.target_privilege,
                    "escalation_step": privilege_check.escalation_step,
                },
            )

        if blocked > 0:
            return PolicyDecision(
                action="block",
                reason="One or more chunks were blocked by security detector.",
                allowed_chunks=allowed,
                quarantined_chunks=quarantined,
                blocked_chunks=blocked,
                metadata={},
            )
        if quarantined > 0:
            return PolicyDecision(
                action="quarantine",
                reason="One or more chunks were quarantined by security detector.",
                allowed_chunks=allowed,
                quarantined_chunks=quarantined,
                blocked_chunks=blocked,
                metadata={},
            )
        return PolicyDecision(
            action="allow",
            reason="All chunks passed security screening.",
            allowed_chunks=allowed,
            quarantined_chunks=quarantined,
            blocked_chunks=blocked,
            metadata={},
        )
