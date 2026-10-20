"""Privilege checks and escalation guards."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Sequence

from src.contracts import AgentMessage, SecurityVerdict

PrivilegeDecision = Literal["allow", "quarantine", "block"]


@dataclass(frozen=True, slots=True)
class PrivilegeCheckResult:
    """Result of privilege transition validation."""

    is_allowed: bool
    decision: PrivilegeDecision
    reason: str
    source_privilege: int
    target_privilege: int
    escalation_step: int


class PrivilegeEscalationGuard:
    """Enforces guardrails for low-to-high privilege transitions."""

    def __init__(self, *, max_unreviewed_escalation_step: int = 1) -> None:
        if max_unreviewed_escalation_step < 0:
            raise ValueError("max_unreviewed_escalation_step must be >= 0.")
        self._max_unreviewed_escalation_step = max_unreviewed_escalation_step

    def check_transition(
        self,
        *,
        message: AgentMessage,
        target_privilege: int,
        verdicts: Sequence[SecurityVerdict] | None = None,
    ) -> PrivilegeCheckResult:
        if not 1 <= target_privilege <= 5:
            raise ValueError("target_privilege must be in range [1, 5].")

        source_privilege = message.privilege_level
        escalation_step = target_privilege - source_privilege

        if escalation_step <= 0:
            return PrivilegeCheckResult(
                is_allowed=True,
                decision="allow",
                reason="No privilege escalation requested.",
                source_privilege=source_privilege,
                target_privilege=target_privilege,
                escalation_step=escalation_step,
            )

        checked_verdicts = list(verdicts or [])
        if checked_verdicts:
            risky = [item for item in checked_verdicts if item.action in {"quarantine", "block"}]
            if risky:
                return PrivilegeCheckResult(
                    is_allowed=False,
                    decision="block",
                    reason="Privilege escalation denied due to suspicious detector verdicts.",
                    source_privilege=source_privilege,
                    target_privilege=target_privilege,
                    escalation_step=escalation_step,
                )
            return PrivilegeCheckResult(
                is_allowed=True,
                decision="allow",
                reason="Privilege escalation approved by clean security verdicts.",
                source_privilege=source_privilege,
                target_privilege=target_privilege,
                escalation_step=escalation_step,
            )

        if escalation_step > self._max_unreviewed_escalation_step:
            return PrivilegeCheckResult(
                is_allowed=False,
                decision="quarantine",
                reason="Privilege escalation requires security verdicts before execution.",
                source_privilege=source_privilege,
                target_privilege=target_privilege,
                escalation_step=escalation_step,
            )

        return PrivilegeCheckResult(
            is_allowed=True,
            decision="allow",
            reason="Limited privilege escalation allowed before security review.",
            source_privilege=source_privilege,
            target_privilege=target_privilege,
            escalation_step=escalation_step,
        )
