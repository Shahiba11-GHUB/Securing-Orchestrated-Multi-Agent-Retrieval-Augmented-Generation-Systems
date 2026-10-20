"""Orchestrator package exports."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .engine import OrchestrationResult, OrchestratorEngine
    from .policy import PolicyDecision, SecurityPolicy
    from .privilege import PrivilegeCheckResult, PrivilegeEscalationGuard
    from .router import OrchestratorRoutes

__all__ = [
    "OrchestrationResult",
    "OrchestratorEngine",
    "OrchestratorRoutes",
    "PolicyDecision",
    "PrivilegeCheckResult",
    "PrivilegeEscalationGuard",
    "SecurityPolicy",
]


def __getattr__(name: str):
    if name in {"OrchestrationResult", "OrchestratorEngine"}:
        from .engine import OrchestrationResult, OrchestratorEngine

        return {"OrchestrationResult": OrchestrationResult, "OrchestratorEngine": OrchestratorEngine}[
            name
        ]
    if name == "OrchestratorRoutes":
        from .router import OrchestratorRoutes

        return OrchestratorRoutes
    if name in {"PolicyDecision", "SecurityPolicy"}:
        from .policy import PolicyDecision, SecurityPolicy

        return {"PolicyDecision": PolicyDecision, "SecurityPolicy": SecurityPolicy}[name]
    if name in {"PrivilegeCheckResult", "PrivilegeEscalationGuard"}:
        from .privilege import PrivilegeCheckResult, PrivilegeEscalationGuard

        return {
            "PrivilegeCheckResult": PrivilegeCheckResult,
            "PrivilegeEscalationGuard": PrivilegeEscalationGuard,
        }[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
