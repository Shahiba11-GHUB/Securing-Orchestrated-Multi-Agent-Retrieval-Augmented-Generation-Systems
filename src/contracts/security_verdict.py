"""SecurityVerdict contract."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Mapping

SecurityDecision = Literal["allow", "quarantine", "block"]


@dataclass(slots=True)
class SecurityVerdict:
    """Security decision routed by the orchestrator."""

    chunk_id: str
    decision: SecurityDecision
    risk_score: float
    is_suspicious: bool
    reason: str
    case_id: str | None = None
    trust_score: float | None = None
    injection_probability: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.chunk_id.strip():
            raise ValueError("chunk_id must be a non-empty string.")
        if self.decision not in {"allow", "quarantine", "block"}:
            raise ValueError("decision must be one of: allow, quarantine, block.")
        if isinstance(self.risk_score, bool) or not isinstance(self.risk_score, (int, float)):
            raise ValueError("risk_score must be numeric.")
        self.risk_score = float(self.risk_score)
        if not 0.0 <= self.risk_score <= 1.0:
            raise ValueError("risk_score must be between 0.0 and 1.0.")
        if not isinstance(self.is_suspicious, bool):
            raise ValueError("is_suspicious must be a bool.")
        if not self.reason.strip():
            raise ValueError("reason must be a non-empty string.")
        if self.trust_score is not None and not 0.0 <= self.trust_score <= 1.0:
            raise ValueError("trust_score must be between 0.0 and 1.0 when provided.")
        if self.injection_probability is not None and not 0.0 <= self.injection_probability <= 1.0:
            raise ValueError(
                "injection_probability must be between 0.0 and 1.0 when provided."
            )

    @property
    def is_safe(self) -> bool:
        return self.decision == "allow" and not self.is_suspicious

    @property
    def action(self) -> SecurityDecision:
        return self.decision

    @classmethod
    def from_detector_result(
        cls,
        result: Mapping[str, Any],
        *,
        chunk_id: str,
        case_id: str | None = None,
    ) -> "SecurityVerdict":
        """Normalize detector output into orchestration contract."""

        decision = result.get("decision")
        if decision is None:
            raise ValueError("Detector output missing required field: decision.")
        if not isinstance(decision, str):
            raise ValueError("Detector field 'decision' must be a string.")
        if decision not in {"allow", "quarantine", "block"}:
            raise ValueError("Detector field 'decision' is invalid.")

        risk_score = result.get("risk_score")
        if risk_score is None:
            raise ValueError("Detector output missing required field: risk_score.")
        if isinstance(risk_score, bool) or not isinstance(risk_score, (int, float)):
            raise ValueError("Detector field 'risk_score' must be numeric.")

        is_suspicious = result.get("is_suspicious")
        if is_suspicious is None:
            raise ValueError("Detector output missing required field: is_suspicious.")
        if not isinstance(is_suspicious, bool):
            raise ValueError("Detector field 'is_suspicious' must be bool.")

        reason = result.get("reason")
        if reason is None:
            raise ValueError("Detector output missing required field: reason.")
        if not isinstance(reason, str):
            raise ValueError("Detector field 'reason' must be a string.")

        return cls(
            chunk_id=chunk_id,
            case_id=case_id,
            decision=decision,
            risk_score=float(risk_score),
            is_suspicious=is_suspicious,
            reason=reason,
            trust_score=result.get("trust_score"),
            injection_probability=result.get("injection_probability"),
            metadata=dict(result.get("metadata") or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "chunk_id": self.chunk_id,
            "case_id": self.case_id,
            "decision": self.decision,
            "action": self.action,
            "risk_score": self.risk_score,
            "is_suspicious": self.is_suspicious,
            "is_safe": self.is_safe,
            "reason": self.reason,
            "trust_score": self.trust_score,
            "injection_probability": self.injection_probability,
            "metadata": dict(self.metadata),
        }
