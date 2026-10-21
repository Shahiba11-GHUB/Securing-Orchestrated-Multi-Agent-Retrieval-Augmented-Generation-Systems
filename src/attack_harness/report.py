"""Post-run reporting and summary generation."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class ScenarioOutcome:
    """Single scenario execution outcome."""

    scenario_id: str
    scenario_kind: str
    status: str
    policy_action: str
    trace_id: str
    history_hops: int
    blocked_or_quarantined_chunks: int
    actions: list[str]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "scenario_kind": self.scenario_kind,
            "status": self.status,
            "policy_action": self.policy_action,
            "trace_id": self.trace_id,
            "history_hops": self.history_hops,
            "blocked_or_quarantined_chunks": self.blocked_or_quarantined_chunks,
            "actions": list(self.actions),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class ScenarioSummary:
    """Aggregate summary across scenario outcomes."""

    total_scenarios: int
    allow_count: int
    blocked_count: int
    quarantined_paths: int
    blocked_paths: int
    action_counts: dict[str, int]
    outcomes: list[ScenarioOutcome]

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_scenarios": self.total_scenarios,
            "allow_count": self.allow_count,
            "blocked_count": self.blocked_count,
            "quarantined_paths": self.quarantined_paths,
            "blocked_paths": self.blocked_paths,
            "action_counts": dict(self.action_counts),
            "outcomes": [outcome.to_dict() for outcome in self.outcomes],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


def summarize_outcomes(outcomes: list[ScenarioOutcome]) -> ScenarioSummary:
    action_counts: dict[str, int] = {}
    allow_count = 0
    blocked_count = 0
    quarantined_paths = 0
    blocked_paths = 0

    for outcome in outcomes:
        if outcome.status == "allow":
            allow_count += 1
        else:
            blocked_count += 1
        if outcome.policy_action == "quarantine":
            quarantined_paths += 1
        if outcome.status == "blocked":
            blocked_paths += 1
        action_counts[outcome.policy_action] = action_counts.get(outcome.policy_action, 0) + 1

    return ScenarioSummary(
        total_scenarios=len(outcomes),
        allow_count=allow_count,
        blocked_count=blocked_count,
        quarantined_paths=quarantined_paths,
        blocked_paths=blocked_paths,
        action_counts=action_counts,
        outcomes=list(outcomes),
    )
