"""Attack harness and scenario execution."""

from .injector import InjectorEnvelope, build_privilege_escalation_probe
from .report import ScenarioOutcome, ScenarioSummary, summarize_outcomes
from .scenario_runner import ScenarioRunner
from .scenarios import AttackScenario, default_scenarios

__all__ = [
    "AttackScenario",
    "InjectorEnvelope",
    "ScenarioOutcome",
    "ScenarioRunner",
    "ScenarioSummary",
    "build_privilege_escalation_probe",
    "default_scenarios",
    "summarize_outcomes",
]
