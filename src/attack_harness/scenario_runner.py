"""Scenario runner for clean vs attacked experiments."""

from __future__ import annotations

from src.attack_harness.injector import build_privilege_escalation_probe
from src.attack_harness.report import ScenarioOutcome, ScenarioSummary, summarize_outcomes
from src.attack_harness.scenarios import AttackScenario
from src.orchestrator.engine import OrchestrationResult, OrchestratorEngine


class ScenarioRunner:
    """Executes attack-harness scenarios against the orchestrator."""

    def __init__(self, *, engine: OrchestratorEngine) -> None:
        self._engine = engine

    def run(self, scenarios: list[AttackScenario]) -> ScenarioSummary:
        outcomes = [self.run_one(scenario) for scenario in scenarios]
        return summarize_outcomes(outcomes)

    def run_one(self, scenario: AttackScenario) -> ScenarioOutcome:
        if scenario.mode == "orchestrator_query":
            result = self._run_orchestrator_query(scenario)
        elif scenario.mode == "direct_privilege_probe":
            result = self._run_privilege_probe(scenario)
        else:
            raise ValueError(f"Unsupported scenario mode: {scenario.mode}")
        return self._to_outcome(result=result, scenario=scenario)

    def _run_orchestrator_query(self, scenario: AttackScenario) -> OrchestrationResult:
        if scenario.case_id is None:
            raise ValueError(f"case_id is required for scenario mode {scenario.mode}")
        return self._engine.process_query(
            query=scenario.query,
            case_id=scenario.case_id,
            top_k=scenario.top_k,
            scenario_id=scenario.scenario_id,
        )

    def _run_privilege_probe(self, scenario: AttackScenario) -> OrchestrationResult:
        envelope = build_privilege_escalation_probe(
            routes=self._engine.routes,
            query=scenario.query,
            scenario_id=scenario.scenario_id,
            source_privilege_level=scenario.source_privilege_level,
        )
        self._engine.bus.send(envelope.message)
        self._engine.action_agent.process_next()
        final_messages = self._engine.bus.receive_for(self._engine.routes.orchestrator_id)
        if not final_messages:
            raise RuntimeError("No final response produced for direct privilege probe.")
        final_message = final_messages[-1]
        history = self._engine.bus.history(trace_id=envelope.trace_id)
        return OrchestrationResult(
            trace_id=envelope.trace_id,
            final_message=final_message,
            history=history,
        )

    @staticmethod
    def _to_outcome(
        *,
        result: OrchestrationResult,
        scenario: AttackScenario,
    ) -> ScenarioOutcome:
        payload = result.final_message.payload
        if not isinstance(payload, dict):
            raise ValueError("Expected dictionary payload in final orchestrator message.")

        status = payload.get("status")
        policy_action = payload.get("policy_action")
        if not isinstance(status, str):
            raise ValueError("Final payload missing required string field: status")
        if not isinstance(policy_action, str):
            raise ValueError("Final payload missing required string field: policy_action")
        blocked_or_quarantined_chunks = payload.get("blocked_or_quarantined_chunks", 0)
        if not isinstance(blocked_or_quarantined_chunks, int):
            raise ValueError("blocked_or_quarantined_chunks must be int.")
        actions = payload.get("actions", [])
        if not isinstance(actions, list):
            raise ValueError("actions must be list.")

        return ScenarioOutcome(
            scenario_id=scenario.scenario_id,
            scenario_kind=scenario.kind,
            status=status,
            policy_action=policy_action,
            trace_id=result.trace_id,
            history_hops=len(result.history),
            blocked_or_quarantined_chunks=blocked_or_quarantined_chunks,
            actions=[str(action) for action in actions],
            metadata={"description": scenario.description},
        )
