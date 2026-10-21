"""CLI for batch-running attack scenarios."""

from __future__ import annotations

import argparse

from src.adapters import BipiaFixtureRetriever, LayeredSecurityAdapter
from src.attack_harness import ScenarioRunner, default_scenarios
from src.orchestrator import OrchestratorEngine


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run attack harness scenarios.")
    parser.add_argument(
        "--dataset-root",
        default="BIPIA_EmailQA_20_Pairs",
        help="Path to BIPIA fixture root.",
    )
    parser.add_argument(
        "--scenario",
        action="append",
        choices=["clean", "attacked", "privilege_escalation", "all"],
        default=["all"],
        help=(
            "Scenario kind to run. Repeat for multiple kinds. "
            "Use 'all' to run clean, attacked, and privilege escalation."
        ),
    )
    return parser


def _resolve_requested_kinds(values: list[str]) -> set[str]:
    kinds = set(values)
    if "all" in kinds:
        return {"clean", "attacked", "privilege_escalation"}
    return kinds


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    retriever = BipiaFixtureRetriever(dataset_root=args.dataset_root)
    security = LayeredSecurityAdapter()
    engine = OrchestratorEngine(retriever=retriever, security_adapter=security)
    runner = ScenarioRunner(engine=engine)

    scenarios = default_scenarios(dataset_root=args.dataset_root)
    requested_kinds = _resolve_requested_kinds(args.scenario)
    selected = [scenario for scenario in scenarios if scenario.kind in requested_kinds]
    if not selected:
        raise ValueError("No scenarios selected to run.")

    summary = runner.run(selected)
    print(summary.to_json())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
