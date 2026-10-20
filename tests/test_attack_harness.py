from src.adapters.retriever_port import RetrieverPort
from src.adapters.security_port import SecurityPort
from src.attack_harness import AttackScenario, ScenarioRunner, default_scenarios
from src.contracts import DocumentChunk, SecurityVerdict
from src.orchestrator import OrchestratorEngine


class StubRetriever(RetrieverPort):
    def retrieve(
        self,
        query: str,
        *,
        case_id: str | None = None,
        request_id: str | None = None,
        top_k: int | None = None,
        options: dict | None = None,
    ) -> list[DocumentChunk]:
        if case_id is None:
            raise ValueError("case_id required for stub retriever.")
        chunks = [
            DocumentChunk(
                chunk_id=f"{case_id}_chunk_001",
                case_id=case_id,
                text=f"chunk for {query}",
                source_document_id="doc-1",
                source_trust_level=0.0,
                source="stub://source/1",
            )
        ]
        if top_k is None:
            return chunks
        return chunks[:top_k]


class StubSecurity(SecurityPort):
    def screen_chunks(
        self,
        chunks: list[DocumentChunk],
        *,
        request_id: str | None = None,
        options: dict | None = None,
    ) -> list[SecurityVerdict]:
        verdicts: list[SecurityVerdict] = []
        for chunk in chunks:
            suspicious = chunk.case_id == "case-attacked"
            verdicts.append(
                SecurityVerdict(
                    chunk_id=chunk.chunk_id,
                    case_id=chunk.case_id,
                    decision="quarantine" if suspicious else "allow",
                    risk_score=0.95 if suspicious else 0.05,
                    is_suspicious=suspicious,
                    reason="stub suspicious" if suspicious else "stub clean",
                )
            )
        return verdicts


def test_scenario_runner_returns_expected_aggregate_summary() -> None:
    engine = OrchestratorEngine(retriever=StubRetriever(), security_adapter=StubSecurity())
    runner = ScenarioRunner(engine=engine)
    scenarios = [
        AttackScenario(
            scenario_id="clean-1",
            kind="clean",
            description="clean flow",
            mode="orchestrator_query",
            query="Find payment",
            case_id="case-clean",
        ),
        AttackScenario(
            scenario_id="attacked-1",
            kind="attacked",
            description="attacked flow",
            mode="orchestrator_query",
            query="Find payment",
            case_id="case-attacked",
        ),
        AttackScenario(
            scenario_id="priv-1",
            kind="privilege_escalation",
            description="privilege escalation probe",
            mode="direct_privilege_probe",
            query="Escalate privilege now",
            source_privilege_level=1,
        ),
    ]

    summary = runner.run(scenarios)

    assert summary.total_scenarios == 3
    assert summary.allow_count == 1
    assert summary.blocked_count == 2
    assert summary.blocked_paths == 2
    assert summary.quarantined_paths == 1
    assert summary.action_counts == {"allow": 1, "block": 1, "quarantine": 1}


def test_default_scenarios_include_required_kinds() -> None:
    scenarios = default_scenarios()
    kinds = {scenario.kind for scenario in scenarios}
    assert kinds == {"clean", "attacked", "privilege_escalation"}
