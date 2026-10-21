from src.adapters.retriever_port import RetrieverPort
from src.adapters.security_port import SecurityPort
from src.contracts import DocumentChunk, SecurityVerdict
from src.orchestrator.engine import OrchestratorEngine


class StubRetriever(RetrieverPort):
    def __init__(self, chunks: list[DocumentChunk]) -> None:
        self._chunks = chunks

    def retrieve(
        self,
        query: str,
        *,
        case_id: str | None = None,
        request_id: str | None = None,
        top_k: int | None = None,
        options: dict | None = None,
    ) -> list[DocumentChunk]:
        if top_k is None:
            return list(self._chunks)
        return list(self._chunks[:top_k])


class StubSecurity(SecurityPort):
    def __init__(self, suspicious: bool) -> None:
        self._suspicious = suspicious

    def screen_chunks(
        self,
        chunks: list[DocumentChunk],
        *,
        request_id: str | None = None,
        options: dict | None = None,
    ) -> list[SecurityVerdict]:
        verdicts: list[SecurityVerdict] = []
        for chunk in chunks:
            verdicts.append(
                SecurityVerdict(
                    chunk_id=chunk.chunk_id,
                    case_id=chunk.case_id,
                    decision="quarantine" if self._suspicious else "allow",
                    risk_score=0.9 if self._suspicious else 0.1,
                    is_suspicious=self._suspicious,
                    reason="stub suspicious" if self._suspicious else "stub benign",
                )
            )
        return verdicts


def _sample_chunks() -> list[DocumentChunk]:
    return [
        DocumentChunk(
            chunk_id="case_001_chunk_001",
            case_id="case_001",
            text="sample text",
            source_document_id="email_train_001",
            source_trust_level=0.0,
        ),
        DocumentChunk(
            chunk_id="case_001_chunk_002",
            case_id="case_001",
            text="second sample text",
            source_document_id="email_train_001",
            source_trust_level=0.0,
        ),
    ]


def test_orchestrator_allows_when_security_allows() -> None:
    engine = OrchestratorEngine(
        retriever=StubRetriever(_sample_chunks()),
        security_adapter=StubSecurity(suspicious=False),
    )

    result = engine.process_query(
        query="Find payment amount",
        case_id="case_001",
        top_k=1,
        scenario_id="scenario-clean",
    )

    assert result.final_message.payload["status"] == "allow"
    assert result.final_message.payload["allowed_chunks"] == 1
    assert result.final_message.payload["blocked_or_quarantined_chunks"] == 0
    assert len(result.history) == 4
    assert [m.sender_agent_id for m in result.history] == [
        "orchestrator",
        "retrieval-agent",
        "security-agent",
        "action-agent",
    ]
    assert [m.receiver_agent_id for m in result.history] == [
        "retrieval-agent",
        "security-agent",
        "action-agent",
        "orchestrator",
    ]


def test_orchestrator_blocks_when_security_flags_content() -> None:
    engine = OrchestratorEngine(
        retriever=StubRetriever(_sample_chunks()),
        security_adapter=StubSecurity(suspicious=True),
    )

    result = engine.process_query(
        query="Find payment amount",
        case_id="case_001",
        top_k=2,
        scenario_id="scenario-attacked",
    )

    assert result.final_message.payload["status"] == "blocked"
    assert result.final_message.payload["allowed_chunks"] == 0
    assert result.final_message.payload["blocked_or_quarantined_chunks"] == 2
    assert all(action == "quarantine" for action in result.final_message.payload["actions"])
