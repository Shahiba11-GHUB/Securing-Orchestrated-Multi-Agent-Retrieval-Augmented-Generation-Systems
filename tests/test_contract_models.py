from src.contracts import AgentMessage, DocumentChunk, SecurityVerdict, TraceEvent


def test_document_chunk_from_retrieval_chunk_maps_fixture_fields() -> None:
    fixture_chunk = {
        "chunk_id": "case_001_chunk_001",
        "case_id": "case_001",
        "document_id": "email_train_001",
        "text": "content",
        "source": "bipia://email/train/1",
        "source_metadata": {"source_trust": "untrusted"},
        "score": 0.92,
    }

    chunk = DocumentChunk.from_retrieval_chunk(fixture_chunk)

    assert chunk.source_document_id == "email_train_001"
    assert chunk.source_trust_level == 0.0
    assert chunk.retrieval_score == 0.92


def test_security_verdict_from_detector_result_accepts_contract_shape() -> None:
    result = {
        "decision": "quarantine",
        "risk_score": 0.9,
        "is_suspicious": True,
        "reason": "Prompt injection pattern detected.",
    }

    verdict = SecurityVerdict.from_detector_result(result, chunk_id="c1", case_id="case_001")

    assert verdict.action == "quarantine"
    assert verdict.is_safe is False


def test_agent_message_enforces_privilege_range() -> None:
    message = AgentMessage(
        sender_agent_id="orchestrator",
        receiver_agent_id="security-agent",
        payload={"query": "hello"},
        privilege_level=3,
    )

    assert message.privilege_level == 3
    assert message.hop == 0


def test_trace_event_requires_non_empty_event_type() -> None:
    event = TraceEvent(event_type="security_decision", trace_id="trace-1")
    assert event.event_type == "security_decision"
