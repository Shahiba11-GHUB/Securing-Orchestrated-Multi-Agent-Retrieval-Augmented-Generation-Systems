import json

from src.contracts import AgentMessage
from src.messaging import EventLogger, MessageBus, PropagationTracker


def _message(
    *,
    sender: str,
    receiver: str,
    trace_id: str,
    message_id: str,
    parent_message_id: str | None,
    hop: int,
    payload: dict,
    metadata: dict | None = None,
) -> AgentMessage:
    return AgentMessage(
        sender_agent_id=sender,
        receiver_agent_id=receiver,
        payload=payload,
        privilege_level=3,
        trace_id=trace_id,
        message_id=message_id,
        parent_message_id=parent_message_id,
        hop=hop,
        scenario_id="scenario-propagation",
        metadata=dict(metadata or {}),
    )


def test_propagation_tracker_builds_lineage_and_decisions(tmp_path) -> None:
    trace_id = "trace-001"
    log_path = tmp_path / "events.jsonl"
    logger = EventLogger(jsonl_path=log_path)
    tracker = PropagationTracker()
    bus = MessageBus(event_logger=logger, propagation_tracker=tracker)

    m1 = _message(
        sender="orchestrator",
        receiver="retrieval-agent",
        trace_id=trace_id,
        message_id="m1",
        parent_message_id=None,
        hop=0,
        payload={"query": "Find amount"},
    )
    m2 = _message(
        sender="retrieval-agent",
        receiver="security-agent",
        trace_id=trace_id,
        message_id="m2",
        parent_message_id="m1",
        hop=1,
        payload={"chunks": ["c1"]},
    )
    m3 = _message(
        sender="security-agent",
        receiver="action-agent",
        trace_id=trace_id,
        message_id="m3",
        parent_message_id="m2",
        hop=2,
        payload={"verdicts": ["quarantine"]},
    )
    m4 = _message(
        sender="action-agent",
        receiver="orchestrator",
        trace_id=trace_id,
        message_id="m4",
        parent_message_id="m3",
        hop=3,
        payload={"status": "blocked"},
        metadata={"policy_action": "quarantine"},
    )

    for message in (m1, m2, m3, m4):
        bus.send(message)

    events = logger.events(trace_id=trace_id)
    assert len(events) == 4
    assert all(event.event_type == "message_sent" for event in events)

    edges = tracker.lineage_edges(trace_id=trace_id)
    assert edges == [("m1", "m2"), ("m2", "m3"), ("m3", "m4")]

    decisions = tracker.decision_transitions(trace_id=trace_id)
    assert decisions == ["quarantine"]

    log_lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(log_lines) == 4
    parsed = [json.loads(line) for line in log_lines]
    assert parsed[0]["trace_id"] == trace_id
    assert parsed[-1]["decision"] == "quarantine"
