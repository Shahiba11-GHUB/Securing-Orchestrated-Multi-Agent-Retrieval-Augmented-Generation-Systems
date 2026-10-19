from src.agents.base_agent import BaseAgent
from src.contracts import AgentMessage
from src.messaging.message_bus import MessageBus


class EchoAgent(BaseAgent):
    def handle_message(self, message: AgentMessage) -> AgentMessage:
        payload = {"echo": message.payload}
        return self.create_message(
            receiver_agent_id=message.sender_agent_id,
            payload=payload,
            trace_id=message.trace_id,
            parent_message_id=message.message_id,
            hop=message.hop + 1,
            metadata={"handled_by": self.agent_id},
        )


def test_message_bus_send_receive_fifo_order() -> None:
    bus = MessageBus()
    first = AgentMessage(
        sender_agent_id="retrieval",
        receiver_agent_id="security",
        payload={"idx": 1},
        privilege_level=2,
        trace_id="trace-1",
        message_id="msg-1",
    )
    second = AgentMessage(
        sender_agent_id="retrieval",
        receiver_agent_id="security",
        payload={"idx": 2},
        privilege_level=2,
        trace_id="trace-1",
        message_id="msg-2",
    )

    bus.send(first)
    bus.send(second)

    received = bus.receive_for("security")
    assert [m.message_id for m in received] == ["msg-1", "msg-2"]
    assert bus.has_messages("security") is False


def test_message_bus_preserves_trace_metadata() -> None:
    bus = MessageBus()
    message = AgentMessage(
        sender_agent_id="retrieval",
        receiver_agent_id="security",
        payload={"chunk_id": "c1"},
        privilege_level=2,
        trace_id="trace-prop-1",
        message_id="msg-parent",
        parent_message_id="root-msg",
        hop=3,
        scenario_id="scenario-attack-1",
        metadata={"source": "fixture"},
    )

    bus.send(message)
    result = bus.receive_for("security")[0]

    assert result.trace_id == "trace-prop-1"
    assert result.parent_message_id == "root-msg"
    assert result.hop == 3
    assert result.scenario_id == "scenario-attack-1"
    assert result.metadata["source"] == "fixture"


def test_message_bus_subscriber_receives_message() -> None:
    bus = MessageBus()
    observed: list[str] = []

    def subscriber(message: AgentMessage) -> None:
        observed.append(message.message_id)

    bus.register_subscriber("security", subscriber)
    bus.send(
        AgentMessage(
            sender_agent_id="retrieval",
            receiver_agent_id="security",
            payload={"x": 1},
            privilege_level=2,
            message_id="msg-sub-1",
            trace_id="trace-sub-1",
        )
    )

    assert observed == ["msg-sub-1"]


def test_base_agent_processes_and_emits_reply() -> None:
    bus = MessageBus()
    agent = EchoAgent(agent_id="security", role="security", privilege_level=3, bus=bus)

    inbound = AgentMessage(
        sender_agent_id="retrieval",
        receiver_agent_id="security",
        payload={"chunk_id": "case_001_chunk_001"},
        privilege_level=2,
        trace_id="trace-echo-1",
        message_id="msg-in-1",
        hop=0,
    )
    bus.send(inbound)

    outbound = agent.process_next()
    assert len(outbound) == 1
    assert outbound[0].receiver_agent_id == "retrieval"
    assert outbound[0].trace_id == "trace-echo-1"
    assert outbound[0].parent_message_id == "msg-in-1"
    assert outbound[0].hop == 1

    received_by_sender = bus.receive_for("retrieval")
    assert len(received_by_sender) == 1
    assert received_by_sender[0].payload["echo"] == {"chunk_id": "case_001_chunk_001"}
