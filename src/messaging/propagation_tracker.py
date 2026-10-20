"""Attack propagation tracking across hops and agents."""

from __future__ import annotations

from collections import defaultdict

from src.contracts import TraceEvent


class PropagationTracker:
    """Maintains message lineage and decision transitions per trace."""

    def __init__(self) -> None:
        self._events_by_trace: dict[str, list[TraceEvent]] = defaultdict(list)

    def record(self, event: TraceEvent) -> None:
        if not isinstance(event, TraceEvent):
            raise TypeError("event must be a TraceEvent instance.")
        self._events_by_trace[event.trace_id].append(event)

    def events(self, *, trace_id: str) -> list[TraceEvent]:
        if not isinstance(trace_id, str) or not trace_id.strip():
            raise ValueError("trace_id must be a non-empty string.")
        return list(self._events_by_trace.get(trace_id, []))

    def lineage_edges(self, *, trace_id: str) -> list[tuple[str, str]]:
        trace_events = self.events(trace_id=trace_id)
        edges: list[tuple[str, str]] = []
        for event in trace_events:
            if event.parent_message_id is None or event.message_id is None:
                continue
            edges.append((event.parent_message_id, event.message_id))
        return edges

    def decision_transitions(self, *, trace_id: str) -> list[str]:
        trace_events = self.events(trace_id=trace_id)
        return [event.decision for event in trace_events if isinstance(event.decision, str)]
