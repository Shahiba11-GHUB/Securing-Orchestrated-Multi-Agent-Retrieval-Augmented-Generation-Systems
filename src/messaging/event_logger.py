"""Structured event logging (JSONL)."""

from __future__ import annotations

import json
from pathlib import Path

from src.contracts import TraceEvent


class EventLogger:
    """Collects and optionally persists trace events as JSONL."""

    def __init__(self, *, jsonl_path: str | Path | None = None) -> None:
        self._events: list[TraceEvent] = []
        self._jsonl_path = Path(jsonl_path) if jsonl_path is not None else None

    def log(self, event: TraceEvent) -> None:
        if not isinstance(event, TraceEvent):
            raise TypeError("event must be a TraceEvent instance.")
        self._events.append(event)

        if self._jsonl_path is None:
            return

        self._jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        with self._jsonl_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event.to_dict(), sort_keys=True))
            handle.write("\n")

    def events(self, *, trace_id: str | None = None) -> list[TraceEvent]:
        if trace_id is None:
            return list(self._events)
        return [event for event in self._events if event.trace_id == trace_id]
