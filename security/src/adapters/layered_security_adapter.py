"""Adapter connecting the layered detector to Mark's SecurityPort contract."""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from src.adapters.security_port import SecurityPort
from src.contracts import DocumentChunk, SecurityVerdict

try:
    from security.layered_detector import layered_detector as _default_detector
except ImportError:
    _default_detector = None

LayeredDetector = Callable[..., Mapping[str, Any]]


class LayeredSecurityAdapter(SecurityPort):
    """Screen retrieved chunks using the layered rule-based detector."""

    def __init__(self, detector: LayeredDetector | None = None) -> None:
        self._detector = detector if detector is not None else _default_detector
        if self._detector is None:
            raise ImportError(
                "Cannot import security.layered_detector.layered_detector. "
                "Add layered_detector.py to the security package."
            )

    def screen_chunks(
        self,
        chunks: Sequence[DocumentChunk],
        *,
        request_id: str | None = None,
        options: Mapping[str, Any] | None = None,
    ) -> list[SecurityVerdict]:
        if options:
            raise ValueError("LayeredSecurityAdapter does not support runtime policy overrides.")

        verdicts = []
        for chunk in chunks:
            result = self._detector(
                text=chunk.text,
                source=chunk.source,
                source_metadata=dict(chunk.source_metadata),
            )
            if not isinstance(result, Mapping):
                raise ValueError(f"Invalid detector output for {chunk.chunk_id}: expected mapping")
            verdict = SecurityVerdict.from_detector_result(
                result,
                chunk_id=chunk.chunk_id,
                case_id=chunk.case_id,
            )
            # A detector that flags suspicious content must not allow it downstream.
            if verdict.is_suspicious and verdict.decision == "allow":
                raise ValueError(f"Contradictory detector result for {chunk.chunk_id}")
            verdict.metadata.update({
                "adapter": "layered",
                "request_id": request_id,
                "source": chunk.source,
                "source_metadata": dict(chunk.source_metadata),
                "instruction_authority": False,
            })
            verdicts.append(verdict)
        return verdicts
