"""DocumentChunk contract."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


def _normalize_source_trust(raw_value: Any) -> float | None:
    if raw_value is None:
        return None
    if isinstance(raw_value, bool):
        raise ValueError("source_trust_level must be numeric when provided.")
    if isinstance(raw_value, (int, float)):
        value = float(raw_value)
        if not 0.0 <= value <= 1.0:
            raise ValueError("source_trust_level must be between 0.0 and 1.0.")
        return value
    if isinstance(raw_value, str):
        normalized = raw_value.strip().lower()
        if normalized == "trusted":
            return 1.0
        if normalized == "untrusted":
            return 0.0
    return None


@dataclass(slots=True)
class DocumentChunk:
    """Standard chunk payload exchanged between retrieval and orchestration."""

    chunk_id: str
    text: str
    source_document_id: str
    source_trust_level: float | None = None
    retrieval_score: float | None = None
    case_id: str | None = None
    source: str | None = None
    source_metadata: dict[str, Any] = field(default_factory=dict)
    rank: int | None = None
    score_type: str | None = None

    def __post_init__(self) -> None:
        if not self.chunk_id.strip():
            raise ValueError("chunk_id must be a non-empty string.")
        if not self.text.strip():
            raise ValueError("text must be a non-empty string.")
        if not self.source_document_id.strip():
            raise ValueError("source_document_id must be a non-empty string.")
        if self.source_trust_level is not None and not 0.0 <= self.source_trust_level <= 1.0:
            raise ValueError("source_trust_level must be between 0.0 and 1.0.")
        if self.retrieval_score is not None:
            if isinstance(self.retrieval_score, bool) or not isinstance(
                self.retrieval_score, (int, float)
            ):
                raise ValueError("retrieval_score must be numeric when provided.")
            self.retrieval_score = float(self.retrieval_score)
        if self.rank is not None and self.rank < 1:
            raise ValueError("rank must be >= 1 when provided.")

    @classmethod
    def from_retrieval_chunk(cls, chunk: Mapping[str, Any]) -> "DocumentChunk":
        """Build a ``DocumentChunk`` from retriever fixture/runtime output."""

        source_metadata = dict(chunk.get("source_metadata") or {})
        trust_level = _normalize_source_trust(
            chunk.get("source_trust_level", source_metadata.get("source_trust_level"))
        )
        if trust_level is None:
            trust_level = _normalize_source_trust(source_metadata.get("source_trust"))

        retrieval_score = chunk.get("retrieval_score", chunk.get("score"))
        source_document_id = chunk.get("source_document_id", chunk.get("document_id"))
        if not source_document_id:
            raise ValueError("Chunk must include source_document_id or document_id.")

        return cls(
            chunk_id=str(chunk["chunk_id"]),
            text=str(chunk["text"]),
            source_document_id=str(source_document_id),
            source_trust_level=trust_level,
            retrieval_score=retrieval_score,
            case_id=chunk.get("case_id"),
            source=chunk.get("source"),
            source_metadata=source_metadata,
            rank=chunk.get("rank"),
            score_type=chunk.get("score_type"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "chunk_id": self.chunk_id,
            "case_id": self.case_id,
            "source_document_id": self.source_document_id,
            "text": self.text,
            "source": self.source,
            "source_trust_level": self.source_trust_level,
            "retrieval_score": self.retrieval_score,
            "rank": self.rank,
            "score_type": self.score_type,
            "source_metadata": dict(self.source_metadata),
        }
