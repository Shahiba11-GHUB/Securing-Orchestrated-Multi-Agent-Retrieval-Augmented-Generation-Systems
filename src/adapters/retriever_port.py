"""Retriever adapter interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Any

from src.contracts import DocumentChunk


class RetrieverPort(ABC):
    """Interface for retrieval providers used by orchestration agents."""

    @abstractmethod
    def retrieve(
        self,
        query: str,
        *,
        case_id: str | None = None,
        request_id: str | None = None,
        top_k: int | None = None,
        options: Mapping[str, Any] | None = None,
    ) -> list[DocumentChunk]:
        """Return ranked chunks for the input query.

        Implementations must raise explicit exceptions for invalid inputs or data
        source failures.
        """
