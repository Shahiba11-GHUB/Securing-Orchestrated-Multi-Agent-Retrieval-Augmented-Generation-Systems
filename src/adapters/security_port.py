"""Security adapter interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from typing import Any

from src.contracts import DocumentChunk, SecurityVerdict


class SecurityPort(ABC):
    """Interface for security-screening providers."""

    @abstractmethod
    def screen_chunks(
        self,
        chunks: Sequence[DocumentChunk],
        *,
        request_id: str | None = None,
        options: Mapping[str, Any] | None = None,
    ) -> list[SecurityVerdict]:
        """Classify chunks and return one verdict per chunk.

        Implementations must raise explicit exceptions for malformed model output
        and contract-violating verdict fields.
        """
