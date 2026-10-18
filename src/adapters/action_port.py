"""Action adapter interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Any

from src.contracts import AgentMessage


class ActionPort(ABC):
    """Interface for action/tool execution providers."""

    @abstractmethod
    def execute(
        self,
        message: AgentMessage,
        *,
        options: Mapping[str, Any] | None = None,
    ) -> AgentMessage:
        """Execute an action request and return a response message.

        Implementations must raise explicit exceptions when execution is blocked,
        unauthorized, or fails.
        """
