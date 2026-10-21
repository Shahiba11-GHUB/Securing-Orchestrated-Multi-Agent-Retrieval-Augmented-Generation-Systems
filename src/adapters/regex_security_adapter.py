"""Regex-detector security adapter."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from src.adapters.security_port import SecurityPort
from src.contracts import DocumentChunk, SecurityVerdict

try:
    from security.regex_detector import detect_injection_regex as _default_regex_detector
except ImportError:  # pragma: no cover - import path can differ in some IDE runs
    _default_regex_detector = None

DetectorResult = Mapping[str, Any]
RegexDetector = Callable[[str], DetectorResult]


class RegexSecurityAdapter(SecurityPort):
    """Normalize regex-detector output into ``SecurityVerdict``."""

    def __init__(
        self,
        detector: RegexDetector | None = None,
        *,
        suspicious_decision: str = "quarantine",
        benign_decision: str = "allow",
        suspicious_score: float = 0.9,
        benign_score: float = 0.1,
    ) -> None:
        self._detector = detector or _default_regex_detector
        if self._detector is None:
            raise ImportError("Regex detector could not be imported from security.regex_detector.")
        self._suspicious_decision = self._validate_decision(suspicious_decision, "suspicious")
        self._benign_decision = self._validate_decision(benign_decision, "benign")
        self._suspicious_score = self._validate_score(suspicious_score, "suspicious_score")
        self._benign_score = self._validate_score(benign_score, "benign_score")

    def screen_chunks(
        self,
        chunks: Sequence[DocumentChunk],
        *,
        request_id: str | None = None,
        options: Mapping[str, Any] | None = None,
    ) -> list[SecurityVerdict]:
        verdicts: list[SecurityVerdict] = []
        runtime_options = dict(options or {})

        suspicious_decision = self._validate_decision(
            runtime_options.get("suspicious_decision", self._suspicious_decision),
            "suspicious",
        )
        benign_decision = self._validate_decision(
            runtime_options.get("benign_decision", self._benign_decision),
            "benign",
        )
        suspicious_score = self._validate_score(
            runtime_options.get("suspicious_score", self._suspicious_score),
            "suspicious_score",
        )
        benign_score = self._validate_score(
            runtime_options.get("benign_score", self._benign_score),
            "benign_score",
        )

        for chunk in chunks:
            raw = self._detector(chunk.text)
            normalized = self._normalize_detector_result(raw, chunk)
            is_suspicious = normalized["is_suspicious"]
            matched_patterns = normalized["matched_patterns"]

            if is_suspicious:
                decision = suspicious_decision
                risk_score = suspicious_score
                reason = (
                    "Matched suspicious regex patterns: " + ", ".join(matched_patterns)
                    if matched_patterns
                    else "Regex detector flagged suspicious content."
                )
            else:
                decision = benign_decision
                risk_score = benign_score
                reason = "No suspicious regex pattern matched."

            verdicts.append(
                SecurityVerdict(
                    chunk_id=chunk.chunk_id,
                    case_id=chunk.case_id,
                    decision=decision,
                    risk_score=risk_score,
                    is_suspicious=is_suspicious,
                    reason=reason,
                    metadata={
                        "adapter": "regex",
                        "request_id": request_id,
                        "matched_patterns": matched_patterns,
                    },
                )
            )
        return verdicts

    @staticmethod
    def _normalize_detector_result(result: Mapping[str, Any], chunk: DocumentChunk) -> dict[str, Any]:
        if not isinstance(result, Mapping):
            raise ValueError(f"Regex detector returned non-mapping output for {chunk.chunk_id}.")

        is_suspicious = result.get("is_suspicious")
        if not isinstance(is_suspicious, bool):
            raise ValueError(
                f"Regex detector output for {chunk.chunk_id} must include bool is_suspicious."
            )

        raw_matches = result.get("matched_patterns", [])
        if raw_matches is None:
            raw_matches = []
        if not isinstance(raw_matches, list) or any(not isinstance(item, str) for item in raw_matches):
            raise ValueError(
                f"Regex detector output for {chunk.chunk_id} has invalid matched_patterns."
            )

        return {"is_suspicious": is_suspicious, "matched_patterns": raw_matches}

    @staticmethod
    def _validate_decision(value: Any, label: str) -> str:
        if value not in {"allow", "quarantine", "block"}:
            raise ValueError(f"{label}_decision must be allow, quarantine, or block.")
        return str(value)

    @staticmethod
    def _validate_score(value: Any, label: str) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{label} must be numeric in [0, 1].")
        numeric = float(value)
        if not 0.0 <= numeric <= 1.0:
            raise ValueError(f"{label} must be numeric in [0, 1].")
        return numeric
