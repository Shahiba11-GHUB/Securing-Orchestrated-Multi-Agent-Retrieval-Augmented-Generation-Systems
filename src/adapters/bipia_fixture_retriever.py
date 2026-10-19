"""BIPIA fixture-based retriever adapter."""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from src.adapters.retriever_port import RetrieverPort
from src.contracts import DocumentChunk


class BipiaFixtureRetriever(RetrieverPort):
    """Retriever backed by the BIPIA fixture package.

    This adapter does not run retrieval ranking. It loads pre-generated chunks
    and filters by ``case_id``.
    """

    def __init__(self, dataset_root: str | Path = "BIPIA_EmailQA_20_Pairs") -> None:
        self._root = Path(dataset_root)
        self._queries_path = self._root / "data" / "queries.jsonl"
        self._clean_chunks_path = self._root / "data" / "clean_chunks.jsonl"
        self._attacked_chunks_path = self._root / "data" / "attacked_chunks.jsonl"

        self._queries_by_case: dict[str, str] = {}
        self._chunks_by_case: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._loaded = False

    def retrieve(
        self,
        query: str,
        *,
        case_id: str | None = None,
        request_id: str | None = None,
        top_k: int | None = None,
        options: Mapping[str, Any] | None = None,
    ) -> list[DocumentChunk]:
        if not isinstance(query, str) or not query.strip():
            raise ValueError("query must be a non-empty string.")
        if case_id is None or not str(case_id).strip():
            raise ValueError("case_id is required for fixture retrieval.")
        if top_k is not None and top_k < 1:
            raise ValueError("top_k must be >= 1 when provided.")

        self._ensure_loaded()
        normalized_case_id = str(case_id)

        if normalized_case_id not in self._queries_by_case:
            raise KeyError(f"Unknown case_id: {normalized_case_id}")

        expected_query = self._queries_by_case[normalized_case_id]
        enforce_query_match = bool((options or {}).get("enforce_query_match", False))
        if enforce_query_match and query.strip() != expected_query:
            raise ValueError(
                f"Query mismatch for case_id '{normalized_case_id}'. "
                "Pass the paired fixture query or disable enforce_query_match."
            )

        selected_chunks = list(self._chunks_by_case.get(normalized_case_id, []))
        if not selected_chunks:
            raise ValueError(f"No fixture chunks found for case_id: {normalized_case_id}")

        if top_k is not None:
            selected_chunks = selected_chunks[:top_k]

        return [DocumentChunk.from_retrieval_chunk(chunk) for chunk in selected_chunks]

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._load_queries()
        self._load_chunks(self._clean_chunks_path)
        self._load_chunks(self._attacked_chunks_path)
        self._loaded = True

    def _load_queries(self) -> None:
        if not self._queries_path.exists():
            raise FileNotFoundError(f"Missing fixture file: {self._queries_path}")
        for row in self._read_jsonl(self._queries_path):
            case_id = row.get("case_id")
            query = row.get("query")
            if not isinstance(case_id, str) or not case_id.strip():
                raise ValueError(f"Invalid case_id in {self._queries_path}")
            if not isinstance(query, str) or not query.strip():
                raise ValueError(f"Invalid query in {self._queries_path} for case_id={case_id}")
            self._queries_by_case[case_id] = query

    def _load_chunks(self, file_path: Path) -> None:
        if not file_path.exists():
            raise FileNotFoundError(f"Missing fixture file: {file_path}")
        for row in self._read_jsonl(file_path):
            case_id = row.get("case_id")
            if not isinstance(case_id, str) or not case_id.strip():
                raise ValueError(f"Invalid case_id in {file_path}")
            self._chunks_by_case[case_id].append(row)

    @staticmethod
    def _read_jsonl(file_path: Path) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        with file_path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                text = line.strip()
                if not text:
                    continue
                try:
                    parsed = json.loads(text)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"Invalid JSONL row in {file_path} at line {line_number}"
                    ) from exc
                if not isinstance(parsed, dict):
                    raise ValueError(
                        f"Expected object rows in {file_path} at line {line_number}"
                    )
                rows.append(parsed)
        return rows
