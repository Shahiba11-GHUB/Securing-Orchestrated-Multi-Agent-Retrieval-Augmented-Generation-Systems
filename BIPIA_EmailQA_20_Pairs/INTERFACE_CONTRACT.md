# Proposed integration contract v1.0 — team confirmation required

## Detector input
Each retrieved chunk contains:

- `chunk_id`: globally unique string, including case and chunk number.
- `case_id`: evaluation case ID. Neutral identifier; does not disclose clean/attacked status.
- `document_id`: original email identity, shared by its clean/attacked versions.
- `text`: exact chunk text, including an injected instruction if present.
- `source`: stable `bipia://email/train/<zero-based-row>` provenance identifier; not a live URL.
- `source_metadata`: dataset, task, original split, pinned revision, `source_trust`, character offsets and chunk hash.

All documents use `source_trust: "untrusted"`. This describes the instruction boundary, not the probability of an attack. A legitimate email can be untrusted input. Any numeric source-reputation score must be a separately defined, system-assigned field; never derive it from attack labels.

The retrieval envelope contains `schema_version`, `request_id`, `case_id`, `query`, `retrieval_method`, `is_mock`, `chunks`. The fixture adapter uses `retrieval_method: "fixture"` and `is_mock: true`. It returns the selected case's chunks directly, without search or ranking. Real retrieval can later add `rank`, `score`, and `score_type`; retrieval scores must never be treated as risk or trust probabilities.

## Detector output
Return one result per chunk:

```json
{
  "chunk_id": "case_001_chunk_001",
  "case_id": "case_001",
  "is_suspicious": true,
  "risk_score": 0.85,
  "decision": "quarantine",
  "reason": "Embedded instruction attempts to redirect the answer."
}
```

This is an illustrative decision, not a measured model result. `risk_score` is numeric in [0,1], higher means greater injection risk. Unless calibrated, describe it as a detector score, not a probability. Allowed decisions: `allow`, `quarantine`, `block`. The security owner defines thresholds and the relation between score, suspicious flag and decision, then freezes those on development data. Missing/invalid outputs should quarantine the chunk at integration rather than silently allow it.

Call signature for the supplied integration adapter:

```python
detector(text=chunk['text'], source=chunk['source'], source_metadata=chunk['source_metadata'])
```

Return `is_suspicious`, `risk_score`, `decision`, `reason`; the adapter attaches the original `chunk_id` and `case_id`. An `allow` decision does not authorize executing instructions inside documents or writing trusted memory. All document text remains untrusted.

## Evaluation isolation
`data/evaluation_private.jsonl` and `data/review.csv` are evaluator-only. Never pass them to the detector, generator or agents. They contain paired-case mapping, expected answers and attack spans. Only chunks intersecting the injected text are injection-positive for chunk-level scoring; an attacked document may contain clean chunks. Original-document recovery is a source-retrieval proxy, not an independently annotated relevance judgment.
