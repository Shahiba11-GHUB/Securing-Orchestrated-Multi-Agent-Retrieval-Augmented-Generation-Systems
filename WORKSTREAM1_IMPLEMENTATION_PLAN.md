# Workstream 1 Implementation Plan (Orchestration, Messaging, Attack Harness)

This plan is for **Mark / Workstream 1** and is designed for **small, meaningful, testable changes**.
It aligns with FR1.1–FR1.6 in [FunctionalRequirements.md](./FunctionalRequirements.md).

## 0) Current baseline (already done)

- Scaffolded modules under [src/](./src)
- Contract models implemented in [src/contracts/](./src/contracts)
  - [document_chunk.py](./src/contracts/document_chunk.py)
  - [security_verdict.py](./src/contracts/security_verdict.py)
  - [agent_message.py](./src/contracts/agent_message.py)
  - [trace_event.py](./src/contracts/trace_event.py)
- Contract tests in [tests/test_contract_models.py](./tests/test_contract_models.py)

---

## Implementation principles

1. **One change set = one purpose** (easy review + rollback).
2. **Each step must run** (tests or executable smoke script).
3. **Prefer adapters over direct teammate imports** to absorb interface drift.
4. **No silent fallback behavior** for security decisions.
5. **Track trace IDs everywhere** once messaging begins.

---

## Step-by-step execution plan

## Step 1 — Import teammate artifacts (integration prerequisites)

**FR coverage:** prerequisite for FR1.4, FR1.5, FR1.6  
**Goal:** bring in retrieval fixtures and baseline detector code used by adapters.

### Files/paths
- Add `BIPIA_EmailQA_20_Pairs/` from `sameer/bipia-emailqa-dev`
- Add `security/` from `feature/security-defense`

### Acceptance criteria
- Both folders exist in this branch.
- `BIPIA_EmailQA_20_Pairs/mock_adapter.py` can run locally.
- No contract files changed in this step.

### Validation
- Run fixture script for one case.

### Suggested commit message
`Import teammate fixture and security baseline code`

---

## Step 2 — Define adapter port interfaces

**FR coverage:** FR1.1, FR1.3  
**Goal:** freeze orchestration-facing interfaces before implementation details.

### Files
- [src/adapters/retriever_port.py](./src/adapters/retriever_port.py)
- [src/adapters/security_port.py](./src/adapters/security_port.py)
- [src/adapters/action_port.py](./src/adapters/action_port.py)

### Acceptance criteria
- Ports are abstract/protocol interfaces.
- Signatures use contracts (`DocumentChunk`, `SecurityVerdict`, `AgentMessage`).
- Errors are explicit (no empty default returns).

### Validation
- Unit test import checks pass.

### Suggested commit message
`Define retrieval security action adapter ports`

---

## Step 3 — Implement BIPIA fixture retriever adapter

**FR coverage:** FR1.1, FR1.4  
**Goal:** convert fixture retrieval payloads into `DocumentChunk`.

### Files
- [src/adapters/bipia_fixture_retriever.py](./src/adapters/bipia_fixture_retriever.py)
- Add test: `tests/test_bipia_fixture_retriever.py`

### Acceptance criteria
- Adapter loads by `case_id`.
- Returns `list[DocumentChunk]`.
- Preserves source metadata and case IDs.
- Fails explicitly on missing case/data.

### Validation
- Test with at least 1 known case.
- Check mapping for `document_id -> source_document_id`, score/trust fields.

### Suggested commit message
`Implement BIPIA fixture retriever adapter`

---

## Step 4 — Implement security adapters (keyword first, regex second)

**FR coverage:** FR1.1, FR1.5  
**Goal:** normalize teammate detector outputs to `SecurityVerdict`.

### Files
- [src/adapters/keyword_security_adapter.py](./src/adapters/keyword_security_adapter.py)
- [src/adapters/regex_security_adapter.py](./src/adapters/regex_security_adapter.py)
- Add test: `tests/test_security_adapters.py`

### Acceptance criteria
- Accepts `DocumentChunk` list and returns `SecurityVerdict` list.
- Fills required fields (`decision`, `risk_score`, `reason`, `is_suspicious`).
- Decision values limited to `allow|quarantine|block`.
- Invalid detector outputs raise explicit exceptions.

### Validation
- Clean sample -> `allow`
- Injected sample -> `quarantine` (or `block` per policy)

### Suggested commit message
`Implement security verdict normalization adapters`

---

## Step 5 — Build message bus and messaging protocol

**FR coverage:** FR1.3, FR1.5  
**Goal:** operational message exchange with trace propagation.

### Files
- [src/messaging/message_bus.py](./src/messaging/message_bus.py)
- [src/agents/base_agent.py](./src/agents/base_agent.py)
- Replace placeholder: [tests/test_message_bus.py](./tests/test_message_bus.py)

### Acceptance criteria
- Can send and retrieve `AgentMessage`.
- Preserves `trace_id`, `message_id`, `parent_message_id`, `hop`.
- Supports deterministic ordering for test runs.

### Validation
- Message bus tests verify order, routing, metadata integrity.

### Suggested commit message
`Implement message bus with trace-aware agent messages`

---

## Step 6 — Implement minimal orchestrator engine (vertical slice)

**FR coverage:** FR1.1, FR1.2, FR1.3  
**Goal:** end-to-end flow from query to decision.

### Files
- [src/orchestrator/engine.py](./src/orchestrator/engine.py)
- [src/orchestrator/router.py](./src/orchestrator/router.py)
- [src/agents/retrieval_agent.py](./src/agents/retrieval_agent.py)
- [src/agents/security_agent.py](./src/agents/security_agent.py)
- [src/agents/action_agent.py](./src/agents/action_agent.py)
- Replace placeholder: [tests/test_orchestrator_routing.py](./tests/test_orchestrator_routing.py)

### Acceptance criteria
- Query -> retrieval agent -> security agent -> action decision flow works.
- Routing is deterministic and testable.
- Security decisions gate downstream actions.

### Validation
- One integration-style unit test for full flow.

### Suggested commit message
`Implement minimal orchestrator retrieval-security-action flow`

---

## Step 7 — Add policy and privilege escalation controls

**FR coverage:** FR1.6 (+ supports FR1.5)  
**Goal:** prevent low-privilege compromised paths to high-privilege execution.

### Files
- [src/orchestrator/policy.py](./src/orchestrator/policy.py)
- [src/orchestrator/privilege.py](./src/orchestrator/privilege.py)
- Replace placeholder: [tests/test_privilege_escalation.py](./tests/test_privilege_escalation.py)
- Replace placeholder: [tests/test_security_policy.py](./tests/test_security_policy.py)

### Acceptance criteria
- Policy encodes allow/quarantine/block behavior.
- Privilege boundary checks are explicit and logged.
- Simulated low->high escalation is blocked/quarantined per policy.

### Validation
- Tests cover at least:
  - clean low->high path allowed
  - suspicious low->high path blocked

### Suggested commit message
`Add policy and privilege escalation enforcement`

---

## Step 8 — Add propagation tracking and event logging

**FR coverage:** FR1.5  
**Goal:** reconstruct attack spread through orchestrator flow.

### Files
- [src/messaging/event_logger.py](./src/messaging/event_logger.py)
- [src/messaging/propagation_tracker.py](./src/messaging/propagation_tracker.py)
- Replace placeholder: [tests/test_propagation_tracking.py](./tests/test_propagation_tracking.py)

### Acceptance criteria
- Structured event records emitted at each hop.
- Can derive path graph by `trace_id` + parent/child message IDs.
- Decision transitions (`allow/quarantine/block`) are observable.

### Validation
- Test builds a simple 3-hop chain and asserts lineage.

### Suggested commit message
`Implement propagation tracking and structured event logging`

---

## Step 9 — Implement attack injection harness

**FR coverage:** FR1.4, FR1.5, FR1.6  
**Goal:** run clean vs attacked scenarios through orchestrator.

### Files
- [src/attack_harness/injector.py](./src/attack_harness/injector.py)
- [src/attack_harness/scenarios.py](./src/attack_harness/scenarios.py)
- [src/attack_harness/scenario_runner.py](./src/attack_harness/scenario_runner.py)
- [src/attack_harness/report.py](./src/attack_harness/report.py)
- [src/cli/run_scenarios.py](./src/cli/run_scenarios.py)

### Acceptance criteria
- At minimum supports:
  - clean baseline scenario
  - attacked scenario
  - privilege escalation scenario
- Produces run summary with action counts and blocked/quarantined paths.

### Validation
- Run scenario CLI on fixed seed and compare deterministic summary fields.

### Suggested commit message
`Add attack scenario runner and reporting pipeline`

---

## Step 10 — Produce midterm reporting deliverables

**FR coverage:** FR1.4, FR1.5, FR1.6 (reporting evidence)  
**Goal:** produce the exact artifacts needed to satisfy the midterm reporting checklist.

### Deliverables
- Written evaluation protocol (fixed setup, metrics, seeds, and run conditions).
- Baseline comparison outputs for:
  - no defense
  - keyword filter
  - trust-aware/layered defense v1
- Results table populated with real numeric values.
- Failure analysis package:
  - at least 20 selected cases
  - at least 3 failure categories
  - at least 5 detailed case writeups
- One depth analysis:
  - single-agent vs multi-agent, or
  - isolated vs shared memory, or
  - fallback: retrieval/top-k sensitivity.
- Communication artifacts:
  - high-level architecture diagram
  - 3–5 minute demo script (one input, one success, one failure, what’s next).

### Suggested implementation surface
- Extend [src/attack_harness/report.py](./src/attack_harness/report.py) to emit per-case and aggregate summaries suitable for the results table.
- Add reporting outputs under a dedicated results folder (for example, JSON/CSV artifacts consumed by the final writeup).
- Add a concise protocol/results section in [README.md](./README.md) (or a dedicated midterm report document if requested).

### Acceptance criteria
- Each checklist item in [midterm_reporting_requirement.md](./midterm_reporting_requirement.md) has a concrete artifact reference.
- Baseline comparisons are reproducible from CLI commands.
- Depth-analysis result includes a clear conclusion paragraph backed by run outputs.

### Validation
- Re-run baseline commands and confirm deterministic identifiers/counts for the same seed.
- Cross-check that reported table values match raw scenario output files.

### Suggested commit message
`Add midterm protocol results failure-analysis and demo artifacts`

---

## Step 11 — Final pass for midterm readiness

**FR coverage:** FR1.1–FR1.6 complete baseline  
**Goal:** ensure coherent docs/tests and integration handoff.

### Checklist
- Remove all placeholder tests.
- Add/update quickstart in README for orchestrator + scenario runs.
- Confirm contract compatibility notes for teammate branches.
- Tag known limitations (e.g., heuristic detector scoring in adapters).

### Suggested commit message
`Finalize Workstream 1 baseline and integration docs`

---

## Delivery cadence recommendation

- One step = one PR or one commit batch.
- Keep each step small enough to review in <15 minutes.
- Demo after Steps 3, 6, 9, and 10.

---

## Notes for future agents

- Treat [src/contracts/](./src/contracts) as the source of truth.
- Do not bypass adapters to call teammate code directly from orchestrator logic.
- Keep all security decisions explicit and traceable (no silent defaults).
- Prefer deterministic behavior in tests and scenario runs.
