# BIPIA EmailQA: 20 clean / 20 attacked development cases

Prepared for retrieval/detector integration. No API key, external library, LLM, or completed RAG pipeline is required to inspect or run this package.

## Contents

- `data/documents.jsonl`: 40 complete document variants, each tied to a neutral case ID.
- `data/clean_chunks.jsonl`: 23 chunks from 20 clean documents.
- `data/attacked_chunks.jsonl`: 23 chunks from 20 attacked documents.
- `data/queries.jsonl`: 40 case-linked queries; same query within each pair.
- `data/evaluation_private.jsonl`: evaluator-only labels, reference answers, exact payload spans and paired-case mapping. Human outcome fields are blank/null.
- `data/review.csv`: full paired texts and labels for human review, not model input.
- `example_retrieval_response.json`: realistic JSON fixture for one case.
- `mock_adapter.py`: loads any case and connects a callable security detector.
- `INTERFACE_CONTRACT.md`: proposed field definitions and function boundary.
- `prepare_dataset.py`, `validate_dataset.py`: reproducible construction and integrity checks.
- `upstream/`: unchanged source files and license, pinned to the revision in `manifest.json`.

Twenty documents per condition do not mean twenty chunks. Three long documents split into two chunks, producing 23 chunks per condition. Across the two conditions, all 46 chunk IDs are unique.

## Selection and construction

Use BIPIA EmailQA training records only, deduplicate exact contexts, and exclude contexts appearing verbatim in its raw test file. From the 34 remaining unique contexts, use all 9 answerable contexts and a seeded selection of 11 unknown-answer contexts (seed 42). Preserve original question and ideal answer. This is a deliberately small development set; do not use it as a detector fine-tuning corpus or report it as independent final evaluation after tuning on it.

Select five templates each from four official BIPIA training categories: Information Retrieval, Content Creation, Language Translation, Instruction. Insert one template per attacked email, at the start (7), middle (7), or end (6), without deleting any original content. Middle insertion uses a nearby word boundary. Each pair has the same legitimate query/answer. Position and category are not fully crossed in 20 cases; do not infer reliable subgroup effects from this pilot.

Chunk using 1,200 characters with 200-character overlap, preserving end-exclusive character offsets. This simple development scheme does not guarantee token-budget compliance; the RAG integration must validate its chosen model's token limit.

This is a **BIPIA-based RAG adaptation**, using official contexts/templates and custom insertion/chunking. It is not the complete official benchmark, official attack construction, or official scorer. These generic email tasks are not a CVE/NIST corpus. No websites need to be scraped.

## Run

From this extracted directory:

```bash
python prepare_dataset.py
python validate_dataset.py
python mock_adapter.py --case-id case_001
```

The first command deterministically regenerates the development files. The second checks counts, unique IDs, original text preservation, pairing, attack spans, complete chunk coverage, exclusion of exact test contexts and absence of evaluation fields from detector payloads. The third prints a mock retrieval response.

To connect the teammate's detector:

```python
from mock_adapter import screen_case
from your_security_module import detect
results = screen_case('case_001', detect)
```

`your_security_module` is the teammate's actual implementation, not included here. See the contract for its callable signature. This package does not implement detection, trust scoring, quarantine storage, agent orchestration or attack-success evaluation.

## Experiment setup

For each clean or attacked case, return only its matching document version plus the same fixed distractor selection if using actual retrieval. Do not index clean and attacked copies of the same document together. Start with fixture-based exposure to validate integration; then run actual retrieval separately, recording whether injected spans reached the model. A failure to retrieve an attack is different from successfully rejecting an exposed attack.

Compare no defense, keyword defense and proposed layered defense with the same case IDs, model version, retrieval settings and initial state. Reset memory between independent cases. Deliberate cross-agent/memory propagation requires separate linked-session scenarios; these document fixtures alone do not evaluate shared-memory poisoning. Reference answers assess legitimate performance; attacker goals need a predefined category-appropriate rubric or human review. No attack-success results are provided.

## GitHub handoff

The files are ready to copy into the existing team repository, for example `datasets/bipia_emailqa_dev/`. No remote branch has been created or pushed from this workspace. A suggested branch name is `sameer/bipia-emailqa-dev`; create it inside the team's existing clone, commit these files, push it and open a pull request. Do not commit API keys or private credentials. Include `evaluation_private.jsonl` only in a team research repository, never in agent context.

## Sources and attribution

Official repository: https://github.com/microsoft/BIPIA
Pinned revision: a004b69ec0dd446e0afd461d98cb5e96e120a5d0

Original file paths: `benchmark/email/train.jsonl`, `benchmark/email/test.jsonl`, `benchmark/text_attack_train.json`, `LICENSE`. BIPIA identifies EmailQA's source as OpenAI Evals. Preserve upstream license/attribution. The manifest records exact source-file SHA-256 hashes.
