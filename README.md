# Securing Orchestrated Multi-Agent RAG Systems

## About This Project

This is our NLP course project. We are studying how prompt-injection attacks can affect a Retrieval-Augmented Generation (RAG) system that uses multiple agents.

In a RAG system, information is retrieved from external documents to help answer a user's question. Sometimes these documents may contain malicious instructions. If the system follows these instructions, it may produce an incorrect or unsafe response.

Our project focuses on identifying suspicious instructions in retrieved email documents and controlling how they are handled by the multi-agent workflow.

## Team Members

- **Shahiba Shamshad** — Prompt-injection detection, security evaluation, and ablation testing
- **Sameer Khan** — BIPIA dataset preparation and retrieval experiments
- **Mark Paulraj** — Multi-agent orchestration, policy checks, and message tracing

## Dataset

We used the Microsoft BIPIA EmailQA dataset for our experiments.

For our midterm development evaluation, we prepared:

- 20 clean email documents
- 20 attacked email documents
- 46 text chunks in total
- 20 chunks containing injected instructions
- 26 chunks without injected instructions

The dataset includes legitimate email questions and separate evaluation labels. We use the labels only to measure performance, not as input to the security detector.

Dataset reference: https://github.com/microsoft/BIPIA

## What We Implemented

### 1. Retrieval

We prepared the EmailQA data and compared BM25, TF-IDF, LSA, and hybrid retrieval methods.

### 2. Multi-Agent Workflow

Our prototype uses retrieval, security, and action agents coordinated by an orchestrator.

The workflow includes security policy decisions, privilege checks, and trace IDs to track agent communication.

### 3. Prompt-Injection Detection

We implemented three detection components:

- Keyword matching
- Regular-expression matching
- Instruction-pattern detection

The full layered detector combines these components to identify suspicious instructions in retrieved text.

## Midterm Results

We compared our layered approach with simpler security configurations.

| Defense | Clean Cases Allowed | Attacked Cases Blocked |
|---|---|---|
| No defense | 20/20 | 0/20 |
| Keyword filter | 20/20 | 0/20 |
| Layered defense | 20/20 | 13/20 |

We also evaluated the detector on all 46 text chunks.

| Metric | Keyword + Regex | Full Layered |
|---|---|---|
| Accuracy | 56.52% | 84.78% |
| Precision | 0% | 100% |
| Recall | 0% | 65% |
| F1-score | 0% | 78.79% |

The layered detector identified 13 out of 20 injected chunks and missed seven. All 26 injection-negative chunks were correctly allowed.

These results come from our development dataset and do not measure final language-model answer correctness.

## How to Run the Project

We tested our project using Google Colab and Python.

1. Clone the GitHub repository.
2. Open the project directory.
3. Run the scenario command to test the clean, attacked, and privilege-escalation cases.

```bash
git clone https://github.com/Shahiba11-GHUB/Securing-Orchestrated-Multi-Agent-Retrieval-Augmented-Generation-Systems.git
cd Securing-Orchestrated-Multi-Agent-Retrieval-Augmented-Generation-Systems
python -m src.cli.run_scenarios --scenario all
```

The scenario output shows the final security decision, message hops, and trace ID.

The saved comparison results are available in `results/midterm/results_table.csv`.

## Project Folders

| Folder | Purpose |
|---|---|
| `BIPIA_EmailQA_20_Pairs` | Prepared dataset and retrieval-related files |
| `security` | Prompt-injection detection methods |
| `src` | Multi-agent workflow and orchestration |
| `tests` | Project tests |
| `results/midterm` | Saved evaluation results |

## Limitations and Future Work

Our layered detector missed seven injected chunks, especially instructions expressed in different ways.

The current midterm workflow uses development fixtures. We have not yet evaluated final LLM-generated answers or persistent shared-memory poisoning.

For our final project, we plan to improve detection, evaluate unseen attacks, connect ranked retrieval to the complete multi-agent workflow, and study shared-memory security.

## References

- Microsoft BIPIA: https://github.com/microsoft/BIPIA
- CS-7347 NLP class materials: Basic Text Processing, Vector Semantics, and Supervised Machine Learning
