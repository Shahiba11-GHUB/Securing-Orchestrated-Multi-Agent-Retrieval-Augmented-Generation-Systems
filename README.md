# Securing-Orchestrated-Multi-Agent-Retrieval-Augmented-Generation-Systems
LLM apps are starting to use RAG and multiple agents together. One agent searches documents, another checks the results, another writes the answer or calls a tool. The problem is that retrieved documents can contain hidden instructions. If one agent reads a malicious document, it might follow those instructions instead of the user's actual request. This is called indirect prompt injection. Most research looks at this in single-agent RAG systems. We want to see what happens in a multi-agent setup. If one agent gets tricked, does the problem spread to the other agents? Does it get saved into shared memory? Can it reach an agent that has permission to call tools? We don't know yet.
Our project is to build a small multi-agent RAG system, attack it with prompt injection, and see how far the attack spreads. Then we'll try a few defenses and measure whether they actually help without breaking normal tasks.
<img width="468" height="182" alt="image" src="https://github.com/user-attachments/assets/d387fdb9-6093-4e62-b292-f41c8ceb3e38" />

## Workstream 1 contract models

The initial orchestration contracts for cross-team integration are implemented in [src/contracts/](./src/contracts):
- [document_chunk.py](./src/contracts/document_chunk.py)
- [security_verdict.py](./src/contracts/security_verdict.py)
- [agent_message.py](./src/contracts/agent_message.py)
- [trace_event.py](./src/contracts/trace_event.py)

These are aligned with the current teammate branch interfaces:
- `sameer/bipia-emailqa-dev` retrieval fixture + detector contract
- `feature/security-defense` detector outputs (`is_suspicious`) via adapter normalization

For security screening integration, the preferred adapter is now [layered_security_adapter.py](./src/adapters/layered_security_adapter.py), which wraps teammate [layered_detector.py](./security/layered_detector.py).
