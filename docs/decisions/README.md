# Architectural Decision Records (ADRs)

This directory contains the Architectural Decision Records for **AI Agentic OS**.

## What is an ADR?
An Architectural Decision Record (ADR) captures an important architectural decision made for the project, along with its context, considered options, decision rationale, and consequences.

## Format
ADRs follow the standard Michael Nygard format:
* **Title**: `ADR-NNNN: Short descriptive title`
* **Status**: `PROPOSED`, `ACCEPTED`, `SUPERSEDED`, or `DEPRECATED`
* **Context**: The context, constraints, and problem statement that led to this decision.
* **Decision**: What was decided.
* **Consequences**: The positive and negative trade-offs of this decision.

## Index of Decisions
* [`ADR-0001-local-only-and-deterministic-security.md`](file:///home/lokamanya/AI%20Agentic%20OS/docs/decisions/ADR-0001-local-only-and-deterministic-security.md): Foundation of local-only operation and deterministic policy enforcement over agent actions.
* [`ADR-0002-ipc-architecture.md`](file:///home/lokamanya/AI%20Agentic%20OS/docs/decisions/ADR-0002-ipc-architecture.md): IPC Architecture for Internal Subsystems (Unix Domain Sockets) and Linux Desktop Integration (Layer 10 D-Bus).
* [`ADR-0003-sandbox-architecture.md`](file:///home/lokamanya/AI%20Agentic%20OS/docs/decisions/ADR-0003-sandbox-architecture.md): Multi-Layered Hybrid Sandbox Architecture for Capability Execution.
* [`ADR-0004-implementation-language.md`](file:///home/lokamanya/AI%20Agentic%20OS/docs/decisions/ADR-0004-implementation-language.md): Implementation Language Architecture (100% Rust Core with Polyglot Sandboxed Capability Plane).
* [`ADR-0005-policy-engine.md`](file:///home/lokamanya/AI%20Agentic%20OS/docs/decisions/ADR-0005-policy-engine.md): Policy and Authorization Engine Architecture (Cedar PBAC Core + AgenticOS Security Wrapper & Confirmation Broker).
* [`ADR-0006-storage-architecture.md`](file:///home/lokamanya/AI%20Agentic%20OS/docs/decisions/ADR-0006-storage-architecture.md): Storage Architecture (SQLite WAL Core, Separated Authoritative vs. Derived vs. Ephemeral State, Encrypted Secret Vault, and Content-Addressed Blobs).
* [`ADR-0007-formal-contracts.md`](file:///home/lokamanya/AI%20Agentic%20OS/docs/decisions/ADR-0007-formal-contracts.md): Formal Subsystem Contracts and Message Protocols (UDS Envelopes, Capability Invocations, Tri-State Decisions, ApprovalTokens, Error Model, and Polyglot JSON Schemas).


