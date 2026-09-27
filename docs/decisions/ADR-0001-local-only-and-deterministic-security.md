# ADR-0001: Local-Only Architecture and Deterministic Authorization Engine

* **Status**: ACCEPTED  
* **Date**: 2026-09-27  
* **Phase**: 0.2  

---

## Context

AI Agentic OS is designed as an AI-native desktop operating system layer positioned above Linux/Ubuntu. 

Conventional integrations of Large Language Models (LLMs) into desktop operating systems frequently adopt an unsafe architecture pattern:
`User Prompt -> LLM -> Unrestricted Shell Interpreter (bash -c) -> sudo / root -> Linux OS`.

This pattern exposes the operating system to fatal security hazards:
1. **Prompt Injection**: Malicious instructions in files, web pages, or prompts hijack model reasoning and execute arbitrary code.
2. **Nondeterminism**: Probabilistic models cannot guarantee safe execution boundaries or adherence to safety policies.
3. **Privilege Escalation**: Ambient credentials and sudo privileges eliminate POSIX security isolation.
4. **Data Privacy Leakage**: Sending system telemetry or user filesystem data to remote cloud services violates user privacy.

## Decision

1. **Strictly Local-First Operation**:
   * AI Agentic OS will operate strictly on the local machine.
   * No code or metadata will be pushed to remote Git repositories.
   * No telemetry or background analytical data will leave the host machine.

2. **Deterministic Authorization Gate (ALLOW, DENY, CONFIRM)**:
   * The LLM / neural agent is **never** the final authorization authority.
   * Agents may only emit structured `CapabilityInvocationRequest` payloads.
   * A deterministic, non-neural Policy & Permission Engine evaluates all requests against declarative security rules.
   * Every request yields one of three verdicts: `ALLOW`, `DENY`, or `CONFIRM`.

3. **Prohibition of Direct Shell Execution**:
   * No capability or runtime component shall invoke raw shell interpreters (`sh`, `bash`, `zsh`) with unparsed strings.
   * All host actions must be mediated through typed, discrete, sandboxed capabilities using direct system APIs.

4. **Zero Phase 0.2 Implementation Code**:
   * Phase 0.2 is strictly restricted to architectural design, security modeling, and conceptual interface specifications. No executable application code or package dependencies shall be created in this phase.

## Consequences

### Positive
* **Deterministic Safety**: Even if an agent's reasoning is completely inverted by prompt injection, the deterministic security engine prevents out-of-scope actions or dangerous operations.
* **Auditability**: Every action has a structured audit record tying high-level human intent to low-level system actions.
* **Privacy by Default**: Operating strictly locally guarantees user data and credentials remain entirely on the local device.
* **Controlled Evolution**: Strict phase gating prevents premature optimization and unvetted dependencies.

### Negative / Trade-offs
* **Initial Development Overhead**: Requires building explicit capability schemas, policy evaluation logic, and sandboxing infrastructure rather than quickly executing shell scripts.
* **Human Interactivity Required**: Mutating operations that trigger `CONFIRM` require human interaction, preventing fully unattended destructive changes.
