# AI Agentic OS: Development Methodology & Engineering Governance

> **Phase 0.2: Development Governance & Roadmap**  
> *Status: Engineering Process Standards*  
> *Environment: Local Linux / Ubuntu*

---

## 1. Development Principles

Building an AI-native operating system abstraction layer requires rigorous engineering governance to avoid architectural degradation, security vulnerabilities, or unintended host mutations. Development is governed by seven core rules:

### 1. Small, Incremental Phases
* Development proceeds in tightly bounded, logical phases (e.g., Phase 0.1, Phase 0.2, Phase 0.3).
* Each phase addresses a single architectural objective.
* Scope creep or jumping ahead to future phases is strictly prohibited.

### 2. Tests and Verification Before Advancing
* No phase is marked complete until all verification gates and assertions for that phase pass.
* Conceptual phases must have fully validated specifications; implementation phases must have automated tests.
* Every capability must be accompanied by both positive (valid input) and negative (security boundary violation) tests.

### 3. Local Git Checkpoints
* Every phase and atomic sub-task produces clean, descriptive, local Git commits.
* **Strictly Local**: Commits exist solely on the local machine on branch `main`.
* **Zero Remote Operations**: No `git push`, no remote origin setup, no remote mirroring.

### 4. Review Every Major Change
* Architectural changes, interface modifications, and policy updates must be documented and reviewed before code modifications.
* Significant design decisions require an Architectural Decision Record (ADR) in `docs/decisions/`.

### 5. No Unrestricted Privileges
* The system is developed and executed strictly as an unprivileged user (`lokamanya`).
* No scripts or test suites may invoke `sudo` or modify system files.
* Bypassing permission checks for convenience during development is strictly prohibited.

### 6. No Automatic System Changes
* The system must never modify the host operating system's boot configuration, partition tables, kernel modules, or core package configurations.
* Development operations remain entirely within the project workspace directory `/home/lokamanya/AI Agentic OS`.

### 7. Explicit Verification Gate for Every Phase
* Advancing from Phase $N$ to Phase $N+1$ requires passing an explicit verification checklist.
* If any gate criterion fails, development halts within Phase $N$ until resolved.

---

## 2. Phase Roadmap

```
+-------------------------------------------------------------------------------+
| PHASE ROADMAP                                                                 |
+-------------------------------------------------------------------------------+
  [x] Phase 0.1: Initial Workspace & Git Repository Setup
  [x] Phase 0.2: Architecture, Security, and Conceptual Specification (CURRENT)
  [ ] Phase 0.3: Core Type Schemas & Validation Contracts
  [ ] Phase 0.4: Deterministic Policy & Permission Engine Design
  [ ] Phase 1.0: Minimal Capability Sandbox Runner (Mock/Loopback)
  [ ] Phase 1.1: Core Filesystem Capabilities & Verification Subsystem
  [ ] Phase 1.2: Workflow & Goal Runtime Orchestration
  [ ] Phase 2.0: Local LLM Intent Gateway & Human Confirmation UI
+-------------------------------------------------------------------------------+
```

### Phase Breakdown

* **Phase 0.1 (Complete)**: Workspace initialization, clean Git repository setup on `main`.
* **Phase 0.2 (Current)**: Foundational architecture, security model, preliminary threat model, development governance, and conceptual contracts. No executable code.
* **Phase 0.3 (Next)**: Formalization of JSON Schemas for all core contracts (`Intent`, `Goal`, `Workflow`, `Agent`, `Capability`, `PermissionDecision`, `AuditEvent`, `StructuredError`, `VerificationResult`). Pure validation tests.
* **Phase 0.4**: Implementation of the deterministic Policy & Permission Engine in pure, isolated code. Rule evaluation for `ALLOW`, `DENY`, and `CONFIRM`.
* **Phase 1.0**: Minimal capability execution harness with Linux process isolation (Landlock / seccomp / namespaces). Execution of mock capabilities without network or shell access.
* **Phase 1.1**: Realization of the first safe filesystem capabilities (`fs.inspect_metadata`, `fs.create_directory`, `fs.read_file`) with end-to-end verification assertions.
* **Phase 1.2**: Workflow DAG engine, agent lifecycle management, and structured audit logging.
* **Phase 2.0**: Integration with local neural models (e.g., via Ollama/llama.cpp) for intent parsing, accompanied by interactive desktop confirmation prompts.

---

## 3. Phase 0.2 Verification Gate

To complete Phase 0.2 and prepare for Phase 0.3, the following verification checklist must be completely satisfied:

- [x] **Local Only**: Workspace verified to have no remote repositories configured (`git remote -v` returns empty).
- [x] **No Application Code**: Zero application code or runtime implementations exist.
- [x] **No System Modifications**: No package installations, boot changes, or partition edits occurred.
- [x] **Documentation Integrity**:
  - [x] `README.md` created with project purpose, layers, and navigation.
  - [x] `docs/architecture.md` created with boundaries, 12 layers, 9 conceptual contracts, and end-to-end "Create a folder called Project in Documents" example trace.
  - [x] `docs/security.md` created with deterministic authorization model, capability risk tiers, and external project evaluation standards.
  - [x] `docs/threat-model.md` created with 10 threat categories, STRIDE mapping, and mitigations.
  - [x] `docs/development.md` created with 7 core rules and roadmap.
  - [x] `docs/decisions/` directory initialized with ADR workflow and ADR-0001.
- [x] **TBD Items Documented**: All unresolved architectural details are explicitly registered as "TBD" with clear explanations of decisions needed.
- [x] **Clean Local Git Status**: Git status shows all documentation properly tracked.

---

## 4. Coding Standards (For Future Implementation Phases)

When implementation commences in future phases, the following standards will be enforced:

1. **Language Choice**: Rust, Go, or strict typed Python (TBD via ADR in Phase 0.3).
2. **Deterministic Errors**: No unhandled exceptions or panic-on-input. All errors must map to `StructuredErrorContract`.
3. **No Shell Execution**: No calls to `os.system()`, `subprocess.Popen(..., shell=True)`, or equivalent shell wrappers.
4. **Strict Schema Conformance**: All IPC payloads must be validated against their respective JSON-Schema before processing.
5. **No Telemetry**: No third-party analytics, crash reporting, or network pings.

---

## 5. Undecided Engineering Decisions (Explicit "TBD" Registry)

| Engineering Question | Status | Decision Needed | Scheduled Phase |
| :--- | :--- | :--- | :--- |
| **Primary Implementation Language** | **TBD** | Choose between Rust (memory safety, low overhead, native seccomp/landlock bindings) vs. Go (concurrency, rapid tooling) vs. Python (prototyping). | Phase 0.3 |
| **Schema Validation Engine** | **TBD** | Select JSON Schema draft (2020-12) or alternative IDL (Protocol Buffers, Cap'n Proto). | Phase 0.3 |
| **Test Framework & Harness** | **TBD** | Select test runner and mock environment for testing sandboxed capabilities without root. | Phase 0.3 |
