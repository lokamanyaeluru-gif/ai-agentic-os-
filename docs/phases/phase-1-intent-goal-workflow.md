# Phase 1.0: Intent → Goal → Workflow Implementation Specification

* **Document Version**: 1.0.0  
* **Date**: 2026-09-27  
* **Phase**: 1.0 (Specification & Contract Definition)  
* **Status**: APPROVED SPECIFICATION / READY FOR IMPLEMENTATION  
* **Architectural Baseline**: ADR-0001 through ADR-0007, `docs/architecture.md`, `docs/security.md`, `docs/threat-model.md`  

---

## 1. Executive Summary & Phase 1 Goal

The foundational architectural decisions for AI Agentic OS were established and verified across Phase 0 (ADR-0001 through ADR-0007). Phase 1 initiates the first concrete domain layer implementation, defining the minimal, deterministic execution path connecting human input to verifiable execution structures:

```text
User Input
    │
    ▼
[Intent Intake & Normalization] ──► Intent Domain Object
    │
    ▼
[Goal Runtime]                  ──► Goal Domain Object
    │
    ▼
[Workflow Runtime]              ──► Workflow Domain Object (Ordered DAG of WorkflowSteps)
    │
    ▼
[Execution Request Synthesis]   ──► CapabilityInvocationRequest (ADR-0007 Contract)
    │
    ▼
[Execution Verification]        ──► Result Domain Object
```

### Foundational Invariants Preserved from Phase 0
1. **Local-Only & Deterministic Operation (ADR-0001)**: The core pipeline operates strictly on the local machine without remote dependencies. Execution logic, state transitions, and validation rules are specified to be deterministic and auditable.
2. **Strict Privilege Boundaries (ADR-0001, ADR-0003)**: No arbitrary shell execution (`/bin/sh`, `/bin/bash`), no root privileges, and no sudo escalation.
3. **No LLM Authorization (ADR-0001, ADR-0005)**: If an LLM is utilized for natural language interpretation, it serves exclusively as an advisory parser. The LLM is never the authorization authority; authorization is strictly governed by the deterministic Security & Governance architecture.
4. **Rust-First Trusted Control Plane (ADR-0004)**: The domain entities and state machines for Intent, Goal, Workflow, and Result are authored exclusively in safe, idiomatic Rust.
5. **Contract Compatibility (ADR-0007)**: All identifiers, timestamps, resource references, error codes, and retry classifications adhere to the formal contracts established in ADR-0007.

---

## 2. Component Architecture & Responsibilities

Phase 1 focuses strictly on Layers 2, 3, and 4 of the 13-layer AgenticOS architecture. Components from higher or lower layers are either stubbed or mediated via formal interfaces.

```
+───────────────────────────────────────────────────────────────────────────────────+
|                           LAYER 2: INTENT INTELLIGENCE                            |
|                                                                                   |
|  +─────────────────────────+            +──────────────────────────────────────+  |
|  |      Intent Intake      | ─────────► |           Intent Normalizer          |  |
|  |  • Ingests raw input    |            |  • Deterministic lexical parsing     |  |
|  |  • Attests principal    |            |  • Extracts action & target resource |  |
|  |  • Generates IDs        |            |  • Emits validated Intent object     |  |
|  +─────────────────────────+            +──────────────────────────────────────+  |
+───────────────────────────────────────────────────────────────────────────────────+
                                          │
                                          │ Formal Intent Object
                                          ▼
+───────────────────────────────────────────────────────────────────────────────────+
|                              LAYER 3: GOAL RUNTIME                                |
|                                                                                   |
|  +─────────────────────────────────────────────────────────────────────────────+  |
|  |                               Goal Runtime                                  |  |
|  |  • Translates Intent into declared declarative Goal                         |  |
|  |  • Establishes formal preconditions, postconditions, and acceptance criteria|  |
|  |  • Maintains Goal lifecycle state machine                                  |  |
|  +─────────────────────────────────────────────────────────────────────────────+  |
+───────────────────────────────────────────────────────────────────────────────────+
                                          │
                                          │ Formal Goal Object
                                          ▼
+───────────────────────────────────────────────────────────────────────────────────+
|                            LAYER 4: WORKFLOW RUNTIME                              |
|                                                                                   |
|  +─────────────────────────────────────────────────────────────────────────────+  |
|  |                             Workflow Runtime                                |  |
|  |  • Compiles Goal into a deterministic Directed Acyclic Graph (DAG) of steps |  |
|  |  • Validates step dependencies, argument schemas, and execution constraints|  |
|  |  • Orchestrates step lifecycle (Waiting ─► Running ─► Completed / Failed)   |  |
|  |  • Synthesizes ADR-0007 CapabilityInvocationRequest for each step           |  |
|  +─────────────────────────────────────────────────────────────────────────────+  |
+───────────────────────────────────────────────────────────────────────────────────+
```

### Component Breakdown
1. **Intent Intake**:
   * *Responsibilities*: Entry point for human or system requests. Captures `raw_input`, binds the caller's attested `PrincipalContext`, mints the root `correlation_id` and unique `intent_id`, and assigns the initial `Created` state.
   * *Prohibitions*: Does not perform semantic action resolution or policy evaluation.
2. **Intent Normalizer**:
   * *Responsibilities*: Parses raw natural or structured input into a canonical, typed `NormalizedIntent`. Matches input against registered deterministic command patterns (e.g. `create directory <name>`).
   * *Prohibitions*: Does not execute actions or invoke capabilities.
3. **Goal Runtime**:
   * *Responsibilities*: Translates an accepted intent into a formal `Goal`. Binds declared objective definitions, declarative acceptance criteria, and workspace context. Enforces Goal state transitions (`Created ─► Accepted ─► Running ─► Completed/Failed/Cancelled`).
   * *Prohibitions*: Does not generate execution task steps or manage worker processes.
4. **Workflow Runtime**:
   * *Responsibilities*: Synthesizes a deterministic `Workflow` consisting of an ordered sequence of `WorkflowStep` items and dependency edges. Validates that the dependency graph is acyclic. Orchestrates step readiness, verifies step arguments against capability schemas, and produces typed ADR-0007 `CapabilityInvocationRequest` payloads.
   * *Prohibitions*: Does not spawn worker containers or evaluate Cedar policy rules (delegated to Layer 8 Capability Runner and cross-cutting Security & Governance).

---

## 3. Formal Domain Object Models

All domain types are authored in Rust and derive standard serialization and schema traits:

```rust
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// Re-exported / aligned with ADR-0007 formal contract crate
use agenticos_contracts::{
    ErrorCode, ErrorPayload, PrincipalContext, ProtocolVersion,
    ResourceRef, RetryClassification,
};
```

### 3.1 Intent Domain Model
Represents the user's initial expressed desire before goal decomposition:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    /// Unique identifier for this specific intent.
    pub intent_id: Uuid,

    /// Root correlation ID tracking all causal operations across the system.
    pub correlation_id: Uuid,

    /// Optional caller-provided deduplication key:
    /// - Scoped to the authenticated originating principal
    /// - Not a correlation ID (does not trace causal trees)
    /// - Not an authorization credential (does not grant permissions)
    pub idempotency_key: Option<String>,

    /// Exact, unmodified input received from the caller.
    pub raw_input: String,

    /// Normalized, structured semantic representation.
    pub normalized: Option<NormalizedIntent>,

    /// Wall-clock timestamp (milliseconds since Unix epoch, UTC) when intent was captured.
    pub created_at_ms: u64,

    /// Originating principal who submitted the input (provenance context; not transport security authority).
    pub originating_principal: PrincipalContext,

    /// Current lifecycle status of the intent.
    pub status: IntentStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedIntent {
    /// Action category (e.g. "fs", "system", "process").
    pub category: String,

    /// Canonical action verb (e.g. "create_directory", "read_file").
    pub action: String,

    /// Target conceptual resource reference.
    pub target_resource: ResourceRef,

    /// Extracted structured parameters governing the intent.
    pub parameters: serde_json::Value,
}
```

### 3.2 Goal Domain Model
Represents an accepted, formal objective with declarative criteria:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Goal {
    /// Unique identifier for this goal.
    pub goal_id: Uuid,

    /// Root correlation ID matching originating intent.
    pub correlation_id: Uuid,

    /// Reference to the intent that gave rise to this goal.
    pub originating_intent_id: Uuid,

    /// Structured objective definition.
    pub objective: GoalObjective,

    /// Current lifecycle status of the goal.
    pub status: GoalStatus,

    /// Wall-clock timestamp (UTC ms) when goal was declared.
    pub created_at_ms: u64,

    /// Wall-clock timestamp (UTC ms) of latest state transition.
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoalObjective {
    /// Concise human-readable name of the objective.
    pub title: String,

    /// Formal description of desired end state.
    pub description: String,

    /// Declarative acceptance-criteria expressions (declarative human/eval criteria; exact predicate schema deferred).
    pub acceptance_criteria: Vec<String>,

    /// Target workspace or system boundary.
    pub scope: String,
}
```

### 3.3 Workflow Domain Model
Represents a deterministic execution plan structured as a Directed Acyclic Graph (DAG):

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workflow {
    /// Unique identifier for this workflow plan.
    pub workflow_id: Uuid,

    /// Reference to the goal this workflow fulfills.
    pub goal_id: Uuid,

    /// Root correlation ID tracking the entire operation.
    pub correlation_id: Uuid,

    /// Ordered list of executable workflow steps.
    pub steps: Vec<WorkflowStep>,

    /// Authoritative dependency relations between steps (step_id -> depends_on step_ids).
    pub dependencies: Vec<StepDependency>,

    /// Current execution status of the overall workflow.
    pub status: WorkflowStatus,

    /// Wall-clock timestamp (UTC ms) when workflow was synthesized.
    pub created_at_ms: u64,

    /// Wall-clock timestamp (UTC ms) of latest status update.
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepDependency {
    /// The dependent step that cannot execute until prerequisite completes.
    pub step_id: Uuid,

    /// The prerequisite step ID that must complete successfully.
    pub depends_on_step_id: Uuid,
}
```

### 3.4 WorkflowStep Domain Model
Represents an individual atomic capability invocation unit within a workflow:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowStep {
    /// Unique identifier for this step.
    pub step_id: Uuid,

    /// Sequence index within the linear plan presentation (0-indexed).
    pub step_index: u32,

    /// Canonical capability identifier (e.g. "fs.create_directory").
    pub capability_id: String,

    /// Version of the capability argument schema.
    pub capability_schema_version: u32,

    /// Conceptual resource reference (ADR-0007).
    pub resource: ResourceRef,

    /// Schema-validated structured arguments for the capability.
    pub arguments: serde_json::Value,

    /// Derived/cached prerequisite step IDs for fast local readiness checks (non-authoritative).
    /// Authoritative dependency graph is defined by Workflow.dependencies.
    pub dependency_step_ids: Vec<Uuid>,

    /// Current execution state of this specific step.
    pub state: StepExecutionState,

    /// Retry classification governed by supervisor (ADR-0007).
    pub retry_classification: RetryClassification,

    /// Relative execution timeout duration in milliseconds (enforced via monotonic clock).
    pub timeout_duration_ms: u64,
}
```

### 3.5 Workflow Dependency Graph Invariants
* **Authoritative Edge Source**: `Workflow.dependencies: Vec<StepDependency>` is the single authoritative source of truth defining the workflow Directed Acyclic Graph (DAG) edges.
* **Derived Non-Authoritative Cache**: `WorkflowStep.dependency_step_ids: Vec<Uuid>` is an internal derived cache populated strictly from `Workflow.dependencies` for local step inspection.
* **Consistency Invariant**: Runtime validation MUST assert that `WorkflowStep.dependency_step_ids` exactly matches the incoming edges in `Workflow.dependencies` for that `step_id`. Any disagreement between the authoritative edge list and the derived step list is an invariant violation that immediately rejects the workflow with `ErrorCode::InvalidRequest`.

### 3.6 ExecutionResult Domain Model
Represents the outcome of a capability step or workflow execution:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionResult {
    /// Unique identifier for this result record.
    pub result_id: Uuid,

    /// Request ID of the specific capability invocation.
    pub request_id: Uuid,

    /// Root correlation ID tracking the causal workflow.
    pub correlation_id: Uuid,

    /// Step ID that generated this result.
    pub step_id: Uuid,

    /// Final status of execution.
    pub status: ExecutionOutcomeStatus,

    /// Structured output data produced by capability upon success.
    pub output: Option<serde_json::Value>,

    /// Structured error information if execution failed or was cancelled.
    pub error: Option<ErrorPayload>,

    /// Wall-clock timestamp (UTC ms) when execution finished.
    pub completed_at_ms: u64,

    /// Elapsed execution duration in milliseconds (measured via monotonic clock).
    pub execution_duration_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionOutcomeStatus {
    Success,
    Failure,
    Cancelled,
}
```

---

## 4. State Machines & Valid Lifecycle Transitions

To guarantee auditability and eliminate illegal states, every domain object adheres to an explicit finite state machine. Arbitrary or backward state transitions are strictly prohibited.

```text
Intent State Machine (Request Lifecycle):
[Created] ──► [Accepted] ──► [Completed]
    │             │
    ├──► [Failed] ├──► [Failed]
                  │
                  └──► [Cancelled]

Goal & Workflow State Machine (Execution Lifecycle):
[Created] ──► [Accepted] ──► [Running] ──► [Completed]
    │             │              │
    └──► [Failed] ├──► [Failed]  ├──► [Failed]
                  │              │
                  └──► [Cancelled] └──► [Cancelled]

WorkflowStep State Machine:
[Created] ──► [Waiting] ──► [Running] ──► [Completed]
    │             │             │
    └──► [Failed] └──► [Cancelled] ├──► [Failed]
                                   └──► [Cancelled]
```

### 4.1 State Definitions

| State | Semantic Definition | Valid For |
| :--- | :--- | :--- |
| `Created` | Object initialized in memory; initial validation pending. | Intent, Goal, Workflow, WorkflowStep |
| `Accepted` | Syntactically and semantically validated; admitted for processing. | Intent, Goal, Workflow |
| `Waiting` | Admitted, but blocked waiting for prerequisite step dependencies to complete. | WorkflowStep |
| `Running` | Currently actively evaluating or executing. | Goal, Workflow, WorkflowStep |
| `Completed` | Terminal state: execution concluded successfully with expected outputs. | Intent, Goal, Workflow, WorkflowStep |
| `Failed` | Terminal state: unrecoverable error encountered or validation failed. | Intent, Goal, Workflow, WorkflowStep |
| `Cancelled` | Terminal state: aborted by user request, supervisor timeout, or DAG cancellation cascade. | Intent, Goal, Workflow, WorkflowStep |

*Note on Intent Lifecycle*: An intent represents request lifecycle, not execution lifecycle. It transitions `Created -> Accepted -> Completed` upon successful completion of underpinned goals, or `Failed` / `Cancelled` if rejected, errored, or aborted. Request entities do not possess an active execution state; runtime execution transitions belong strictly to `Goal` and `Workflow`.

### 4.2 Valid Transition Matrix

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntentStatus {
    Created,
    Accepted,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GoalStatus {
    Created,
    Accepted,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkflowStatus {
    Created,
    Accepted,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepExecutionState {
    Created,
    Waiting,
    Running,
    Completed,
    Failed,
    Cancelled,
}
```

#### State Transition Invariant Table
| Entity | Current State | Allowed Next States | Trigger / Invariant |
| :--- | :--- | :--- | :--- |
| **Intent** | `Created` | `Accepted`, `Failed` | Normalization succeeds (`Accepted`) or input invalid (`Failed`). |
| | `Accepted` | `Completed`, `Failed`, `Cancelled` | Underpinned goal(s) complete successfully (`Completed`), child goal fails (`Failed`), or request is cancelled (`Cancelled`). |
| | `Completed` | *(None - Terminal)* | Invariant: Terminal states cannot transition. |
| | `Failed` | *(None - Terminal)* | Invariant: Terminal states cannot transition. |
| | `Cancelled` | *(None - Terminal)* | Invariant: Terminal states cannot transition. |
| **Goal** | `Created` | `Accepted`, `Failed` | Semantic validation succeeds or fails. |
| | `Accepted` | `Running`, `Cancelled` | Workflow compilation begins (`Running`) or user cancels (`Cancelled`). |
| | `Running` | `Completed`, `Failed`, `Cancelled` | Workflow reaches terminal outcome. |
| | `Completed` / `Failed` / `Cancelled` | *(None - Terminal)* | Invariant: Terminal states cannot transition. |
| **Workflow** | `Created` | `Accepted`, `Failed` | DAG validation passes (acyclic, valid steps). |
| | `Accepted` | `Running`, `Cancelled` | First ready step scheduled for execution (`Running`) or user cancels (`Cancelled`). |
| | `Running` | `Completed`, `Failed`, `Cancelled` | All steps complete (`Completed`), any unrecoverable step fails (`Failed`), or aborted (`Cancelled`). |
| | `Completed` / `Failed` / `Cancelled` | *(None - Terminal)* | Invariant: Terminal states cannot transition. |
| **WorkflowStep** | `Created` | `Waiting`, `Running`, `Failed` | Has unmet dependencies (`Waiting`), no dependencies (`Running`), or arg error (`Failed`). |
| | `Waiting` | `Running`, `Cancelled` | All prerequisite steps reach `Completed` (`Running`) or parent workflow aborts (`Cancelled`). |
| | `Running` | `Completed`, `Failed`, `Cancelled` | Capability execution completes (`Completed`), fails (`Failed`), or supervisor delivers abort signal (`Cancelled`). |
| | `Completed` / `Failed` / `Cancelled` | *(None - Terminal)* | Invariant: Terminal states cannot transition. |

---

## 5. Trust Boundaries & Security Governance

The minimal execution path establishes strict unidirectional privilege flow:

```
[Untrusted User Input]
        │
        ▼ (Boundary 1: Lexical Validation & Transport Attestation)
[Intent Intake & Normalizer]
        │
        ▼ (Boundary 2: Semantic Goal Formulation)
[Goal Runtime]
        │
        ▼ (Boundary 3: Deterministic Plan Compilation)
[Workflow Runtime]
        │
        ▼ (Boundary 4: Typed Contract Synthesis)
[CapabilityInvocationRequest]
        │
        ▼ (Boundary 5: Security & Governance Gateway - Phase 0 ADR-0005)
[Cedar Policy Engine + Security Governor] ──► ALLOW / DENY / CONFIRM
```

### 5.1 Principal Authentication vs. Provenance Context
* **Transport Security Authentication**: Callers connecting over private Unix Domain Sockets (UDS) are authenticated by the kernel transport boundary via `SO_PEERCRED` (recovering caller PID, UID, and GID). Transport security is authoritative.
* **Intent Provenance Context**: `Intent.originating_principal` represents historical provenance and context carried with the request. It records the logical user/session identity on whose behalf the intent was declared.
* **Zero Untrusted Claims**: Domain entities do not trust caller-supplied identity claims over the wire without transport attestation. Any discrepancy between caller-claimed identity and the socket `SO_PEERCRED` credential is an authentication violation resulting in immediate connection termination or rejection. Copied Intent principal data is never the ultimate security authorization authority.

### 5.2 Security Invariants for Phase 1
1. **Advisory LLM Principle**: If an LLM is introduced to assist in natural language normalization, its output is treated as **untrusted candidate input**. The candidate output must parse into a strictly validated `NormalizedIntent`. The LLM has zero authority to bypass schema validation, omit required fields, or declare an operation pre-authorized.
2. **Deterministic Governance Mandate**: Authorization is performed exclusively by the Cedar Policy Engine and Security Governor (ADR-0005) when the synthesized `CapabilityInvocationRequest` is dispatched. Phase 1 domain objects *propose* actions; they do *not* authorize them.
3. **No Root or Privileged Execution**: Operations execute strictly under the unprivileged user's UID/GID within sandbox boundaries. No sudo escalation or root execution paths are permitted anywhere in the system.
4. **No Arbitrary Shell Interpreter**: Capability references in `WorkflowStep` target discrete, registered capability executables (e.g. `fs.create_directory`). Passing arbitrary shell command strings to `/bin/sh` or `/bin/bash` is architecturally prohibited.

---

## 6. Persistence Architecture

Phase 1 persistence strictly adheres to **ADR-0006 (Storage Architecture)**. State is partitioned strictly by domain ownership, where each authoritative state domain maintains a single logical owner process and cannot become a shared cross-layer database:

```
~/.local/share/agenticos/data/
├── intents.db        ◄── Authoritative SQLite WAL Database (Intent Domain, Layer 2)
├── goals.db          ◄── Authoritative SQLite WAL Database (Goal Domain, Layer 3)
└── workflows.db      ◄── Authoritative SQLite WAL Database (Workflow Domain, Layer 4)

/run/user/<uid>/agenticos/
└── session/          ◄── Ephemeral In-Memory / tmpfs Runtime State (IPC Sockets & Queues)
```

### 6.1 Domain Ownership & State Classification (ADR-0006)

Each authoritative database has a single logical owner process. Direct database sharing or cross-layer SQLite access is strictly forbidden; other subsystems access domain data exclusively via typed IPC interfaces.

| Domain Database | Sole Authoritative Owner | Phase 1 Managed Objects | Durability & Recovery Rules |
| :--- | :--- | :--- | :--- |
| `intents.db` (SQLite WAL) | Intent Runtime (Layer 2) | `Intent`, `NormalizedIntent` | Persisted on intake/normalization. Survives restarts. Authoritative Intent state and request history. (Security/audit records remain owned by Layer 12 Observability & Reliability according to ADR-0006 and ADR-0007; the Intent store does not replace the Layer 12 audit subsystem). |
| `goals.db` (SQLite WAL) | Goal Runtime (Layer 3) | `Goal`, `GoalObjective` | Persisted on goal declaration and status update. Tracks objective lifecycle. |
| `workflows.db` (SQLite WAL) | Workflow Runtime (Layer 4) | `Workflow`, `WorkflowStep`, `ExecutionResult` | Persisted on workflow compilation, step state changes, and completion. Survives crashes. |
| **Ephemeral Session State** | In-Memory / tmpfs | Active in-flight scheduling queues, monotonic timer handles, peer socket buffers | Volatile. Discarded on process termination. On restart, active workflows reconcile against authoritative domain stores. |
| **Derived State** | Derived Indexes (FTS5) | Search indexes, metrics | Deferred to Phase 2+; reconstructible entirely from authoritative domain databases. |

*Note*: Direct table schemas, migrations, and index definitions remain internal implementation details of each domain runtime, respecting ADR-0006.

---

## 7. Inter-Process Communication (IPC)

Phase 1 defines the logical domain model and state transitions. As subsystems evolve into distinct processes, communication boundaries adhere to **ADR-0002** and **ADR-0007**:

### 7.1 Target Process Boundaries & Sockets

```
[CLI / Intake Client]
        │
        ▼ (Internal UDS: /run/user/<uid>/agenticos/intake.sock)
[Intent & Goal Runtime]
        │
        ▼ (Internal UDS: /run/user/<uid>/agenticos/workflow.sock)
[Workflow Runtime]
        │
        ▼ (Internal UDS: /run/user/<uid>/agenticos/capability.sock)
[Security Gateway & Capability Sandbox Runner]
```

### 7.2 UDS Wire Protocol Framing (ADR-0007)
* All inter-process communication across these sockets uses length-prefixed JSON framing:
  - 4-byte big-endian length prefix.
  - Length validated *before* memory allocation.
  - 16 MiB maximum frame ceiling.
  - Sockets run bounded loops for partial reads/writes.
  - Malformed frames trigger immediate connection termination.
* In Phase 1.0, components are implemented as modular Rust modules within the core workspace, with interfaces structured identically to the UDS envelope contracts so that socket boundaries can be activated without refactoring domain logic.

---

## 8. Comprehensive Error Model

Phase 1 operations reuse the error taxonomy established in ADR-0007.

```rust
use agenticos_contracts::{ErrorCode, ErrorPayload, RetryClassification};
```

### 8.1 Error Mapping Table

| Phase 1 Failure Mode | ADR-0007 ErrorCode | Retry Classification | Handling Semantics |
| :--- | :--- | :--- | :--- |
| **Malformed Raw Input** (unsupported length, null bytes, syntax rejection) | `ErrorCode::InvalidRequest` | `RetryClassification::Never` | Reject at intake; Intent marked `Failed`. Note: In Rust, `String` is guaranteed valid UTF-8, so invalid UTF-8 byte streams are rejected at the transport/decoding boundary before `String` construction. |
| **Normalization Failure** (unknown verb, bad format) | `ErrorCode::InvalidRequest` | `RetryClassification::Never` | Intent marked `Failed`; diagnostic error returned. |
| **Goal Generation Failure** (unresolvable scope) | `ErrorCode::InvalidRequest` | `RetryClassification::Never` | Goal marked `Failed`; prompt returned for clarification. |
| **Workflow DAG Cycle Detected** | `ErrorCode::InvalidRequest` | `RetryClassification::Never` | Workflow rejected before scheduling; marked `Failed`. |
| **Unknown Capability Reference** | `ErrorCode::CapabilityNotFound` | `RetryClassification::Never` | Workflow validation fails immediately. |
| **Step Execution Timeout** | `ErrorCode::Timeout` | `RetryClassification::Conditional` | Step marked `Failed`; retry only if idempotent. |
| **Step Dependency Failure** | `ErrorCode::DependencyFailed` | `RetryClassification::Never` | Downstream dependent steps marked `Cancelled`. |
| **User / System Cancellation** | `ErrorCode::Cancelled` | `RetryClassification::Never` | In-flight step killed; pending steps marked `Cancelled`. |
| **Internal Supervisor Fault** | `ErrorCode::InternalError` | `RetryClassification::Safe` | Transient supervisor fault; safe to re-poll state. |

---

## 9. Identity Taxonomy, Idempotency & Retry Semantics

Every Phase 1 operation declares its identity and deduplication characteristics to maintain deterministic behavior under transient network retries or duplicate user submissions:

### 9.1 Subsystem Identity Taxonomy
* **`correlation_id` (Causal Tracing)**: A system-wide UUID that links all causal events, goals, workflows, and steps originating from a user request. It is strictly an observability and distributed causal tracing instrument; it is not an identity deduplication key.
* **`request_id` (Invocation Identifier)**: A unique UUID assigned to a specific capability invocation request or IPC message. Correlates individual request and response pairs.
* **`idempotency_key` (Deduplication Key)**: An optional caller-supplied string token (`Intent.idempotency_key: Option<String>`) used to deduplicate submissions. If provided, submissions with the same `(originating_principal, idempotency_key)` within a sliding deduplication window return the existing `Intent` rather than minting duplicate entities or triggering duplicate execution graphs.

### 9.2 Operation Classes & Retry Rules
* *Naturally Idempotent Read Operations*: Querying status of Intent, Goal, or Workflow by ID (`GET /intent/:id`). Safe to repeat unconditionally.
* *Keyed Deduplication for Submissions*: Intent submission with a supplied `idempotency_key` is deduplicated at the intake boundary. If omitted, each submission is treated as distinct and mints a unique `intent_id` and root causal trace identifier.
* *Workflow Step Mutations*: Governed strictly by the capability's declared `RetryClassification` (`Never`, `Safe`, or `Conditional`). Non-idempotent mutations (e.g. appending data to a file) are marked `RetryClassification::Never` and are never automatically retried by the supervisor without explicit pre-condition checks.

---

## 10. Comprehensive Test Plan

Testing must precede and guide implementation. Phase 1 unit and integration test suites must achieve 100% pass rates across these core scenarios:

### 10.1 Unit Test Matrix
1. **Valid Intent Creation**: Verify valid string creates an `Intent` with valid `intent_id`, matching `correlation_id`, `created_at_ms > 0`, and `status == Created`.
2. **Invalid Intent Rejection**: Verify that empty strings, strings exceeding length limits (e.g. > 64 KiB), or strings with prohibited characters (e.g. null bytes) are rejected with `ErrorCode::InvalidRequest`. (Transport-level invalid UTF-8 byte sequences are rejected at the frame decoding boundary prior to `String` construction).
3. **Intent Normalization**: Verify deterministic parsing of valid inputs into typed `NormalizedIntent` instances.
4. **Intent → Goal Conversion**: Verify `Goal` correctly inherits `correlation_id` and `originating_intent_id`, and initializes `status == Created`.
5. **Goal → Workflow DAG Compilation**: Verify that a Goal compiles into a `Workflow` with correct step order and dependency references.
6. **DAG Acyclicity Validation**: Verify that introducing a cycle into step dependencies (e.g. Step A -> Step B -> Step A) is rejected during workflow validation with `ErrorCode::InvalidRequest`.
7. **Topological Execution Scheduling**: Verify that in a multi-step workflow, Step B (dependent on Step A) remains in `Waiting` state until Step A reaches `Completed`.
8. **Cancellation Cascade**: Verify that cancelling an active workflow immediately transitions pending `Waiting` steps to `Cancelled`.
9. **Monotonic Timeout Representation**: Verify that `timeout_duration_ms` is strictly checked against the supervisor's monotonic clock and bounded by system ceilings.
10. **Idempotency Enforcement**: Verify that submitting an Intent with an existing `(originating_principal, idempotency_key)` within the deduplication window returns the existing `Intent` without creating duplicate records or initiating duplicate workflow graphs.
11. **Principal Provenance & Transport Attestation**: Verify that `originating_principal` is preserved as request provenance context across the pipeline, while asserting that security authorization evaluates caller identity transport-attested at the UDS socket boundary (`SO_PEERCRED`), without treating copied Intent principal data as the ultimate security authorization authority.
12. **Deterministic Output Invariant**: Verify that executing identical input strings through normalization produces bit-for-bit identical `NormalizedIntent` structures.

---

## 11. First Vertical-Slice Demo Specification

To validate the implementation end-to-end, Phase 1 defines a single minimal vertical-slice demo:

### Demo Scenario: "Create a project folder called demo"

```text
Step 1: Intake
Input String: "Create a project folder called demo"
Principal: User(UID=1000, GID=1000)
Action: Intent Intake admits request:
- intent_id: U1
- correlation_id: C1
- idempotency_key: None
- Status: Created -> Accepted

Step 2: Normalization
Output: NormalizedIntent {
    category: "fs",
    action: "create_directory",
    target_resource: ResourceRef { kind: "Path", identifier: "demo" },
    parameters: { "path": "demo" }
}

Step 3: Goal Declaration
Output: Goal {
    goal_id: G1,
    correlation_id: C1,
    originating_intent_id: U1,
    objective: GoalObjective {
        title: "Create Directory",
        description: "Ensure directory 'demo' exists in the active workspace",
        acceptance_criteria: ["Directory 'demo' exists and is readable"],
        scope: "workspace"
    },
    status: Accepted -> Running
}

Step 4: Workflow DAG Synthesis
Output: Workflow {
    workflow_id: W1,
    goal_id: G1,
    steps: [
        WorkflowStep {
            step_id: S1,
            step_index: 0,
            capability_id: "fs.create_directory",
            capability_schema_version: 1,
            resource: ResourceRef { kind: "Path", identifier: "demo" },
            arguments: { "path": "demo" },
            dependency_step_ids: [],
            state: Running,
            retry_classification: Safe,
            timeout_duration_ms: 10000
        }
    ],
    dependencies: [],
    status: Running
}

Step 5: Capability Invocation Request Synthesis
Synthesizes ADR-0007 CapabilityInvocationRequest:
{
    request_id: R1,
    correlation_id: C1,
    capability_id: "fs.create_directory",
    capability_schema_version: 1,
    resource: { kind: "Path", identifier: "demo" },
    arguments: { "path": "demo" },
    deadline_ms: <timestamp + 10000>,
    timeout_duration_ms: 10000,
    policy_snapshot_hash: <sha256 of active policy set>, // Note: SHA-256 digest of active Cedar policy set (test fixture harnesses may stub this with fixed test bytes, but production MUST evaluate genuine policy hash)
    approval_token: None
}

Step 6: Simulated Execution & Result
(Capability execution itself is simulated/stubbed in Phase 1.0)
ExecutionResult {
    result_id: RES1,
    request_id: R1,
    correlation_id: C1,
    step_id: S1,
    status: Success,
    output: { "created": true, "path": "demo" },
    error: None,
    completed_at_ms: <timestamp>,
    execution_duration_ms: 12
}

Step 7: Lifecycle Resolution
WorkflowStep S1 -> Completed
Workflow W1     -> Completed
Goal G1         -> Completed
Intent U1       -> Completed  (Request lifecycle: Created -> Accepted -> Completed)
```

---

## 12. Non-Goals & Architectural Prohibitions

To ensure disciplined execution and avoid premature complexity, Phase 1 strictly enforces the following boundaries:

### Explicitly Deferred to Future Phases (Non-Goals)
* **Autonomous Multi-Agent Planning**: No autonomous agent loops or multi-agent negotiations (deferred to Phase 2+).
* **Global Agent Manager Layer (Layer 5)**: No dynamic agent spawning, agent process pools, or agent registry.
* **Knowledge & Memory / RAG (Layer 7)**: No vector databases, semantic embeddings, or long-term episodic memory indexing.
* **Human Interface Desktop UI (Layer 1)**: No graphical user interface, desktop widgets, or tray icons.
* **LLM Tool Autonomy**: No open-ended LLM function calling or unconstrained agent tool loops.
* **Kernel & System Intelligence (Layer 11)**: No eBPF probes, kernel telemetry consumers, or thermal monitors.
* **Hardware & GPU Orchestration**: No direct GPU kernel launches or PCIe device management.
* **OS ISO & Distribution Packaging**: No live ISO generation, Debian packaging, or installer media.

### Strict Architectural Prohibitions
* **Prohibited**: Running as root or using `sudo` under any circumstance.
* **Prohibited**: Invoking raw shell interpreters (`/bin/sh`, `/bin/bash`, `cmd.exe`).
* **Prohibited**: Unrestricted host filesystem or network access outside declared sandbox constraints.
* **Prohibited**: LLM authorization authority (the LLM cannot grant permissions, mint tokens, or bypass policy checks).

---

## 13. Definition of Done for Phase 1.0

Phase 1.0 is considered complete when:
1. The domain models (`Intent`, `Goal`, `Workflow`, `WorkflowStep`, `ExecutionResult`) are concretely defined with unambiguous Rust struct and enum definitions.
2. The state machines and valid transition rules have explicit state sets and transition tables with prohibited transitions clearly enforced.
3. The trust boundaries, error mappings, and idempotency semantics align with ADR-0001 through ADR-0007.
4. The test plan provides concrete unit and integration test scenarios covering happy paths, edge cases, error conditions, and lifecycle invariants.
5. The next development phase (Phase 1.1) can implement the Rust structs, state transitions, and unit tests directly from this specification without making new architectural decisions.
