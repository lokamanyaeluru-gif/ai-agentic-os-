# Phase 2.0: Global Agent Manager Specification & Architecture

* **Document Version**: 2.0.0
* **Date**: 2026-09-28
* **Phase**: 2.0 (Specification & Contract Definition)
* **Status**: APPROVED SPECIFICATION / READY FOR IMPLEMENTATION
* **Architectural Baseline**: ADR-0001 through ADR-0007, `docs/architecture.md`, `docs/security.md`, `docs/phases/phase-1-complete.md`

---

## 1. Executive Summary & Phase 2 Goal

Phase 1 established the deterministic control path translating human requests into verifiable workflows (`User Input ─► Intent ─► Goal ─► Workflow`) with domain-owned persistent storage across `intents.db`, `goals.db`, and `workflows.db`.

**Phase 2 implements Layer 5: Global Agent Manager.**

The Global Agent Manager acts as the authoritative orchestration and supervisory control plane for agents in AI Agentic OS. It is responsible for:
1. **Agent Registration**: Registering specialized agent definitions and instances with attested provenance, declared capabilities, and policy scopes.
2. **Deterministic Identity**: Providing unique, deterministic agent identity binding provenance, capability declarations, lifecycle policy, and local instance-disambiguation data.
3. **Lifecycle Management**: Supervising agent lifecycle state transitions (`Registered ─► Starting ─► Ready ─► Running ─► Stopping ─► Stopped`, and failure recovery paths).
4. **Work Assignment**: Evaluating `WorkflowStep` requirements from Layer 4 against eligible agent capabilities and assigning work deterministically under concurrency.
5. **Health & Liveness Monitoring**: Tracking heartbeats, detecting stale or dead processes, and differentiating authoritative state from derived health telemetry.
6. **Failure Recovery & Restart Handling**: Enforcing declarative restart policies (`Never`, `OnFailure`, `Always`) and orchestrating clean recovery without state corruption.
7. **Authoritative Persistence**: Persisting agent metadata, lifecycle states, assignments, and registration history in `agent_registry.db` per ADR-0006.
8. **End-to-End Tracing**: Preserving full causal lineage across `request_id`, `correlation_id`, `originating_principal`, `workflow_id`, `workflow_step_id`, and `agent_id`.

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        PHASE 2 CONTROL & DATA FLOW                                     │
├────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                        │
│   [Layer 4: Workflow Runtime]                                                          │
│         │                                                                              │
│         │  (1) WorkflowStep (capability_id, arguments, resource, correlation_id)       │
│         ▼                                                                              │
│   ┌────────────────────────────────────────────────────────────────────────────────┐   │
│   │                    LAYER 5: GLOBAL AGENT MANAGER                               │   │
│   │                                                                                │   │
│   │  +─────────────────────────+     +──────────────────────────────────────────+  │   │
│   │  |      Agent Registry     | ──► |          Selection & Assignment          |  │   │
│   │  |  • Authoritative State  |     |  • Capability Matcher                    |  │   │
│   │  |  • Scope/Policy Filter  |     |  • Serialized Atomic Reservation         |  │   │
│   │  |  • agent_registry.db    |     |  • Tie-Break & Contention Fallback       |  │   │
│   │  +─────────────────────────+     +──────────────────────────────────────────+  │   │
│   │                │                                       │                       │   │
│   │                ▼                                       ▼                       │   │
│   │  +─────────────────────────+     +──────────────────────────────────────────+  │   │
│   │  |    Lifecycle Machine    |     |       Observed Telemetry & Health        |  │   │
│   │  |  • Legal Transitions    |     |  • Heartbeat Ingestion (Observed)        |  │   │
│   │  |  • Restart Policies     |     |  • Health Evaluator (Derived)            |  │   │
│   │  +─────────────────────────+     +──────────────────────────────────────────+  │   │
│   └────────────────────────────────────────────────────────────────────────────────┘   │
│         │                                                                              │
│         │  (2) WorkAssignment (Task Assignment Contract)                               │
│         ▼                                                                              │
│   [Layer 6: Agent Runtime] ──(Deferred: Executes assigned steps via Agent Loop)        │
│         │                                                                              │
│         │  (3) CapabilityInvocationRequest (ADR-0007 over UDS)                         │
│         ▼                                                                              │
│   [Security Governor (Cedar PBAC) & Confirmation Broker] ──(Mandatory Policy Gate)     │
│         │                                                                              │
│         │  (4) Sandboxed Launch                                                        │
│         ▼                                                                              │
│   [Layer 8: Capability Layer (Sandbox Runner: Bubblewrap + Landlock + seccomp)]        │
│         │                                                                              │
│         ▼                                                                              │
│   [Layer 10: Linux Host Execution Boundary]                                            │
│                                                                                        │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Invariants & Foundational Principles

### 2.1 Local-Only and Deterministic (ADR-0001)
- The Global Agent Manager operates purely on the local host.
- Agent selection, work assignment, and state progression are deterministic algorithms. Given the same registered agents, capabilities, and workflow step, selection yields the identical choice.
- No network queries, remote registries, or external cloud supervisors.

### 2.2 Security Boundary & Policy Enforcement (ADR-0001, ADR-0003, ADR-0005)
- The Global Agent Manager **never provides unrestricted shell, unrestricted root access, or direct arbitrary Linux execution**.
- Agents are bound to explicit `DeclaredCapabilities` matching canonical namespaced capability identifiers (e.g. `fs.create_directory`, `fs.read_file`).
- **WorkAssignment Does NOT Bypass Security**: `WorkAssignment` only tasks an agent with executing a step. It does not grant execution privileges or bypass policy evaluation. When the agent runtime actually executes the assigned work in Layer 6, it must construct an ADR-0007 `CapabilityInvocationRequest` and submit it to the Security Governor (Cedar PBAC) and Confirmation Broker before any capability is run inside a sandbox.
- **Agent Ownership vs. Eligibility**:
  - `owner` (`PrincipalContext`) represents registration provenance and administrative governance (who registered/owns the agent).
  - Agent ownership is **not** a hardcoded eligibility equality check (`agent.owner == request.principal`).
  - Eligibility is governed by policy and explicit `AgentScope` (e.g. `Private`, `SharedSession`, `SystemWide`), permitting shared or system agents to serve authorized principals under Cedar policy rules.

### 2.3 Real Data Rule
- **Production execution must use real agent state, real process identity, real health information, real timestamps, and real persistent state.**
- Test fixtures, simulated heartbeats, and mock agent runtimes may only be used inside unit and integration test harnesses and must never be represented as real system state in production databases.

### 2.4 Strict Storage Domain Ownership (ADR-0006)
- The Global Agent Manager is the **sole authoritative owner** of `agent_registry.db` (`$XDG_DATA_HOME/agenticos/data/agent_registry.db`).
- Neither Layer 4 (Workflow Runtime) nor Layer 6 (Agent Runtime) may open or query `agent_registry.db` directly. All interactions occur via Layer 5 domain interfaces.
- Standard SQLite production pragmas are mandatory: `journal_mode = WAL`, `synchronous = NORMAL`, `foreign_keys = ON`, `busy_timeout = 5000`, `temp_store = MEMORY`, `auto_vacuum = INCREMENTAL`.
- Migration versioning is tracked via `PRAGMA user_version`.

### 2.5 Contract Preservation (ADR-0007)
- Reuses and strictly aligns with `agenticos-contracts`:
  - `PrincipalContext` (`actor_id`, `uid`, `gid`)
  - `ResourceRef` (`kind`, `identifier`)
  - `ProtocolVersion` (`major`, `minor`)
  - `ErrorCode`, `ErrorPayload`, `RetryClassification`
  - Causal continuity: `correlation_id`, `request_id`, `workflow_id`, `step_id`, `agent_id`.

---

## 3. Formal Domain Models

### 3.1 Agent Scope & Identity (`AgentRecord`)

```rust
use std::collections::BTreeSet;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use agenticos_contracts::{PrincipalContext, ProtocolVersion};

/// Unique identifier for an agent instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(pub Uuid);

/// Categorical classification of the agent.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum AgentType {
    /// System built-in agent type (e.g., "FileAgent", "MonitorAgent").
    Builtin(String),
    /// User or extension-defined specialized agent.
    Custom(String),
}

/// Semantic version of the agent specification/implementation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

/// Authorization and visibility scope of an agent instance.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum AgentScope {
    /// Dedicated to a single originating principal.
    Private(PrincipalContext),
    /// Available to any authenticated principal within the current local user session.
    SharedSession,
    /// System-wide shared agent accessible to authorized principals via policy.
    SystemWide,
}

/// Host process identity disambiguation data.
///
/// Disambiguation uses the tuple `(pid, start_time_ticks, instance_nonce)` to distinguish
/// local process instances within an OS boot session and detect stale registrations across crashes.
///
/// IMPORTANT ARCHITECTURAL BOUNDARY:
/// - This tuple is strictly an INSTANCE-DISAMBIGUATION and lifecycle tracking data structure.
/// - It is NOT an authentication or attestation primitive.
/// - Agent process authenticity is established by the approved IPC registration/handshake
///   mechanism and kernel-enforced peer credential verification from ADR-0002 (`SO_PEERCRED`
///   over local Unix Domain Sockets or private descriptor inheritance via `socketpair(2)`).
/// - The `instance_nonce` is a manager-issued token that identifies the manager-approved
///   instance session; it does NOT by itself authenticate an arbitrary connecting process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    /// Host OS process ID (ephemeral, assigned by OS).
    pub pid: Option<u32>,
    /// Process start time in clock ticks since system boot from `/proc/[pid]/stat` (field 22, starttime).
    /// Used by the manager to detect whether a PID has been recycled by the OS during a crash.
    pub start_time_ticks: Option<u64>,
    /// Manager-issued instance nonce identifying this approved agent instance session.
    pub instance_nonce: Uuid,
    /// Effective user ID owning the agent process.
    pub uid: u32,
    /// Effective group ID owning the agent process.
    pub gid: u32,
    /// Wall-clock timestamp (ms, UTC) when process was spawned.
    pub process_started_at_ms: Option<u64>,
}

/// Authoritative persistent domain model for a registered agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRecord {
    /// Unique agent instance ID.
    pub agent_id: AgentId,

    /// Categorical classification of the agent.
    pub agent_type: AgentType,

    /// Implementation version of the agent.
    pub agent_version: AgentVersion,

    /// IPC communication protocol version supported by the agent.
    pub protocol_version: ProtocolVersion,

    /// Attested principal asserting ownership/registration authority (provenance).
    pub owner: PrincipalContext,

    /// Authorization scope governing which principals may be served by this agent.
    pub scope: AgentScope,

    /// Set of canonical capability identifiers this agent is qualified to execute.
    /// Uses `BTreeSet<String>` (instead of `HashSet`) to guarantee lexicographically sorted,
    /// deterministic serialization order in JSON payloads, SQLite storage, and audit logs,
    /// ensuring reproducibility in cryptographic hashes, signatures, and equality comparisons.
    /// Example: `["fs.create_directory", "fs.read_file"]`.
    pub declared_capabilities: BTreeSet<String>,

    /// Host OS process identity tracking with PID recycling protection.
    pub process_identity: ProcessIdentity,

    /// Authoritative lifecycle state machine state.
    pub state: AgentLifecycleState,

    /// Policy governing automatic failure recovery and restart.
    pub restart_policy: RestartPolicy,

    /// Timestamp (ms since Unix epoch, UTC) when registration occurred.
    pub registered_at_ms: u64,

    /// Timestamp (ms since Unix epoch, UTC) of last authoritative state update.
    pub updated_at_ms: u64,
}
```

---

### 3.2 Distinction: Authoritative State vs. Observed Data vs. Derived Health

To avoid architectural confusion and race conditions, the specification strictly separates:

1. **Authoritative `AgentLifecycleState`**:
   - The official state machine state stored in the `agents.state` column of `agent_registry.db`.
   - Mutates **only** via explicit domain events (`register`, `start`, `mark_ready`, `assign_work`, `complete_work`, `stop`, `fail`, `restart`).
2. **Observed Heartbeat Data (`HeartbeatRecord`)**:
   - Raw time-series telemetry received from an active agent process over IPC.
   - Stored in the append-only `agent_heartbeats` table for auditing and analysis.
   - Does **not** mutate `AgentLifecycleState` directly.
3. **Derived Operational Health (`AgentHealthState`)**:
   - Dynamically evaluated by the health monitor based on observed heartbeat arrival times, process liveness, and error rates.
   - Used for work selection eligibility.
   - If an unrecoverable health threshold is breached (e.g. heartbeat timeout), the health monitor dispatches an explicit lifecycle transition to `Failed`.

```rust
/// Authoritative lifecycle state of an agent instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AgentLifecycleState {
    /// Agent is formally registered in storage but not yet spawned or active.
    Registered,

    /// Agent initialization / bootstrap in progress (process spawning, handshake).
    Starting,

    /// Agent is initialized, healthy, and idle; ready to accept task assignments.
    Ready,

    /// Agent is actively executing an assigned task.
    Running,

    /// Graceful termination or shutdown requested.
    Stopping,

    /// Gracefully terminated; terminal resting state.
    Stopped,

    /// Abnormally terminated or irrecoverably degraded; terminal resting state.
    Failed,
}

impl AgentLifecycleState {
    /// Returns true if this state is terminal (cannot transition further without explicit restart action).
    pub const fn is_terminal(&self) -> bool {
        matches!(self, AgentLifecycleState::Stopped | AgentLifecycleState::Failed)
    }

    /// Evaluates whether a transition from `self` to `next` is permitted.
    pub fn can_transition_to(&self, next: AgentLifecycleState) -> bool {
        match self {
            AgentLifecycleState::Registered => {
                matches!(next, AgentLifecycleState::Starting | AgentLifecycleState::Stopped)
            }
            AgentLifecycleState::Starting => {
                matches!(next, AgentLifecycleState::Ready | AgentLifecycleState::Failed | AgentLifecycleState::Stopping)
            }
            AgentLifecycleState::Ready => {
                matches!(next, AgentLifecycleState::Running | AgentLifecycleState::Stopping | AgentLifecycleState::Failed)
            }
            AgentLifecycleState::Running => {
                matches!(next, AgentLifecycleState::Ready | AgentLifecycleState::Stopping | AgentLifecycleState::Failed)
            }
            AgentLifecycleState::Stopping => {
                matches!(next, AgentLifecycleState::Stopped | AgentLifecycleState::Failed)
            }
            // Terminal states are strictly immutable; transition out requires restart API
            AgentLifecycleState::Stopped | AgentLifecycleState::Failed => false,
        }
    }
}
```

```rust
/// Observed raw heartbeat telemetry received over IPC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatRecord {
    pub agent_id: AgentId,
    pub instance_nonce: Uuid,
    pub timestamp_ms: u64,
    pub sequence_number: u64,
    pub metrics: AgentResourceMetrics,
}

/// Resource telemetry accompanying heartbeats.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentResourceMetrics {
    pub cpu_usage_permille: u32,
    pub memory_rss_bytes: u64,
    pub open_fds: u32,
}

/// Derived operational health status of an agent (computed dynamically).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum AgentHealthState {
    /// Agent is responsive, sending heartbeats within threshold.
    Healthy,

    /// Agent is alive but degraded (e.g. high memory, missed heartbeat within tolerance).
    Degraded { reason: String },

    /// Agent has missed heartbeat deadlines or failed self-health check.
    Unhealthy { reason: String },

    /// Health has not yet been established (e.g. Registered or Starting).
    Unknown,
}
```

---

### 3.3 Restart & Recovery Policy

```rust
/// Declarative policy governing recovery when an agent reaches Failed or terminates unexpectedly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum RestartPolicy {
    /// Never restart on failure. Transitions to terminal Failed.
    Never,

    /// Restart only on non-zero exit or failure up to `max_retries`.
    OnFailure {
        max_retries: u32,
        current_retries: u32,
        backoff_ms: u64,
    },

    /// Always restart when agent exits or fails, up to `max_retries`.
    Always {
        max_retries: u32,
        current_retries: u32,
        backoff_ms: u64,
    },
}

impl RestartPolicy {
    /// Determines whether another restart attempt is permitted.
    pub fn can_restart(&self) -> bool {
        match self {
            RestartPolicy::Never => false,
            RestartPolicy::OnFailure { max_retries, current_retries, .. } => {
                current_retries < max_retries
            }
            RestartPolicy::Always { max_retries, current_retries, .. } => {
                current_retries < max_retries
            }
        }
    }
}
```

---

### 3.4 Work Assignment Domain Model

The Global Agent Manager binds a `WorkflowStep` from Layer 4 to an eligible, qualified `AgentRecord`:

```rust
/// Unique identifier for an assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AssignmentId(pub Uuid);

/// Lifecycle state of a work assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AssignmentStatus {
    /// Assignment created and bound to agent; dispatch pending.
    Assigned,

    /// Agent has acknowledged and is actively executing.
    InProgress,

    /// Successfully completed.
    Completed,

    /// Execution failed.
    Failed,

    /// Cancelled by user, timeout, or workflow abort.
    Cancelled,
}

impl AssignmentStatus {
    pub const fn is_terminal(&self) -> bool {
        matches!(self, AssignmentStatus::Completed | AssignmentStatus::Failed | AssignmentStatus::Cancelled)
    }

    pub fn can_transition_to(&self, next: AssignmentStatus) -> bool {
        match self {
            AssignmentStatus::Assigned => matches!(
                next,
                AssignmentStatus::InProgress | AssignmentStatus::Failed | AssignmentStatus::Cancelled
            ),
            AssignmentStatus::InProgress => matches!(
                next,
                AssignmentStatus::Completed | AssignmentStatus::Failed | AssignmentStatus::Cancelled
            ),
            AssignmentStatus::Completed | AssignmentStatus::Failed | AssignmentStatus::Cancelled => false,
        }
    }
}

/// Formal record of work assigned to an agent instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkAssignment {
    /// Unique assignment identifier.
    pub assignment_id: AssignmentId,

    /// Root causal trace ID inherited from Intent/Workflow.
    pub correlation_id: Uuid,

    /// Request invocation ID tracking this specific assignment dispatch.
    pub request_id: Uuid,

    /// Originating human or system principal requesting execution.
    pub originating_principal: PrincipalContext,

    /// Parent workflow identifier from Layer 4.
    pub workflow_id: Uuid,

    /// Specific step within the workflow being executed.
    pub step_id: Uuid,

    /// Assigned agent instance ID.
    pub agent_id: AgentId,

    /// Required capability identifier to be invoked (e.g. "fs.create_directory").
    pub capability_id: String,

    /// Exact parameters for execution.
    pub arguments: serde_json::Value,

    /// Target resource reference.
    pub resource: agenticos_contracts::ResourceRef,

    /// Current status of the assignment.
    pub status: AssignmentStatus,

    /// Timestamp (ms, UTC) when assignment was created.
    pub assigned_at_ms: u64,

    /// Timestamp (ms, UTC) when status was last updated.
    pub updated_at_ms: u64,

    /// Execution timeout duration in milliseconds (must be non-zero).
    pub timeout_duration_ms: u64,
}
```

---

## 4. Deterministic Work Assignment & Selection Algorithm

When Layer 4 requests execution of a `WorkflowStep`:

```rust
pub struct AssignmentRequest {
    pub correlation_id: Uuid,
    pub request_id: Uuid,
    pub originating_principal: PrincipalContext,
    pub workflow_id: Uuid,
    pub step: crate::workflow::WorkflowStep,
    pub timestamp_ms: u64,
}
```

### 4.1 Selection Steps (Deterministic Filter Pipeline)
1. **Capability Matching**:
   Filter all registered agents where `agent.declared_capabilities.contains(&request.step.capability_id)`.
2. **Lifecycle State Eligibility**:
   Filter matching agents where `agent.state == AgentLifecycleState::Ready`.
3. **Scope & Policy Authorization**:
   Filter matching agents where the agent's `scope` authorizes `request.originating_principal`:
   - `AgentScope::Private(owner)`: Permitted only if `owner.actor_id == request.originating_principal.actor_id`.
   - `AgentScope::SharedSession`: Permitted for any principal within the authenticated local session.
   - `AgentScope::SystemWide`: Permitted for authorized principals (delegated to Cedar policy in Security Governor).
   *Crucial rule*: Agent ownership is provenance, not an eligibility blocker. Shared and system agents can serve authorized callers.
4. **Health State Filtering**:
   Filter matching agents where derived health is `Healthy` (or `Degraded` if policy permits). Reject `Unhealthy` or `Unknown`.

### 4.2 Authoritative Ordering / Tie-Break Rule
If multiple candidate agents satisfy all eligibility criteria above, the manager sorts the candidate list deterministically using the following hierarchical ordering:
1. **Least Currently Active Assignments**: Ascending count of active `InProgress` or `Assigned` tasks bound to the agent (load balancing).
2. **Least Total Historical Assignments**: Ascending count of total assignments recorded for this agent instance.
3. **Lexicographical Agent ID**: Ascending order of `agent.agent_id.0.to_string()` (guaranteeing a unique, deterministic total order with zero ambiguity).

### 4.3 Atomic Reservation & Concurrency Control
Under concurrent execution, multiple workflow steps may be evaluated simultaneously. To prevent two concurrent workflow steps from both reserving the same agent based on a stale candidate snapshot:

1. **Serialized / Atomic Reservation Critical Section**:
   - The selection and reservation of an agent is executed as a single, atomic manager transaction.
   - Concurrency is serialized via the manager's internal transaction lock (`Arc<Mutex<Connection>>` on `agent_registry.db` and manager critical-section mutex).
2. **Optimistic State Transition with Candidate Fallback**:
   - The manager evaluates the sorted candidate list.
   - For the highest-ranked candidate, the manager attempts an atomic conditional state transition in the database:
     ```sql
     UPDATE agents
     SET state = 'Running', updated_at_ms = ?
     WHERE agent_id = ? AND state = 'Ready';
     ```
   - **Contention / Race Handling**:
     If an agent becomes unavailable between candidate evaluation and reservation (for example, another concurrent step reservation succeeded first, or the agent process crashed/transitioned out of `Ready`):
     - The atomic update affects `0` rows.
     - The manager detects this reservation collision immediately.
     - Rather than failing the workflow step, the manager deterministically advances to the next candidate in the pre-sorted tie-break list and attempts atomic reservation.
     - This loop continues until an eligible agent is successfully reserved or all candidates are exhausted.
3. **Exhaustion Outcome**:
   - If no candidate successfully reserves (or candidate list is empty), the transaction rolls back cleanly and returns `RuntimeError::NoEligibleAgent { capability_id: request.step.capability_id }`.
4. **Assignment Record Creation**:
   - Upon successful reservation of an agent, the `WorkAssignment` record is inserted with `AssignmentStatus::Assigned` within the same atomic transaction.

### 4.4 Preservation of the No-Bypass Security Boundary
- The successful reservation of an agent and issuance of a `WorkAssignment` **does NOT grant the agent permission to execute arbitrary Linux commands or bypass policy gates**.
- `WorkAssignment` is strictly a task dispatch contract between Layer 5 (Global Agent Manager) and Layer 6 (Agent Runtime).
- When the agent runtime proceeds to execute the step, it must issue a formal ADR-0007 `CapabilityInvocationRequest` over UDS to the Security Governor and Confirmation Broker.
- The Security Governor evaluates Cedar PBAC policies, confirms interactive approvals when required, and launches capabilities exclusively inside Layer 8 sandboxes (Bubblewrap + Landlock + seccomp).
- The Global Agent Manager does not perform execution, sandbox configuration, or policy bypassing.

---

## 5. Persistent Storage Architecture (`agent_registry.db`)

Conforming strictly to ADR-0006, Layer 5 owns `agent_registry.db`.

### 5.1 Authoritative vs. Derived Data Separation

| Storage Table | Data Classification | Purpose | Invalidation / Rebuild |
|---|---|---|---|
| `agents` | **Authoritative** | Registered agents, identities, declared capabilities, scopes, restart policies, and lifecycle state. | Immutable historical records; authoritative across reboots. |
| `agent_capabilities` | **Authoritative (Index)**| Relational mapping of `(agent_id, capability_id)` for index-accelerated query. | Managed synchronously within agent registration transaction. |
| `assignments` | **Authoritative** | Causal work assignment records, task status, arguments, and timestamps. | Authoritative task execution history. |
| `agent_heartbeats` | **Derived / Telemetry** | Observed periodic heartbeat records and resource usage metrics. | Append-only observability log; pruned periodically. |

### 5.2 SQLite Schema & Migrations

```sql
-- Migration 1: Initialize agent_registry tables and indexes
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY NOT NULL,
    description TEXT NOT NULL
);

-- Authoritative agents table
CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY NOT NULL,
    agent_type TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    instance_nonce TEXT NOT NULL UNIQUE,
    pid INTEGER,
    start_time_ticks INTEGER,
    state TEXT NOT NULL,
    registered_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    payload TEXT NOT NULL
);

-- Agent capability mapping table (indexed for fast capability lookup)
CREATE TABLE IF NOT EXISTS agent_capabilities (
    agent_id TEXT NOT NULL,
    capability_id TEXT NOT NULL,
    PRIMARY KEY (agent_id, capability_id),
    FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
);

-- Authoritative work assignments table
CREATE TABLE IF NOT EXISTS assignments (
    assignment_id TEXT PRIMARY KEY NOT NULL,
    correlation_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    workflow_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    capability_id TEXT NOT NULL,
    status TEXT NOT NULL,
    assigned_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    payload TEXT NOT NULL,
    FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
);

-- Derived heartbeat telemetry table
CREATE TABLE IF NOT EXISTS agent_heartbeats (
    agent_id TEXT NOT NULL,
    timestamp_ms INTEGER NOT NULL,
    sequence_number INTEGER NOT NULL,
    cpu_usage_permille INTEGER NOT NULL,
    memory_rss_bytes INTEGER NOT NULL,
    open_fds INTEGER NOT NULL,
    PRIMARY KEY (agent_id, timestamp_ms),
    FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
);

-- Indexes for performance and isolation
CREATE INDEX IF NOT EXISTS idx_agents_principal_id ON agents(principal_id);
CREATE INDEX IF NOT EXISTS idx_agents_state ON agents(state);
CREATE INDEX IF NOT EXISTS idx_agents_type ON agents(agent_type);
CREATE INDEX IF NOT EXISTS idx_agents_instance_nonce ON agents(instance_nonce);
CREATE INDEX IF NOT EXISTS idx_agent_capabilities_cap ON agent_capabilities(capability_id);
CREATE INDEX IF NOT EXISTS idx_assignments_correlation ON assignments(correlation_id);
CREATE INDEX IF NOT EXISTS idx_assignments_request ON assignments(request_id);
CREATE INDEX IF NOT EXISTS idx_assignments_agent ON assignments(agent_id);
CREATE INDEX IF NOT EXISTS idx_assignments_status ON assignments(status);
```

### 5.3 Storage Integrity Invariants
1. **Payload/Index Consistency**: On every `get()` or query, indexed columns (`agent_id`, `state`, `principal_id`, `instance_nonce`) are compared against the deserialized JSON `payload`. Any mismatch yields `StorageError::CorruptRecord`.
2. **Terminal State Protection**: Updates to records already in terminal state (`Stopped`, `Failed`) are rejected at the storage layer unless accompanied by a verified restart action.
3. **Transaction Isolation**: Agent registration and capability indexing are executed within a single SQLite atomic transaction (`tx.commit()`).
4. **Heartbeat Timing Invariant**: `agent_heartbeats` enforces `PRIMARY KEY (agent_id, timestamp_ms)`. Heartbeats are discrete periodic telemetry samples (default interval 1000ms, >= 100ms enforced). Multiple valid heartbeat records for the same agent cannot legally share the same millisecond timestamp; duplicate submissions or burst collisions sharing `(agent_id, timestamp_ms)` are rejected as duplicate key violations (`StorageError::DuplicateKey`), ensuring time-series uniqueness and deduplicating IPC retransmissions. Process instance validity is verified via `instance_nonce`, and monotonic per-session ordering is tracked via `sequence_number`.

---

## 6. Duplicate Registration & Stale State Recovery

### 6.1 Duplicate Agent Registration
- **Existing `AgentId`**: Attempting to register an agent with an already-persisted `agent_id` is rejected immediately (`StorageError::DuplicateKey` / `AgentManagerError::DuplicateAgentId`).
- **Existing `instance_nonce`**: The unique constraint on `instance_nonce` prevents registering duplicate process instances.
- **Active Type/Process Collision**: Attempting to register an active agent instance of identical `agent_type` and active `(pid, start_time_ticks)` rejects the duplicate.

### 6.2 Stale Registration Recovery on Manager Startup
When the Global Agent Manager reopens `agent_registry.db` after a crash or process restart:
1. **Scan In-Flight States**: Queries all agents with state `Starting` or `Running`.
2. **Process Liveness Verification**:
   - Inspects host OS process table using `(pid, start_time_ticks)` via `ProcessObserver`.
   - On Linux, `DefaultProcessObserver` / `LinuxProcfsObserver` inspects actual `/proc/[pid]/stat` field 22 `starttime`.
   - Distinguishes five explicit states:
     - `Alive`: Process exists on host and verified `start_time_ticks` matches. Agent remains untouched.
     - `Dead`: Actual host evidence confirms the PID does not exist (`ENOENT`).
     - `Recycled`: PID exists on host, but observed `starttime` does not match `start_time_ticks`.
     - `Unspawned`: Agent identity has no PID/ticks (awaiting spawn). Agent remains untouched in `Starting`.
     - `Unknown`: Host evidence is inaccessible or platform unsupported. **Fails closed non-destructively**: the agent is NOT transitioned to `Failed`, active assignments are NOT failed, retries are NOT incremented, and no restart decision is created.
3. **Deterministic Non-Destructive Reconciliation**:
   - For confirmed `Dead` or `Recycled` processes:
     - Stale active assignments bound to the dead agent are transitioned to `AssignmentStatus::Failed` with reason `"Agent process died during manager restart"`, preserving causal lineage.
     - The agent record is transitioned to `AgentLifecycleState::Failed`.
     - If the agent's `RestartPolicy` permits restart (`OnFailure` / `Always`), the manager schedules a clean restart transition (`Failed ─► Starting`) with an incremented retry counter and a fresh `instance_nonce`.
     - If retries are exhausted or policy is `Never`, the agent remains in terminal `Failed`.
     - No duplicate processes are spawned, and no corrupt state is silently overwritten.

---

## 7. Causal Tracing & Lineage Preservation

The manager enforces causal correlation across all entities:
- Every `WorkAssignment` retains:
  - `correlation_id`: Root causal trace ID inherited directly from `Intent ─► Goal ─► Workflow ─► WorkflowStep`.
  - `request_id`: Point-to-point invocation ID for this specific assignment dispatch.
  - `originating_principal`: Preserving caller provenance.
  - `workflow_id`: Layer 4 parent graph.
  - `step_id`: Specific step in DAG.
  - `agent_id`: Designated executor.
- No new correlation IDs are minted for retries or sub-operations; the causal root is strictly preserved.

---

## 8. Checkpoints & Deliverables

Phase 2 will be executed and verified across the following sub-phase checkpoints:

### Checkpoint 2.0: Specification & Architecture (Current)
- Authoritative specification defined in `docs/phases/phase-2-global-agent-manager.md`.
- Formal models, state machines, SQLite schemas, and invariants aligned with ADR-0001 through ADR-0007.

### Checkpoint 2.1: Agent Contracts & Domain Model
- Create/extend Rust modules in `crates/agenticos-core`:
  - `src/agent/mod.rs`: Module exports and facade.
  - `src/agent/identity.rs`: `AgentId`, `AgentType`, `AgentVersion`, `AgentScope`, `ProcessIdentity`, `AgentRecord`.
  - `src/agent/lifecycle.rs`: `AgentLifecycleState`, legal transitions, validation rules.
  - `src/agent/health.rs`: `AgentHealthState`, `HeartbeatRecord`, `AgentResourceMetrics`.
  - `src/agent/policy.rs`: `RestartPolicy` and retry counter logic.
  - `src/agent/assignment.rs`: `AssignmentId`, `AssignmentStatus`, `WorkAssignment`.
- Unit tests verifying domain invariants, serde roundtrips, and `deny_unknown_fields`.

### Checkpoint 2.2: Persistent Agent Registry (`agent_registry.db`)
- Implement `AgentRegistryStore` in `crates/agenticos-core/src/storage/agent_store.rs`.
- Linear schema migrations (version 1), SQLite WAL mode, foreign keys, and pragmas.
- Authoritative CRUD operations: `register_agent()`, `update_agent()`, `get_agent()`, `list_agents()`, `find_by_capability()`, `find_by_principal()`.
- Storage integration tests covering payload/index consistency, duplicates, and corruption detection.

### Checkpoint 2.3: Agent Lifecycle State Machine
- Transition validation engine in `crates/agenticos-core/src/agent/machine.rs`.
- Transition enforcement on storage update.
- Terminal record immutability tests and lifecycle edge case verification.

### Checkpoint 2.4: Global Agent Manager Runtime
- Implement `GlobalAgentManager` coordinator in `crates/agenticos-core/src/agent/manager.rs`.
- Deterministic capability matching and agent selection algorithm with atomic reservation.
- Assignment dispatch and tracking API: `assign_step()`, `complete_assignment()`, `fail_assignment()`, `cancel_assignment()`.
- Typed error hierarchy: `AgentManagerError` / `RuntimeError` mappings.

### Checkpoint 2.5: Failure Recovery & Restart Handling
- Heartbeat ingest and liveness evaluation in `crates/agenticos-core/src/agent/monitor.rs`.
- Host process observation (`crates/agenticos-core/src/agent/observer.rs`) via read-only Linux procfs inspection (`(pid, start_time_ticks)`).
- Zero writable/general filesystem operations outside the authoritative SQLite registry. The production process observer performs read-only procfs observation of `/proc/[pid]/stat`.
- Fail-closed non-destructive handling for `Unknown` liveness states without inventing process death.
- Stale state and orphaned assignment reconciliation on manager startup (`crates/agenticos-core/src/agent/recovery.rs`).
- Declarative restart policy execution (`Never`, `OnFailure`, `Always`).
- Non-destructive recovery and regression tests.

### Checkpoint 2.6: End-to-End Manager Verification
- Comprehensive integration suite connecting Phase 1 `WorkflowStep` synthesis to Layer 5 `GlobalAgentManager`:
  `WorkflowStep ─► Agent Selection ─► WorkAssignment ─► Lifecycle State Transitions ─► Crash Simulation ─► Restart & Rehydration`.
- Verification of zero unrestricted shell, zero root execution, and zero unauthenticated access.
- Toolchain verification (`cargo check`, `cargo fmt`, `cargo clippy`, `cargo test`).

---

## 9. Phase 2 Non-Goals

The following areas are **strictly excluded** from Phase 2 and reserved for subsequent phases:
- **Concrete Agent Implementations**: File Agent, Monitor Agent, Git Agent, Application Agent (Layer 6).
- **Capability Execution Engine**: Local subprocess runner, Python executor, system tool runner (Layer 8).
- **Linux Sandboxing**: Bubblewrap namespaces, Landlock filesystem rules, seccomp filters (Layer 7 / 8).
- **Inter-Process IPC Daemon**: D-Bus daemon or live UDS socket listeners (Layer 1).
- **Policy Engine Implementation**: Cedar PBAC evaluation integration (Layer 6 / Security Governor).
- **Human Interface UI**: Desktop GUI, web dashboard, CLI client (Layer 13).
- **LLM Reasoning**: Model prompts, streaming, function calling, agent prompt templates.

---

## 10. Completion Criteria

Phase 2 is officially complete only when:
1. All agent lifecycle states and legal transitions are formally defined and programmatically enforced.
2. Agent identity (`AgentRecord`) is deterministic, auditable, and immutable once registered.
3. Persistent storage in `agent_registry.db` is verified with WAL, migrations, integrity checking, and dual-write index validation.
4. Invalid registrations and duplicate identities are rejected with typed errors.
5. Work assignment selection is strictly deterministic and executes atomic reservation preventing concurrent over-assignment.
6. Cancellation and failure recovery operate non-destructively without state corruption.
7. Restart policies are tested under simulated process crashes and manager restarts.
8. Tracing causality (`correlation_id`, `request_id`, `originating_principal`, `workflow_id`, `step_id`, `agent_id`) is strictly preserved across the chain.
9. Security invariants remain unbroken (zero shell execution, zero root escalation, zero remote network calls).
10. `cargo fmt --check`, `cargo check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test` pass with 100% success.
11. Working tree is clean and recorded at an official checkpoint.
