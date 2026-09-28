# Phase 2: Global Agent Manager — Formal Completion Record

* **Phase**: 2.0 (Agent Domain Models, Persistent Registry Store, Lifecycle State Machine, Global Agent Manager Runtime, Failure Recovery, and End-to-End Verification)
* **Date**: 2026-09-28
* **Status**: PHASE 2 COMPLETE / VERIFIED
* **Architectural Baseline**: ADR-0001 through ADR-0007, `docs/phases/phase-2-global-agent-manager.md`

---

## 1. Phase 2 Objective

The objective of Phase 2 is to design, implement, and verify the Layer 5 Global Agent Manager subsystem of the AI Agentic OS. Layer 5 bridges execution planning (Layer 4 Workflow Runtime) with agent execution dispatch (Layer 6 Agent Runtime), serving as the authoritative coordinator for agent identity, lifecycle, health, work assignment, and crash recovery:

```text
Layer 4: Workflow Runtime (WorkflowStep)
       │
       ▼
Layer 5: Global Agent Manager (GlobalAgentManager)
       ├── Agent Registry Persistence (agent_registry.db)
       ├── Lifecycle State Machine (AgentLifecycleEngine)
       ├── Deterministic Selection & Atomic Reservation (BEGIN IMMEDIATE)
       ├── Process Liveness Observer (read-only Linux /proc/[pid]/stat)
       └── Declarative Failure Recovery & Restart Scheduling
       │
       ▼
[WorkAssignment Dispatch Contract] ──► (Dispatched to Layer 6 Agent Runtime)
```

---

## 2. Layer 5 Global Agent Manager Architecture

Layer 5 operates as a deterministic, local-first control plane coordinator:

1. **Intake**: Accepts a `WorkflowStep` synthesized by Layer 4 via an `AssignmentRequest`.
2. **Eligibility Filtering**: Identifies valid candidates based on:
   - Capability matching (agent declared capabilities must include step `capability_id`).
   - Lifecycle state (agent must be strictly `Ready`).
   - Scope authorization (`Private(owner)` matches originating principal; `SharedSession` and `SystemWide` allow authenticated principals).
   - Dynamic health evaluation (must be `Healthy`, or `Degraded` if `DegradedEligibility::Allow` is configured; `Unhealthy` and `Unknown` rejected).
   - Host process liveness verification (dead or recycled PIDs rejected).
3. **Deterministic Selection**: Hierarchical tie-breaking selects the optimal candidate:
   - Fewest active tasks (least-loaded).
   - Fewest historical tasks (work distribution).
   - Lexicographically smallest `AgentId` (canonical tie-breaker).
4. **Atomic Reservation**: Uses SQLite `BEGIN IMMEDIATE` write transactions to atomically transition the candidate agent from `Ready` to `Running` and persist the new `WorkAssignment` (`Assigned` status) in a single atomic transaction.
5. **Assignment Lifecycle Coordination**: Tracks assignment status (`Assigned ─► InProgress ─► Completed / Failed / Cancelled`), releasing the agent back to `Ready` upon terminal completion or cancellation.
6. **Recovery & Reconciliation**: Automatically scans and reconciles stale in-flight agents and orphaned assignments during startup or upon heartbeat timeout.

---

## 3. Sub-Phase Milestones Completed

### Checkpoint 2.1: Agent Contracts & Domain Model
* Implemented formal domain types in `crates/agenticos-core/src/agent`:
  - `identity.rs`: `AgentId`, `AgentType`, `AgentVersion`, `AgentScope` (`Private`, `SharedSession`, `SystemWide`), `ProcessIdentity` (`Unspawned`, `Active` with `pid`, `start_time_ticks`, `instance_nonce`), `AgentRecord`.
  - `lifecycle.rs`: `AgentLifecycleState` (`Registered`, `Starting`, `Ready`, `Running`, `Stopping`, `Stopped`, `Failed`), closed transition table, and validation rules.
  - `health.rs`: `AgentHealthState` (`Healthy`, `Degraded`, `Unhealthy`, `Unknown`), `HeartbeatRecord`, `AgentResourceMetrics` (`cpu_usage_permille`, `memory_rss_bytes`, `active_task_count`).
  - `policy.rs`: `RestartPolicy` (`Never`, `OnFailure`, `Always`) with exponential backoff and max retry tracking.
  - `assignment.rs`: `AssignmentId`, `AssignmentStatus` (`Assigned`, `InProgress`, `Completed`, `Failed`, `Cancelled`), `WorkAssignment`.
* Enforced serde validation with `#[serde(deny_unknown_fields)]` and contract compatibility with ADR-0007.

### Checkpoint 2.2: Persistent Agent Registry Store (`agent_registry.db`)
* Implemented `AgentRegistryStore` in `crates/agenticos-core/src/storage/agent_store.rs`.
* Single, domain-owned SQLite database with linear migration versioning (`PRAGMA user_version = 1`).
* Production SQLite PRAGMA configuration:
  - `journal_mode = WAL`
  - `synchronous = NORMAL`
  - `foreign_keys = ON`
  - `busy_timeout = 5000`
  - `temp_store = MEMORY`
  - `auto_vacuum = INCREMENTAL` (mode 2 strictly verified; fails closed if existing database has incompatible vacuum mode).
* Startup integrity validation:
  - Runs `PRAGMA integrity_check;` requiring `"ok"`.
  - Runs `PRAGMA foreign_key_check;` requiring zero violations.
* Relational tables: `agents`, `agent_capabilities`, `assignments`, `agent_heartbeats`, `schema_migrations`.
* Dual-write payload/index consistency validation ensuring indexed metadata cannot contradict serialized JSON domain payloads.
* Terminal record update protection at the storage boundary.

### Checkpoint 2.3: Agent Lifecycle State Machine
* Transition validation engine implemented in `crates/agenticos-core/src/agent/machine.rs` (`AgentLifecycleEngine`).
* Enforces legal transitions:
  - `Registered ─► Starting | Stopped`
  - `Starting ─► Ready | Stopping | Failed`
  - `Ready ─► Running | Stopping | Failed`
  - `Running ─► Ready | Stopping | Failed`
  - `Stopping ─► Stopped | Failed`
  - `Stopped | Failed` (terminal; immutability enforced).
* Controlled restart capability: re-arms terminal agents (`Stopped` or `Failed`) to `Starting` only when permitted by `RestartPolicy` and retry quotas, generating a fresh `instance_nonce` and resetting process identity.
* Prevents timestamp regression on lifecycle updates.

### Checkpoint 2.4: Global Agent Manager Runtime
* Implemented `GlobalAgentManager` in `crates/agenticos-core/src/agent/manager.rs`.
* Accepts `AssignmentRequest` wrapping a `WorkflowStep` from Layer 4.
* Implements deterministic multi-candidate selection with hierarchical tie-breaking.
* Atomic reservation inside `BEGIN IMMEDIATE` SQLite transaction:
  - Prevents concurrent over-allocation of agents.
  - Transitions agent from `Ready` to `Running`.
  - Inserts `WorkAssignment` with status `Assigned`.
* Full assignment lifecycle methods:
  - `start_assignment(&assignment_id, timestamp_ms)` (`Assigned ─► InProgress`).
  - `complete_assignment(&assignment_id, timestamp_ms)` (`InProgress ─► Completed`, agent `Running ─► Ready`).
  - `fail_assignment(&assignment_id, reason, timestamp_ms)` (`Assigned | InProgress ─► Failed`, agent `Running ─► Ready`).
  - `cancel_assignment(&assignment_id, reason, timestamp_ms)` (`Assigned | InProgress ─► Cancelled`, agent `Running ─► Ready`).
* Strict causal lineage preservation across all entities: `correlation_id`, `request_id`, `workflow_id`, `step_id`, `agent_id`, `capability_id`.

### Checkpoint 2.5: Failure Recovery & Restart Handling
* Implemented `ProcessObserver` trait in `crates/agenticos-core/src/agent/observer.rs` with 5 distinct states:
  - `Unspawned`: Agent identity has not yet been bound to an OS process.
  - `Alive`: Process exists with matching PID and identical `start_time_ticks`.
  - `Dead`: Process no longer exists on host (confirmed via procfs).
  - `Recycled`: PID exists on host but with different `start_time_ticks` (OS recycled the PID).
  - `Unknown`: Host observation is unavailable or indeterminate.
* Production `LinuxProcfsObserver`: Performs **read-only** inspection of `/proc/[pid]/stat` to read process start time (field 22) in clock ticks since boot.
* **Fail-Closed Non-Destructive `Unknown` Semantics**: If process state is `Unknown`, the manager strictly refuses to invent process death. It does NOT transition the agent to `Failed`, does NOT fail active assignments, does NOT increment restart retries, and does NOT trigger restarts.
* Recovery runtime in `crates/agenticos-core/src/agent/recovery.rs`:
  - `reconcile_startup(timestamp_ms)`: Idempotently reconciles in-flight agents across restarts.
  - `reconcile_agent(&agent_id, timestamp_ms)`: Targeted single-agent reconciliation.
  - `check_heartbeat_timeouts(timestamp_ms)`: Ingests telemetry and marks expired agents failed/recovered.
  - `HeartbeatMonitor`: Background monitoring coordinator for periodic health sweeps.
* Declarative restart policy enforcement (`Never`, `OnFailure`, `Always`) with exponential backoff and max retry bounds.

### Checkpoint 2.6: Final End-to-End Manager Verification
* Comprehensive integration test suite in `crates/agenticos-core/tests/agent_e2e_tests.rs` (27 integration tests).
* Verified end-to-end scenarios covering the full lifecycle and operational invariants:
  1. `WorkflowStep` -> `GlobalAgentManager` -> `WorkAssignment` dispatch.
  2. Deterministic candidate selection (fewest active tasks).
  3. Deterministic candidate selection (lexicographic tie-breaker).
  4. Atomic reservation: 2 threads racing for 1 agent; exactly one succeeds.
  5. Work assignment persistence across database reopen.
  6. Assignment lifecycle: `Assigned ─► InProgress ─► Completed`.
  7. Completion releases `Running ─► Ready`; agent immediately accepts new work.
  8. Failure releases `Running ─► Ready`.
  9. Cancellation releases `Running ─► Ready`.
  10. Manager reopen preserves agent state across 3 separate sessions.
  11. Stale/dead process detection excludes candidate from assignment.
  12. PID recycling detection excludes candidate from assignment.
  13. `RestartPolicy::Never` prevents restart scheduling.
  14. `RestartPolicy::OnFailure` schedules restart on dead process.
  15. `RestartPolicy::Always` schedules restart on dead process.
  16. Retry exhaustion stops restart cycles.
  17. Idempotent startup reconciliation produces no duplicates.
  18. Multi-agent deterministic selection order across 5 agents.
  19. Concurrent reservation atomicity: 3 threads racing for 2 agents; exactly 2 win, 1 gets `NoEligibleAgent`, zero double-assignments.
  20. Causal lineage preservation across the complete chain.
  21. `Unknown` process observation is strictly non-destructive.
  22. Database dual-write consistency and `PRAGMA integrity_check = "ok"` after full lifecycle.
  23. Phase 1 `WorkflowStep` synthesis through Layer 5 dispatch bridge.
  24. Production source code security audit scanning 11 Phase 2 files.
  25. Private scope isolation preventing cross-principal access.
  26. Terminal state protection preventing assignment of failed agents.
  27. Timestamp regression protection on assignments.

---

## 4. Phase 1 → Layer 5 Integration & Boundary Audit

The integration between Phase 1 and Layer 5 was explicitly verified in `test_e2e_phase1_workflow_step_dispatched_via_layer5`:
1. `Phase1Runtime::submit()` deterministically synthesizes `Intent ─► Goal ─► Workflow` with a `WorkflowStep` specifying `capability_id: "fs.create_directory"`.
2. The `WorkflowStep` is passed to `GlobalAgentManager::assign_step()` via `AssignmentRequest`.
3. An eligible `Ready` agent declaring `"fs.create_directory"` is atomically reserved and transitions to `Running`.
4. A persistent `WorkAssignment` is created in `Assigned` status.

### Capability Execution Non-Execution Audit
* **No directory is created**: The test does NOT execute any filesystem operation.
* **No capability runner is invoked**: Layer 8 (Capability Execution Engine) does not exist in Phase 2.
* **No capability implementation is called**: The capability identifier `"fs.create_directory"` is handled purely as a typed routing and contract string.
* **The test stops at the dispatch boundary**: Verification asserts `WorkAssignment.status == AssignmentStatus::Assigned` and `WorkAssignment.capability_id == "fs.create_directory"`. Capability execution is strictly deferred to future layers.

---

## 5. Security & Isolation Boundaries

1. **Zero Execution in Control Plane (ADR-0001, ADR-0003)**:
   - Zero shell invocation (`sh`, `bash`).
   - Zero subprocess spawning (`std::process::Command`, `Command::new`).
   - Zero process lifecycle tampering (`fork`, `execve`, `process::exit`).
   - Zero live network access (`TcpStream`, `TcpListener`, `UdpSocket`, `reqwest`, `hyper`, `tokio::net`).
   - Zero LLM execution, model calling, prompt generation, or autonomous decision engines.
   - Zero UI/GUI/web components.
2. **Filesystem Boundary**:
   - Zero writable or general filesystem operations outside the domain-owned SQLite registry database (`agent_registry.db`).
   - The production `LinuxProcfsObserver` performs strictly **read-only** file reads of `/proc/[pid]/stat` to determine process start time ticks.
3. **Domain Ownership of Storage (ADR-0006)**:
   - `agent_registry.db` is completely owned by Layer 5 with independent schema migrations and integrity verification. No cross-database queries or shared connections.
4. **Attested Identity & Scope Governance (ADR-0007)**:
   - Agents scoped to `Private(owner)` cannot be claimed by foreign principals.
   - Full causal trace metadata (`correlation_id`, `request_id`, `workflow_id`, `step_id`, `agent_id`) is persisted in every record.
5. **Real-Data Rule**:
   - All tests use real SQLite database files in temporary directories, real serialized JSON domain objects, and real SQLite write transactions.
   - Zero fake production data. `MockProcessObserver` is used strictly within unit/integration tests to provide deterministic simulation of host process states.

---

## 6. Verification & Test Summary

All toolchain checks pass with zero errors and zero warnings:

```bash
cargo fmt --all --check
cargo check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

### Exact Repository Test Breakdown (230 Tests Total)

Enumerated directly via `cargo test -- --list`:

| Test Suite / Target | Source File | Test Count | Status |
|---|---|---|---|
| `agenticos-contracts` (unit) | `crates/agenticos-contracts/src/lib.rs` | 0 | PASS |
| `agenticos-core` (unit) | `crates/agenticos-core/src/lib.rs` | 0 | PASS |
| **Phase 2 Integration Suites** | | | |
| `agent_e2e_tests` | `crates/agenticos-core/tests/agent_e2e_tests.rs` | 27 | PASS |
| `agent_lifecycle_tests` | `crates/agenticos-core/tests/agent_lifecycle_tests.rs` | 12 | PASS |
| `agent_manager_tests` | `crates/agenticos-core/tests/agent_manager_tests.rs` | 24 | PASS |
| `agent_recovery_tests` | `crates/agenticos-core/tests/agent_recovery_tests.rs` | 26 | PASS |
| `agent_storage_tests` | `crates/agenticos-core/tests/agent_storage_tests.rs` | 21 | PASS |
| `agent_tests` | `crates/agenticos-core/tests/agent_tests.rs` | 30 | PASS |
| **Phase 1 Regression Suites** | | | |
| `domain_tests` | `crates/agenticos-core/tests/domain_tests.rs` | 30 | PASS |
| `runtime_tests` | `crates/agenticos-core/tests/runtime_tests.rs` | 40 | PASS |
| `storage_tests` | `crates/agenticos-core/tests/storage_tests.rs` | 20 | PASS |
| Doc-tests | `agenticos_contracts` / `agenticos_core` | 0 | PASS |
| **Phase 1 Subtotal** | | **90** | **PASS** |
| **Phase 2 Subtotal** | | **140** | **PASS** |
| **Total Test Count** | | **230 passed; 0 failed** | **PASS** |

---

## 7. Explicit Non-Goals & Deferred Scope

The following architectural layers remain **strictly excluded** from Phase 2 and are deferred to future phases:
- **Layer 6: Concrete Agent Runtimes**: File Agent, Git Agent, Monitor Agent, Application Agent implementations.
- **Layer 7: Linux Sandboxing**: Bubblewrap namespace isolation, Landlock filesystem restriction, seccomp-bpf syscall filtering, and cgroup resource limits.
- **Layer 8: Capability Execution Engine**: Subprocess runner, Python runtime runner, system command executor.
- **Layer 1: Inter-Process Communication (IPC)**: Live Unix Domain Socket (UDS) listeners, D-Bus system/session service daemons.
- **Security Governor Policy Engine**: Cedar policy evaluation daemon for capability invocation authorization.
- **Layer 13: User Interfaces**: Web dashboard, desktop GUI, or interactive terminal client.
- **LLM Reasoning**: Model prompts, inference streaming, tokenization, or agentic prompt loops.

---

## 8. Conclusion

**Phase 2 of the AI Agentic OS (Global Agent Manager) is complete, verified, and architecturally sealed.**
The system provides authoritative, persistent agent management, deterministic task reservation, robust Linux procfs liveness observation, fail-closed recovery, and complete causal auditability while maintaining strict zero-execution control plane security invariants.
