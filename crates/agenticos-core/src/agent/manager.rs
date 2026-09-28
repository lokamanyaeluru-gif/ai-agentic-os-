//! Layer 5: Global Agent Manager Runtime.
//!
//! Aligned with Phase 2.0 specification, ADR-0002 through ADR-0007.
//!
//! # Architecture & Scope
//!
//! The Global Agent Manager is responsible for:
//! - Accepting a `WorkflowStep` from Layer 4.
//! - Identifying eligible agents based on capability, lifecycle readiness, scope, and health.
//! - Deterministic candidate selection with hierarchical tie-breaking.
//! - Atomic agent reservation via SQLite write transaction (`BEGIN IMMEDIATE`).
//! - Persisting and coordinating `WorkAssignment` records.
//! - Non-destructive task cancellation and failure propagation.
//! - Preserving causal lineage across all entities.
//!
//! # Security Boundary Invariant (CRITICAL)
//!
//! - Agent Manager selection is NOT authorization.
//! - `WorkAssignment` is strictly a task dispatch contract between Layer 5 (Global Agent Manager)
//!   and Layer 6 (Agent Runtime).
//! - `WorkAssignment` **does NOT grant capability execution privileges or bypass security controls**.
//! - When the agent runtime proceeds to execute the step, it must issue a formal ADR-0007
//!   `CapabilityInvocationRequest` over UDS to the Security Governor and Confirmation Broker.
//! - The Global Agent Manager does not perform execution, sandbox configuration, or policy bypassing.

use std::sync::Arc;

use agenticos_contracts::{ErrorCode, ErrorPayload, PrincipalContext, RetryClassification};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::agent::observer::{DefaultProcessObserver, ProcessLiveness, ProcessObserver};
use crate::agent::recovery::{AgentFailureReason, AgentRecoveryOutcome, ReconciliationReport};
use crate::agent::{
    AgentHealthState, AgentId, AgentLifecycleEngine, AgentLifecycleError, AgentLifecycleState,
    AgentRecord, AssignmentId, AssignmentStatus, HeartbeatRecord, WorkAssignment,
};
use crate::error::DomainError;
use crate::storage::{map_sqlite_err, verify_agent_capabilities, AgentRegistryStore, StorageError};
use crate::workflow::WorkflowStep;

/// Policy controlling whether agents with degraded health may receive work assignments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DegradedEligibility {
    /// Allow degraded agents to be selected if eligible.
    Allow,
    /// Deny degraded agents from receiving work assignments.
    Deny,
}

/// Operational configuration governing Global Agent Manager runtime decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagerConfig {
    /// Policy governing eligibility of degraded agents.
    pub degraded_eligibility: DegradedEligibility,
    /// Maximum permitted time (ms) without heartbeats before an agent is classified as Unhealthy.
    pub heartbeat_timeout_ms: u64,
}

impl Default for ManagerConfig {
    fn default() -> Self {
        Self {
            degraded_eligibility: DegradedEligibility::Allow,
            heartbeat_timeout_ms: 5_000,
        }
    }
}

/// Dynamic evaluator for deriving operational agent health from telemetry.
pub trait HealthEvaluator: Send + Sync {
    /// Evaluates the health state of an agent using observed telemetry in SQLite.
    fn evaluate_health(
        &self,
        agent: &AgentRecord,
        conn: &Connection,
        timestamp_ms: u64,
    ) -> AgentHealthState;
}

/// Default production health evaluator inspecting persistent `agent_heartbeats` telemetry.
#[derive(Debug, Clone)]
pub struct DefaultHealthEvaluator {
    heartbeat_timeout_ms: u64,
}

impl DefaultHealthEvaluator {
    pub fn new(heartbeat_timeout_ms: u64) -> Self {
        Self {
            heartbeat_timeout_ms,
        }
    }
}

impl HealthEvaluator for DefaultHealthEvaluator {
    fn evaluate_health(
        &self,
        agent: &AgentRecord,
        conn: &Connection,
        timestamp_ms: u64,
    ) -> AgentHealthState {
        let hb_res: Result<String, rusqlite::Error> = conn.query_row(
            "SELECT payload FROM agent_heartbeats WHERE agent_id = ? ORDER BY timestamp_ms DESC LIMIT 1;",
            rusqlite::params![agent.agent_id.to_string()],
            |row| row.get(0),
        );

        match hb_res {
            Ok(payload) => {
                let hb: HeartbeatRecord = match serde_json::from_str(&payload) {
                    Ok(h) => h,
                    Err(_) => {
                        return AgentHealthState::Unhealthy {
                            reason: "Corrupt heartbeat telemetry payload in database".into(),
                        }
                    }
                };

                let elapsed = timestamp_ms.saturating_sub(hb.timestamp_ms);
                if elapsed > self.heartbeat_timeout_ms {
                    return AgentHealthState::Unhealthy {
                        reason: format!(
                            "Heartbeat deadline expired: elapsed {}ms exceeds timeout {}ms",
                            elapsed, self.heartbeat_timeout_ms
                        ),
                    };
                }

                if hb.metrics.cpu_usage_permille >= 900 {
                    return AgentHealthState::Degraded {
                        reason: format!(
                            "High CPU usage: {} permille (threshold: 900)",
                            hb.metrics.cpu_usage_permille
                        ),
                    };
                }

                if hb.metrics.memory_rss_bytes >= 16 * 1024 * 1024 * 1024 {
                    return AgentHealthState::Degraded {
                        reason: format!(
                            "High memory consumption: {} bytes",
                            hb.metrics.memory_rss_bytes
                        ),
                    };
                }

                AgentHealthState::Healthy
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                // If an agent is in Ready state and has no heartbeats recorded yet,
                // it is freshly initialized and healthy.
                if agent.state == AgentLifecycleState::Ready {
                    AgentHealthState::Healthy
                } else {
                    AgentHealthState::Unknown
                }
            }
            Err(e) => AgentHealthState::Unhealthy {
                reason: format!("Failed to query heartbeat telemetry: {}", e),
            },
        }
    }
}

/// Request to assign a workflow step to an eligible agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignmentRequest {
    /// Root causal trace ID inherited from Intent/Workflow.
    pub correlation_id: Uuid,
    /// Request invocation ID tracking this specific assignment dispatch.
    pub request_id: Uuid,
    /// Originating principal requesting execution.
    pub originating_principal: PrincipalContext,
    /// Parent workflow identifier from Layer 4.
    pub workflow_id: Uuid,
    /// Specific workflow step to be assigned.
    pub step: WorkflowStep,
    /// Timestamp (ms, UTC) when assignment is initiated.
    pub timestamp_ms: u64,
}

impl AssignmentRequest {
    pub fn new(
        correlation_id: Uuid,
        request_id: Uuid,
        originating_principal: PrincipalContext,
        workflow_id: Uuid,
        step: WorkflowStep,
        timestamp_ms: u64,
    ) -> Self {
        Self {
            correlation_id,
            request_id,
            originating_principal,
            workflow_id,
            step,
            timestamp_ms,
        }
    }
}

/// Typed errors produced by the Global Agent Manager runtime.
#[derive(Debug, thiserror::Error)]
pub enum AgentManagerError {
    #[error("No eligible agent found for capability '{capability_id}'")]
    NoEligibleAgent { capability_id: String },

    #[error("Work assignment '{assignment_id}' not found")]
    AssignmentNotFound { assignment_id: AssignmentId },

    #[error("Agent '{agent_id}' not found in registry")]
    AgentNotFound { agent_id: AgentId },

    #[error("Agent '{agent_id}' is unavailable for assignment (current state: {state:?})")]
    AgentUnavailable {
        agent_id: AgentId,
        state: AgentLifecycleState,
    },

    #[error(
        "Work assignment '{assignment_id}' is in terminal status {status:?} and cannot transition"
    )]
    AssignmentTerminal {
        assignment_id: AssignmentId,
        status: AssignmentStatus,
    },

    #[error("Invalid assignment transition for '{assignment_id}': cannot transition from {from:?} to {to:?}")]
    InvalidAssignmentTransition {
        assignment_id: AssignmentId,
        from: AssignmentStatus,
        to: AssignmentStatus,
    },

    #[error("Timestamp regression for assignment '{assignment_id}': current {current_ms}, proposed {proposed_ms}")]
    TimestampRegression {
        assignment_id: AssignmentId,
        current_ms: u64,
        proposed_ms: u64,
    },

    #[error("Lifecycle error: {0}")]
    Lifecycle(#[from] AgentLifecycleError),

    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("Domain error: {0}")]
    Domain(#[from] DomainError),

    #[error("Serialization failure: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl From<AgentManagerError> for ErrorPayload {
    fn from(err: AgentManagerError) -> Self {
        match err {
            AgentManagerError::NoEligibleAgent { .. } => ErrorPayload::new(
                ErrorCode::CapabilityNotFound,
                err.to_string(),
                "agenticos-core::agent::manager",
                RetryClassification::Conditional,
            ),
            AgentManagerError::AssignmentNotFound { .. }
            | AgentManagerError::AgentNotFound { .. } => ErrorPayload::new(
                ErrorCode::InvalidRequest,
                err.to_string(),
                "agenticos-core::agent::manager",
                RetryClassification::Never,
            ),
            AgentManagerError::Storage(storage_err) => storage_err.into(),
            AgentManagerError::Lifecycle(lifecycle_err) => lifecycle_err.into(),
            AgentManagerError::Domain(domain_err) => domain_err.into(),
            AgentManagerError::Serialization(ref json_err) => ErrorPayload::new(
                ErrorCode::MalformedArguments,
                json_err.to_string(),
                "agenticos-core::agent::manager",
                RetryClassification::Never,
            ),
            other => ErrorPayload::new(
                ErrorCode::InvalidRequest,
                other.to_string(),
                "agenticos-core::agent::manager",
                RetryClassification::Never,
            ),
        }
    }
}

/// Internal metric struct for candidate sorting.
struct CandidateMetric {
    agent: AgentRecord,
    active_count: u64,
    historical_count: u64,
    agent_id_str: String,
}

/// Authoritative coordinator for agent lifecycle and work assignment in Layer 5.
#[derive(Clone)]
pub struct GlobalAgentManager {
    store: AgentRegistryStore,
    lifecycle: AgentLifecycleEngine,
    config: ManagerConfig,
    health_evaluator: Arc<dyn HealthEvaluator>,
    process_observer: Arc<dyn ProcessObserver>,
}

impl GlobalAgentManager {
    /// Creates a new `GlobalAgentManager` backed by the authoritative `AgentRegistryStore`.
    pub fn new(store: AgentRegistryStore) -> Self {
        let config = ManagerConfig::default();
        let health_evaluator = Arc::new(DefaultHealthEvaluator::new(config.heartbeat_timeout_ms));
        let lifecycle = AgentLifecycleEngine::new(store.clone());
        let process_observer = Arc::new(DefaultProcessObserver::new());
        Self {
            store,
            lifecycle,
            config,
            health_evaluator,
            process_observer,
        }
    }

    /// Creates a new `GlobalAgentManager` with a customized `ManagerConfig`.
    pub fn with_config(store: AgentRegistryStore, config: ManagerConfig) -> Self {
        let health_evaluator = Arc::new(DefaultHealthEvaluator::new(config.heartbeat_timeout_ms));
        let lifecycle = AgentLifecycleEngine::new(store.clone());
        let process_observer = Arc::new(DefaultProcessObserver::new());
        Self {
            store,
            lifecycle,
            config,
            health_evaluator,
            process_observer,
        }
    }

    /// Configures a custom `HealthEvaluator` for this manager.
    pub fn with_health_evaluator(mut self, health_evaluator: Arc<dyn HealthEvaluator>) -> Self {
        self.health_evaluator = health_evaluator;
        self
    }

    /// Configures a custom `ProcessObserver` for this manager.
    pub fn with_process_observer(mut self, process_observer: Arc<dyn ProcessObserver>) -> Self {
        self.process_observer = process_observer;
        self
    }

    /// Returns a reference to the active `ProcessObserver`.
    pub fn process_observer(&self) -> &Arc<dyn ProcessObserver> {
        &self.process_observer
    }

    /// Overrides degraded eligibility policy.
    pub fn with_degraded_eligibility(mut self, eligibility: DegradedEligibility) -> Self {
        self.config.degraded_eligibility = eligibility;
        self
    }

    /// Returns a reference to the underlying `AgentRegistryStore`.
    pub fn store(&self) -> &AgentRegistryStore {
        &self.store
    }

    /// Returns a reference to the underlying `AgentLifecycleEngine`.
    pub fn lifecycle(&self) -> &AgentLifecycleEngine {
        &self.lifecycle
    }

    /// Returns a reference to the active `ManagerConfig`.
    pub fn config(&self) -> &ManagerConfig {
        &self.config
    }

    /// Registers a new agent record in the authoritative store.
    pub fn register_agent(&self, agent: &AgentRecord) -> Result<(), AgentManagerError> {
        self.store.register_agent(agent).map_err(Into::into)
    }

    /// Retrieves an agent record by `AgentId`.
    pub fn get_agent(&self, agent_id: &AgentId) -> Result<Option<AgentRecord>, AgentManagerError> {
        self.store.get_agent(agent_id).map_err(Into::into)
    }

    /// Transitions an agent to a new lifecycle state via the lifecycle engine.
    pub fn update_agent_state(
        &self,
        agent_id: &AgentId,
        next_state: AgentLifecycleState,
        timestamp_ms: u64,
    ) -> Result<AgentRecord, AgentManagerError> {
        self.lifecycle
            .transition(agent_id, next_state, timestamp_ms)
            .map_err(Into::into)
    }

    /// Appends an observed heartbeat telemetry record.
    pub fn record_heartbeat(&self, heartbeat: &HeartbeatRecord) -> Result<(), AgentManagerError> {
        self.store.append_heartbeat(heartbeat).map_err(Into::into)
    }

    /// Assigns a `WorkflowStep` to an eligible agent through atomic selection and reservation.
    ///
    /// ### Selection & Reservation Invariants
    /// 1. **Capability Matching**: candidate declared capabilities must contain step capability.
    /// 2. **Lifecycle State**: candidate state must be strictly `Ready`.
    /// 3. **Scope Authorization**: candidate scope must authorize the originating principal.
    ///    - `Private(owner)`: requires `owner.actor_id == principal.actor_id`.
    ///    - `SharedSession` & `SystemWide`: permits any authenticated principal.
    /// 4. **Health Evaluation**: candidate derived health must be `Healthy` (or `Degraded` if policy permits).
    /// 5. **Deterministic Ordering**: candidates sorted by fewest active tasks, then fewest historical tasks,
    ///    then lexicographically smallest `AgentId`.
    /// 6. **Atomic Reservation**: uses a real SQLite `BEGIN IMMEDIATE` transaction to conditionally transition
    ///    the agent to `Running` and insert the `WorkAssignment`. If collision occurs, falls back to the next candidate.
    pub fn assign_step(
        &self,
        request: &AssignmentRequest,
    ) -> Result<WorkAssignment, AgentManagerError> {
        self.store.with_write_transaction(|tx| {
            // 1. Query registered agents declaring this capability
            let mut stmt = tx
                .prepare(
                    r#"
                    SELECT a.agent_id, a.state, a.principal_id, a.instance_nonce, a.payload
                    FROM agents a
                    INNER JOIN agent_capabilities c ON a.agent_id = c.agent_id
                    WHERE c.capability_id = ?
                    ORDER BY a.agent_id ASC;
                    "#,
                )
                .map_err(map_sqlite_err)?;

            let rows = stmt
                .query_map(rusqlite::params![request.step.capability_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                })
                .map_err(map_sqlite_err)?;

            let mut candidates = Vec::new();
            for item in rows {
                let (col_id, col_state, col_principal, col_nonce, payload) =
                    item.map_err(map_sqlite_err)?;
                let agent: AgentRecord = serde_json::from_str(&payload)?;

                // Dual-write integrity check
                if agent.agent_id.to_string() != col_id
                    || format!("{:?}", agent.state) != col_state
                    || agent.owner.actor_id != col_principal
                    || agent.process_identity.instance_nonce.to_string() != col_nonce
                {
                    return Err(StorageError::CorruptRecord {
                        entity: "Agent",
                        id: col_id,
                        reason: "Indexed database columns contradict serialized JSON payload".into(),
                    }
                    .into());
                }

                verify_agent_capabilities(tx, &agent)?;

                // 1. Capability filter (double-check declared capabilities)
                if !agent.declared_capabilities.contains(&request.step.capability_id) {
                    continue;
                }

                // 2. Lifecycle readiness: only Ready agents can accept new assignments
                if agent.state != AgentLifecycleState::Ready {
                    continue;
                }

                // 3. Scope authorization
                if !agent.scope.authorizes(&request.originating_principal) {
                    continue;
                }

                // 4. Health state filtering
                let health =
                    self.health_evaluator
                        .evaluate_health(&agent, tx, request.timestamp_ms);
                match health {
                    AgentHealthState::Healthy => {}
                    AgentHealthState::Degraded { .. } => {
                        if self.config.degraded_eligibility != DegradedEligibility::Allow {
                            continue;
                        }
                    }
                    AgentHealthState::Unhealthy { .. } | AgentHealthState::Unknown => {
                        continue;
                    }
                }

                // 4b. Host process liveness verification
                let liveness = self.process_observer.check_liveness(&agent.process_identity);
                if liveness.is_dead_or_recycled() {
                    continue;
                }

                // Load balancing metric: active assignments count
                let active_count: i64 = tx
                    .query_row(
                        "SELECT COUNT(*) FROM assignments WHERE agent_id = ? AND status IN ('Assigned', 'InProgress');",
                        rusqlite::params![col_id],
                        |row| row.get(0),
                    )
                    .map_err(map_sqlite_err)?;

                // Historical assignments count
                let historical_count: i64 = tx
                    .query_row(
                        "SELECT COUNT(*) FROM assignments WHERE agent_id = ?;",
                        rusqlite::params![col_id],
                        |row| row.get(0),
                    )
                    .map_err(map_sqlite_err)?;

                candidates.push(CandidateMetric {
                    agent,
                    active_count: active_count as u64,
                    historical_count: historical_count as u64,
                    agent_id_str: col_id,
                });
            }
            drop(stmt);

            if candidates.is_empty() {
                return Err(AgentManagerError::NoEligibleAgent {
                    capability_id: request.step.capability_id.clone(),
                });
            }

            // 5. Deterministic tie-breaking sort
            candidates.sort_by(|a, b| {
                (a.active_count, a.historical_count, &a.agent_id_str)
                    .cmp(&(b.active_count, b.historical_count, &b.agent_id_str))
            });

            // 6. Atomic reservation loop with candidate fallback
            let mut reserved: Option<WorkAssignment> = None;

            for cand in candidates {
                let mut updated_agent = cand.agent.clone();
                if updated_agent
                    .transition(AgentLifecycleState::Running, request.timestamp_ms)
                    .is_err()
                {
                    continue;
                }
                let updated_payload = match serde_json::to_string(&updated_agent) {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                // Conditional update ensures the agent is still Ready at reservation moment
                let affected = tx
                    .execute(
                        r#"
                        UPDATE agents
                        SET state = 'Running',
                            updated_at_ms = ?,
                            payload = ?
                        WHERE agent_id = ? AND state = 'Ready';
                        "#,
                        rusqlite::params![
                            request.timestamp_ms,
                            updated_payload,
                            cand.agent_id_str,
                        ],
                    )
                    .map_err(map_sqlite_err)?;

                if affected == 0 {
                    // Collision! Another transaction or action transitioned the agent.
                    // Fall back to next candidate.
                    continue;
                }

                // Reservation succeeded! Create and persist WorkAssignment atomically.
                let assignment = WorkAssignment::new(
                    request.correlation_id,
                    request.request_id,
                    request.originating_principal.clone(),
                    request.workflow_id,
                    request.step.step_id,
                    cand.agent.agent_id,
                    request.step.capability_id.clone(),
                    request.step.arguments.clone(),
                    request.step.resource.clone(),
                    request.timestamp_ms,
                    request.step.timeout_duration_ms,
                )?;

                let assignment_payload = serde_json::to_string(&assignment)?;
                let assignment_id_str = assignment.assignment_id.to_string();
                let status_str = format!("{:?}", assignment.status);

                tx.execute(
                    r#"
                    INSERT INTO assignments (
                        assignment_id,
                        correlation_id,
                        request_id,
                        workflow_id,
                        step_id,
                        agent_id,
                        capability_id,
                        status,
                        assigned_at_ms,
                        updated_at_ms,
                        payload
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    "#,
                    rusqlite::params![
                        assignment_id_str,
                        assignment.correlation_id.to_string(),
                        assignment.request_id.to_string(),
                        assignment.workflow_id.to_string(),
                        assignment.step_id.to_string(),
                        cand.agent_id_str,
                        assignment.capability_id,
                        status_str,
                        assignment.assigned_at_ms,
                        assignment.updated_at_ms,
                        assignment_payload,
                    ],
                )
                .map_err(map_sqlite_err)?;

                reserved = Some(assignment);
                break;
            }

            reserved.ok_or_else(|| AgentManagerError::NoEligibleAgent {
                capability_id: request.step.capability_id.clone(),
            })
        })
    }

    /// Retrieves a work assignment by `AssignmentId`.
    pub fn get_assignment(
        &self,
        assignment_id: &AssignmentId,
    ) -> Result<Option<WorkAssignment>, AgentManagerError> {
        self.store.get_assignment(assignment_id).map_err(Into::into)
    }

    /// Lists all work assignments bound to a specific agent.
    pub fn list_assignments_for_agent(
        &self,
        agent_id: &AgentId,
    ) -> Result<Vec<WorkAssignment>, AgentManagerError> {
        self.store
            .list_assignments_for_agent(agent_id)
            .map_err(Into::into)
    }

    /// Lists all work assignments associated with a parent workflow.
    pub fn list_assignments_for_workflow(
        &self,
        workflow_id: &Uuid,
    ) -> Result<Vec<WorkAssignment>, AgentManagerError> {
        self.store
            .list_assignments_for_workflow(workflow_id)
            .map_err(Into::into)
    }

    /// Lists all work assignments associated with a specific workflow step.
    pub fn list_assignments_for_step(
        &self,
        step_id: &Uuid,
    ) -> Result<Vec<WorkAssignment>, AgentManagerError> {
        self.store
            .list_assignments_for_step(step_id)
            .map_err(Into::into)
    }

    /// Transitions an assignment to `InProgress`.
    pub fn start_assignment(
        &self,
        assignment_id: &AssignmentId,
        timestamp_ms: u64,
    ) -> Result<WorkAssignment, AgentManagerError> {
        self.store.with_write_transaction(|tx| {
            let mut assignment = self.get_assignment_from_tx(tx, assignment_id)?;

            if assignment.status.is_terminal() {
                return Err(AgentManagerError::AssignmentTerminal {
                    assignment_id: *assignment_id,
                    status: assignment.status,
                });
            }

            if timestamp_ms < assignment.updated_at_ms {
                return Err(AgentManagerError::TimestampRegression {
                    assignment_id: *assignment_id,
                    current_ms: assignment.updated_at_ms,
                    proposed_ms: timestamp_ms,
                });
            }

            if !assignment
                .status
                .can_transition_to(AssignmentStatus::InProgress)
            {
                return Err(AgentManagerError::InvalidAssignmentTransition {
                    assignment_id: *assignment_id,
                    from: assignment.status,
                    to: AssignmentStatus::InProgress,
                });
            }

            assignment.transition(AssignmentStatus::InProgress, timestamp_ms)?;
            self.update_assignment_in_tx(tx, &assignment)?;

            Ok(assignment)
        })
    }

    /// Marks an assignment successfully completed, releasing the agent back to `Ready`.
    pub fn complete_assignment(
        &self,
        assignment_id: &AssignmentId,
        timestamp_ms: u64,
    ) -> Result<(WorkAssignment, AgentRecord), AgentManagerError> {
        self.store.with_write_transaction(|tx| {
            let mut assignment = self.get_assignment_from_tx(tx, assignment_id)?;

            if assignment.status.is_terminal() {
                return Err(AgentManagerError::AssignmentTerminal {
                    assignment_id: *assignment_id,
                    status: assignment.status,
                });
            }

            if timestamp_ms < assignment.updated_at_ms {
                return Err(AgentManagerError::TimestampRegression {
                    assignment_id: *assignment_id,
                    current_ms: assignment.updated_at_ms,
                    proposed_ms: timestamp_ms,
                });
            }

            if !assignment
                .status
                .can_transition_to(AssignmentStatus::Completed)
            {
                return Err(AgentManagerError::InvalidAssignmentTransition {
                    assignment_id: *assignment_id,
                    from: assignment.status,
                    to: AssignmentStatus::Completed,
                });
            }

            assignment.transition(AssignmentStatus::Completed, timestamp_ms)?;
            self.update_assignment_in_tx(tx, &assignment)?;

            let mut agent = self.get_agent_from_tx(tx, &assignment.agent_id)?;
            if agent.state == AgentLifecycleState::Running {
                if timestamp_ms < agent.updated_at_ms {
                    return Err(AgentManagerError::TimestampRegression {
                        assignment_id: *assignment_id,
                        current_ms: agent.updated_at_ms,
                        proposed_ms: timestamp_ms,
                    });
                }
                agent.transition(AgentLifecycleState::Ready, timestamp_ms)?;
                self.update_agent_in_tx(tx, &agent)?;
            }

            Ok((assignment, agent))
        })
    }

    /// Marks an assignment failed, releasing the agent back to `Ready` if still running.
    pub fn fail_assignment(
        &self,
        assignment_id: &AssignmentId,
        _reason: &str,
        timestamp_ms: u64,
    ) -> Result<(WorkAssignment, AgentRecord), AgentManagerError> {
        self.store.with_write_transaction(|tx| {
            let mut assignment = self.get_assignment_from_tx(tx, assignment_id)?;

            if assignment.status.is_terminal() {
                return Err(AgentManagerError::AssignmentTerminal {
                    assignment_id: *assignment_id,
                    status: assignment.status,
                });
            }

            if timestamp_ms < assignment.updated_at_ms {
                return Err(AgentManagerError::TimestampRegression {
                    assignment_id: *assignment_id,
                    current_ms: assignment.updated_at_ms,
                    proposed_ms: timestamp_ms,
                });
            }

            if !assignment
                .status
                .can_transition_to(AssignmentStatus::Failed)
            {
                return Err(AgentManagerError::InvalidAssignmentTransition {
                    assignment_id: *assignment_id,
                    from: assignment.status,
                    to: AssignmentStatus::Failed,
                });
            }

            assignment.transition(AssignmentStatus::Failed, timestamp_ms)?;
            self.update_assignment_in_tx(tx, &assignment)?;

            let mut agent = self.get_agent_from_tx(tx, &assignment.agent_id)?;
            if agent.state == AgentLifecycleState::Running {
                if timestamp_ms < agent.updated_at_ms {
                    return Err(AgentManagerError::TimestampRegression {
                        assignment_id: *assignment_id,
                        current_ms: agent.updated_at_ms,
                        proposed_ms: timestamp_ms,
                    });
                }
                agent.transition(AgentLifecycleState::Ready, timestamp_ms)?;
                self.update_agent_in_tx(tx, &agent)?;
            }

            Ok((assignment, agent))
        })
    }

    /// Cancels an assigned or in-progress assignment, releasing the agent back to `Ready`.
    pub fn cancel_assignment(
        &self,
        assignment_id: &AssignmentId,
        _reason: &str,
        timestamp_ms: u64,
    ) -> Result<(WorkAssignment, AgentRecord), AgentManagerError> {
        self.store.with_write_transaction(|tx| {
            let mut assignment = self.get_assignment_from_tx(tx, assignment_id)?;

            if assignment.status.is_terminal() {
                return Err(AgentManagerError::AssignmentTerminal {
                    assignment_id: *assignment_id,
                    status: assignment.status,
                });
            }

            if timestamp_ms < assignment.updated_at_ms {
                return Err(AgentManagerError::TimestampRegression {
                    assignment_id: *assignment_id,
                    current_ms: assignment.updated_at_ms,
                    proposed_ms: timestamp_ms,
                });
            }

            if !assignment
                .status
                .can_transition_to(AssignmentStatus::Cancelled)
            {
                return Err(AgentManagerError::InvalidAssignmentTransition {
                    assignment_id: *assignment_id,
                    from: assignment.status,
                    to: AssignmentStatus::Cancelled,
                });
            }

            assignment.transition(AssignmentStatus::Cancelled, timestamp_ms)?;
            self.update_assignment_in_tx(tx, &assignment)?;

            let mut agent = self.get_agent_from_tx(tx, &assignment.agent_id)?;
            if agent.state == AgentLifecycleState::Running {
                if timestamp_ms < agent.updated_at_ms {
                    return Err(AgentManagerError::TimestampRegression {
                        assignment_id: *assignment_id,
                        current_ms: agent.updated_at_ms,
                        proposed_ms: timestamp_ms,
                    });
                }
                agent.transition(AgentLifecycleState::Ready, timestamp_ms)?;
                self.update_agent_in_tx(tx, &agent)?;
            }

            Ok((assignment, agent))
        })
    }

    fn get_assignment_from_tx(
        &self,
        conn: &Connection,
        assignment_id: &AssignmentId,
    ) -> Result<WorkAssignment, AgentManagerError> {
        let assignment_id_str = assignment_id.to_string();
        let row: Result<(String, String, String, String, String, String), rusqlite::Error> = conn
            .query_row(
                r#"
                SELECT assignment_id, correlation_id, request_id, agent_id, status, payload
                FROM assignments
                WHERE assignment_id = ?;
                "#,
                rusqlite::params![assignment_id_str],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            );

        let (col_id, col_corr, col_req, col_agent, col_status, payload) = match row {
            Ok(vals) => vals,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                return Err(AgentManagerError::AssignmentNotFound {
                    assignment_id: *assignment_id,
                });
            }
            Err(e) => return Err(map_sqlite_err(e).into()),
        };

        let assignment: WorkAssignment = serde_json::from_str(&payload)?;
        if assignment.assignment_id.to_string() != col_id
            || assignment.correlation_id.to_string() != col_corr
            || assignment.request_id.to_string() != col_req
            || assignment.agent_id.to_string() != col_agent
            || format!("{:?}", assignment.status) != col_status
        {
            return Err(StorageError::CorruptRecord {
                entity: "WorkAssignment",
                id: col_id,
                reason: "Indexed database columns contradict serialized JSON payload".into(),
            }
            .into());
        }

        Ok(assignment)
    }

    fn update_assignment_in_tx(
        &self,
        conn: &Connection,
        assignment: &WorkAssignment,
    ) -> Result<(), AgentManagerError> {
        let assignment_id_str = assignment.assignment_id.to_string();
        let status_str = format!("{:?}", assignment.status);
        let payload = serde_json::to_string(assignment)?;

        let affected = conn
            .execute(
                r#"
                UPDATE assignments
                SET status = ?,
                    updated_at_ms = ?,
                    payload = ?
                WHERE assignment_id = ?;
                "#,
                rusqlite::params![
                    status_str,
                    assignment.updated_at_ms,
                    payload,
                    assignment_id_str,
                ],
            )
            .map_err(map_sqlite_err)?;

        if affected == 0 {
            return Err(AgentManagerError::AssignmentNotFound {
                assignment_id: assignment.assignment_id,
            });
        }

        Ok(())
    }

    fn get_agent_from_tx(
        &self,
        conn: &Connection,
        agent_id: &AgentId,
    ) -> Result<AgentRecord, AgentManagerError> {
        let agent_id_str = agent_id.to_string();
        let row: Result<(String, String, String, String, String), rusqlite::Error> = conn
            .query_row(
                r#"
            SELECT agent_id, state, principal_id, instance_nonce, payload
            FROM agents
            WHERE agent_id = ?;
            "#,
                rusqlite::params![agent_id_str],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            );

        let (col_id, col_state, col_principal, col_nonce, payload) = match row {
            Ok(vals) => vals,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                return Err(AgentManagerError::AgentNotFound {
                    agent_id: *agent_id,
                });
            }
            Err(e) => return Err(map_sqlite_err(e).into()),
        };

        let agent: AgentRecord = serde_json::from_str(&payload)?;
        if agent.agent_id.to_string() != col_id
            || format!("{:?}", agent.state) != col_state
            || agent.owner.actor_id != col_principal
            || agent.process_identity.instance_nonce.to_string() != col_nonce
        {
            return Err(StorageError::CorruptRecord {
                entity: "Agent",
                id: col_id,
                reason: "Indexed database columns contradict serialized JSON payload".into(),
            }
            .into());
        }

        verify_agent_capabilities(conn, &agent)?;

        Ok(agent)
    }

    fn update_agent_in_tx(
        &self,
        conn: &Connection,
        agent: &AgentRecord,
    ) -> Result<(), AgentManagerError> {
        let agent_id_str = agent.agent_id.to_string();
        let payload = serde_json::to_string(agent)?;
        let state_str = format!("{:?}", agent.state);
        let scope_str = format!("{:?}", agent.scope);
        let nonce_str = agent.process_identity.instance_nonce.to_string();

        let affected = conn
            .execute(
                r#"
                UPDATE agents
                SET agent_type = ?,
                    principal_id = ?,
                    scope = ?,
                    instance_nonce = ?,
                    pid = ?,
                    start_time_ticks = ?,
                    state = ?,
                    updated_at_ms = ?,
                    payload = ?
                WHERE agent_id = ?;
                "#,
                rusqlite::params![
                    agent.agent_type.as_str(),
                    agent.owner.actor_id,
                    scope_str,
                    nonce_str,
                    agent.process_identity.pid,
                    agent.process_identity.start_time_ticks,
                    state_str,
                    agent.updated_at_ms,
                    payload,
                    agent_id_str,
                ],
            )
            .map_err(map_sqlite_err)?;

        if affected == 0 {
            return Err(AgentManagerError::AgentNotFound {
                agent_id: agent.agent_id,
            });
        }

        // Resync capability indexes
        conn.execute(
            "DELETE FROM agent_capabilities WHERE agent_id = ?;",
            rusqlite::params![agent_id_str],
        )
        .map_err(map_sqlite_err)?;

        for cap in &agent.declared_capabilities {
            conn.execute(
                "INSERT INTO agent_capabilities (agent_id, capability_id) VALUES (?, ?);",
                rusqlite::params![agent_id_str, cap],
            )
            .map_err(map_sqlite_err)?;
        }

        Ok(())
    }

    /// Reconciles stale and dead in-flight agents on manager startup or recovery.
    ///
    /// Aligned with Phase 2.0 specification, Section 6.2:
    /// 1. Queries all registered agents with state in `('Starting', 'Running')`.
    /// 2. Verifies process liveness via `ProcessObserver` using `(pid, start_time_ticks)`.
    /// 3. For any dead or PID-recycled process:
    ///    - Fails all active assignments bound to the agent with causal lineage preserved.
    ///    - Transitions agent record to `AgentLifecycleState::Failed`.
    ///    - Evaluates declarative `RestartPolicy`: if permitted, schedules clean restart
    ///      (`Failed ─► Starting`) with incremented retry counter, fresh `instance_nonce`,
    ///      and unspawned process identity.
    ///    - If restart is prohibited or retries exhausted, agent remains in `Failed`.
    /// 4. All transitions and assignment updates are committed within a single SQLite transaction.
    /// 5. Strictly idempotent: running reconciliation again immediately results in 0 recoveries.
    pub fn reconcile_startup(
        &self,
        timestamp_ms: u64,
    ) -> Result<ReconciliationReport, AgentManagerError> {
        self.store.with_write_transaction(|tx| {
            let mut stmt = tx
                .prepare(
                    r#"
                    SELECT agent_id, state, principal_id, instance_nonce, payload
                    FROM agents
                    WHERE state IN ('Starting', 'Running')
                    ORDER BY agent_id ASC;
                    "#,
                )
                .map_err(map_sqlite_err)?;

            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                })
                .map_err(map_sqlite_err)?;

            let mut in_flight_agents = Vec::new();
            for item in rows {
                let (col_id, col_state, col_principal, col_nonce, payload) =
                    item.map_err(map_sqlite_err)?;
                let agent: AgentRecord = serde_json::from_str(&payload)?;

                if agent.agent_id.to_string() != col_id
                    || format!("{:?}", agent.state) != col_state
                    || agent.owner.actor_id != col_principal
                    || agent.process_identity.instance_nonce.to_string() != col_nonce
                {
                    return Err(StorageError::CorruptRecord {
                        entity: "Agent",
                        id: col_id,
                        reason: "Indexed database columns contradict serialized JSON payload"
                            .into(),
                    }
                    .into());
                }

                verify_agent_capabilities(tx, &agent)?;
                in_flight_agents.push(agent);
            }

            let agents_scanned = in_flight_agents.len();
            let mut agents_recovered = Vec::new();
            let mut total_assignments_failed = 0;

            for agent in in_flight_agents {
                let liveness = self
                    .process_observer
                    .check_liveness(&agent.process_identity);
                match liveness {
                    ProcessLiveness::Alive => {
                        // Confirmed alive; continues uninterrupted
                    }
                    ProcessLiveness::Unspawned => {
                        // Unspawned starting state awaiting spawn; remains untouched
                    }
                    ProcessLiveness::Dead | ProcessLiveness::Recycled { .. } => {
                        let failure_reason = match liveness {
                            ProcessLiveness::Recycled { observed_ticks } => {
                                AgentFailureReason::PidRecycled {
                                    pid: agent.process_identity.pid.unwrap_or(0),
                                    expected_ticks: agent
                                        .process_identity
                                        .start_time_ticks
                                        .unwrap_or(0),
                                    observed_ticks,
                                }
                            }
                            _ => AgentFailureReason::ProcessTerminated {
                                pid: agent.process_identity.pid,
                                start_time_ticks: agent.process_identity.start_time_ticks,
                            },
                        };

                        let outcome =
                            self.recover_dead_agent_in_tx(tx, agent, failure_reason, timestamp_ms)?;
                        total_assignments_failed += outcome.failed_assignments.len();
                        agents_recovered.push(outcome);
                    }
                    ProcessLiveness::Unknown => {
                        // Fail-closed non-destructive handling: cannot verify host process state.
                        // Must NOT transition agent to Failed.
                        // Must NOT fail active assignments.
                        // Must NOT increment restart retries.
                        // Must NOT create a restart decision.
                    }
                }
            }

            Ok(ReconciliationReport {
                reconciled_at_ms: timestamp_ms,
                agents_scanned,
                agents_recovered,
                total_assignments_failed,
            })
        })
    }

    /// Inspects and reconciles an individual agent if its process is dead or recycled.
    pub fn reconcile_agent(
        &self,
        agent_id: &AgentId,
        timestamp_ms: u64,
    ) -> Result<Option<AgentRecoveryOutcome>, AgentManagerError> {
        self.store.with_write_transaction(|tx| {
            let agent = self.get_agent_from_tx(tx, agent_id)?;
            if agent.state.is_terminal() {
                return Ok(None);
            }

            let liveness = self
                .process_observer
                .check_liveness(&agent.process_identity);
            match liveness {
                ProcessLiveness::Alive | ProcessLiveness::Unspawned | ProcessLiveness::Unknown => {
                    Ok(None)
                }
                ProcessLiveness::Dead | ProcessLiveness::Recycled { .. } => {
                    let failure_reason = match liveness {
                        ProcessLiveness::Recycled { observed_ticks } => {
                            AgentFailureReason::PidRecycled {
                                pid: agent.process_identity.pid.unwrap_or(0),
                                expected_ticks: agent
                                    .process_identity
                                    .start_time_ticks
                                    .unwrap_or(0),
                                observed_ticks,
                            }
                        }
                        _ => AgentFailureReason::ProcessTerminated {
                            pid: agent.process_identity.pid,
                            start_time_ticks: agent.process_identity.start_time_ticks,
                        },
                    };
                    let outcome =
                        self.recover_dead_agent_in_tx(tx, agent, failure_reason, timestamp_ms)?;
                    Ok(Some(outcome))
                }
            }
        })
    }

    /// Explicitly transitions an agent to failure, failing active assignments and evaluating restart policy.
    pub fn handle_agent_failure(
        &self,
        agent_id: &AgentId,
        reason: AgentFailureReason,
        timestamp_ms: u64,
    ) -> Result<AgentRecoveryOutcome, AgentManagerError> {
        self.store.with_write_transaction(|tx| {
            let agent = self.get_agent_from_tx(tx, agent_id)?;
            if agent.state.is_terminal() {
                return Err(AgentLifecycleError::TerminalState {
                    agent_id: *agent_id,
                    state: agent.state,
                }
                .into());
            }

            self.recover_dead_agent_in_tx(tx, agent, reason, timestamp_ms)
        })
    }

    /// Scans non-terminal agents and fails any agents whose heartbeat deadline has expired.
    pub fn check_heartbeat_timeouts(
        &self,
        timestamp_ms: u64,
    ) -> Result<Vec<AgentRecoveryOutcome>, AgentManagerError> {
        self.store.with_write_transaction(|tx| {
            let mut stmt = tx
                .prepare(
                    r#"
                    SELECT agent_id, state, principal_id, instance_nonce, payload
                    FROM agents
                    WHERE state NOT IN ('Stopped', 'Failed')
                    ORDER BY agent_id ASC;
                    "#,
                )
                .map_err(map_sqlite_err)?;

            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                })
                .map_err(map_sqlite_err)?;

            let mut timed_out_agents = Vec::new();
            for item in rows {
                let (col_id, col_state, col_principal, col_nonce, payload) =
                    item.map_err(map_sqlite_err)?;
                let agent: AgentRecord = serde_json::from_str(&payload)?;

                if agent.agent_id.to_string() != col_id
                    || format!("{:?}", agent.state) != col_state
                    || agent.owner.actor_id != col_principal
                    || agent.process_identity.instance_nonce.to_string() != col_nonce
                {
                    return Err(StorageError::CorruptRecord {
                        entity: "Agent",
                        id: col_id,
                        reason: "Indexed database columns contradict serialized JSON payload"
                            .into(),
                    }
                    .into());
                }

                verify_agent_capabilities(tx, &agent)?;

                let health = self
                    .health_evaluator
                    .evaluate_health(&agent, tx, timestamp_ms);
                if let AgentHealthState::Unhealthy { ref reason } = health {
                    if reason.contains("Heartbeat deadline expired") {
                        timed_out_agents.push(agent);
                    }
                }
            }

            let mut outcomes = Vec::new();
            for agent in timed_out_agents {
                let failure_reason = AgentFailureReason::HeartbeatTimeout {
                    elapsed_ms: self.config.heartbeat_timeout_ms + 1,
                    timeout_ms: self.config.heartbeat_timeout_ms,
                };
                let outcome =
                    self.recover_dead_agent_in_tx(tx, agent, failure_reason, timestamp_ms)?;
                outcomes.push(outcome);
            }

            Ok(outcomes)
        })
    }

    /// Recovers a failed or dead agent record within an active SQLite transaction.
    ///
    /// Validates timestamps, transitions all active assignments to `Failed` (preserving causal lineage),
    /// transitions the agent to `Failed`, and if permitted by `RestartPolicy`, re-arms the agent into
    /// `Starting` state with a fresh `instance_nonce` and unspawned process identity.
    fn recover_dead_agent_in_tx(
        &self,
        tx: &rusqlite::Transaction,
        mut agent: AgentRecord,
        failure_reason: AgentFailureReason,
        timestamp_ms: u64,
    ) -> Result<AgentRecoveryOutcome, AgentManagerError> {
        if agent.state.is_terminal() {
            return Err(AgentLifecycleError::TerminalState {
                agent_id: agent.agent_id,
                state: agent.state,
            }
            .into());
        }

        if timestamp_ms < agent.updated_at_ms {
            return Err(AgentLifecycleError::TimestampRegression {
                agent_id: agent.agent_id,
                current_ms: agent.updated_at_ms,
                proposed_ms: timestamp_ms,
            }
            .into());
        }

        let previous_state = agent.state;

        // 1. Query active assignments for this agent
        let agent_id_str = agent.agent_id.to_string();
        let mut stmt = tx
            .prepare(
                r#"
                SELECT assignment_id, correlation_id, request_id, agent_id, status, payload
                FROM assignments
                WHERE agent_id = ? AND status IN ('Assigned', 'InProgress')
                ORDER BY assigned_at_ms ASC;
                "#,
            )
            .map_err(map_sqlite_err)?;

        let rows = stmt
            .query_map(rusqlite::params![agent_id_str], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .map_err(map_sqlite_err)?;

        let mut failed_assignments = Vec::new();
        for item in rows {
            let (id, corr, req, ag, stat, payload) = item.map_err(map_sqlite_err)?;
            let mut assignment: WorkAssignment = serde_json::from_str(&payload)?;

            // Verify dual-write consistency
            if assignment.assignment_id.to_string() != id
                || assignment.correlation_id.to_string() != corr
                || assignment.request_id.to_string() != req
                || assignment.agent_id.to_string() != ag
                || format!("{:?}", assignment.status) != stat
            {
                return Err(StorageError::CorruptRecord {
                    entity: "WorkAssignment",
                    id,
                    reason: "Indexed database columns contradict serialized JSON payload".into(),
                }
                .into());
            }

            if timestamp_ms < assignment.updated_at_ms {
                return Err(AgentManagerError::TimestampRegression {
                    assignment_id: assignment.assignment_id,
                    current_ms: assignment.updated_at_ms,
                    proposed_ms: timestamp_ms,
                });
            }

            assignment.transition(AssignmentStatus::Failed, timestamp_ms)?;
            self.update_assignment_in_tx(tx, &assignment)?;
            failed_assignments.push(assignment.assignment_id);
        }

        // 2. Transition agent to Failed
        agent.transition(AgentLifecycleState::Failed, timestamp_ms)?;

        // 3. Declarative restart policy evaluation
        let (restarted, new_nonce, retries) = if agent.restart_policy.can_restart() {
            let next_nonce = Uuid::new_v4();
            agent.restart(next_nonce, timestamp_ms)?;
            let retries = match agent.restart_policy {
                crate::agent::RestartPolicy::OnFailure {
                    current_retries, ..
                }
                | crate::agent::RestartPolicy::Always {
                    current_retries, ..
                } => current_retries,
                crate::agent::RestartPolicy::Never => 0,
            };
            (true, Some(next_nonce), retries)
        } else {
            let retries = match agent.restart_policy {
                crate::agent::RestartPolicy::OnFailure {
                    current_retries, ..
                }
                | crate::agent::RestartPolicy::Always {
                    current_retries, ..
                } => current_retries,
                crate::agent::RestartPolicy::Never => 0,
            };
            (false, None, retries)
        };

        // 4. Persist updated agent record in tx
        self.update_agent_in_tx(tx, &agent)?;

        Ok(AgentRecoveryOutcome {
            agent_id: agent.agent_id,
            previous_state,
            new_state: agent.state,
            restarted,
            new_instance_nonce: new_nonce,
            retries_attempted: retries,
            failed_assignments,
            failure_reason,
        })
    }
}
