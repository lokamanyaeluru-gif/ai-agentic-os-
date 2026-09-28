//! Failure recovery, stale-state reconciliation, and restart scheduling.
//!
//! Aligned with Phase 2.0 specification, Section 6 and Section 8.5.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::agent::{AgentId, AgentLifecycleState, AssignmentId};

/// Typed reason for agent failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentFailureReason {
    /// Agent process terminated or crashed (PID no longer exists on host).
    ProcessTerminated {
        pid: Option<u32>,
        start_time_ticks: Option<u64>,
    },

    /// Host OS recycled the PID (PID exists but `start_time_ticks` does not match).
    PidRecycled {
        pid: u32,
        expected_ticks: u64,
        observed_ticks: u64,
    },

    /// Agent failed to send a heartbeat within the configured deadline.
    HeartbeatTimeout { elapsed_ms: u64, timeout_ms: u64 },

    /// Stale agent instance detected and reconciled during manager startup recovery.
    StartupReconciliation { details: String },

    /// Explicit failure signaled by runtime or test harness.
    ExplicitFailure { reason: String },
}

impl std::fmt::Display for AgentFailureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProcessTerminated {
                pid,
                start_time_ticks,
            } => {
                write!(
                    f,
                    "Process terminated (pid: {:?}, start_time_ticks: {:?})",
                    pid, start_time_ticks
                )
            }
            Self::PidRecycled {
                pid,
                expected_ticks,
                observed_ticks,
            } => {
                write!(
                    f,
                    "PID {} recycled by host OS (expected start_time_ticks: {}, observed: {})",
                    pid, expected_ticks, observed_ticks
                )
            }
            Self::HeartbeatTimeout {
                elapsed_ms,
                timeout_ms,
            } => {
                write!(
                    f,
                    "Heartbeat deadline expired (elapsed: {}ms, timeout: {}ms)",
                    elapsed_ms, timeout_ms
                )
            }
            Self::StartupReconciliation { details } => {
                write!(f, "Startup reconciliation: {}", details)
            }
            Self::ExplicitFailure { reason } => {
                write!(f, "Explicit failure: {}", reason)
            }
        }
    }
}

/// Typed reason for assignment failure during agent recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssignmentFailureReason {
    /// The assigned agent process died or became stale while the assignment was active.
    AgentDiedDuringExecution { agent_id: AgentId, cause: String },

    /// Assignment failed due to manager startup reconciliation of stale agent.
    StartupReconciliation { agent_id: AgentId },

    /// Assignment execution timed out.
    ExecutionTimeout { timeout_ms: u64 },

    /// Explicit failure.
    ExplicitFailure { reason: String },
}

impl std::fmt::Display for AssignmentFailureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AgentDiedDuringExecution { agent_id, cause } => {
                write!(
                    f,
                    "Assigned agent '{}' died during execution: {}",
                    agent_id, cause
                )
            }
            Self::StartupReconciliation { agent_id } => {
                write!(
                    f,
                    "Assigned agent '{}' died prior to manager startup reconciliation",
                    agent_id
                )
            }
            Self::ExecutionTimeout { timeout_ms } => {
                write!(f, "Assignment execution timed out after {}ms", timeout_ms)
            }
            Self::ExplicitFailure { reason } => {
                write!(f, "Assignment failed: {}", reason)
            }
        }
    }
}

/// Detailed outcome of recovering an individual agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRecoveryOutcome {
    /// Agent identifier that underwent recovery.
    pub agent_id: AgentId,

    /// State prior to recovery transition (e.g. `Running` or `Starting`).
    pub previous_state: AgentLifecycleState,

    /// Final state after recovery (either `Starting` if restarted, or `Failed` if terminal).
    pub new_state: AgentLifecycleState,

    /// True if the agent's restart policy permitted and triggered a restart.
    pub restarted: bool,

    /// Newly minted instance nonce if restarted; None if left in `Failed`.
    pub new_instance_nonce: Option<Uuid>,

    /// Total retries attempted so far under the restart policy.
    pub retries_attempted: u32,

    /// List of active work assignment IDs that were failed due to this agent's failure.
    pub failed_assignments: Vec<AssignmentId>,

    /// Reason why the agent was failed.
    pub failure_reason: AgentFailureReason,
}

/// Summary report of manager startup reconciliation across all in-flight agents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconciliationReport {
    /// Timestamp (ms, UTC) when reconciliation occurred.
    pub reconciled_at_ms: u64,

    /// Number of in-flight agents inspected.
    pub agents_scanned: usize,

    /// List of agent recovery outcomes for agents that were recovered.
    pub agents_recovered: Vec<AgentRecoveryOutcome>,

    /// Total number of work assignments failed during reconciliation.
    pub total_assignments_failed: usize,
}
