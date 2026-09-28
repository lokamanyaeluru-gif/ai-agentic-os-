//! Agent health telemetry and derived operational state.
//!
//! # Distinction Between Authoritative State, Observed Telemetry, and Derived Health
//!
//! - **Authoritative State (`AgentLifecycleState`)**:
//!   The official state machine status stored in the primary agent record.
//!   It advances only through explicit lifecycle events (spawn, ready, assign, stop, fail).
//!
//! - **Observed Telemetry (`HeartbeatRecord`)**:
//!   Raw time-series heartbeats and resource metrics emitted by an active agent process.
//!   It is strictly observational and does not directly mutate authoritative state.
//!
//! - **Derived Operational Health (`AgentHealthState`)**:
//!   Dynamically evaluated by the health monitor based on observed heartbeat arrival times,
//!   process liveness, and resource thresholds. It informs selection eligibility and can
//!   trigger an explicit lifecycle transition to `Failed` if unrecoverable thresholds are breached.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::identity::AgentId;

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

impl AgentHealthState {
    /// Returns true if the agent is eligible to receive work assignments.
    pub fn is_work_eligible(&self) -> bool {
        matches!(self, Self::Healthy | Self::Degraded { .. })
    }
}

/// Observed raw heartbeat telemetry record received over IPC from an active agent process.
///
/// ### Heartbeat Timing Invariant
/// - Agent heartbeats are discrete periodic telemetry samples emitted on a configured interval
///   (default `1000ms`, minimum `100ms`).
/// - Multiple valid heartbeat records for the same agent cannot legally share the same millisecond
///   timestamp. Exactly one heartbeat record is permitted per `(agent_id, timestamp_ms)`.
/// - In the persistent telemetry table (`agent_heartbeats`), `(agent_id, timestamp_ms)` forms the
///   primary key. Attempting to record multiple heartbeats with identical timestamps for the same
///   agent is rejected as a duplicate key error, ensuring time-series uniqueness and deduplicating
///   IPC retransmissions.
/// - `sequence_number` provides monotonic per-instance ordering and packet loss detection over IPC,
///   while `instance_nonce` identifies the manager-approved process session to reject stale heartbeats.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatRecord {
    /// Agent instance identifier.
    pub agent_id: AgentId,

    /// Manager-issued session token verifying the instance session.
    pub instance_nonce: Uuid,

    /// Epoch timestamp (ms, UTC) when heartbeat was generated.
    pub timestamp_ms: u64,

    /// Monotonically increasing sequence number for ordering heartbeats.
    pub sequence_number: u64,

    /// Resource telemetry snapshot accompanying the heartbeat.
    pub metrics: AgentResourceMetrics,
}

impl HeartbeatRecord {
    pub fn new(
        agent_id: AgentId,
        instance_nonce: Uuid,
        timestamp_ms: u64,
        sequence_number: u64,
        metrics: AgentResourceMetrics,
    ) -> Self {
        Self {
            agent_id,
            instance_nonce,
            timestamp_ms,
            sequence_number,
            metrics,
        }
    }
}

/// Resource telemetry accompanying observed heartbeats.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentResourceMetrics {
    /// CPU usage in permille (0 to 1000, representing 0.0% to 100.0%).
    pub cpu_usage_permille: u32,

    /// Resident set size (RSS) memory in bytes.
    pub memory_rss_bytes: u64,

    /// Number of open file descriptors.
    pub open_fds: u32,
}

impl AgentResourceMetrics {
    pub const fn new(cpu_usage_permille: u32, memory_rss_bytes: u64, open_fds: u32) -> Self {
        Self {
            cpu_usage_permille,
            memory_rss_bytes,
            open_fds,
        }
    }
}
