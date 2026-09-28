//! Heartbeat monitoring and liveness evaluation for Layer 5 (Global Agent Manager).
//!
//! Aligned with Phase 2.0 specification, Checkpoint 2.5.

use crate::agent::manager::{AgentManagerError, GlobalAgentManager};
use crate::agent::recovery::AgentRecoveryOutcome;

/// Heartbeat and liveness monitor for agent instances.
#[derive(Clone)]
pub struct HeartbeatMonitor {
    manager: GlobalAgentManager,
}

impl HeartbeatMonitor {
    /// Creates a new `HeartbeatMonitor` wrapping a `GlobalAgentManager`.
    pub fn new(manager: GlobalAgentManager) -> Self {
        Self { manager }
    }

    /// Evaluates all registered agents for heartbeat deadlines and fails timed-out agents.
    pub fn scan_and_reconcile_heartbeats(
        &self,
        timestamp_ms: u64,
    ) -> Result<Vec<AgentRecoveryOutcome>, AgentManagerError> {
        self.manager.check_heartbeat_timeouts(timestamp_ms)
    }
}
