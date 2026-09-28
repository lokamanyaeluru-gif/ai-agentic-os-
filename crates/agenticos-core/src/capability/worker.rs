//! Worker-process boundary: descriptor, stdio, and supervision plans.
//!
//! Data only. No process is spawned, no descriptor is passed, no signal is
//! sent. These records exist so a future supervisor cannot substitute
//! self-spawned, self-attested, or socket-less workers: the specified shape
//! mandates supervisor-spawned children on private `socketpair(2)`
//! descriptors with transport attestation (ADR-0002).

use serde::{Deserialize, Serialize};

/// Descriptor-passing intent for the future worker socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocketpairPlan {
    /// Private anonymous `socketpair(2)` between supervisor and worker.
    pub private_socketpair: bool,
    /// Future `SCM_RIGHTS` descriptor names (empty in Phase 3.2).
    pub future_rights: Vec<String>,
}

/// Stdio capture plan with bounded buffers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StdioPlan {
    pub piped: bool,
    pub bounded_buffer_bytes: u64,
}

/// Signal-escalation policy names (no timing constants: TBD §30.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EscalationPolicy {
    pub first_signal: String,
    pub final_signal: String,
}

impl EscalationPolicy {
    /// Specified escalation: SIGTERM first, SIGKILL final.
    pub fn sigterm_then_sigkill() -> Self {
        Self {
            first_signal: "SIGTERM".to_string(),
            final_signal: "SIGKILL".to_string(),
        }
    }
}

/// Supervision lifecycle shape (specified transitions, not implemented).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisionShape {
    pub stages: Vec<String>,
    pub escalation: EscalationPolicy,
    pub crash_signal: String,
}

/// Worker-process boundary plan (data only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerBoundary {
    pub transport: SocketpairPlan,
    pub stdio: StdioPlan,
    pub supervision: SupervisionShape,
}

impl WorkerBoundary {
    /// Standard boundary: private socketpair, piped bounded stdio,
    /// spawn → confine → run → reap supervision with hangup-based crash
    /// detection. Buffer bound is a NON-NORMATIVE implementation default.
    pub fn standard() -> Self {
        Self {
            transport: SocketpairPlan {
                private_socketpair: true,
                future_rights: Vec::new(),
            },
            stdio: StdioPlan {
                piped: true,
                bounded_buffer_bytes: 65_536,
            },
            supervision: SupervisionShape {
                stages: vec![
                    "Spawned".to_string(),
                    "Confined".to_string(),
                    "Running".to_string(),
                    "Reaped".to_string(),
                ],
                escalation: EscalationPolicy::sigterm_then_sigkill(),
                crash_signal: "POLLHUP".to_string(),
            },
        }
    }
}
