//! Execution report, cancellation, timeout, and restart/crash shapes.
//!
//! Shapes only: no report is ever produced, no signal is sent, no worker is
//! supervised in Phase 3.2. Cancellation never implies rollback unless the
//! manifest declares `atomicity` + `compensation` (ADR-0007).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Terminal execution outcome (shape only; `Planned` never advances here).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionStatus {
    Success,
    Failure,
    Cancelled,
    ViolationTerminated,
}

/// Execution report shape (never produced in Phase 3.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionReport {
    pub report_id: Uuid,
    pub binding_id: Uuid,
    pub correlation_id: Uuid,
    pub status: ExecutionStatus,
    pub output: Option<serde_json::Value>,
    pub error: Option<agenticos_contracts::ErrorPayload>,
    pub wall_time_ms: u64,
    pub verification_ref: VerificationRef,
}

/// Reference from a report to its verification record (shape only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationRef {
    pub verification_id: Uuid,
    pub is_satisfied: bool,
}

/// Cancellation signal shape (first-class signal, no rollback implication).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelSignal {
    pub binding_id: Uuid,
    pub reason: String,
}

/// Timeout specification data (enforcement deferred to a future supervisor).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeoutSpec {
    pub wall_time_ms: u64,
}

/// Restart supervision shape (transitions specified, not implemented).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestartShape {
    pub policy: String,
    pub max_retries: u32,
}

/// Crash supervision shape (detection specified, not implemented).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrashShape {
    pub detection: String,
    pub reconcile_to: String,
}
