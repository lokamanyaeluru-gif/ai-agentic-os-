//! ExecutionResult domain model and outcome statuses.
//!
//! Aligned with Phase 1.0 specification and ADR-0007.

use agenticos_contracts::ErrorPayload;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Final outcome status of a capability step or workflow execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExecutionOutcomeStatus {
    Success,
    Failure,
    Cancelled,
}

/// Represents the outcome of a capability step or workflow execution.
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

impl ExecutionResult {
    /// Constructs a successful execution result.
    pub fn success(
        request_id: Uuid,
        correlation_id: Uuid,
        step_id: Uuid,
        output: serde_json::Value,
        completed_at_ms: u64,
        execution_duration_ms: u64,
    ) -> Self {
        Self {
            result_id: Uuid::new_v4(),
            request_id,
            correlation_id,
            step_id,
            status: ExecutionOutcomeStatus::Success,
            output: Some(output),
            error: None,
            completed_at_ms,
            execution_duration_ms,
        }
    }

    /// Constructs a failed execution result.
    pub fn failure(
        request_id: Uuid,
        correlation_id: Uuid,
        step_id: Uuid,
        error: ErrorPayload,
        completed_at_ms: u64,
        execution_duration_ms: u64,
    ) -> Self {
        Self {
            result_id: Uuid::new_v4(),
            request_id,
            correlation_id,
            step_id,
            status: ExecutionOutcomeStatus::Failure,
            output: None,
            error: Some(error),
            completed_at_ms,
            execution_duration_ms,
        }
    }

    /// Constructs a cancelled execution result.
    pub fn cancelled(
        request_id: Uuid,
        correlation_id: Uuid,
        step_id: Uuid,
        error: Option<ErrorPayload>,
        completed_at_ms: u64,
        execution_duration_ms: u64,
    ) -> Self {
        Self {
            result_id: Uuid::new_v4(),
            request_id,
            correlation_id,
            step_id,
            status: ExecutionOutcomeStatus::Cancelled,
            output: None,
            error,
            completed_at_ms,
            execution_duration_ms,
        }
    }
}
