//! Typed runtime errors for the Phase 1 coordinator.
//!
//! Distinct from `DomainError` (which covers in-memory state-machine violations)
//! and `StorageError` (which covers SQLite persistence failures).
//! `RuntimeError` covers orchestration-level failures: idempotency, partial state
//! inconsistency, unsupported input, and coordination logic errors.

use agenticos_contracts::{ErrorCode, ErrorPayload, RetryClassification};
use thiserror::Error;
use uuid::Uuid;

use crate::error::DomainError;
use crate::storage::error::StorageError;

/// Runtime orchestration errors for the Phase 1 Intent → Goal → Workflow coordinator.
#[derive(Debug, Error)]
pub enum RuntimeError {
    // -------------------------------------------------------------------------
    // Invalid input / domain validation
    // -------------------------------------------------------------------------
    /// Raw input was structurally invalid before normalization (empty, null bytes, oversized).
    #[error("Invalid intent input: {reason}")]
    InvalidInput { reason: String },

    /// Input normalized successfully but resolved to an unsupported workflow pattern.
    #[error("Unsupported workflow pattern: {reason}")]
    UnsupportedWorkflow { reason: String },

    /// A domain state-machine invariant was violated during orchestration.
    #[error("Domain state machine violation: {0}")]
    DomainViolation(#[from] DomainError),

    // -------------------------------------------------------------------------
    // Persistence
    // -------------------------------------------------------------------------
    /// An underlying domain store operation failed.
    #[error("Storage failure: {0}")]
    StorageFailure(#[from] StorageError),

    // -------------------------------------------------------------------------
    // Idempotency / deduplication
    // -------------------------------------------------------------------------
    /// An idempotency key was reused with materially different raw_input content.
    ///
    /// Idempotent replays (same key + same content) are NOT errors — they are
    /// surfaced as `Phase1Result { is_replay: true }` from the successful result.
    #[error(
        "Idempotency key conflict: key '{idempotency_key}' was previously submitted with \
         different raw_input (existing intent {existing_intent_id})"
    )]
    IdempotencyKeyConflict {
        idempotency_key: String,
        existing_intent_id: Uuid,
    },

    // -------------------------------------------------------------------------
    // Partial state / recovery
    // -------------------------------------------------------------------------
    /// An intent exists in storage but its Goal is missing, and the intent is in
    /// a state from which goal creation cannot be resumed (terminal, or not Accepted).
    #[error(
        "Irreconcilable partial state: intent {intent_id} is in terminal or non-resumable \
         state '{intent_status}' but no goal exists"
    )]
    IrreconcilableIntentState {
        intent_id: Uuid,
        intent_status: String,
    },

    /// A goal exists but its Workflow is missing and the goal is in a non-resumable state.
    #[error(
        "Irreconcilable partial state: goal {goal_id} is in terminal or non-resumable \
         state '{goal_status}' but no workflow exists"
    )]
    IrreconcilableGoalState { goal_id: Uuid, goal_status: String },

    /// The persisted state is internally inconsistent (e.g. goal does not reference
    /// the expected intent, IDs are mismatched, or the uniqueness invariant is violated).
    /// Operator intervention required.
    #[error("Inconsistent persisted state: {reason} (correlation_id: {correlation_id})")]
    InconsistentState {
        correlation_id: Uuid,
        reason: String,
    },

    // -------------------------------------------------------------------------
    // Lifecycle enforcement
    // -------------------------------------------------------------------------
    /// A state transition was attempted that the current runtime phase does not perform.
    /// For example, this runtime never marks Goal/Workflow Completed (no execution yet).
    #[error("Illegal lifecycle operation in this runtime phase: {reason}")]
    IllegalLifecycleOperation { reason: String },
}

impl From<RuntimeError> for ErrorPayload {
    fn from(err: RuntimeError) -> Self {
        let (code, retry) = match &err {
            RuntimeError::InvalidInput { .. } | RuntimeError::UnsupportedWorkflow { .. } => {
                (ErrorCode::InvalidRequest, RetryClassification::Never)
            }
            RuntimeError::DomainViolation(_) => {
                (ErrorCode::InvalidRequest, RetryClassification::Never)
            }
            RuntimeError::IdempotencyKeyConflict { .. } => {
                (ErrorCode::InvalidRequest, RetryClassification::Never)
            }
            RuntimeError::StorageFailure(_) => {
                (ErrorCode::StorageFailure, RetryClassification::Safe)
            }
            RuntimeError::IrreconcilableIntentState { .. }
            | RuntimeError::IrreconcilableGoalState { .. }
            | RuntimeError::InconsistentState { .. } => {
                (ErrorCode::InternalError, RetryClassification::Never)
            }
            RuntimeError::IllegalLifecycleOperation { .. } => {
                (ErrorCode::InvalidRequest, RetryClassification::Never)
            }
        };

        ErrorPayload::new(code, err.to_string(), "runtime", retry)
    }
}
