//! Domain error types for AI Agentic OS core domain models and state machines.

use agenticos_contracts::{ErrorCode, ErrorPayload, RetryClassification};
use uuid::Uuid;

/// Domain error conditions across Intent, Goal, Workflow, and Step lifecycles.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum DomainError {
    #[error("Invalid state transition for {entity} from {from} to {to}")]
    InvalidStateTransition {
        entity: &'static str,
        from: String,
        to: String,
    },

    #[error("Cannot transition {entity} from terminal state {state}")]
    TerminalState { entity: &'static str, state: String },

    #[error("Cycle detected in workflow dependency graph involving step: {step_id}")]
    DependencyCycle { step_id: Uuid },

    #[error("Step dependency references non-existent step: {step_id}")]
    StepNotFound { step_id: Uuid },

    #[error("Step cannot depend on itself: {step_id}")]
    SelfDependency { step_id: Uuid },

    #[error("Duplicate step dependency edge: {step_id} -> {depends_on_step_id}")]
    DuplicateDependency {
        step_id: Uuid,
        depends_on_step_id: Uuid,
    },

    #[error("Duplicate step ID detected in workflow: {step_id}")]
    DuplicateStepId { step_id: Uuid },

    #[error("Dependency cache inconsistency for step {step_id}: derived cache does not match authoritative workflow dependencies")]
    DependencyInconsistency { step_id: Uuid },

    #[error("Correlation ID mismatch: expected {expected}, found {found}")]
    CorrelationIdMismatch { expected: Uuid, found: Uuid },

    #[error("Invalid raw input: {reason}")]
    InvalidRawInput { reason: &'static str },

    #[error("Intent normalization failed: {reason}")]
    NormalizationFailed { reason: String },
}

impl From<DomainError> for ErrorPayload {
    fn from(err: DomainError) -> Self {
        let code = match &err {
            DomainError::InvalidStateTransition { .. } => ErrorCode::InvalidRequest,
            DomainError::TerminalState { .. } => ErrorCode::InvalidRequest,
            DomainError::DependencyCycle { .. } => ErrorCode::InvalidRequest,
            DomainError::StepNotFound { .. } => ErrorCode::InvalidRequest,
            DomainError::SelfDependency { .. } => ErrorCode::InvalidRequest,
            DomainError::DuplicateDependency { .. } => ErrorCode::InvalidRequest,
            DomainError::DuplicateStepId { .. } => ErrorCode::InvalidRequest,
            DomainError::DependencyInconsistency { .. } => ErrorCode::InvalidRequest,
            DomainError::CorrelationIdMismatch { .. } => ErrorCode::InvalidRequest,
            DomainError::InvalidRawInput { .. } => ErrorCode::InvalidRequest,
            DomainError::NormalizationFailed { .. } => ErrorCode::InvalidRequest,
        };

        ErrorPayload::new(
            code,
            err.to_string(),
            "agenticos-core",
            RetryClassification::Never,
        )
    }
}
