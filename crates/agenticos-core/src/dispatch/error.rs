//! Dispatch-local faults mapped to the ADR-0007 error taxonomy.
//!
//! Only two faults originate in the dispatcher itself (`SynthesisConflict`
//! for schema-version ambiguity, `ClaimRejected` as a defense-in-depth
//! pre-check behind the authoritative manager guards). Every other failure
//! surfaces verbatim from Phase 2 (`AgentManagerError`), Phase 3.1
//! (`PolicyError`), or Phase 3.2 (`CapabilityError`) without rewrapping
//! that loses codes.

use agenticos_contracts::{ErrorCode, ErrorPayload, RetryClassification};
use thiserror::Error;

/// Typed faults originating in the Layer 6 dispatch consumer.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DispatchError {
    /// Schema-version resolution failed: zero or multiple registered
    /// versions for the assignment's capability (no silent fallback, ever).
    #[error("synthesis conflict: {reason}")]
    SynthesisConflict { reason: String },

    /// Assignment not claimable (not `Assigned`, unknown ID). Defense in
    /// depth: the manager's own transition guards remain authoritative.
    #[error("claim rejected: {reason}")]
    ClaimRejected { reason: String },
}

impl DispatchError {
    /// Stable source-component label for all dispatch errors.
    pub const SOURCE_COMPONENT: &'static str = "dispatch-consumer";

    /// Map this error to the ADR-0007 [`ErrorPayload`] taxonomy.
    pub fn to_payload(&self) -> ErrorPayload {
        let (code, retry) = match self {
            DispatchError::SynthesisConflict { .. } => {
                (ErrorCode::InvalidRequest, RetryClassification::Never)
            }
            DispatchError::ClaimRejected { .. } => {
                (ErrorCode::InvalidRequest, RetryClassification::Never)
            }
        };
        ErrorPayload::new(code, self.to_string(), Self::SOURCE_COMPONENT, retry)
    }
}
