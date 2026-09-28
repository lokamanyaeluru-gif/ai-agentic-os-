//! Typed capability-boundary errors mapped to the ADR-0007 taxonomy.
//!
//! All handoff and construction failures are fail-closed: no binding yields
//! no plan, and no plan is ever launched. Variants convert to
//! [`ErrorPayload`](agenticos_contracts::ErrorPayload) with
//! supervisor-governed retry classes.

use agenticos_contracts::{ErrorCode, ErrorPayload, RetryClassification};
use thiserror::Error;

/// Typed failures of the Layer 9 capability boundary plane.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CapabilityError {
    /// Manifest or bundle input failed structural validation.
    #[error("invalid capability manifest: {reason}")]
    InvalidManifest { reason: String },

    /// No manifest matches `(capability_id, schema_version)` exactly.
    #[error("capability not found: {capability_id} v{capability_schema_version}")]
    UnknownCapability {
        capability_id: String,
        capability_schema_version: u32,
    },

    /// Handoff validation failed (non-`ALLOW` decision, stale snapshot,
    /// scope mismatch, missing confirmation binding).
    #[error("invocation binding rejected: {reason}")]
    BindingRejected { reason: String },

    /// Request arguments violate the manifest input schema.
    #[error("capability arguments invalid: {reason}")]
    SchemaViolation { reason: String },

    /// A Tier 2+ handoff arrived without a bound approval token reference.
    #[error("confirmation required for destructive capability: {capability_id}")]
    TokenRequired { capability_id: String },

    /// A presented decision/token context no longer matches active state.
    #[error("stale authorization context: {reason}")]
    StaleAuthorization { reason: String },

    /// A construction plan failed `validate()`.
    #[error("sandbox plan rejected: {reason}")]
    PlanRejected { reason: String },

    /// Internal boundary fault (hashing, canonicalization, index fault).
    /// Fail-closed.
    #[error("internal capability fault: {reason}")]
    InternalError { reason: String },
}

impl CapabilityError {
    /// Stable source-component label for all Layer 9 errors.
    pub const SOURCE_COMPONENT: &'static str = "capability-boundary";

    /// Map this error to the ADR-0007 [`ErrorPayload`] taxonomy.
    pub fn to_payload(&self) -> ErrorPayload {
        let (code, retry) = match self {
            CapabilityError::InvalidManifest { .. } => {
                (ErrorCode::InvalidRequest, RetryClassification::Never)
            }
            CapabilityError::UnknownCapability { .. } => {
                (ErrorCode::CapabilityNotFound, RetryClassification::Never)
            }
            CapabilityError::BindingRejected { .. } => {
                (ErrorCode::PolicyDenied, RetryClassification::Never)
            }
            CapabilityError::SchemaViolation { .. } => {
                (ErrorCode::MalformedArguments, RetryClassification::Never)
            }
            CapabilityError::TokenRequired { .. } => {
                (ErrorCode::ConfirmationRequired, RetryClassification::Never)
            }
            CapabilityError::StaleAuthorization { .. } => {
                (ErrorCode::InvalidApprovalToken, RetryClassification::Never)
            }
            CapabilityError::PlanRejected { .. } => {
                (ErrorCode::InvalidRequest, RetryClassification::Never)
            }
            CapabilityError::InternalError { .. } => {
                (ErrorCode::InternalError, RetryClassification::Never)
            }
        };
        ErrorPayload::new(code, self.to_string(), Self::SOURCE_COMPONENT, retry)
    }
}
