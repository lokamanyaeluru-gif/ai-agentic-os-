//! Typed policy errors mapped to the ADR-0007 error taxonomy.
//!
//! All evaluation failures are fail-closed: unexpected states yield `DENY`
//! at the decision layer, surfaced here as typed [`PolicyError`]s convertible
//! to [`ErrorPayload`](agenticos_contracts::ErrorPayload).

use agenticos_contracts::{ErrorCode, ErrorPayload, RetryClassification};
use thiserror::Error;

/// Typed failures of the Layer 8 policy evaluation plane.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PolicyError {
    /// Request failed structural validation (empty capability, zero timeout,
    /// malformed resource reference, NUL bytes, oversized fields).
    #[error("invalid capability request: {reason}")]
    InvalidRequest { reason: String },

    /// Request arguments or envelope cannot be processed as structured data.
    #[error("malformed capability arguments: {reason}")]
    MalformedArguments { reason: String },

    /// Referenced capability has no matching declaration in the bundle.
    /// (Issued when no tier declares the capability and no policy matches.)
    #[error("capability not found: {capability_id}")]
    CapabilityNotFound { capability_id: String },

    /// Policy evaluation denied the request by rule.
    #[error("policy denied: {reason}")]
    PolicyDenied {
        reason: String,
        contributing_policies: Vec<String>,
    },

    /// Request requires out-of-band human confirmation.
    #[error("confirmation required: {reason}")]
    ConfirmationRequired {
        reason: String,
        contributing_policies: Vec<String>,
    },

    /// A presented approval token is structurally invalid, expired,
    /// snapshot-mismatched, or cryptographically unverifiable (verification
    /// itself is TBD and therefore never succeeds in Phase 3.1).
    #[error("invalid approval token: {reason}")]
    InvalidApprovalToken { reason: String },

    /// A presented approval token was already redeemed.
    #[error("approval token replay detected")]
    TokenReplayDetected,

    /// Canonical serialization (JCS profile) failed.
    #[error("canonicalization failed: {reason}")]
    CanonicalizationFailed { reason: String },

    /// Policy bundle parsing, schema validation, or snapshot construction
    /// failed. The active snapshot is retained.
    #[error("policy bundle rejected: {reason}")]
    BundleRejected { reason: String },

    /// Requested snapshot version or hash is unknown.
    #[error("unknown policy snapshot: {reason}")]
    UnknownSnapshot { reason: String },

    /// Internal evaluation fault (Cedar error, clock/UUID fault). Fail-closed.
    #[error("internal policy fault: {reason}")]
    InternalError { reason: String },
}

impl PolicyError {
    /// Stable source-component label for all Layer 8 errors.
    pub const SOURCE_COMPONENT: &'static str = "policy-engine";

    /// Map this error to the ADR-0007 [`ErrorPayload`] taxonomy.
    pub fn to_payload(&self) -> ErrorPayload {
        let (code, retry) = match self {
            PolicyError::InvalidRequest { .. } => {
                (ErrorCode::InvalidRequest, RetryClassification::Never)
            }
            PolicyError::MalformedArguments { .. } => {
                (ErrorCode::MalformedArguments, RetryClassification::Never)
            }
            PolicyError::CapabilityNotFound { .. } => {
                (ErrorCode::CapabilityNotFound, RetryClassification::Never)
            }
            PolicyError::PolicyDenied { .. } => {
                (ErrorCode::PolicyDenied, RetryClassification::Never)
            }
            PolicyError::ConfirmationRequired { .. } => {
                (ErrorCode::ConfirmationRequired, RetryClassification::Never)
            }
            PolicyError::InvalidApprovalToken { .. } => {
                (ErrorCode::InvalidApprovalToken, RetryClassification::Never)
            }
            PolicyError::TokenReplayDetected => {
                (ErrorCode::TokenReplayDetected, RetryClassification::Never)
            }
            PolicyError::CanonicalizationFailed { .. } => {
                (ErrorCode::InvalidRequest, RetryClassification::Never)
            }
            PolicyError::BundleRejected { .. } => {
                (ErrorCode::InvalidRequest, RetryClassification::Never)
            }
            PolicyError::UnknownSnapshot { .. } => {
                (ErrorCode::InvalidRequest, RetryClassification::Never)
            }
            PolicyError::InternalError { .. } => {
                (ErrorCode::InternalError, RetryClassification::Never)
            }
        };
        ErrorPayload::new(code, self.to_string(), Self::SOURCE_COMPONENT, retry)
    }
}
