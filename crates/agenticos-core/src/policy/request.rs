//! Evaluation input contracts: [`CapabilityInvocationRequest`],
//! [`ApprovalSubject`], and structural [`ApprovalToken`] shapes.
//!
//! Field-for-field compatible with ADR-0007 and Phase 3.0 §5/§14. The
//! `ResourceRef` is consumed **opaquely** (see crate docs): no path
//! hierarchy, no prefix containment, no filesystem authorization is
//! performed at this layer.
//!
//! Cryptographic token *verification* is TBD and therefore never succeeds
//! in Phase 3.1: only structural binding (hash equality, snapshot binding,
//! principal/capability/resource binding, expiry shape, single-use shape)
//! is checked, and only against explicitly labeled test fixtures.

use super::canonical::{canonical_json_bytes, sha256};
use super::error::PolicyError;
use agenticos_contracts::ResourceRef;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Maximum accepted lengths (NON-NORMATIVE implementation safety bounds
/// guarding against resource-exhaustion inputs; not architectural limits
/// and not a resolution of any Phase 3 TBD).
pub const MAX_CAPABILITY_ID_LEN: usize = 256;
pub const MAX_RESOURCE_FIELD_LEN: usize = 1024;
pub const MAX_ACTOR_ID_LEN: usize = 1024;

/// Canonical approval subject: the request fields covered by `request_hash`.
///
/// Excludes `approval_token` to avoid the circular hash dependency
/// (ADR-0007 / Phase 3.0 §14).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalSubject {
    pub request_id: Uuid,
    pub correlation_id: Uuid,
    pub capability_id: String,
    pub capability_schema_version: u32,
    pub resource: ResourceRef,
    pub arguments: serde_json::Value,
    pub deadline_ms: u64,
    pub timeout_duration_ms: u64,
    pub policy_snapshot_hash: [u8; 32],
}

/// Signed payload portion of an approval token (structural shape only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalTokenSignedPayload {
    pub single_use_id: Uuid,
    pub request_hash: [u8; 32],
    pub policy_snapshot_hash: [u8; 32],
    pub principal: String,
    pub capability: String,
    pub resource: ResourceRef,
    pub confirmation_reason: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub nonce: [u8; 16],
}

/// Approval token: canonical payload plus an opaque signature blob.
///
/// The signature algorithm, encoding, key custody, and verification are
/// explicitly TBD and NOT implemented. The `signature` bytes are carried
/// opaquely and never verified in Phase 3.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalToken {
    pub payload: ApprovalTokenSignedPayload,
    pub signature: Vec<u8>,
}

/// Capability invocation request consumed by the Layer 8 evaluator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityInvocationRequest {
    pub request_id: Uuid,
    pub correlation_id: Uuid,
    pub capability_id: String,
    pub capability_schema_version: u32,
    pub resource: ResourceRef,
    pub arguments: serde_json::Value,
    pub deadline_ms: u64,
    pub timeout_duration_ms: u64,
    pub policy_snapshot_hash: [u8; 32],
    pub approval_token: Option<ApprovalToken>,
}

impl CapabilityInvocationRequest {
    /// Extract the canonical [`ApprovalSubject`] (drops `approval_token`).
    pub fn approval_subject(&self) -> ApprovalSubject {
        ApprovalSubject {
            request_id: self.request_id,
            correlation_id: self.correlation_id,
            capability_id: self.capability_id.clone(),
            capability_schema_version: self.capability_schema_version,
            resource: self.resource.clone(),
            arguments: self.arguments.clone(),
            deadline_ms: self.deadline_ms,
            timeout_duration_ms: self.timeout_duration_ms,
            policy_snapshot_hash: self.policy_snapshot_hash,
        }
    }
}

/// Compute `SHA-256(canonical_json(subject))` per the ADR-0007 profile.
pub fn compute_request_hash(subject: &ApprovalSubject) -> Result<[u8; 32], PolicyError> {
    let value = serde_json::to_value(subject).map_err(|_| PolicyError::CanonicalizationFailed {
        reason: "approval subject serialization failed".to_string(),
    })?;
    let bytes = canonical_json_bytes(&value)?;
    Ok(sha256(&bytes))
}

/// Strict structural validation of an evaluation request.
///
/// Rejects empty/oversized capability IDs, empty resource fields, NUL
/// bytes, and zero timeouts with [`PolicyError::InvalidRequest`].
/// Arguments may be any JSON value; canonicalizability is enforced only
/// where a token binding is evaluated.
pub fn validate_request(request: &CapabilityInvocationRequest) -> Result<(), PolicyError> {
    let invalid = |reason: &str| PolicyError::InvalidRequest {
        reason: reason.to_string(),
    };
    if request.capability_id.is_empty() {
        return Err(invalid("capability_id must not be empty"));
    }
    if request.capability_id.len() > MAX_CAPABILITY_ID_LEN {
        return Err(invalid("capability_id exceeds length limit"));
    }
    if request.capability_id.contains('\0') {
        return Err(invalid("capability_id contains NUL byte"));
    }
    if request.resource.kind.is_empty() || request.resource.identifier.is_empty() {
        return Err(invalid("resource kind and identifier must not be empty"));
    }
    if request.resource.kind.len() > MAX_RESOURCE_FIELD_LEN
        || request.resource.identifier.len() > MAX_RESOURCE_FIELD_LEN
    {
        return Err(invalid("resource field exceeds length limit"));
    }
    if request.resource.kind.contains('\0') || request.resource.identifier.contains('\0') {
        return Err(invalid("resource field contains NUL byte"));
    }
    if request.timeout_duration_ms == 0 {
        return Err(invalid("timeout_duration_ms must be non-zero"));
    }
    Ok(())
}

/// Validate an attested principal label for use in evaluation fixtures.
pub fn validate_actor_label(actor_id: &str) -> Result<(), PolicyError> {
    if actor_id.is_empty() {
        return Err(PolicyError::InvalidRequest {
            reason: "actor_id must not be empty".to_string(),
        });
    }
    if actor_id.len() > MAX_ACTOR_ID_LEN {
        return Err(PolicyError::InvalidRequest {
            reason: "actor_id exceeds length limit".to_string(),
        });
    }
    if actor_id.contains('\0') {
        return Err(PolicyError::InvalidRequest {
            reason: "actor_id contains NUL byte".to_string(),
        });
    }
    Ok(())
}
