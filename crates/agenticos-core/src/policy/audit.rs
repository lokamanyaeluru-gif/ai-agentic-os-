//! Audit event *shapes* for Layer 8 evaluations (Phase 3.0 §16).
//!
//! Shapes only: sequence numbers, authoritative timestamps, event IDs, and
//! hash-chain linkage are assigned solely by the Layer 12 writer, which is
//! NOT implemented here. Integrity anchors remain TBD (ADR-0006).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Append-only audit record shape for one policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyAuditRecord {
    /// Fixed event discriminator.
    pub event_type: String,
    /// Caller-supplied clock reading (fixture time in tests; supervisor
    /// time in production). Never sourced from the request itself.
    pub timestamp_ms: u64,
    pub request_id: Uuid,
    pub correlation_id: Uuid,
    /// Verbatim actor label (provenance, not auth authority).
    pub principal: String,
    /// Capability identifier under evaluation.
    pub action: String,
    pub resource_kind: String,
    pub resource_id: String,
    /// `ALLOW`, `DENY`, or `CONFIRM`.
    pub decision: String,
    /// Tier-scoped determining policy IDs (`{tier}-{index}`).
    pub contributing_policies: Vec<String>,
    pub confirmation_required: bool,
    /// Redeemed/presented token ID, if any.
    pub approval_token_id: Option<Uuid>,
    /// Snapshot hash the request was formed under (hex).
    pub request_snapshot_hash: String,
    /// Active snapshot hash at evaluation (hex).
    pub active_snapshot_hash: String,
    /// Active snapshot version at evaluation.
    pub active_snapshot_version: String,
}

impl PolicyAuditRecord {
    /// Construct the shape for a terminal decision. Hashes are rendered as
    /// lowercase hex via manual formatting (no `hex` crate per §26).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        timestamp_ms: u64,
        request_id: Uuid,
        correlation_id: Uuid,
        principal: String,
        action: String,
        resource_kind: String,
        resource_id: String,
        decision: &str,
        contributing_policies: Vec<String>,
        confirmation_required: bool,
        approval_token_id: Option<Uuid>,
        request_snapshot_hash: &[u8; 32],
        active_snapshot_hash: &[u8; 32],
        active_snapshot_version: String,
    ) -> Self {
        Self {
            event_type: "policy_evaluation".to_string(),
            timestamp_ms,
            request_id,
            correlation_id,
            principal,
            action,
            resource_kind,
            resource_id,
            decision: decision.to_string(),
            contributing_policies,
            confirmation_required,
            approval_token_id,
            request_snapshot_hash: hex_of(request_snapshot_hash),
            active_snapshot_hash: hex_of(active_snapshot_hash),
            active_snapshot_version,
        }
    }
}

fn hex_of(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).unwrap_or('0'));
        out.push(char::from_digit((byte & 0x0F) as u32, 16).unwrap_or('0'));
    }
    out
}
