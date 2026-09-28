//! Authorization-to-execution handoff: [`InvocationBinding`] construction,
//! scope intersection, and content hashing.
//!
//! A binding joins exactly one validated request, one Layer 8 `ALLOW`
//! decision, and one registry manifest. Phase 3.1 remains the sole
//! authorization authority: this module re-validates, never re-decides.
//! An `ALLOW` is permission to PLAN, never permission to execute.
//!
//! Scope intersection follows Decision 1 (independent carry-through):
//! Layer-8 path/resource data travels verbatim; manifest scope labels match
//! by exact string equality only. Scope labels are symbolic — never paths,
//! never prefixes, never filesystem authority.

use super::error::CapabilityError;
use super::manifest::{CapabilityManifest, RiskTier};
use super::registry::CapabilityRegistry;
use crate::policy::{
    canonical::{canonical_json_bytes, sha256},
    request::validate_request,
    CapabilityInvocationRequest, PolicyDecision, SandboxConstraints,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

/// Decision reference carried into the binding (provenance, not authority).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionRef {
    pub snapshot_hash: [u8; 32],
    pub contributing_policies: Vec<String>,
}

/// Resolved post-intersection constraints for ONE bound invocation.
///
/// Relationship to Phase 3.1 `SandboxConstraints` (which is UNCHANGED):
/// `SandboxConstraints` is the Layer 8 authorization output — what policy
/// allows. `ResolvedConstraints` is that output intersected with the
/// manifest's declared scopes — what policy allows AND the capability
/// declares. Every field is carried verbatim except scope-label matching
/// (exact equality, Decision 1) and the network dual-authorization rule.
/// `ResolvedConstraints` never widens `SandboxConstraints`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedConstraints {
    /// Layer-8 read paths, verbatim (policy-scoped).
    pub read_paths: Vec<PathBuf>,
    /// Layer-8 write paths, verbatim (policy-scoped).
    pub write_paths: Vec<PathBuf>,
    /// Manifest read-scope labels exactly matching the request kind.
    pub matched_read_scopes: Vec<String>,
    /// Manifest write-scope labels exactly matching the request kind.
    pub matched_write_scopes: Vec<String>,
    /// True only under dual authorization (§11 rule below).
    pub allow_network: bool,
    /// Named endpoint when dual-authorized, else None.
    pub network_endpoint: Option<String>,
    /// Routing label carried through (contents TBD, never interpreted).
    pub seccomp_profile: String,
    pub max_memory_bytes: u64,
    pub max_cpu_quota_percent: u32,
    pub max_wall_time_ms: u64,
}

/// Frozen authorization-to-execution handoff record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationBinding {
    pub binding_id: Uuid,
    pub request_id: Uuid,
    pub correlation_id: Uuid,
    pub capability_id: String,
    pub capability_schema_version: u32,
    pub decision_ref: DecisionRef,
    pub manifest_ref: String,
    pub resolved: ResolvedConstraints,
    pub binding_hash: [u8; 32],
}

/// Construct a binding: the §10 five-step order, fail-closed at every step.
///
/// 1. Re-validate the request (Phase 3.1 structural rules).
/// 2. Require `PolicyDecision::Allow` (type-level: other variants reject).
/// 3. Require `request.policy_snapshot_hash` to equal the active snapshot.
/// 4. Registry exact lookup (miss → `UnknownCapability`).
/// 5. Schema check, Tier 2+ token presence, scope intersection.
pub fn bind(
    request: &CapabilityInvocationRequest,
    decision: &PolicyDecision,
    active_snapshot_hash: &[u8; 32],
    registry: &CapabilityRegistry,
) -> Result<InvocationBinding, CapabilityError> {
    validate_request(request).map_err(|err| CapabilityError::BindingRejected {
        reason: format!("request re-validation failed: {err}"),
    })?;
    let (constraints, contributing) = match decision {
        PolicyDecision::Allow {
            constraints,
            contributing_policies,
        } => (constraints, contributing_policies.clone()),
        PolicyDecision::Deny { .. } => {
            return Err(CapabilityError::BindingRejected {
                reason: "decision is DENY: handoff refused".to_string(),
            });
        }
        PolicyDecision::Confirm { .. } => {
            return Err(CapabilityError::BindingRejected {
                reason: "decision is CONFIRM without redeemed token: handoff refused".to_string(),
            });
        }
    };
    if &request.policy_snapshot_hash != active_snapshot_hash {
        return Err(CapabilityError::StaleAuthorization {
            reason: "request snapshot differs from active snapshot: no silent downgrade"
                .to_string(),
        });
    }
    let manifest = registry.get(&request.capability_id, request.capability_schema_version)?;
    if matches!(manifest.risk_tier, RiskTier::Tier2 | RiskTier::Tier3)
        && request.approval_token.is_none()
    {
        return Err(CapabilityError::TokenRequired {
            capability_id: request.capability_id.clone(),
        });
    }
    super::manifest::check_arguments(&manifest.input_schema, &request.arguments)?;
    let resolved = intersect(constraints, manifest, &request.resource.kind)?;
    let mut contributing = contributing;
    contributing.sort();
    let binding_id = Uuid::new_v4();
    let manifest_ref = format!(
        "{}@{}",
        manifest.capability_id, manifest.capability_schema_version
    );
    let decision_ref = DecisionRef {
        snapshot_hash: *active_snapshot_hash,
        contributing_policies: contributing,
    };
    let binding_hash =
        binding_content_hash(binding_id, request, &decision_ref, &manifest_ref, &resolved)
            .map_err(|reason| CapabilityError::InternalError { reason })?;
    Ok(InvocationBinding {
        binding_id,
        request_id: request.request_id,
        correlation_id: request.correlation_id,
        capability_id: request.capability_id.clone(),
        capability_schema_version: request.capability_schema_version,
        decision_ref,
        manifest_ref,
        resolved,
        binding_hash,
    })
}

/// Intersect Layer-8 constraints with manifest scopes (Decision 1).
///
/// * Paths travel verbatim; Tier 0 rejects non-empty `write_paths`.
/// * `resource.kind` must exactly equal a declared read or write scope
///   label, else the intersection is empty → reject.
/// * Network requires both sides: constraints flag plus an identical
///   manifest endpoint string. A manifest-declared need denied by policy
///   rejects the handoff (required access unavailable).
/// * Ceilings and the seccomp label travel verbatim.
fn intersect(
    constraints: &SandboxConstraints,
    manifest: &CapabilityManifest,
    resource_kind: &str,
) -> Result<ResolvedConstraints, CapabilityError> {
    let mismatch = |reason: &str| CapabilityError::BindingRejected {
        reason: reason.to_string(),
    };
    if manifest.risk_tier == RiskTier::Tier0 && !constraints.write_paths.is_empty() {
        return Err(mismatch(
            "Tier 0 read-only binding must not carry write paths",
        ));
    }
    let matched_read_scopes: Vec<String> = manifest
        .declared_read_scopes
        .iter()
        .filter(|scope| scope.as_str() == resource_kind)
        .cloned()
        .collect();
    let matched_write_scopes: Vec<String> = manifest
        .declared_write_scopes
        .iter()
        .filter(|scope| scope.as_str() == resource_kind)
        .cloned()
        .collect();
    if matched_read_scopes.is_empty() && matched_write_scopes.is_empty() {
        return Err(mismatch("resource kind matches no declared manifest scope"));
    }
    let (allow_network, network_endpoint) =
        match (constraints.allow_network, manifest.network_need.as_deref()) {
            (true, Some(endpoint)) => (true, Some(endpoint.to_string())),
            (true, None) => (false, None),
            (false, None) => (false, None),
            (false, Some(_)) => {
                return Err(mismatch(
                    "manifest requires network access denied by policy",
                ));
            }
        };
    let mut read_paths = constraints.read_paths.clone();
    read_paths.sort();
    let mut write_paths = constraints.write_paths.clone();
    write_paths.sort();
    Ok(ResolvedConstraints {
        read_paths,
        write_paths,
        matched_read_scopes,
        matched_write_scopes,
        allow_network,
        network_endpoint,
        seccomp_profile: constraints.seccomp_profile.clone(),
        max_memory_bytes: constraints.max_memory_bytes,
        max_cpu_quota_percent: constraints.max_cpu_quota_percent,
        max_wall_time_ms: constraints.max_wall_time_ms,
    })
}

/// Binding content hash: SHA-256 over the JCS canonical encoding
/// (Decision 2 — the Phase 3.1 mechanism, no new scheme).
fn binding_content_hash(
    binding_id: Uuid,
    request: &CapabilityInvocationRequest,
    decision_ref: &DecisionRef,
    manifest_ref: &str,
    resolved: &ResolvedConstraints,
) -> Result<[u8; 32], String> {
    let value = serde_json::json!({
        "domain": "agenticos-invocation-binding/v1",
        "binding_id": binding_id,
        "request_id": request.request_id,
        "correlation_id": request.correlation_id,
        "capability_id": request.capability_id,
        "capability_schema_version": request.capability_schema_version,
        "resource_kind": request.resource.kind,
        "resource_id": request.resource.identifier,
        "arguments": request.arguments,
        "snapshot_hash": decision_ref.snapshot_hash.to_vec(),
        "contributing_policies": decision_ref.contributing_policies,
        "manifest_ref": manifest_ref,
        "resolved": serde_json::to_value(resolved).map_err(|e| format!("{e}"))?,
    });
    canonical_json_bytes(&value)
        .map(|bytes| sha256(&bytes))
        .map_err(|e| format!("{e}"))
}
