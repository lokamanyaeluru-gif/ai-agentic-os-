//! Mechanical request synthesis (Phase 3.3 §6).
//!
//! Every field derives from the assignment, the active policy snapshot, or
//! the caller clock. Nothing is modeled or defaulted from ambition: the
//! single non-mechanical field (`capability_schema_version`) resolves
//! through the deterministic §6.1 registry-count rule, failing closed on
//! zero or multiple registered versions.

use super::error::DispatchError;
use crate::agent::WorkAssignment;
use crate::capability::CapabilityRegistry;
use crate::policy::CapabilityInvocationRequest;

/// Synthesize a `CapabilityInvocationRequest` from a claimed assignment.
///
/// Field rules (spec §6 table): IDs, capability, resource, arguments, and
/// timeout copy verbatim; `deadline_ms` is a saturating add; the snapshot
/// hash is freshly read; `approval_token` is always `None` (dispatch mints
/// nothing — Tier 2+ flows terminate `ConfirmPending` by construction).
pub fn synthesize(
    assignment: &WorkAssignment,
    active_snapshot_hash: &[u8; 32],
    registry: &CapabilityRegistry,
) -> Result<CapabilityInvocationRequest, DispatchError> {
    let capability_schema_version = resolve_schema_version(&assignment.capability_id, registry)?;
    Ok(CapabilityInvocationRequest {
        request_id: assignment.request_id,
        correlation_id: assignment.correlation_id,
        capability_id: assignment.capability_id.clone(),
        capability_schema_version,
        resource: assignment.resource.clone(),
        arguments: assignment.arguments.clone(),
        deadline_ms: assignment
            .assigned_at_ms
            .saturating_add(assignment.timeout_duration_ms),
        timeout_duration_ms: assignment.timeout_duration_ms,
        policy_snapshot_hash: *active_snapshot_hash,
        approval_token: None,
    })
}

/// Deterministic schema-version resolution (§6.1).
///
/// Collects all registered versions for the capability ID: exactly one →
/// use it; zero → `SynthesisConflict` naming the capability (the registry
/// lookup in `bind` would equally refuse an unknown ID); more than one →
/// `SynthesisConflict` (no silent version fallback, ever).
pub fn resolve_schema_version(
    capability_id: &str,
    registry: &CapabilityRegistry,
) -> Result<u32, DispatchError> {
    let mut versions: Vec<u32> = registry
        .manifests()
        .filter(|manifest| manifest.capability_id == capability_id)
        .map(|manifest| manifest.capability_schema_version)
        .collect();
    versions.sort_unstable();
    versions.dedup();
    match versions.as_slice() {
        [version] => Ok(*version),
        [] => Err(DispatchError::SynthesisConflict {
            reason: format!("no registered version for '{capability_id}'"),
        }),
        _ => Err(DispatchError::SynthesisConflict {
            reason: format!("ambiguous versions for '{capability_id}': no silent fallback"),
        }),
    }
}
