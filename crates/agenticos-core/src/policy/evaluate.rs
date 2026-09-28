//! Deterministic staged evaluation: default-deny, forbid-overrides,
//! four-tier precedence, and `@confirm` detection.
//!
//! Tier semantics (ADR-0005 / Phase 3.0 §8), enforced structurally:
//!
//! * System and user tiers are evaluated independently; a `forbid` match in
//!   either tier yields `DENY` (system reported first). User permits fill
//!   system silence, but can never override a system `forbid`.
//! * The session tier is evaluated independently and can only *restrict*:
//!   a session `forbid` downgrades a base `ALLOW` to `DENY`, while session
//!   permits never grant (a base `DENY` stays denied).
//! * `@confirm("true")` on any determining permit (any tier) forces
//!   `CONFIRM` unless a structurally bound token is presented. A lower-trust
//!   autonomous permit cannot waive a higher-tier confirmation.
//!
//! Cedar entity mapping note (TBD preserved): the principal UID is a local
//! routing handle derived from `(uid, gid)`; the verbatim actor label and
//! the opaque `(resource_kind, resource_id)` travel in the request context
//! and match by exact string equality only. No hierarchy, no prefix
//! containment, no filesystem authorization exists here by construction.

use super::audit::PolicyAuditRecord;
use super::bundle::PolicyTier;
use super::error::PolicyError;
use super::request::{
    compute_request_hash, validate_actor_label, validate_request, CapabilityInvocationRequest,
};
use super::snapshot::{PolicyEngine, PolicySnapshot};
use agenticos_contracts::PrincipalContext;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

/// Implementation-defined bounded ceilings (NON-NORMATIVE).
///
/// The specification fixes boundedness, not values: ADR-0007 cites
/// 300,000 ms (request timeout) and 60,000 ms (token TTL) as non-normative
/// examples. These constants adopt those example values as explicit
/// implementation safety defaults. They are NOT architectural decisions
/// and do NOT resolve any Phase 3 TBD (token cryptography, retention
/// schedules, and profile ceilings remain TBD).
pub const ENGINE_MAX_TIMEOUT_MS: u64 = 300_000;
pub const MAX_CONFIRMATION_TOKEN_TTL_MS: u64 = 60_000;

/// Tri-state authorization outcome (Phase 3.0 §9 + ADR-0007 wrapper shape).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum PolicyDecision {
    /// Autonomous execution allowed under synthesized constraints (data).
    Allow {
        constraints: SandboxConstraints,
        contributing_policies: Vec<String>,
    },
    /// Execution forbidden with diagnostics.
    Deny {
        reason: String,
        contributing_policies: Vec<String>,
    },
    /// Execution suspended pending out-of-band human confirmation.
    Confirm {
        challenge_id: Uuid,
        prompt: String,
        blast_radius: String,
        required_scope: String,
        contributing_policies: Vec<String>,
    },
}

/// Sandbox handoff constraints: data only, no enforcement (Phase 3.0 §15).
///
/// All path/network/compute fields are inert in Phase 3.1. `allow_network`
/// defaults to false; numeric ceilings are bounded data for downstream
/// consumers. Enforcement is deferred to the Layer 9 sandbox plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxConstraints {
    pub read_paths: Vec<PathBuf>,
    pub write_paths: Vec<PathBuf>,
    pub allow_network: bool,
    pub seccomp_profile: String,
    pub max_memory_bytes: u64,
    pub max_cpu_quota_percent: u32,
    pub max_wall_time_ms: u64,
}

impl SandboxConstraints {
    /// Minimal inert constraint record for an allowed request.
    fn evaluation_only(wall_time_ms: u64) -> Self {
        Self {
            read_paths: Vec::new(),
            write_paths: Vec::new(),
            allow_network: false,
            seccomp_profile: "phase31-evaluation-only".to_string(),
            max_memory_bytes: 0,
            max_cpu_quota_percent: 0,
            max_wall_time_ms: wall_time_ms,
        }
    }
}

/// Cedar fixed points for the fixture-level mapping.
const CALLER_TYPE: &str = "Caller";
const TARGET_TYPE: &str = "Target";
const INVOKE_ACTION: &str = "invoke";
const FIXED_TARGET_ID: &str = "target";

/// Per-tier Cedar outcome classified for wrapper combination.
struct TierOutcome {
    tier: PolicyTier,
    forbids: Vec<String>,
    permits: Vec<String>,
}

/// A determining permit that mandates human confirmation.
struct ConfirmSite {
    policy_id: String,
    prompt: String,
    blast_radius: String,
}

impl PolicyEngine {
    /// Deterministically evaluate a request under the active snapshot.
    ///
    /// `now_ms` is trusted supervisor/broker time supplied by the caller
    /// (never sourced from the request). Returns the decision plus its
    /// audit shape; structural failures return typed [`PolicyError`]s.
    pub fn evaluate(
        &self,
        request: &CapabilityInvocationRequest,
        attested: &PrincipalContext,
        now_ms: u64,
    ) -> Result<(PolicyDecision, PolicyAuditRecord), PolicyError> {
        validate_request(request)?;
        validate_actor_label(&attested.actor_id)?;

        let snapshot = self.active_snapshot();

        let snapshot_mismatch = request.policy_snapshot_hash != snapshot.hash;
        let authorizer = cedar_policy::Authorizer::new();
        let cedar_request =
            build_cedar_request(&snapshot.schema, request, attested).map_err(|reason| {
                PolicyError::InternalError {
                    reason: format!("cedar request construction failed: {reason}"),
                }
            })?;

        let system = eval_tier(
            &authorizer,
            &snapshot,
            PolicyTier::System,
            request,
            &cedar_request,
        )?;
        let user = eval_tier(
            &authorizer,
            &snapshot,
            PolicyTier::User,
            request,
            &cedar_request,
        )?;
        let session = eval_tier(
            &authorizer,
            &snapshot,
            PolicyTier::Session,
            request,
            &cedar_request,
        )?;

        // 1. Forbid-overrides with tier precedence for diagnostics.
        let audit_base = AuditBase::new(request, attested, &snapshot, snapshot_mismatch);
        for outcome in [&system, &user, &session] {
            if !outcome.forbids.is_empty() {
                let decision = PolicyDecision::Deny {
                    reason: format!(
                        "forbidden by {} policy '{}'",
                        outcome.tier.as_str(),
                        outcome.forbids[0]
                    ),
                    contributing_policies: outcome.forbids.clone(),
                };
                let audit = audit_base.finish("DENY", &decision, false, None, now_ms);
                return Ok((decision, audit));
            }
        }

        // 2. Base allow requires a system or user permit (session never grants).
        let mut base_permits = system.permits.clone();
        base_permits.extend(user.permits.iter().cloned());
        base_permits.sort();
        if base_permits.is_empty() {
            let decision = PolicyDecision::Deny {
                reason: "DefaultDenyNoMatchingPermit".to_string(),
                contributing_policies: Vec::new(),
            };
            let audit = audit_base.finish("DENY", &decision, false, None, now_ms);
            return Ok((decision, audit));
        }

        // 3. Confirmation scan across all determining permits (any tier).
        // Malformed wrapper metadata fails closed to DENY with an audit
        // record (§8/§18), not to an unlogged error.
        let mut confirm_sites = match collect_confirms(&snapshot, [&system, &user, &session]) {
            Ok(sites) => sites,
            Err(ConfirmScanFault::Malformed(reason, contributing)) => {
                let decision = PolicyDecision::Deny {
                    reason,
                    contributing_policies: contributing,
                };
                let audit = audit_base.finish("DENY", &decision, false, None, now_ms);
                return Ok((decision, audit));
            }
            Err(ConfirmScanFault::Internal(err)) => return Err(err),
        };
        confirm_sites.sort_by(|a, b| a.policy_id.cmp(&b.policy_id));
        confirm_sites.dedup_by(|a, b| a.policy_id == b.policy_id);

        if confirm_sites.is_empty() {
            let decision = allow(request, base_permits.clone());
            let audit = audit_base.finish("ALLOW", &decision, false, None, now_ms);
            return Ok((decision, audit));
        }

        // 4. Confirmation required: absent token -> CONFIRM challenge.
        let site = &confirm_sites[0];
        let contributing: Vec<String> = confirm_sites
            .iter()
            .map(|site| site.policy_id.clone())
            .collect();
        let Some(token) = request.approval_token.as_ref() else {
            let decision = PolicyDecision::Confirm {
                challenge_id: Uuid::new_v4(),
                prompt: site.prompt.clone(),
                blast_radius: site.blast_radius.clone(),
                required_scope: request.capability_id.clone(),
                contributing_policies: contributing,
            };
            let audit = audit_base.finish("CONFIRM", &decision, true, None, now_ms);
            return Ok((decision, audit));
        };

        // 5. Token present: structural binding only (crypto TBD, never verified).
        validate_token_binding(&snapshot, request, attested, token, now_ms)?;
        if !self.try_redeem(token.payload.single_use_id) {
            return Err(PolicyError::TokenReplayDetected);
        }
        let decision = allow(request, base_permits.clone());
        let audit = audit_base.finish(
            "ALLOW",
            &decision,
            false,
            Some(token.payload.single_use_id),
            now_ms,
        );
        Ok((decision, audit))
    }
}

/// Effective wall-clock bound for handoff data.
fn effective_timeout_ms(request: &CapabilityInvocationRequest) -> u64 {
    request.timeout_duration_ms.min(ENGINE_MAX_TIMEOUT_MS)
}

fn allow(request: &CapabilityInvocationRequest, mut contributing: Vec<String>) -> PolicyDecision {
    contributing.sort();
    contributing.dedup();
    PolicyDecision::Allow {
        constraints: SandboxConstraints::evaluation_only(effective_timeout_ms(request)),
        contributing_policies: contributing,
    }
}

/// Evaluate one tier's policy set through Cedar and classify the outcome.
fn eval_tier(
    authorizer: &cedar_policy::Authorizer,
    snapshot: &PolicySnapshot,
    tier: PolicyTier,
    _request: &CapabilityInvocationRequest,
    cedar_request: &cedar_policy::Request,
) -> Result<TierOutcome, PolicyError> {
    let set = match tier {
        PolicyTier::System => &snapshot.system,
        PolicyTier::User => &snapshot.user,
        PolicyTier::Session => &snapshot.session,
    };
    let entities = cedar_policy::Entities::empty();
    let response = authorizer.is_authorized(cedar_request, set, &entities);
    let mut forbids = Vec::new();
    let mut permits = Vec::new();
    for policy_id in response.diagnostics().reason() {
        // Tier policy IDs are assigned as `{tier}-{index}` at load, so they
        // are already unique and tier-attributed; no further qualification.
        let qualified = policy_id.to_string();
        match set.policies().find(|policy| policy.id() == policy_id) {
            Some(policy) => match policy.effect() {
                cedar_policy::Effect::Forbid => forbids.push(qualified),
                cedar_policy::Effect::Permit => permits.push(qualified),
            },
            None => {
                return Err(PolicyError::InternalError {
                    reason: format!("diagnostic references unknown policy '{policy_id}'"),
                });
            }
        }
    }
    forbids.sort();
    permits.sort();
    Ok(TierOutcome {
        tier,
        forbids,
        permits,
    })
}

/// Confirm-scan fault: fail-closed malformed metadata (→ DENY with audit)
/// versus an internal invariant fault (→ typed error).
enum ConfirmScanFault {
    Malformed(String, Vec<String>),
    Internal(PolicyError),
}

/// Collect `@confirm` mandates from the determining permits of all tiers.
///
/// A present `@confirm` annotation with any value other than `"true"`, or
/// a `@confirm("true")` without `@confirm_prompt` (no challenge can be
/// formed), fails closed to `DENY` with an audit record (Phase 3.0 §8/§18),
/// never to an unlogged error.
fn collect_confirms(
    snapshot: &PolicySnapshot,
    outcomes: [&TierOutcome; 3],
) -> Result<Vec<ConfirmSite>, ConfirmScanFault> {
    let mut sites = Vec::new();
    for outcome in outcomes {
        // Permits live in their own tier set; session permits are looked up
        // in the session set (they contribute confirms but never grants).
        let set = match outcome.tier {
            PolicyTier::System => &snapshot.system,
            PolicyTier::User => &snapshot.user,
            PolicyTier::Session => &snapshot.session,
        };
        for qualified in &outcome.permits {
            let policy = set
                .policies()
                .find(|policy| &policy.id().to_string() == qualified)
                .ok_or_else(|| {
                    ConfirmScanFault::Internal(PolicyError::InternalError {
                        reason: format!("determining permit '{qualified}' not found"),
                    })
                })?;
            match policy.annotation("confirm") {
                None => {}
                Some("true") => {
                    let prompt =
                        policy
                            .annotation("confirm_prompt")
                            .ok_or_else(|| {
                                ConfirmScanFault::Malformed(
                                    format!(
                                        "malformed confirm metadata on '{qualified}': missing confirm_prompt"
                                    ),
                                    vec![qualified.clone()],
                                )
                            })?;
                    // Absent `@blast_radius` is optional metadata, not
                    // malformed input: fall back to a NON-NORMATIVE
                    // implementation default label (no TBD resolved).
                    let blast_radius = policy
                        .annotation("blast_radius")
                        .unwrap_or("unspecified")
                        .to_string();
                    sites.push(ConfirmSite {
                        policy_id: qualified.clone(),
                        prompt: prompt.to_string(),
                        blast_radius,
                    });
                }
                Some(other) => {
                    return Err(ConfirmScanFault::Malformed(
                        format!(
                            "malformed confirm metadata on '{qualified}': unexpected value '{other}'"
                        ),
                        vec![qualified.clone()],
                    ));
                }
            }
        }
    }
    Ok(sites)
}

/// Structural token binding checks (no cryptography — TBD).
///
/// Verifies request-hash equality, snapshot binding, principal /
/// capability / resource binding, expiry against supervisor time, TTL
/// ceiling, and issuance sanity. Single-use redemption is enforced by the
/// caller via the replay set.
fn validate_token_binding(
    snapshot: &PolicySnapshot,
    request: &CapabilityInvocationRequest,
    attested: &PrincipalContext,
    token: &super::request::ApprovalToken,
    now_ms: u64,
) -> Result<(), PolicyError> {
    let invalid = |reason: &str| PolicyError::InvalidApprovalToken {
        reason: reason.to_string(),
    };
    let expected = compute_request_hash(&request.approval_subject())
        .map_err(|_| invalid("request hash computation failed"))?;
    if token.payload.request_hash != expected {
        return Err(invalid("request hash mismatch"));
    }
    if token.payload.policy_snapshot_hash != snapshot.hash {
        return Err(invalid("policy snapshot mismatch: token invalidated"));
    }
    if token.payload.principal != attested.actor_id {
        return Err(invalid("principal binding mismatch"));
    }
    if token.payload.capability != request.capability_id {
        return Err(invalid("capability binding mismatch"));
    }
    if token.payload.resource != request.resource {
        return Err(invalid("resource binding mismatch"));
    }
    if token.payload.expires_at_ms < token.payload.issued_at_ms {
        return Err(invalid("token expiry precedes issuance"));
    }
    if token.payload.expires_at_ms - token.payload.issued_at_ms > MAX_CONFIRMATION_TOKEN_TTL_MS {
        return Err(invalid("token TTL exceeds architectural maximum"));
    }
    if now_ms < token.payload.issued_at_ms || now_ms > token.payload.expires_at_ms {
        return Err(invalid("token expired or not yet valid"));
    }
    // NOTE: signature bytes are opaque in Phase 3.1 (algorithm TBD).
    // Structural binding is necessary but NOT sufficient for authenticity;
    // production use requires the deferred cryptographic verification.
    Ok(())
}

/// Build the Cedar request from validated inputs.
///
/// Principal UID `u{uid}g{gid}` is a routing handle only; the verbatim
/// actor label is preserved in context for policy matching. The resource
/// UID is the fixed routing constant; kind/identifier travel in context.
fn build_cedar_request(
    schema: &cedar_policy::Schema,
    request: &CapabilityInvocationRequest,
    attested: &PrincipalContext,
) -> Result<cedar_policy::Request, String> {
    use cedar_policy::{Context, EntityId, EntityTypeName, RestrictedExpression};
    let principal_type: EntityTypeName = CALLER_TYPE.parse().map_err(|e| format!("{e}"))?;
    let principal_id: EntityId = format!("u{}g{}", attested.uid, attested.gid)
        .parse()
        .map_err(|e| format!("{e}"))?;
    let action_type: EntityTypeName = "Action".parse().map_err(|e| format!("{e}"))?;
    let action_id: EntityId = INVOKE_ACTION.parse().map_err(|e| format!("{e}"))?;
    let resource_type: EntityTypeName = TARGET_TYPE.parse().map_err(|e| format!("{e}"))?;
    let resource_id: EntityId = FIXED_TARGET_ID.parse().map_err(|e| format!("{e}"))?;
    let context = Context::from_pairs([
        (
            "capability_id".to_string(),
            RestrictedExpression::new_string(request.capability_id.clone()),
        ),
        (
            "resource_kind".to_string(),
            RestrictedExpression::new_string(request.resource.kind.clone()),
        ),
        (
            "resource_id".to_string(),
            RestrictedExpression::new_string(request.resource.identifier.clone()),
        ),
        (
            "principal_actor".to_string(),
            RestrictedExpression::new_string(attested.actor_id.clone()),
        ),
    ])
    .map_err(|e| format!("{e}"))?;
    cedar_policy::Request::new(
        cedar_policy::EntityUid::from_type_name_and_id(principal_type, principal_id),
        cedar_policy::EntityUid::from_type_name_and_id(action_type, action_id),
        cedar_policy::EntityUid::from_type_name_and_id(resource_type, resource_id),
        context,
        Some(schema),
    )
    .map_err(|e| format!("{e}"))
}

/// Audit-shape assembly shared by all terminal decisions.
///
/// Both the request-bound snapshot hash and the active snapshot hash are
/// always recorded, so snapshot-mismatch evaluations remain traceable
/// without silent downgrade (§11).
struct AuditBase<'a> {
    request: &'a CapabilityInvocationRequest,
    attested: &'a PrincipalContext,
    snapshot: &'a PolicySnapshot,
}

impl<'a> AuditBase<'a> {
    fn new(
        request: &'a CapabilityInvocationRequest,
        attested: &'a PrincipalContext,
        snapshot: &'a PolicySnapshot,
        _snapshot_mismatch: bool,
    ) -> Self {
        Self {
            request,
            attested,
            snapshot,
        }
    }

    fn finish(
        &self,
        decision: &str,
        outcome: &PolicyDecision,
        confirmation_required: bool,
        approval_token_id: Option<Uuid>,
        now_ms: u64,
    ) -> PolicyAuditRecord {
        // Both snapshot hashes are recorded in the audit shape, so a
        // mismatch evaluation stays traceable with no silent downgrade.
        let contributing = match outcome {
            PolicyDecision::Allow {
                contributing_policies,
                ..
            } => contributing_policies.clone(),
            PolicyDecision::Deny {
                contributing_policies,
                ..
            } => contributing_policies.clone(),
            PolicyDecision::Confirm {
                contributing_policies,
                ..
            } => contributing_policies.clone(),
        };
        PolicyAuditRecord::new(
            now_ms,
            self.request.request_id,
            self.request.correlation_id,
            self.attested.actor_id.clone(),
            self.request.capability_id.clone(),
            self.request.resource.kind.clone(),
            self.request.resource.identifier.clone(),
            decision,
            contributing,
            confirmation_required,
            approval_token_id,
            &self.request.policy_snapshot_hash,
            &self.snapshot.hash,
            self.snapshot.version.clone(),
        )
    }
}

/// Deterministic principal-handle rendering (shared with tests).
pub fn principal_handle(uid: u32, gid: u32) -> String {
    format!("u{uid}g{gid}")
}

/// Cedar entity literal for a principal handle (fixture policies).
pub fn principal_entity_literal(uid: u32, gid: u32) -> String {
    format!("Caller::\"{}\"", principal_handle(uid, gid))
}
