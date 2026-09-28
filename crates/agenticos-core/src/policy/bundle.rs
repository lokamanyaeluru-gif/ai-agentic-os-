//! Policy bundle loading, Cedar schema validation, and snapshot hashing.
//!
//! A [`PolicyBundleSource`] carries the four text inputs for one snapshot
//! version: the shared Cedar schema plus one policy-text list per tier
//! (system / user / session). Each list entry holds exactly one Cedar
//! policy statement; entries are parsed with deterministic per-tier IDs
//! (`{tier}-{index}`), so independently authored tier files can never
//! collide on auto-generated policy IDs.
//!
//! The Cedar schema is a *fixture-level* mapping (exact-equality matching
//! over context attributes). It does NOT resolve the TBD `ResourceRef` →
//! Cedar entity hierarchy: resources travel as opaque
//! `(resource_kind, resource_id)` strings, principals as `(uid, gid)`
//! routing handles plus verbatim actor labels in context. No prefix
//! containment, no path comparator, no filesystem authorization exists
//! at this layer by construction.

use super::canonical::sha256;
use super::error::PolicyError;

/// Policy hierarchy tier (ADR-0005 four-tier model; mandatory-system and
/// user tiers form the base decision, session only restricts).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyTier {
    System,
    User,
    Session,
}

impl PolicyTier {
    pub const fn as_str(&self) -> &'static str {
        match self {
            PolicyTier::System => "system",
            PolicyTier::User => "user",
            PolicyTier::Session => "session",
        }
    }
}

/// Shared Cedar schema for all snapshots.
///
/// Generic `Caller` / `Target` entities with a single `invoke` action.
/// Capability identity, resource kind/identifier, and the verbatim actor
/// label travel in the request context record and are matched by exact
/// string equality only. The fixed resource UID (`Target::"target"`) is a
/// routing constant, not a resource model.
pub const POLICY_SCHEMA_SRC: &str = r#"
entity Caller, Target;
action invoke appliesTo {
  principal: [Caller],
  resource: [Target],
  context: {
    capability_id: String,
    resource_kind: String,
    resource_id: String,
    principal_actor: String
  }
};
"#;

/// Declarative bundle inputs for one snapshot version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyBundleSource {
    /// Semantic version label for this bundle (e.g. `"v1.0.0"`).
    pub version: String,
    /// One Cedar policy statement per entry (system tier).
    pub system_policies: Vec<String>,
    /// One Cedar policy statement per entry (user tier).
    pub user_policies: Vec<String>,
    /// One Cedar policy statement per entry (session tier, restrict-only).
    pub session_policies: Vec<String>,
}

impl PolicyBundleSource {
    /// Structural validation of the bundle source (non-empty version,
    /// bounded sizes). The size caps below are NON-NORMATIVE implementation
    /// safety bounds against resource exhaustion, not architectural limits.
    /// Semantic validation happens at snapshot build.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.version.is_empty() || self.version.len() > 64 {
            return Err(PolicyError::BundleRejected {
                reason: "bundle version must be 1..=64 chars".to_string(),
            });
        }
        if self.version.contains('\0') {
            return Err(PolicyError::BundleRejected {
                reason: "bundle version contains NUL byte".to_string(),
            });
        }
        for tier_policies in [
            &self.system_policies,
            &self.user_policies,
            &self.session_policies,
        ] {
            if tier_policies.len() > 1024 {
                return Err(PolicyError::BundleRejected {
                    reason: "tier exceeds 1024 policies".to_string(),
                });
            }
            for policy in tier_policies {
                if policy.len() > 65_536 {
                    return Err(PolicyError::BundleRejected {
                        reason: "policy text exceeds 64 KiB".to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    /// All tiers in evaluation order.
    pub fn tiers(&self) -> [(PolicyTier, &Vec<String>); 3] {
        [
            (PolicyTier::System, &self.system_policies),
            (PolicyTier::User, &self.user_policies),
            (PolicyTier::Session, &self.session_policies),
        ]
    }
}

/// Compute the snapshot content hash: SHA-256 over a length-prefixed
/// encoding of `(domain, version, schema, system, user, session)`.
///
/// Domain separation plus explicit lengths make the encoding unambiguous;
/// tier policy lists are hashed in order with per-entry length prefixes.
pub fn snapshot_hash(source: &PolicyBundleSource) -> [u8; 32] {
    let mut bytes = Vec::new();
    push_field(&mut bytes, b"agenticos-policy-snapshot/v1");
    push_field(&mut bytes, source.version.as_bytes());
    push_field(&mut bytes, POLICY_SCHEMA_SRC.as_bytes());
    for (_, policies) in source.tiers() {
        push_u64(&mut bytes, policies.len() as u64);
        for policy in policies {
            push_field(&mut bytes, policy.as_bytes());
        }
    }
    sha256(&bytes)
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_field(out: &mut Vec<u8>, field: &[u8]) {
    push_u64(out, field.len() as u64);
    out.extend_from_slice(field);
}

/// Parse one tier's policy texts into a Cedar [`PolicySet`] with
/// deterministic IDs (`{tier}-{index}`).
///
/// Syntax errors are fail-closed at load: the whole bundle is rejected and
/// the active snapshot is retained (Phase 3.0 §10).
pub fn parse_tier(
    tier: PolicyTier,
    policies: &[String],
) -> Result<cedar_policy::PolicySet, PolicyError> {
    use cedar_policy::{Policy, PolicyId, PolicySet};
    let mut parsed = Vec::with_capacity(policies.len());
    for (index, src) in policies.iter().enumerate() {
        let id = PolicyId::new(format!("{}-{index}", tier.as_str()));
        let policy =
            Policy::parse(Some(id), src.clone()).map_err(|errs| PolicyError::BundleRejected {
                reason: format!("{} tier policy {index} syntax error: {errs}", tier.as_str()),
            })?;
        parsed.push(policy);
    }
    PolicySet::from_policies(parsed).map_err(|err| PolicyError::BundleRejected {
        reason: format!("{} tier policy set error: {err}", tier.as_str()),
    })
}

/// Validate a tier policy set against the schema (strict mode).
pub fn validate_tier(
    tier: PolicyTier,
    schema: &cedar_policy::Schema,
    set: &cedar_policy::PolicySet,
) -> Result<(), PolicyError> {
    use cedar_policy::{ValidationMode, Validator};
    let result = Validator::new(schema.clone()).validate(set, ValidationMode::default());
    if result.validation_passed() {
        Ok(())
    } else {
        // Keep diagnostics bounded; surface the count plus first error.
        let mut errors = result.validation_errors();
        let first = errors.next().map(|e| e.to_string()).unwrap_or_default();
        let count = 1 + errors.count();
        Err(PolicyError::BundleRejected {
            reason: format!(
                "{} tier schema validation failed ({count} errors; first: {first})",
                tier.as_str()
            ),
        })
    }
}
