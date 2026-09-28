//! Immutable policy snapshots and the atomic-swap [`PolicyEngine`].
//!
//! A [`PolicySnapshot`] bundles one validated schema plus one validated
//! [`PolicySet`] per tier, content-addressed by SHA-256 (§11). Snapshots
//! are immutable and reference-counted (`Arc`); activation and rollback
//! are atomic pointer swaps under a write lock. Rejected candidates never
//! disturb the active snapshot.
//!
//! The redeemed-token set is in-memory only: replay-durability across
//! restarts is explicitly TBD (ADR-0007 Q3) and NOT implemented.

use super::bundle::{
    parse_tier, snapshot_hash, validate_tier, PolicyBundleSource, PolicyTier, POLICY_SCHEMA_SRC,
};
use super::error::PolicyError;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// Maximum retained prior snapshots (NON-NORMATIVE implementation bound;
/// exact retention schedules remain TBD per ADR-0006 and are not fixed by
/// the spec — this cap is a memory-safety default, not an architectural
/// decision).
const MAX_RETAINED_SNAPSHOTS: usize = 32;

/// One validated, immutable policy snapshot.
#[derive(Debug)]
pub struct PolicySnapshot {
    /// Semantic version label from the bundle source.
    pub version: String,
    /// SHA-256 content hash over the canonical bundle encoding.
    pub hash: [u8; 32],
    /// Cedar schema shared by all tiers.
    pub schema: cedar_policy::Schema,
    /// Validated system-tier policy set.
    pub system: cedar_policy::PolicySet,
    /// Validated user-tier policy set.
    pub user: cedar_policy::PolicySet,
    /// Validated session-tier policy set (restrict-only at evaluation).
    pub session: cedar_policy::PolicySet,
}

impl PolicySnapshot {
    /// Parse, schema-validate, and freeze a bundle source.
    ///
    /// Any failure rejects the candidate with [`PolicyError::BundleRejected`]
    /// and constructs nothing (fail-closed at load).
    pub fn build(source: &PolicyBundleSource) -> Result<Self, PolicyError> {
        source.validate()?;
        let schema: cedar_policy::Schema =
            POLICY_SCHEMA_SRC
                .parse()
                .map_err(|err| PolicyError::BundleRejected {
                    reason: format!("policy schema parse error: {err}"),
                })?;
        let system = parse_tier(PolicyTier::System, &source.system_policies)?;
        let user = parse_tier(PolicyTier::User, &source.user_policies)?;
        let session = parse_tier(PolicyTier::Session, &source.session_policies)?;
        validate_tier(PolicyTier::System, &schema, &system)?;
        validate_tier(PolicyTier::User, &schema, &user)?;
        validate_tier(PolicyTier::Session, &schema, &session)?;
        Ok(Self {
            version: source.version.clone(),
            hash: snapshot_hash(source),
            schema,
            system,
            user,
            session,
        })
    }
}

struct EngineInner {
    active: Arc<PolicySnapshot>,
    /// Prior snapshots by content hash (rollback pool).
    retained: HashMap<[u8; 32], Arc<PolicySnapshot>>,
    /// Insertion order of retained hashes for bounded eviction.
    retained_order: Vec<[u8; 32]>,
    /// Redeemed single-use token IDs (ephemeral; durability TBD).
    replay: HashSet<Uuid>,
}

/// Layer 8 evaluation-plane handle: atomic snapshot management plus
/// single-use token redemption tracking.
///
/// Evaluations are serialized through the inner lock; evaluation itself is
/// pure and deterministic.
pub struct PolicyEngine {
    inner: RwLock<EngineInner>,
}

impl std::fmt::Debug for PolicyEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.read().expect("policy engine lock poisoned");
        f.debug_struct("PolicyEngine")
            .field("active_version", &inner.active.version)
            .field("retained", &inner.retained_order.len())
            .field("redeemed", &inner.replay.len())
            .finish()
    }
}

impl PolicyEngine {
    /// Create an engine with an initial validated snapshot.
    pub fn new(initial: PolicySnapshot) -> Self {
        Self {
            inner: RwLock::new(EngineInner {
                active: Arc::new(initial),
                retained: HashMap::new(),
                retained_order: Vec::new(),
                replay: HashSet::new(),
            }),
        }
    }

    /// Build an engine directly from a bundle source.
    pub fn from_source(source: &PolicyBundleSource) -> Result<Self, PolicyError> {
        Ok(Self::new(PolicySnapshot::build(source)?))
    }

    /// Current active snapshot.
    pub fn active(&self) -> Arc<PolicySnapshot> {
        self.active_snapshot()
    }

    /// Current active snapshot (crate-internal alias).
    pub(crate) fn active_snapshot(&self) -> Arc<PolicySnapshot> {
        self.inner
            .read()
            .expect("policy engine lock poisoned")
            .active
            .clone()
    }

    /// Attempt to redeem a single-use token ID.
    ///
    /// Returns true on first presentation, false on replay. Ephemeral and
    /// non-durable by design (replay durability TBD).
    pub(crate) fn try_redeem(&self, single_use_id: Uuid) -> bool {
        self.inner
            .write()
            .expect("policy engine lock poisoned")
            .replay
            .insert(single_use_id)
    }

    /// Parse, validate, and atomically activate a candidate bundle.
    ///
    /// On any failure the candidate is rejected and the active snapshot is
    /// untouched. Returns the new snapshot hash.
    pub fn load_and_activate(&self, source: &PolicyBundleSource) -> Result<[u8; 32], PolicyError> {
        let snapshot = Arc::new(PolicySnapshot::build(source)?);
        let hash = snapshot.hash;
        let mut inner = self.inner.write().expect("policy engine lock poisoned");
        let prior = std::mem::replace(&mut inner.active, snapshot);
        Self::retain_locked(&mut inner, prior);
        Ok(hash)
    }

    /// Atomically roll back to a retained snapshot by version label.
    ///
    /// Retained snapshots were parsed and schema-validated at load and are
    /// immutable (`Arc`), so no re-validation is possible or needed: the
    /// content cannot have changed since activation. Rollback always serves
    /// from the archive: it swaps the active pointer to the retained
    /// snapshot, even when the active snapshot happens to carry the same
    /// version label. Selection scans retained snapshots in oldest-first
    /// insertion order and takes the first version match, so selection is
    /// deterministic even if duplicate version labels somehow exist. An
    /// unknown version yields [`PolicyError::UnknownSnapshot`] without
    /// disturbing the active snapshot.
    pub fn rollback_to_version(&self, version: &str) -> Result<[u8; 32], PolicyError> {
        let mut inner = self.inner.write().expect("policy engine lock poisoned");
        let target_hash = inner
            .retained_order
            .iter()
            .find(|hash| {
                inner
                    .retained
                    .get(*hash)
                    .map(|snapshot| snapshot.version == version)
                    .unwrap_or(false)
            })
            .copied()
            .ok_or_else(|| PolicyError::UnknownSnapshot {
                reason: format!("no retained snapshot with version '{version}'"),
            })?;
        let target = inner.retained.get(&target_hash).cloned().ok_or_else(|| {
            PolicyError::InternalError {
                reason: format!("retained snapshot index inconsistent for '{version}'"),
            }
        })?;
        let hash = target.hash;
        let prior = std::mem::replace(&mut inner.active, target);
        Self::retain_locked(&mut inner, prior);
        Ok(hash)
    }

    /// Retained snapshot versions, oldest first (active version excluded).
    pub fn retained_versions(&self) -> Vec<String> {
        let inner = self.inner.read().expect("policy engine lock poisoned");
        inner
            .retained_order
            .iter()
            .filter_map(|hash| inner.retained.get(hash))
            .map(|snapshot| snapshot.version.clone())
            .collect()
    }

    fn retain_locked(inner: &mut EngineInner, snapshot: Arc<PolicySnapshot>) {
        if inner.retained.contains_key(&snapshot.hash) || inner.active.hash == snapshot.hash {
            return;
        }
        inner.retained_order.push(snapshot.hash);
        inner.retained.insert(snapshot.hash, snapshot);
        while inner.retained_order.len() > MAX_RETAINED_SNAPSHOTS {
            let oldest = inner.retained_order.remove(0);
            if oldest != inner.active.hash {
                inner.retained.remove(&oldest);
            }
        }
    }
}
