//! Terminal caller-owned dispatch records (Phase 3.3 §13).
//!
//! Records are returned values; retention and crash-survival are the
//! caller's concern (no store, no journal — specifying either would require
//! ADR-0006 ownership that does not exist). Manifest pre/postcondition
//! expressions are embedded verbatim as declared; they are never evaluated
//! here and no `is_satisfied` outcome is ever synthesized.

use crate::agent::{AgentId, AssignmentId};
use crate::capability::{CheckExpr, DecisionRef};
use agenticos_contracts::ErrorPayload;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Terminal dispatch outcome (Phase 3.3 §13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DispatchOutcome {
    /// Validated plan data attached (binding + plan hashes present).
    Planned,
    /// Layer 8 `DENY` (reason attached).
    Denied,
    /// Layer 8 `CONFIRM` with no token minted (challenge attached).
    ConfirmPending,
    /// Typed error (mapping in `error.rs` + reused plane errors).
    Failed,
    /// Cooperative flag observed (no error).
    Cancelled,
}

/// Terminal caller-owned dispatch record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchRecord {
    /// Fresh per dispatch attempt.
    pub dispatch_id: Uuid,
    /// Layer 5 lineage (verbatim).
    pub assignment_id: AssignmentId,
    /// Root causal trace (verbatim).
    pub correlation_id: Uuid,
    /// Layer 4 lineage (verbatim).
    pub workflow_id: Uuid,
    /// Layer 4 lineage (verbatim).
    pub step_id: Uuid,
    /// Layer 5 lineage (verbatim).
    pub agent_id: AgentId,
    pub outcome: DispatchOutcome,
    /// Reused assignment `request_id` (§6 lineage rule).
    pub request_id: Uuid,
    /// Snapshot hash + contributing policies (present iff evaluated).
    /// Reuses the Phase 3.2 type verbatim; the verdict class is carried by
    /// `outcome` (Planned→Allow, Denied→Deny, ConfirmPending→Confirm).
    pub decision_ref: Option<DecisionRef>,
    /// Binding content hash (present iff bound or planned).
    pub binding_hash: Option<[u8; 32]>,
    /// Plan content hash (present iff planned).
    pub plan_hash: Option<[u8; 32]>,
    /// Manifest expressions, verbatim as declared (never evaluated).
    pub declared_preconditions: Vec<CheckExpr>,
    /// Manifest expressions, verbatim as declared (never evaluated).
    pub declared_postconditions: Vec<CheckExpr>,
    /// Layer 8 challenge, present iff `ConfirmPending`.
    pub confirmation: Option<ConfirmationChallenge>,
    /// Terminal failure diagnostics (none for Planned/Cancelled).
    pub error: Option<ErrorPayload>,
}

/// Human-confirmation challenge attached to `ConfirmPending` records.
///
/// Carries the Layer 8 challenge verbatim (prompt, blast radius, scope,
/// contributors). Dispatch mints nothing and upgrades nothing: a future
/// broker phase resubmits explicitly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfirmationChallenge {
    pub prompt: String,
    pub blast_radius: String,
    pub required_scope: String,
    pub contributing_policies: Vec<String>,
}
