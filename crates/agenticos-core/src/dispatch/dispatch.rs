//! Deterministic dispatch stage machine (Phase 3.3 §5).
//!
//! Exact stage flow with cooperative cancellation checks:
//!
//! ```text
//! claim → cancelled? → synthesize → cancelled? → evaluate
//!   → branch → ALLOW-only bind → cancelled? → build_plan → validate
//!   → terminal DispatchRecord → existing manager release transition
//! ```
//!
//! The dispatcher proposes and conveys; Layer 8 disposes. Cancellation is
//! cooperative and in-process only: an observed flag aborts at the next
//! check point with nothing retained. In-flight Cedar evaluation
//! (synchronous, bounded) is never interrupted mid-call.

use super::error::DispatchError;
use super::record::{ConfirmationChallenge, DispatchOutcome, DispatchRecord};
use super::synthesize;
use crate::agent::{AssignmentId, AssignmentStatus, GlobalAgentManager, WorkAssignment};
use crate::capability::{CapabilityRegistry, DecisionRef};
use crate::policy::{PolicyDecision, PolicyEngine};
use agenticos_contracts::{ErrorCode, ErrorPayload, RetryClassification};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use uuid::Uuid;

/// Caller-provided cooperative cancellation flag (standard-library only:
/// no signals, no handlers, no new dependency).
pub type CancelFlag = Arc<AtomicBool>;

/// A never-signaled flag for uninterrupted dispatches.
pub fn never_cancel() -> CancelFlag {
    Arc::new(AtomicBool::new(false))
}

fn is_cancelled(cancel: &CancelFlag) -> bool {
    cancel.load(Ordering::SeqCst)
}

/// Layer 6 dispatch consumer: borrowed handles, no ownership, no state.
///
/// Borrowing (never owning) the manager, policy engine, and registry keeps
/// all authority and persistence where prior phases placed it. Dispatch
/// keeps no state between calls.
pub struct Dispatcher<'a> {
    manager: &'a GlobalAgentManager,
    policy: &'a PolicyEngine,
    registry: &'a CapabilityRegistry,
}

impl<'a> Dispatcher<'a> {
    /// Borrow the three planes. No validation here; every stage re-checks.
    pub fn new(
        manager: &'a GlobalAgentManager,
        policy: &'a PolicyEngine,
        registry: &'a CapabilityRegistry,
    ) -> Self {
        Self {
            manager,
            policy,
            registry,
        }
    }

    /// Dispatch one assignment to a terminal record.
    ///
    /// Always returns a terminal `DispatchRecord` (errors embedded, never
    /// `Err`, except lock poisoning which follows house style and panics
    /// like the rest of the codebase). The assigned agent is released
    /// through the existing manager transition matching the terminal
    /// outcome on every path.
    pub fn dispatch(
        &self,
        assignment_id: &AssignmentId,
        now_ms: u64,
        cancel: &CancelFlag,
    ) -> DispatchRecord {
        // --- Claim: defense-in-depth pre-check, manager authoritative. ---
        let claimed = match self.manager.get_assignment(assignment_id) {
            Ok(Some(assignment)) => assignment,
            Ok(None) => {
                return self.failed_record(
                    assignment_id,
                    crate::agent::AgentManagerError::AssignmentNotFound {
                        assignment_id: *assignment_id,
                    }
                    .into(),
                );
            }
            Err(err) => {
                return self.failed_record(assignment_id, err.into());
            }
        };
        if claimed.status != AssignmentStatus::Assigned {
            return self.failed_record(
                assignment_id,
                DispatchError::ClaimRejected {
                    reason: format!(
                        "assignment '{}' has status {:?}, expected Assigned",
                        assignment_id.0, claimed.status
                    ),
                }
                .to_payload(),
            );
        }
        if is_cancelled(cancel) {
            let record = self.base_record(&claimed, DispatchOutcome::Cancelled, now_ms);
            let _ = self.manager.cancel_assignment(
                &claimed.assignment_id,
                "cancelled before claim",
                now_ms,
            );
            return record;
        }
        let assignment = match self.manager.start_assignment(assignment_id, now_ms) {
            Ok(assignment) => assignment,
            Err(err) => {
                return self.failed_record(assignment_id, err.into());
            }
        };

        // --- Synthesize (mechanical mapping, §6). ---
        if is_cancelled(cancel) {
            return self.release_cancelled(&assignment, now_ms);
        }
        let active_hash = self.policy.active().hash;
        let request = match synthesize::synthesize(&assignment, &active_hash, self.registry) {
            Ok(request) => request,
            Err(err) => {
                return self.release_failed(&assignment, now_ms, err.to_payload());
            }
        };

        // --- Submit to the sole authorization authority. ---
        if is_cancelled(cancel) {
            return self.release_cancelled(&assignment, now_ms);
        }
        let attested = assignment.originating_principal.clone();
        let (decision, _audit) = match self.policy.evaluate(&request, &attested, now_ms) {
            Ok(result) => result,
            Err(err) => {
                return self.release_failed(&assignment, now_ms, err.to_payload());
            }
        };

        // --- Branch on the Layer 8 verdict (original decision throughout). ---
        match &decision {
            PolicyDecision::Deny {
                reason,
                contributing_policies,
            } => {
                let decision_ref = DecisionRef {
                    snapshot_hash: active_hash,
                    contributing_policies: contributing_policies.clone(),
                };
                let error = ErrorPayload::new(
                    ErrorCode::PolicyDenied,
                    format!("policy denied: {reason}"),
                    DispatchError::SOURCE_COMPONENT,
                    RetryClassification::Never,
                );
                let record = self.base_record(&assignment, DispatchOutcome::Denied, now_ms);
                let record = DispatchRecord {
                    decision_ref: Some(decision_ref),
                    error: Some(error),
                    ..record
                };
                let _ = self.manager.fail_assignment(
                    &assignment.assignment_id,
                    "policy denied",
                    now_ms,
                );
                record
            }
            PolicyDecision::Confirm {
                prompt,
                blast_radius,
                required_scope,
                contributing_policies,
                ..
            } => {
                // Terminal by design: dispatch mints no tokens and performs
                // no upgrade. A future broker phase resubmits explicitly.
                let decision_ref = DecisionRef {
                    snapshot_hash: active_hash,
                    contributing_policies: contributing_policies.clone(),
                };
                let error = ErrorPayload::new(
                    ErrorCode::ConfirmationRequired,
                    format!("confirmation required: {prompt}"),
                    DispatchError::SOURCE_COMPONENT,
                    RetryClassification::Never,
                );
                let record = self.base_record(&assignment, DispatchOutcome::ConfirmPending, now_ms);
                let record = DispatchRecord {
                    decision_ref: Some(decision_ref),
                    confirmation: Some(ConfirmationChallenge {
                        prompt: prompt.clone(),
                        blast_radius: blast_radius.clone(),
                        required_scope: required_scope.clone(),
                        contributing_policies: contributing_policies.clone(),
                    }),
                    error: Some(error),
                    ..record
                };
                let _ = self.manager.fail_assignment(
                    &assignment.assignment_id,
                    "confirmation required: assignment cannot proceed unattended",
                    now_ms,
                );
                record
            }
            PolicyDecision::Allow { .. } => {
                if is_cancelled(cancel) {
                    return self.release_cancelled(&assignment, now_ms);
                }
                // Re-read the live hash: rotation between evaluation and
                // binding fails closed inside `bind` (no silent downgrade).
                let live_hash = self.policy.active().hash;
                let binding =
                    match crate::capability::bind(&request, &decision, &live_hash, self.registry) {
                        Ok(binding) => binding,
                        Err(err) => {
                            return self.release_failed(&assignment, now_ms, err.to_payload());
                        }
                    };
                let manifest = match self
                    .registry
                    .get(&binding.capability_id, binding.capability_schema_version)
                {
                    Ok(manifest) => manifest.clone(),
                    Err(err) => {
                        return self.release_failed(&assignment, now_ms, err.to_payload());
                    }
                };
                let plan = match crate::capability::build_plan(&binding, &manifest) {
                    Ok(plan) => plan,
                    Err(err) => {
                        return self.release_failed(&assignment, now_ms, err.to_payload());
                    }
                };
                if let Err(err) = crate::capability::validate(&plan) {
                    return self.release_failed(&assignment, now_ms, err.to_payload());
                }
                let record = self.base_record(&assignment, DispatchOutcome::Planned, now_ms);
                // Authoritative lineage: the binding froze the Layer 8
                // decision reference at handoff (sorted by construction in
                // Phase 3.2). Reuse it verbatim — never recompute.
                let record = DispatchRecord {
                    decision_ref: Some(binding.decision_ref.clone()),
                    binding_hash: Some(binding.binding_hash),
                    plan_hash: Some(plan.plan_hash),
                    declared_preconditions: manifest.preconditions.clone(),
                    declared_postconditions: manifest.postconditions.clone(),
                    ..record
                };
                let _ = self
                    .manager
                    .complete_assignment(&assignment.assignment_id, now_ms);
                record
            }
        }
    }

    /// Base terminal record: lineage verbatim, empty outcome attachments.
    fn base_record(
        &self,
        assignment: &WorkAssignment,
        outcome: DispatchOutcome,
        _now_ms: u64,
    ) -> DispatchRecord {
        DispatchRecord {
            dispatch_id: Uuid::new_v4(),
            assignment_id: assignment.assignment_id,
            correlation_id: assignment.correlation_id,
            workflow_id: assignment.workflow_id,
            step_id: assignment.step_id,
            agent_id: assignment.agent_id,
            outcome,
            request_id: assignment.request_id,
            decision_ref: None,
            binding_hash: None,
            plan_hash: None,
            declared_preconditions: Vec::new(),
            declared_postconditions: Vec::new(),
            confirmation: None,
            error: None,
        }
    }

    /// Terminal failure for unknown assignments (no manager state touched).
    fn failed_record(&self, assignment_id: &AssignmentId, error: ErrorPayload) -> DispatchRecord {
        DispatchRecord {
            dispatch_id: Uuid::new_v4(),
            assignment_id: *assignment_id,
            correlation_id: Uuid::nil(),
            workflow_id: Uuid::nil(),
            step_id: Uuid::nil(),
            agent_id: crate::agent::AgentId(Uuid::nil()),
            outcome: DispatchOutcome::Failed,
            request_id: Uuid::nil(),
            decision_ref: None,
            binding_hash: None,
            plan_hash: None,
            declared_preconditions: Vec::new(),
            declared_postconditions: Vec::new(),
            confirmation: None,
            error: Some(error),
        }
    }

    /// Release paths: run the existing manager transition, ignore its
    /// secondary result (the terminal record is authoritative for dispatch;
    /// manager guards already validated the transition).
    fn release_failed(
        &self,
        assignment: &WorkAssignment,
        now_ms: u64,
        error: ErrorPayload,
    ) -> DispatchRecord {
        let record = DispatchRecord {
            error: Some(error),
            ..self.base_record(assignment, DispatchOutcome::Failed, now_ms)
        };
        let _ = self
            .manager
            .fail_assignment(&assignment.assignment_id, "dispatch failed", now_ms);
        record
    }

    fn release_cancelled(&self, assignment: &WorkAssignment, now_ms: u64) -> DispatchRecord {
        let record = self.base_record(assignment, DispatchOutcome::Cancelled, now_ms);
        let _ = self.manager.cancel_assignment(
            &assignment.assignment_id,
            "cancelled by caller",
            now_ms,
        );
        record
    }
}
