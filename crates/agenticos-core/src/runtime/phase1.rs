//! Phase 1 deterministic runtime coordinator.
//!
//! Orchestrates the Intent → Goal → Workflow lifecycle across the three
//! domain-owned SQLite stores. The coordinator is explicitly responsible for:
//!
//! - Accepting a submission request
//! - Persisting the Intent
//! - Normalizing the Intent
//! - Creating and persisting the Goal
//! - Synthesizing and persisting the Workflow
//! - Advancing each entity through the minimal setup/acceptance states
//!
//! The coordinator is NOT responsible for capability execution, shell execution,
//! subprocesses, agents, LLM calls, network, UDS, D-Bus, sandboxing, or UI.
//!
//! # Partial Failure and Recovery
//!
//! Intent, Goal, and Workflow are stored in THREE separate SQLite databases.
//! There is no cross-database transaction. The coordinator handles partial
//! failures deterministically:
//!
//! - Intent persisted, Goal missing → reuse Intent, create Goal
//! - Intent + Goal persisted, Workflow missing → reuse both, create Workflow
//! - Full chain exists → validate consistency and return existing chain
//!
//! # Idempotency
//!
//! If a submission contains a `principal + idempotency_key` pair that matches
//! an existing Intent, the coordinator returns the existing chain without
//! creating duplicate entities. If the key matches but the raw_input differs
//! materially, `RuntimeError::IdempotencyKeyConflict` is returned.
//!
//! # Determinism
//!
//! The coordinator does not use randomness for control decisions, system time
//! inside orchestration logic, environment-dependent branching, filesystem
//! inspection beyond the storage layer, or LLM decisions.
//! Explicit timestamps MUST be provided by the caller.

use uuid::Uuid;

use crate::goal::{Goal, GoalObjective, GoalStatus};
use crate::intent::{Intent, IntentStatus};
use crate::normalizer::normalize_intent;
use crate::runtime::error::RuntimeError;
use crate::runtime::planner::synthesize_workflow;
use crate::storage::{GoalStore, IntentStore, WorkflowStore};
use crate::workflow::{Workflow, WorkflowStatus};
use agenticos_contracts::PrincipalContext;

// ---------------------------------------------------------------------------
// Public API types
// ---------------------------------------------------------------------------

/// Input for a new or retried intent submission.
#[derive(Debug, Clone)]
pub struct SubmitRequest {
    /// Exact, unmodified input received from the caller.
    pub raw_input: String,

    /// Attested originating principal (provenance context).
    pub principal: PrincipalContext,

    /// Root causal trace ID. Callers must supply this; the runtime never
    /// generates a new correlation_id during a retry.
    pub correlation_id: Uuid,

    /// Optional caller-supplied deduplication key.
    /// Scoped to the authenticated originating principal.
    pub idempotency_key: Option<String>,

    /// Wall-clock timestamp (ms since Unix epoch, UTC) when the submission
    /// was captured. The runtime does not acquire system time internally.
    pub created_at_ms: u64,
}

/// Output of a successful `Phase1Runtime::submit` or `Phase1Runtime::resume` call.
/// Contains the complete persisted chain at the state reached during this call.
#[derive(Debug, Clone)]
pub struct Phase1Result {
    /// Persisted Intent at its current lifecycle state.
    pub intent: Intent,

    /// Persisted Goal at its current lifecycle state.
    pub goal: Goal,

    /// Persisted Workflow at its current lifecycle state.
    pub workflow: Workflow,

    /// Whether this result was produced by replaying an existing submission
    /// (idempotent replay) rather than creating a new chain.
    pub is_replay: bool,
}

// ---------------------------------------------------------------------------
// Phase1Runtime
// ---------------------------------------------------------------------------

/// Deterministic runtime coordinator for the Phase 1 Intent → Goal → Workflow lifecycle.
///
/// Holds references to the three domain-owned stores. Uses dependency injection
/// so tests can operate with isolated temporary databases.
///
/// # Thread Safety
/// Each underlying store wraps its `Connection` in `Arc<Mutex<>>`.
/// `Phase1Runtime` is `Clone` as a result. Callers sharing a single runtime
/// across threads will serialize on each store's internal mutex.
#[derive(Debug, Clone)]
pub struct Phase1Runtime {
    intent_store: IntentStore,
    goal_store: GoalStore,
    workflow_store: WorkflowStore,
}

impl Phase1Runtime {
    /// Creates a new `Phase1Runtime` backed by the three provided domain stores.
    ///
    /// The stores must already be initialized (schemas migrated, WAL enabled).
    pub fn new(
        intent_store: IntentStore,
        goal_store: GoalStore,
        workflow_store: WorkflowStore,
    ) -> Self {
        Self {
            intent_store,
            goal_store,
            workflow_store,
        }
    }

    // -------------------------------------------------------------------------
    // Primary submit path
    // -------------------------------------------------------------------------

    /// Submits an intent and drives it through Intent → Goal → Workflow setup.
    ///
    /// # Idempotency
    ///
    /// If `request.idempotency_key` is `Some` and an existing Intent with the
    /// same `(principal, idempotency_key)` is found:
    ///
    /// - **Exact retry** (same raw_input): the existing chain is resumed/returned.
    /// - **Content conflict** (different raw_input): returns
    ///   `RuntimeError::IdempotencyKeyConflict`.
    ///
    /// If `request.idempotency_key` is `None`, every submission is treated as
    /// a distinct new intent.
    ///
    /// # Partial Failure Recovery
    ///
    /// The runtime detects partial chains (Intent without Goal, Goal without
    /// Workflow) and resumes them rather than creating duplicates.
    ///
    /// # State Transitions Performed
    ///
    /// ```text
    /// Intent:   Created → Accepted
    /// Goal:     Created → Accepted
    /// Workflow: Created → Accepted
    /// ```
    ///
    /// The runtime does NOT advance to Running, Completed, or Failed in this
    /// subphase. That is reserved for the execution phase.
    pub fn submit(&self, request: SubmitRequest) -> Result<Phase1Result, RuntimeError> {
        // --- Step 1: Idempotency check ---
        if let Some(ref key) = request.idempotency_key {
            if let Some(existing_intent) = self
                .intent_store
                .find_by_idempotency_key(&request.principal, key)?
            {
                // Detect content conflict: same key, materially different raw_input
                if existing_intent.raw_input != request.raw_input {
                    return Err(RuntimeError::IdempotencyKeyConflict {
                        idempotency_key: key.clone(),
                        existing_intent_id: existing_intent.intent_id,
                    });
                }

                // Exact retry: resume the existing chain
                return self.resume_from_intent(existing_intent, request.created_at_ms, true);
            }
        }

        // --- Step 2: Create and persist new Intent ---
        let mut intent = Intent::new(
            request.raw_input,
            request.principal,
            request.correlation_id,
            request.idempotency_key,
            request.created_at_ms,
        )
        .map_err(|e| RuntimeError::InvalidInput {
            reason: e.to_string(),
        })?;

        self.intent_store.insert(&intent)?;

        // --- Step 3: Normalize and accept Intent ---
        let normalized =
            normalize_intent(&intent.raw_input).map_err(|e| RuntimeError::InvalidInput {
                reason: e.to_string(),
            })?;

        intent
            .accept(normalized)
            .map_err(RuntimeError::DomainViolation)?;

        self.intent_store.update(&intent)?;

        // --- Step 4: Create and persist Goal ---
        let (goal, workflow) = self.create_goal_and_workflow(&intent, request.created_at_ms)?;

        Ok(Phase1Result {
            intent,
            goal,
            workflow,
            is_replay: false,
        })
    }

    // -------------------------------------------------------------------------
    // Recovery / reconciliation
    // -------------------------------------------------------------------------

    /// Resumes an existing chain starting from a known Intent ID.
    ///
    /// Inspects the persisted state of the Intent and continues only where
    /// valid persisted state exists:
    ///
    /// - If Goal is missing and Intent is resumable: creates Goal + Workflow.
    /// - If Goal exists but Workflow is missing and Goal is resumable: creates Workflow.
    /// - If all three exist: validates consistency and returns the existing chain.
    ///
    /// Returns `RuntimeError::IrreconcilableIntentState` if the Intent is in a
    /// terminal or non-resumable state without a downstream chain.
    pub fn resume(
        &self,
        intent_id: &Uuid,
        timestamp_ms: u64,
    ) -> Result<Phase1Result, RuntimeError> {
        let intent =
            self.intent_store
                .get(intent_id)?
                .ok_or_else(|| RuntimeError::InconsistentState {
                    correlation_id: *intent_id, // best effort; real correlation_id unknown
                    reason: format!("Intent {} not found in storage", intent_id),
                })?;

        self.resume_from_intent(intent, timestamp_ms, false)
    }

    /// Returns the current persisted state of an existing chain by intent ID.
    ///
    /// Does not perform any state transitions. Returns `None` fields for missing
    /// downstream objects.
    pub fn get_state(&self, intent_id: &Uuid) -> Result<ChainState, RuntimeError> {
        let intent = self.intent_store.get(intent_id)?;

        let (goal, workflow) = if let Some(ref i) = intent {
            let goals = self.goal_store.find_by_intent_id(&i.intent_id)?;
            let goal = goals.into_iter().next();
            let workflow = if let Some(ref g) = goal {
                let workflows = self.workflow_store.find_by_goal_id(&g.goal_id)?;
                workflows.into_iter().next()
            } else {
                None
            };
            (goal, workflow)
        } else {
            (None, None)
        };

        Ok(ChainState {
            intent,
            goal,
            workflow,
        })
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /// Core resume logic given an already-loaded Intent.
    fn resume_from_intent(
        &self,
        intent: Intent,
        timestamp_ms: u64,
        is_replay: bool,
    ) -> Result<Phase1Result, RuntimeError> {
        // Find existing goal for this intent
        let existing_goals = self.goal_store.find_by_intent_id(&intent.intent_id)?;
        let existing_goal = existing_goals.into_iter().next();

        match existing_goal {
            None => {
                // No goal yet — can we create one?
                match intent.status {
                    IntentStatus::Accepted => {
                        // Intent is accepted; create Goal and Workflow
                        let (goal, workflow) =
                            self.create_goal_and_workflow(&intent, timestamp_ms)?;
                        Ok(Phase1Result {
                            intent,
                            goal,
                            workflow,
                            is_replay,
                        })
                    }
                    IntentStatus::Created => {
                        // Intent not yet accepted — this is an inconsistency:
                        // submit() always accepts before returning, so this
                        // only happens if the process crashed between insert
                        // and update. Attempt to normalize and accept.
                        let mut intent = intent;
                        let normalized = normalize_intent(&intent.raw_input).map_err(|e| {
                            RuntimeError::InvalidInput {
                                reason: e.to_string(),
                            }
                        })?;
                        intent
                            .accept(normalized)
                            .map_err(RuntimeError::DomainViolation)?;
                        self.intent_store.update(&intent)?;

                        let (goal, workflow) =
                            self.create_goal_and_workflow(&intent, timestamp_ms)?;
                        Ok(Phase1Result {
                            intent,
                            goal,
                            workflow,
                            is_replay,
                        })
                    }
                    _ => Err(RuntimeError::IrreconcilableIntentState {
                        intent_id: intent.intent_id,
                        intent_status: format!("{:?}", intent.status),
                    }),
                }
            }

            Some(existing_goal) => {
                // Goal exists — look for Workflow
                let existing_workflows = self
                    .workflow_store
                    .find_by_goal_id(&existing_goal.goal_id)?;
                let existing_workflow = existing_workflows.into_iter().next();

                // Verify cross-store consistency
                if existing_goal.originating_intent_id != intent.intent_id {
                    return Err(RuntimeError::InconsistentState {
                        correlation_id: intent.correlation_id,
                        reason: format!(
                            "Goal {} has originating_intent_id {} but expected {}",
                            existing_goal.goal_id,
                            existing_goal.originating_intent_id,
                            intent.intent_id
                        ),
                    });
                }

                if existing_goal.correlation_id != intent.correlation_id {
                    return Err(RuntimeError::InconsistentState {
                        correlation_id: intent.correlation_id,
                        reason: format!(
                            "Goal {} has correlation_id {} but intent has {}",
                            existing_goal.goal_id,
                            existing_goal.correlation_id,
                            intent.correlation_id
                        ),
                    });
                }

                match existing_workflow {
                    None => {
                        // Goal exists but no Workflow — create it if goal is resumable
                        let goal = existing_goal;
                        match goal.status {
                            GoalStatus::Accepted | GoalStatus::Created => {
                                // Ensure Goal is in Accepted state before creating Workflow
                                let goal = if goal.status == GoalStatus::Created {
                                    let mut g = goal;
                                    g.transition(GoalStatus::Accepted, timestamp_ms)
                                        .map_err(RuntimeError::DomainViolation)?;
                                    self.goal_store.update(&g)?;
                                    g
                                } else {
                                    goal
                                };

                                let normalized = intent.normalized.as_ref().ok_or_else(|| {
                                    RuntimeError::IrreconcilableGoalState {
                                        goal_id: goal.goal_id,
                                        goal_status: format!("{:?}", goal.status),
                                    }
                                })?;

                                let workflow = self.create_and_persist_workflow(
                                    &goal,
                                    normalized,
                                    timestamp_ms,
                                )?;

                                Ok(Phase1Result {
                                    intent,
                                    goal,
                                    workflow,
                                    is_replay,
                                })
                            }
                            _ => Err(RuntimeError::IrreconcilableGoalState {
                                goal_id: goal.goal_id,
                                goal_status: format!("{:?}", goal.status),
                            }),
                        }
                    }

                    Some(existing_workflow) => {
                        // Complete chain exists — validate consistency
                        if existing_workflow.goal_id != existing_goal.goal_id {
                            return Err(RuntimeError::InconsistentState {
                                correlation_id: intent.correlation_id,
                                reason: format!(
                                    "Workflow {} has goal_id {} but expected {}",
                                    existing_workflow.workflow_id,
                                    existing_workflow.goal_id,
                                    existing_goal.goal_id
                                ),
                            });
                        }

                        if existing_workflow.correlation_id != intent.correlation_id {
                            return Err(RuntimeError::InconsistentState {
                                correlation_id: intent.correlation_id,
                                reason: format!(
                                    "Workflow {} has correlation_id {} but expected {}",
                                    existing_workflow.workflow_id,
                                    existing_workflow.correlation_id,
                                    intent.correlation_id
                                ),
                            });
                        }

                        Ok(Phase1Result {
                            intent,
                            goal: existing_goal,
                            workflow: existing_workflow,
                            is_replay,
                        })
                    }
                }
            }
        }
    }

    /// Creates, accepts, and persists a Goal from an accepted Intent,
    /// then creates, accepts, and persists the Workflow.
    ///
    /// Both entities are advanced only through legal domain transitions.
    /// Does NOT mark either Running, Completed, or Failed.
    fn create_goal_and_workflow(
        &self,
        intent: &Intent,
        timestamp_ms: u64,
    ) -> Result<(Goal, Workflow), RuntimeError> {
        // Require normalized intent for goal/workflow synthesis
        let normalized =
            intent
                .normalized
                .as_ref()
                .ok_or_else(|| RuntimeError::IllegalLifecycleOperation {
                    reason: format!(
                        "create_goal_and_workflow called on intent {} which is not yet Accepted \
                     (normalized is None)",
                        intent.intent_id
                    ),
                })?;

        // Build the GoalObjective from the NormalizedIntent
        let objective = build_goal_objective(normalized);

        // Create Goal in Created state
        let mut goal = Goal::from_intent(intent, objective, timestamp_ms);

        // Persist Goal (Created)
        self.goal_store.insert(&goal)?;

        // Accept Goal: Created → Accepted
        goal.transition(GoalStatus::Accepted, timestamp_ms)
            .map_err(RuntimeError::DomainViolation)?;

        self.goal_store.update(&goal)?;

        // Synthesize and persist Workflow
        let workflow = self.create_and_persist_workflow(&goal, normalized, timestamp_ms)?;

        Ok((goal, workflow))
    }

    /// Synthesizes, accepts, and persists a Workflow for a given Goal.
    ///
    /// The Workflow is advanced: Created → Accepted.
    fn create_and_persist_workflow(
        &self,
        goal: &Goal,
        normalized: &crate::intent::NormalizedIntent,
        timestamp_ms: u64,
    ) -> Result<Workflow, RuntimeError> {
        // Synthesize deterministic Workflow from the normalized intent pattern
        let mut workflow = synthesize_workflow(goal, normalized, timestamp_ms)?;

        // Persist Workflow (Created)
        self.workflow_store.insert(&workflow)?;

        // Accept Workflow: Created → Accepted
        workflow
            .transition(WorkflowStatus::Accepted, timestamp_ms)
            .map_err(RuntimeError::DomainViolation)?;

        self.workflow_store.update(&workflow)?;

        Ok(workflow)
    }
}

// ---------------------------------------------------------------------------
// Goal objective synthesis
// ---------------------------------------------------------------------------

/// Builds a `GoalObjective` from a `NormalizedIntent`.
///
/// This is a deterministic mapping — identical inputs produce identical objectives.
fn build_goal_objective(normalized: &crate::intent::NormalizedIntent) -> GoalObjective {
    match (normalized.category.as_str(), normalized.action.as_str()) {
        ("fs", "create_directory") => {
            let path = normalized
                .parameters
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            GoalObjective::new(
                "Create Directory",
                format!("Ensure directory '{}' exists in the active workspace", path),
                vec![format!("Directory '{}' exists and is readable", path)],
                "workspace",
            )
        }
        (category, action) => {
            // Fallback: generic objective — reached only for patterns the planner
            // also rejects, so this is a defensive safety net.
            GoalObjective::new(
                format!("{}/{}", category, action),
                format!("Execute {} operation: {}", category, action),
                vec![format!("{} {} completed successfully", category, action)],
                "workspace",
            )
        }
    }
}

// ---------------------------------------------------------------------------
// ChainState (read-only query result)
// ---------------------------------------------------------------------------

/// Read-only snapshot of the current persisted chain for an intent.
///
/// Any field may be `None` if the corresponding entity has not been created yet
/// or does not exist in storage.
#[derive(Debug, Clone)]
pub struct ChainState {
    pub intent: Option<Intent>,
    pub goal: Option<Goal>,
    pub workflow: Option<Workflow>,
}
