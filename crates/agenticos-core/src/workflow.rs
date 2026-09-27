//! Workflow domain model, Directed Acyclic Graph (DAG) validation, and step state machines.
//!
//! Aligned with Phase 1.0 specification and ADR-0007.

use std::collections::{HashMap, HashSet, VecDeque};

use agenticos_contracts::{ResourceRef, RetryClassification};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::DomainError;
use crate::goal::Goal;

/// Lifecycle status of an overall Workflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WorkflowStatus {
    Created,
    Accepted,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl WorkflowStatus {
    /// Returns true if this state is terminal (cannot transition further).
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self,
            WorkflowStatus::Completed | WorkflowStatus::Failed | WorkflowStatus::Cancelled
        )
    }

    /// Validates whether a transition from `self` to `next` is permitted.
    pub fn can_transition_to(&self, next: WorkflowStatus) -> bool {
        match self {
            WorkflowStatus::Created => {
                matches!(next, WorkflowStatus::Accepted | WorkflowStatus::Failed)
            }
            WorkflowStatus::Accepted => {
                matches!(next, WorkflowStatus::Running | WorkflowStatus::Cancelled)
            }
            WorkflowStatus::Running => matches!(
                next,
                WorkflowStatus::Completed | WorkflowStatus::Failed | WorkflowStatus::Cancelled
            ),
            WorkflowStatus::Completed | WorkflowStatus::Failed | WorkflowStatus::Cancelled => false,
        }
    }
}

/// Execution state of an individual WorkflowStep.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StepExecutionState {
    Created,
    Waiting,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl StepExecutionState {
    /// Returns true if this state is terminal (cannot transition further).
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self,
            StepExecutionState::Completed
                | StepExecutionState::Failed
                | StepExecutionState::Cancelled
        )
    }

    /// Validates whether a transition from `self` to `next` is permitted.
    pub fn can_transition_to(&self, next: StepExecutionState) -> bool {
        match self {
            StepExecutionState::Created => matches!(
                next,
                StepExecutionState::Waiting
                    | StepExecutionState::Running
                    | StepExecutionState::Failed
            ),
            StepExecutionState::Waiting => matches!(
                next,
                StepExecutionState::Running | StepExecutionState::Cancelled
            ),
            StepExecutionState::Running => matches!(
                next,
                StepExecutionState::Completed
                    | StepExecutionState::Failed
                    | StepExecutionState::Cancelled
            ),
            StepExecutionState::Completed
            | StepExecutionState::Failed
            | StepExecutionState::Cancelled => false,
        }
    }
}

/// Dependency edge between workflow steps.
///
/// The `step_id` cannot execute until `depends_on_step_id` reaches `Completed`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepDependency {
    /// The dependent step that cannot execute until prerequisite completes.
    pub step_id: Uuid,

    /// The prerequisite step ID that must complete successfully.
    pub depends_on_step_id: Uuid,
}

impl StepDependency {
    pub fn new(step_id: Uuid, depends_on_step_id: Uuid) -> Self {
        Self {
            step_id,
            depends_on_step_id,
        }
    }
}

/// Individual atomic capability invocation unit within a workflow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowStep {
    /// Unique identifier for this step.
    pub step_id: Uuid,

    /// Sequence index within the linear plan presentation (0-indexed).
    pub step_index: u32,

    /// Canonical capability identifier (e.g. "fs.create_directory").
    pub capability_id: String,

    /// Version of the capability argument schema.
    pub capability_schema_version: u32,

    /// Conceptual resource reference (ADR-0007).
    pub resource: ResourceRef,

    /// Schema-validated structured arguments for the capability.
    pub arguments: serde_json::Value,

    /// Derived/cached prerequisite step IDs for fast local readiness checks (non-authoritative).
    /// Authoritative dependency graph is defined by `Workflow.dependencies`.
    pub dependency_step_ids: Vec<Uuid>,

    /// Current execution state of this specific step.
    pub state: StepExecutionState,

    /// Retry classification governed by supervisor (ADR-0007).
    pub retry_classification: RetryClassification,

    /// Relative execution timeout duration in milliseconds (enforced via monotonic clock).
    pub timeout_duration_ms: u64,
}

impl WorkflowStep {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        step_index: u32,
        capability_id: impl Into<String>,
        capability_schema_version: u32,
        resource: ResourceRef,
        arguments: serde_json::Value,
        dependency_step_ids: Vec<Uuid>,
        retry_classification: RetryClassification,
        timeout_duration_ms: u64,
    ) -> Self {
        Self {
            step_id: Uuid::new_v4(),
            step_index,
            capability_id: capability_id.into(),
            capability_schema_version,
            resource,
            arguments,
            dependency_step_ids,
            state: StepExecutionState::Created,
            retry_classification,
            timeout_duration_ms,
        }
    }

    /// Transitions the step to a new execution state.
    pub fn transition(&mut self, next: StepExecutionState) -> Result<(), DomainError> {
        if self.state.is_terminal() {
            return Err(DomainError::TerminalState {
                entity: "WorkflowStep",
                state: format!("{:?}", self.state),
            });
        }

        if !self.state.can_transition_to(next) {
            return Err(DomainError::InvalidStateTransition {
                entity: "WorkflowStep",
                from: format!("{:?}", self.state),
                to: format!("{:?}", next),
            });
        }

        self.state = next;
        Ok(())
    }
}

/// Represents a deterministic execution plan structured as a Directed Acyclic Graph (DAG).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workflow {
    /// Unique identifier for this workflow plan.
    pub workflow_id: Uuid,

    /// Reference to the goal this workflow fulfills.
    pub goal_id: Uuid,

    /// Root correlation ID tracking the entire operation.
    pub correlation_id: Uuid,

    /// Ordered list of executable workflow steps.
    pub steps: Vec<WorkflowStep>,

    /// Authoritative dependency relations between steps (step_id -> depends_on step_ids).
    pub dependencies: Vec<StepDependency>,

    /// Current execution status of the overall workflow.
    pub status: WorkflowStatus,

    /// Wall-clock timestamp (UTC ms) when workflow was synthesized.
    pub created_at_ms: u64,

    /// Wall-clock timestamp (UTC ms) of latest status update.
    pub updated_at_ms: u64,
}

impl Workflow {
    /// Creates and validates a new `Workflow` linked to a `Goal`.
    ///
    /// Preserves `correlation_id` from Goal and validates the dependency graph.
    pub fn from_goal(
        goal: &Goal,
        steps: Vec<WorkflowStep>,
        dependencies: Vec<StepDependency>,
        created_at_ms: u64,
    ) -> Result<Self, DomainError> {
        let workflow = Self {
            workflow_id: Uuid::new_v4(),
            goal_id: goal.goal_id,
            correlation_id: goal.correlation_id,
            steps,
            dependencies,
            status: WorkflowStatus::Created,
            created_at_ms,
            updated_at_ms: created_at_ms,
        };

        // Invariant: DAG must be valid and consistent upon creation
        workflow.validate_dependencies()?;

        Ok(workflow)
    }

    /// Validates the workflow dependency graph invariants:
    /// 1. All step IDs must be unique.
    /// 2. All dependency references must exist in `steps`.
    /// 3. No self-dependencies.
    /// 4. No duplicate dependency edges.
    /// 5. Derived cache `step.dependency_step_ids` must match authoritative `Workflow.dependencies`.
    /// 6. Dependency graph must be strictly acyclic (DAG).
    pub fn validate_dependencies(&self) -> Result<(), DomainError> {
        let mut step_ids = HashSet::new();
        for step in &self.steps {
            if !step_ids.insert(step.step_id) {
                return Err(DomainError::DuplicateStepId {
                    step_id: step.step_id,
                });
            }
        }

        // Validate dependencies reference existing steps, no self-dependency, no duplicates
        let mut seen_edges = HashSet::new();
        let mut authoritative_incoming: HashMap<Uuid, HashSet<Uuid>> = HashMap::new();

        for dep in &self.dependencies {
            if !step_ids.contains(&dep.step_id) {
                return Err(DomainError::StepNotFound {
                    step_id: dep.step_id,
                });
            }

            if !step_ids.contains(&dep.depends_on_step_id) {
                return Err(DomainError::StepNotFound {
                    step_id: dep.depends_on_step_id,
                });
            }

            if dep.step_id == dep.depends_on_step_id {
                return Err(DomainError::SelfDependency {
                    step_id: dep.step_id,
                });
            }

            if !seen_edges.insert((dep.step_id, dep.depends_on_step_id)) {
                return Err(DomainError::DuplicateDependency {
                    step_id: dep.step_id,
                    depends_on_step_id: dep.depends_on_step_id,
                });
            }

            authoritative_incoming
                .entry(dep.step_id)
                .or_default()
                .insert(dep.depends_on_step_id);
        }

        // Consistency invariant: verify step.dependency_step_ids matches authoritative dependencies
        for step in &self.steps {
            let cached_set: HashSet<Uuid> = step.dependency_step_ids.iter().copied().collect();
            let auth_set = authoritative_incoming
                .get(&step.step_id)
                .cloned()
                .unwrap_or_default();

            if cached_set != auth_set {
                return Err(DomainError::DependencyInconsistency {
                    step_id: step.step_id,
                });
            }
        }

        // DAG Acyclicity: Kahn's algorithm (topological sort)
        // Adjacency: prerequisite -> list of dependents
        let mut in_degree: HashMap<Uuid, usize> = HashMap::new();
        let mut dependents: HashMap<Uuid, Vec<Uuid>> = HashMap::new();

        for step in &self.steps {
            in_degree.insert(step.step_id, 0);
            dependents.insert(step.step_id, Vec::new());
        }

        for dep in &self.dependencies {
            *in_degree.entry(dep.step_id).or_insert(0) += 1;
            dependents
                .entry(dep.depends_on_step_id)
                .or_default()
                .push(dep.step_id);
        }

        let mut queue: VecDeque<Uuid> = in_degree
            .iter()
            .filter(|&(_, &deg)| deg == 0)
            .map(|(&id, _)| id)
            .collect();

        let mut visited_count = 0;
        while let Some(u) = queue.pop_front() {
            visited_count += 1;
            if let Some(deps) = dependents.get(&u) {
                for &v in deps {
                    if let Some(deg) = in_degree.get_mut(&v) {
                        *deg -= 1;
                        if *deg == 0 {
                            queue.push_back(v);
                        }
                    }
                }
            }
        }

        if visited_count != self.steps.len() {
            // Find a step that could not be scheduled due to a cycle
            let cycle_step_id = in_degree
                .into_iter()
                .find(|&(_, deg)| deg > 0)
                .map(|(id, _)| id)
                .unwrap_or_else(Uuid::nil);

            return Err(DomainError::DependencyCycle {
                step_id: cycle_step_id,
            });
        }

        Ok(())
    }

    /// Transitions the workflow to a new lifecycle state.
    ///
    /// Updates `updated_at_ms`. Enforces terminal-state protection and valid transition rules.
    pub fn transition(
        &mut self,
        next: WorkflowStatus,
        updated_at_ms: u64,
    ) -> Result<(), DomainError> {
        if self.status.is_terminal() {
            return Err(DomainError::TerminalState {
                entity: "Workflow",
                state: format!("{:?}", self.status),
            });
        }

        if !self.status.can_transition_to(next) {
            return Err(DomainError::InvalidStateTransition {
                entity: "Workflow",
                from: format!("{:?}", self.status),
                to: format!("{:?}", next),
            });
        }

        // Before accepting, re-verify DAG invariants
        if next == WorkflowStatus::Accepted {
            self.validate_dependencies()?;
        }

        self.status = next;
        self.updated_at_ms = updated_at_ms;
        Ok(())
    }
}
