//! Goal domain model and lifecycle state machine.
//!
//! Aligned with Phase 1.0 specification and ADR-0007.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::DomainError;
use crate::intent::Intent;

/// Lifecycle status of a Goal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GoalStatus {
    Created,
    Accepted,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl GoalStatus {
    /// Returns true if this state is terminal (cannot transition further).
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self,
            GoalStatus::Completed | GoalStatus::Failed | GoalStatus::Cancelled
        )
    }

    /// Validates whether a transition from `self` to `next` is permitted.
    pub fn can_transition_to(&self, next: GoalStatus) -> bool {
        match self {
            GoalStatus::Created => matches!(next, GoalStatus::Accepted | GoalStatus::Failed),
            GoalStatus::Accepted => matches!(next, GoalStatus::Running | GoalStatus::Cancelled),
            GoalStatus::Running => matches!(
                next,
                GoalStatus::Completed | GoalStatus::Failed | GoalStatus::Cancelled
            ),
            GoalStatus::Completed | GoalStatus::Failed | GoalStatus::Cancelled => false,
        }
    }
}

/// Structured objective definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoalObjective {
    /// Concise human-readable name of the objective.
    pub title: String,

    /// Formal description of desired end state.
    pub description: String,

    /// Declarative acceptance-criteria expressions (declarative human/eval criteria; exact predicate schema deferred).
    pub acceptance_criteria: Vec<String>,

    /// Target workspace or system boundary.
    pub scope: String,
}

impl GoalObjective {
    pub fn new(
        title: impl Into<String>,
        description: impl Into<String>,
        acceptance_criteria: Vec<String>,
        scope: impl Into<String>,
    ) -> Self {
        Self {
            title: title.into(),
            description: description.into(),
            acceptance_criteria,
            scope: scope.into(),
        }
    }
}

/// Represents an accepted, formal objective with declarative criteria.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Goal {
    /// Unique identifier for this goal.
    pub goal_id: Uuid,

    /// Root correlation ID matching originating intent.
    pub correlation_id: Uuid,

    /// Reference to the intent that gave rise to this goal.
    pub originating_intent_id: Uuid,

    /// Structured objective definition.
    pub objective: GoalObjective,

    /// Current lifecycle status of the goal.
    pub status: GoalStatus,

    /// Wall-clock timestamp (UTC ms) when goal was declared.
    pub created_at_ms: u64,

    /// Wall-clock timestamp (UTC ms) of latest state transition.
    pub updated_at_ms: u64,
}

impl Goal {
    /// Creates a new `Goal` linked to an originating `Intent`.
    ///
    /// Preserves and propagates `correlation_id` and binds `originating_intent_id`.
    pub fn from_intent(
        originating_intent: &Intent,
        objective: GoalObjective,
        created_at_ms: u64,
    ) -> Self {
        Self {
            goal_id: Uuid::new_v4(),
            correlation_id: originating_intent.correlation_id,
            originating_intent_id: originating_intent.intent_id,
            objective,
            status: GoalStatus::Created,
            created_at_ms,
            updated_at_ms: created_at_ms,
        }
    }

    /// Transitions the goal to a new lifecycle state.
    ///
    /// Updates `updated_at_ms`. Returns an error if illegal or terminal.
    pub fn transition(&mut self, next: GoalStatus, updated_at_ms: u64) -> Result<(), DomainError> {
        if self.status.is_terminal() {
            return Err(DomainError::TerminalState {
                entity: "Goal",
                state: format!("{:?}", self.status),
            });
        }

        if !self.status.can_transition_to(next) {
            return Err(DomainError::InvalidStateTransition {
                entity: "Goal",
                from: format!("{:?}", self.status),
                to: format!("{:?}", next),
            });
        }

        self.status = next;
        self.updated_at_ms = updated_at_ms;
        Ok(())
    }
}
