//! Agent lifecycle state machine for Layer 5 (Global Agent Manager).
//!
//! Enforces deterministic lifecycle state transitions and terminal state protections.
//!
//! State Diagram:
//! ```text
//! Registered -> Starting -> Ready <-> Running -> Stopping -> Stopped (terminal)
//!                 |           |          |          |
//!                 +-----------+----------+----------+-----> Failed (terminal)
//! ```

use serde::{Deserialize, Serialize};

use crate::error::DomainError;

/// Authoritative lifecycle state of an agent instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AgentLifecycleState {
    /// Agent is formally registered in storage but not yet active or ready.
    Registered,

    /// Agent initialization or process bootstrap in progress.
    Starting,

    /// Agent is initialized, healthy, and idle; ready to accept work assignments.
    Ready,

    /// Agent is actively executing an assigned workflow step.
    Running,

    /// Graceful termination or shutdown requested.
    Stopping,

    /// Gracefully terminated; terminal resting state.
    Stopped,

    /// Abnormally terminated or irrecoverably degraded; terminal resting state.
    Failed,
}

impl AgentLifecycleState {
    /// Returns true if this state is terminal (cannot transition further without an explicit restart action).
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Stopped | Self::Failed)
    }

    /// Evaluates whether a transition from `self` to `next` is permitted.
    pub fn can_transition_to(&self, next: AgentLifecycleState) -> bool {
        match self {
            Self::Registered => matches!(next, Self::Starting | Self::Stopped),
            Self::Starting => matches!(next, Self::Ready | Self::Failed | Self::Stopping),
            Self::Ready => matches!(next, Self::Running | Self::Stopping | Self::Failed),
            Self::Running => matches!(next, Self::Ready | Self::Stopping | Self::Failed),
            Self::Stopping => matches!(next, Self::Stopped | Self::Failed),
            // Terminal states cannot transition to any other state via standard transition.
            Self::Stopped | Self::Failed => false,
        }
    }

    /// Validates and executes a state transition.
    ///
    /// Rejects transitions from terminal states or invalid transitions with `DomainError`.
    pub fn transition_to(&mut self, next: AgentLifecycleState) -> Result<(), DomainError> {
        if self.is_terminal() {
            return Err(DomainError::TerminalState {
                entity: "Agent",
                state: format!("{:?}", self),
            });
        }

        if !self.can_transition_to(next) {
            return Err(DomainError::InvalidStateTransition {
                entity: "Agent",
                from: format!("{:?}", self),
                to: format!("{:?}", next),
            });
        }

        *self = next;
        Ok(())
    }
}
