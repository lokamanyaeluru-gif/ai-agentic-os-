//! Work assignment domain models for Layer 5 (Global Agent Manager).
//!
//! # Security Boundary Invariant (CRITICAL)
//!
//! - `WorkAssignment` is strictly a task dispatch contract between Layer 5 (Global Agent Manager)
//!   and Layer 6 (Agent Runtime).
//! - `WorkAssignment` **does NOT grant capability execution privileges or bypass security controls**.
//! - When the agent runtime proceeds to execute the step, it must issue a formal ADR-0007
//!   `CapabilityInvocationRequest` over UDS to the Security Governor and Confirmation Broker.
//! - The Security Governor evaluates Cedar PBAC policies, confirms interactive approvals when required,
//!   and executes capabilities exclusively inside Layer 8 sandboxes (Bubblewrap + Landlock + seccomp).
//! - The Global Agent Manager does not perform execution, sandbox configuration, or policy bypassing.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use agenticos_contracts::{PrincipalContext, ResourceRef};

use super::identity::AgentId;
use crate::error::DomainError;

/// Unique identifier for a work assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AssignmentId(pub Uuid);

impl AssignmentId {
    /// Generates a fresh random `AssignmentId`.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Wraps an existing UUID into an `AssignmentId`.
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Returns the underlying UUID.
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for AssignmentId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for AssignmentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Lifecycle status of a work assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AssignmentStatus {
    /// Assignment created and bound to agent; dispatch pending.
    Assigned,

    /// Agent has acknowledged and is actively executing the step.
    InProgress,

    /// Successfully completed.
    Completed,

    /// Execution failed.
    Failed,

    /// Cancelled by user, timeout, or workflow abort.
    Cancelled,
}

impl AssignmentStatus {
    /// Returns true if this state is terminal.
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }

    /// Evaluates whether a transition from `self` to `next` is permitted.
    pub fn can_transition_to(&self, next: AssignmentStatus) -> bool {
        match self {
            Self::Assigned => matches!(next, Self::InProgress | Self::Failed | Self::Cancelled),
            Self::InProgress => matches!(next, Self::Completed | Self::Failed | Self::Cancelled),
            Self::Completed | Self::Failed | Self::Cancelled => false,
        }
    }

    /// Validates and executes a state transition.
    pub fn transition_to(&mut self, next: AssignmentStatus) -> Result<(), DomainError> {
        if self.is_terminal() {
            return Err(DomainError::TerminalState {
                entity: "WorkAssignment",
                state: format!("{:?}", self),
            });
        }

        if !self.can_transition_to(next) {
            return Err(DomainError::InvalidStateTransition {
                entity: "WorkAssignment",
                from: format!("{:?}", self),
                to: format!("{:?}", next),
            });
        }

        *self = next;
        Ok(())
    }
}

/// Formal record of work assigned to an agent instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkAssignment {
    /// Unique assignment identifier.
    pub assignment_id: AssignmentId,

    /// Root causal trace ID inherited from Intent/Goal/Workflow.
    pub correlation_id: Uuid,

    /// Point-to-point invocation ID tracking this specific assignment dispatch.
    pub request_id: Uuid,

    /// Originating human or system principal requesting execution (provenance).
    pub originating_principal: PrincipalContext,

    /// Parent workflow identifier from Layer 4.
    pub workflow_id: Uuid,

    /// Specific step identifier within the workflow DAG being executed.
    pub step_id: Uuid,

    /// Designated agent instance ID.
    pub agent_id: AgentId,

    /// Required capability identifier to be invoked (e.g. "fs.create_directory").
    pub capability_id: String,

    /// Exact parameters for execution.
    pub arguments: serde_json::Value,

    /// Target resource reference.
    pub resource: ResourceRef,

    /// Current status of the assignment.
    pub status: AssignmentStatus,

    /// Timestamp (ms, UTC) when assignment was created.
    pub assigned_at_ms: u64,

    /// Timestamp (ms, UTC) when status was last updated.
    pub updated_at_ms: u64,

    /// Timeout duration in milliseconds governing execution.
    pub timeout_duration_ms: u64,
}

impl WorkAssignment {
    /// Creates and validates a new `WorkAssignment` in the `Assigned` status.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        correlation_id: Uuid,
        request_id: Uuid,
        originating_principal: PrincipalContext,
        workflow_id: Uuid,
        step_id: Uuid,
        agent_id: AgentId,
        capability_id: impl Into<String>,
        arguments: serde_json::Value,
        resource: ResourceRef,
        assigned_at_ms: u64,
        timeout_duration_ms: u64,
    ) -> Result<Self, DomainError> {
        let capability_id = capability_id.into();

        if capability_id.trim().is_empty() {
            return Err(DomainError::InvalidWorkAssignment {
                reason: "Capability identifier cannot be empty",
            });
        }

        if capability_id.contains('\0') {
            return Err(DomainError::InvalidWorkAssignment {
                reason: "Capability identifier cannot contain null bytes",
            });
        }

        if timeout_duration_ms == 0 {
            return Err(DomainError::InvalidWorkAssignment {
                reason: "Timeout duration must be non-zero",
            });
        }

        Ok(Self {
            assignment_id: AssignmentId::new(),
            correlation_id,
            request_id,
            originating_principal,
            workflow_id,
            step_id,
            agent_id,
            capability_id,
            arguments,
            resource,
            status: AssignmentStatus::Assigned,
            assigned_at_ms,
            updated_at_ms: assigned_at_ms,
            timeout_duration_ms,
        })
    }

    /// Transitions the work assignment to a new status.
    pub fn transition(
        &mut self,
        next: AssignmentStatus,
        updated_at_ms: u64,
    ) -> Result<(), DomainError> {
        self.status.transition_to(next)?;
        self.updated_at_ms = updated_at_ms;
        Ok(())
    }
}
