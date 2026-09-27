//! Intent domain model and lifecycle state machine.
//!
//! Aligned with Phase 1.0 specification and ADR-0007.

use agenticos_contracts::{PrincipalContext, ResourceRef};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::DomainError;

/// Maximum allowable length for raw intent input (64 KiB).
pub const MAX_RAW_INPUT_LEN: usize = 65536;

/// Lifecycle status of an Intent.
///
/// Intent represents the request lifecycle (not execution lifecycle).
/// Runtime execution state belongs strictly to Goal and Workflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IntentStatus {
    Created,
    Accepted,
    Completed,
    Failed,
    Cancelled,
}

impl IntentStatus {
    /// Returns true if this state is terminal (cannot transition further).
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self,
            IntentStatus::Completed | IntentStatus::Failed | IntentStatus::Cancelled
        )
    }

    /// Validates whether a transition from `self` to `next` is permitted.
    pub fn can_transition_to(&self, next: IntentStatus) -> bool {
        match self {
            IntentStatus::Created => matches!(next, IntentStatus::Accepted | IntentStatus::Failed),
            IntentStatus::Accepted => matches!(
                next,
                IntentStatus::Completed | IntentStatus::Failed | IntentStatus::Cancelled
            ),
            IntentStatus::Completed | IntentStatus::Failed | IntentStatus::Cancelled => false,
        }
    }
}

/// Normalized, structured semantic representation of user intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedIntent {
    /// Action category (e.g. "fs", "system", "process").
    pub category: String,

    /// Canonical action verb (e.g. "create_directory", "read_file").
    pub action: String,

    /// Target conceptual resource reference.
    pub target_resource: ResourceRef,

    /// Extracted structured parameters governing the intent.
    pub parameters: serde_json::Value,
}

impl NormalizedIntent {
    pub fn new(
        category: impl Into<String>,
        action: impl Into<String>,
        target_resource: ResourceRef,
        parameters: serde_json::Value,
    ) -> Self {
        Self {
            category: category.into(),
            action: action.into(),
            target_resource,
            parameters,
        }
    }
}

/// Represents the user's initial expressed desire before goal decomposition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    /// Unique identifier for this specific intent.
    pub intent_id: Uuid,

    /// Root correlation ID tracking all causal operations across the system.
    /// Strictly for causal tracing and observability; NOT an idempotency key.
    pub correlation_id: Uuid,

    /// Optional caller-provided deduplication key:
    /// - Scoped to the authenticated originating principal
    /// - Not a correlation ID (does not trace causal trees)
    /// - Not an authorization credential (does not grant permissions)
    pub idempotency_key: Option<String>,

    /// Exact, unmodified input received from the caller.
    pub raw_input: String,

    /// Normalized, structured semantic representation.
    pub normalized: Option<NormalizedIntent>,

    /// Wall-clock timestamp (milliseconds since Unix epoch, UTC) when intent was captured.
    pub created_at_ms: u64,

    /// Originating principal who submitted the input (provenance context; not transport security authority).
    pub originating_principal: PrincipalContext,

    /// Current lifecycle status of the intent.
    pub status: IntentStatus,
}

impl Intent {
    /// Creates and validates a new `Intent` in the `Created` state.
    ///
    /// Validates raw input constraints:
    /// - Must not be empty.
    /// - Must not exceed length ceiling (64 KiB).
    /// - Must not contain null bytes.
    pub fn new(
        raw_input: impl Into<String>,
        originating_principal: PrincipalContext,
        correlation_id: Uuid,
        idempotency_key: Option<String>,
        created_at_ms: u64,
    ) -> Result<Self, DomainError> {
        let raw_input = raw_input.into();

        if raw_input.is_empty() {
            return Err(DomainError::InvalidRawInput {
                reason: "raw_input cannot be empty",
            });
        }

        if raw_input.len() > MAX_RAW_INPUT_LEN {
            return Err(DomainError::InvalidRawInput {
                reason: "raw_input exceeds maximum length ceiling (64 KiB)",
            });
        }

        if raw_input.contains('\0') {
            return Err(DomainError::InvalidRawInput {
                reason: "raw_input contains prohibited null bytes",
            });
        }

        Ok(Self {
            intent_id: Uuid::new_v4(),
            correlation_id,
            idempotency_key,
            raw_input,
            normalized: None,
            created_at_ms,
            originating_principal,
            status: IntentStatus::Created,
        })
    }

    /// Attaches normalized semantic structure and transitions status to `Accepted`.
    pub fn accept(&mut self, normalized: NormalizedIntent) -> Result<(), DomainError> {
        self.transition(IntentStatus::Accepted)?;
        self.normalized = Some(normalized);
        Ok(())
    }

    /// Transitions the intent to a new lifecycle state.
    ///
    /// Returns an error if the transition is illegal or if the current state is terminal.
    pub fn transition(&mut self, next: IntentStatus) -> Result<(), DomainError> {
        if self.status.is_terminal() {
            return Err(DomainError::TerminalState {
                entity: "Intent",
                state: format!("{:?}", self.status),
            });
        }

        if !self.status.can_transition_to(next) {
            return Err(DomainError::InvalidStateTransition {
                entity: "Intent",
                from: format!("{:?}", self.status),
                to: format!("{:?}", next),
            });
        }

        self.status = next;
        Ok(())
    }
}
