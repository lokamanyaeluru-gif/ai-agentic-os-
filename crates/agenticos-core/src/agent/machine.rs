//! Agent lifecycle state machine engine for Layer 5 (Global Agent Manager).
//!
//! Provides deterministic state machine execution and authoritative persistence
//! through `AgentRegistryStore`.

use agenticos_contracts::{ErrorCode, ErrorPayload, RetryClassification};
use uuid::Uuid;

use crate::agent::{AgentId, AgentLifecycleState, AgentRecord, ProcessIdentity};
use crate::error::DomainError;
use crate::storage::{AgentRegistryStore, StorageError};

/// Typed errors produced by the agent lifecycle engine.
#[derive(Debug, thiserror::Error)]
pub enum AgentLifecycleError {
    #[error("Agent '{agent_id}' not found in registry")]
    AgentNotFound { agent_id: AgentId },

    #[error("Invalid state transition for agent '{agent_id}': cannot transition from {from:?} to {to:?}")]
    InvalidTransition {
        agent_id: AgentId,
        from: AgentLifecycleState,
        to: AgentLifecycleState,
    },

    #[error("Agent '{agent_id}' is in terminal state {state:?} and cannot transition")]
    TerminalState {
        agent_id: AgentId,
        state: AgentLifecycleState,
    },

    #[error("Cannot restart agent '{agent_id}': agent is in non-terminal state {state:?}")]
    CannotRestartNonTerminal {
        agent_id: AgentId,
        state: AgentLifecycleState,
    },

    #[error("Restart policy 'Never' prohibits restarting agent '{agent_id}'")]
    RestartPolicyNever { agent_id: AgentId },

    #[error("Restart policy exhausted for agent '{agent_id}': max retries {max_retries}, current retries {current_retries}")]
    RestartPolicyExhausted {
        agent_id: AgentId,
        max_retries: u32,
        current_retries: u32,
    },

    #[error(
        "Timestamp regression for agent '{agent_id}': current {current_ms}, proposed {proposed_ms}"
    )]
    TimestampRegression {
        agent_id: AgentId,
        current_ms: u64,
        proposed_ms: u64,
    },

    #[error("Provenance violation for agent '{agent_id}': immutable identity or provenance fields cannot be modified")]
    ProvenanceViolation { agent_id: AgentId },

    #[error("Storage failure: {0}")]
    Storage(#[from] StorageError),

    #[error("Domain violation: {0}")]
    Domain(#[from] DomainError),
}

impl From<AgentLifecycleError> for ErrorPayload {
    fn from(err: AgentLifecycleError) -> Self {
        match err {
            AgentLifecycleError::Storage(storage_err) => storage_err.into(),
            AgentLifecycleError::Domain(domain_err) => domain_err.into(),
            other => ErrorPayload::new(
                ErrorCode::InvalidRequest,
                other.to_string(),
                "agenticos-core::agent::machine",
                RetryClassification::Never,
            ),
        }
    }
}

/// Deterministic lifecycle state machine engine for agent instances.
///
/// Ensures all state transitions, terminal protections, and restart policies
/// are strictly enforced and persisted via `AgentRegistryStore`.
#[derive(Debug, Clone)]
pub struct AgentLifecycleEngine {
    store: AgentRegistryStore,
}

impl AgentLifecycleEngine {
    /// Creates a new lifecycle engine backed by the provided authoritative store.
    pub fn new(store: AgentRegistryStore) -> Self {
        Self { store }
    }

    /// Returns a reference to the underlying `AgentRegistryStore`.
    pub fn store(&self) -> &AgentRegistryStore {
        &self.store
    }

    /// Fetches the authoritative `AgentRecord` from storage.
    pub fn get_agent(&self, agent_id: &AgentId) -> Result<AgentRecord, AgentLifecycleError> {
        self.store
            .get_agent(agent_id)?
            .ok_or(AgentLifecycleError::AgentNotFound {
                agent_id: *agent_id,
            })
    }

    /// Transitions an agent to a new lifecycle state.
    ///
    /// Validates:
    /// 1. Agent exists in storage.
    /// 2. Agent is not currently in a terminal state (`Stopped` or `Failed`).
    /// 3. Transition is permitted by `AgentLifecycleState::can_transition_to`.
    /// 4. `timestamp_ms` does not regress backwards (`timestamp_ms >= agent.updated_at_ms`).
    ///
    /// Atomically updates and persists the record to `AgentRegistryStore`.
    pub fn transition(
        &self,
        agent_id: &AgentId,
        next_state: AgentLifecycleState,
        timestamp_ms: u64,
    ) -> Result<AgentRecord, AgentLifecycleError> {
        let mut agent = self.get_agent(agent_id)?;

        if agent.state.is_terminal() {
            return Err(AgentLifecycleError::TerminalState {
                agent_id: *agent_id,
                state: agent.state,
            });
        }

        if timestamp_ms < agent.updated_at_ms {
            return Err(AgentLifecycleError::TimestampRegression {
                agent_id: *agent_id,
                current_ms: agent.updated_at_ms,
                proposed_ms: timestamp_ms,
            });
        }

        if !agent.state.can_transition_to(next_state) {
            return Err(AgentLifecycleError::InvalidTransition {
                agent_id: *agent_id,
                from: agent.state,
                to: next_state,
            });
        }

        agent.transition(next_state, timestamp_ms)?;
        self.store.update_agent(&agent)?;

        Ok(agent)
    }

    /// Updates the process identity of an agent while preserving its current lifecycle state.
    ///
    /// Permitted only for non-terminal agents (e.g. during `Starting` or `Running`).
    pub fn update_process_identity(
        &self,
        agent_id: &AgentId,
        pid: u32,
        start_time_ticks: u64,
        process_started_at_ms: u64,
        timestamp_ms: u64,
    ) -> Result<AgentRecord, AgentLifecycleError> {
        let mut agent = self.get_agent(agent_id)?;

        if agent.state.is_terminal() {
            return Err(AgentLifecycleError::TerminalState {
                agent_id: *agent_id,
                state: agent.state,
            });
        }

        if timestamp_ms < agent.updated_at_ms {
            return Err(AgentLifecycleError::TimestampRegression {
                agent_id: *agent_id,
                current_ms: agent.updated_at_ms,
                proposed_ms: timestamp_ms,
            });
        }

        agent.process_identity = ProcessIdentity::active(
            pid,
            start_time_ticks,
            agent.process_identity.instance_nonce,
            agent.owner.uid,
            agent.owner.gid,
            process_started_at_ms,
        );
        agent.updated_at_ms = timestamp_ms;

        self.store.update_agent(&agent)?;
        Ok(agent)
    }

    /// Re-arms a terminal agent (`Stopped` or `Failed`) via explicit restart action.
    ///
    /// Validates:
    /// 1. Agent exists in storage.
    /// 2. Agent is currently in a terminal state (`Stopped` or `Failed`).
    /// 3. Restart policy permits restart (`can_restart()`).
    /// 4. `timestamp_ms >= agent.updated_at_ms`.
    ///
    /// On success:
    /// - Increments the retry counter in `RestartPolicy`.
    /// - Resets `ProcessIdentity` to unspawned with the provided `next_instance_nonce`.
    /// - Transitions state to `Starting`.
    /// - Updates `updated_at_ms`.
    /// - Atomically persists through `AgentRegistryStore`.
    pub fn restart(
        &self,
        agent_id: &AgentId,
        next_instance_nonce: Uuid,
        timestamp_ms: u64,
    ) -> Result<AgentRecord, AgentLifecycleError> {
        let mut agent = self.get_agent(agent_id)?;

        if !agent.state.is_terminal() {
            return Err(AgentLifecycleError::CannotRestartNonTerminal {
                agent_id: *agent_id,
                state: agent.state,
            });
        }

        if timestamp_ms < agent.updated_at_ms {
            return Err(AgentLifecycleError::TimestampRegression {
                agent_id: *agent_id,
                current_ms: agent.updated_at_ms,
                proposed_ms: timestamp_ms,
            });
        }

        if !agent.restart_policy.can_restart() {
            match agent.restart_policy {
                crate::agent::RestartPolicy::Never => {
                    return Err(AgentLifecycleError::RestartPolicyNever {
                        agent_id: *agent_id,
                    });
                }
                crate::agent::RestartPolicy::OnFailure {
                    max_retries,
                    current_retries,
                    ..
                }
                | crate::agent::RestartPolicy::Always {
                    max_retries,
                    current_retries,
                    ..
                } => {
                    return Err(AgentLifecycleError::RestartPolicyExhausted {
                        agent_id: *agent_id,
                        max_retries,
                        current_retries,
                    });
                }
            }
        }

        agent.restart(next_instance_nonce, timestamp_ms)?;
        self.store.update_agent(&agent)?;

        Ok(agent)
    }
}
