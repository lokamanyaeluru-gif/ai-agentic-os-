//! AI Agentic OS Core Domain Models and State Machines.
//!
//! Provides formal, local-only domain types and lifecycle state machines for:
//! - Intent (request lifecycle: Created -> Accepted -> Completed / Failed / Cancelled)
//! - Goal (execution lifecycle: Created -> Accepted -> Running -> Completed / Failed / Cancelled)
//! - Workflow (DAG execution plan lifecycle)
//! - WorkflowStep (atomic capability invocation unit lifecycle)
//! - ExecutionResult (execution outcome)
//! - Agent & Assignment (Layer 5 Global Agent Manager domain models and lifecycles)

pub mod agent;
pub mod error;
pub mod execution;
pub mod goal;
pub mod intent;
pub mod normalizer;
pub mod runtime;
pub mod storage;
pub mod workflow;

// Re-export agent domain models (Phase 2)
pub use agent::{
    AgentHealthState, AgentId, AgentLifecycleEngine, AgentLifecycleError, AgentLifecycleState,
    AgentRecord, AgentResourceMetrics, AgentScope, AgentType, AgentVersion, AssignmentId,
    AssignmentStatus, HeartbeatRecord, ProcessIdentity, RestartPolicy, WorkAssignment,
};

// Re-export core types for ergonomic consumption (Phase 1)
pub use error::DomainError;
pub use execution::{ExecutionOutcomeStatus, ExecutionResult};
pub use goal::{Goal, GoalObjective, GoalStatus};
pub use intent::{Intent, IntentStatus, NormalizedIntent, MAX_RAW_INPUT_LEN};
pub use normalizer::normalize_intent;
pub use runtime::{ChainState, Phase1Result, Phase1Runtime, RuntimeError, SubmitRequest};
pub use storage::{
    default_data_dir, AgentRegistryStore, GoalStore, IntentStore, StorageError, WorkflowStore,
};
pub use workflow::{StepDependency, StepExecutionState, Workflow, WorkflowStatus, WorkflowStep};

// Re-export contract types from agenticos-contracts
pub use agenticos_contracts::{
    ErrorCode, ErrorPayload, PrincipalContext, ProtocolVersion, ResourceRef, RetryClassification,
};
