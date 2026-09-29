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
pub mod capability;
pub mod dispatch;
pub mod error;
pub mod execution;
pub mod goal;
pub mod intent;
pub mod normalizer;
pub mod policy;
pub mod runtime;
pub mod storage;
pub mod supervisor;
pub mod workflow;

// Re-export supervisor foundations (Phase 4.1, Layer 7)
pub use supervisor::{
    close_range_above, create_pipe, create_seqpacket_socketpair, get_peer_credentials, read_frame,
    read_process_start_time_ticks, reap_child_process, receive_message, run_worker_loop,
    send_message, spawn_worker_process, terminate_escalate, verify_worker_identity, write_frame,
    CapabilitySupervisor, IpcError, IpcMessage, RollingLogBuffer, SupervisorConfig,
    SupervisorError, WorkerExecutionRecord, WorkerFailureReason, WorkerHandle,
    WorkerLifecycleState, DEFAULT_LOG_BUFFER_CAPACITY, DEFAULT_MAX_OUTPUT_SIZE, MAX_FRAME_SIZE,
};

// Re-export agent domain models (Phase 2)
pub use agent::{
    AgentFailureReason, AgentHealthState, AgentId, AgentLifecycleEngine, AgentLifecycleError,
    AgentLifecycleState, AgentManagerError, AgentRecord, AgentRecoveryOutcome,
    AgentResourceMetrics, AgentScope, AgentType, AgentVersion, AssignmentFailureReason,
    AssignmentId, AssignmentRequest, AssignmentStatus, DefaultHealthEvaluator,
    DefaultProcessObserver, DegradedEligibility, GlobalAgentManager, HealthEvaluator,
    HeartbeatMonitor, HeartbeatRecord, LinuxProcfsObserver, ManagerConfig, MockProcessObserver,
    ProcessIdentity, ProcessLiveness, ProcessObserver, ReconciliationReport, RestartPolicy,
    UnknownProcessObserver, WorkAssignment,
};

// Re-export policy evaluation plane (Phase 3.1, Layer 8)
pub use policy::{
    compute_request_hash, sha256_hex, ApprovalSubject, ApprovalToken, ApprovalTokenSignedPayload,
    CapabilityInvocationRequest, PolicyAuditRecord, PolicyBundleSource, PolicyDecision,
    PolicyEngine, PolicyError, PolicySnapshot, PolicyTier, SandboxConstraints,
    ENGINE_MAX_TIMEOUT_MS, MAX_CONFIRMATION_TOKEN_TTL_MS, POLICY_SCHEMA_SRC,
};

// Re-export capability boundary plane (Phase 3.2, Layer 9)
pub use capability::{
    bind, build_plan, evaluate_conditions, fixture_bundle_manifests, fixture_create_directory,
    fixture_delete_tree, fixture_read_file, validate, Atomicity, BwrapArgv, CancelSignal,
    CapabilityError, CapabilityManifest, CapabilityRegistry, Ceilings, CheckExpr, ConditionResult,
    CrashShape, DecisionRef, EscalationPolicy, ExecArg, ExecPlan, ExecutionReport, ExecutionStatus,
    FdPlan, FileMeta, FilesystemView, InvocationBinding, LandlockRights, LandlockRule,
    ManifestBundle, MemView, MountEntry, MountMode, MountSource, ResolvedConstraints, RestartShape,
    RiskTier, SandboxConstructionPlan, SandboxProfile, SeccompData, StdioPlan, SupervisionShape,
    TimeoutSpec, UnshareSet, VerificationRef, VerificationResult, WorkerBoundary,
};

// Re-export dispatch consumer plane (Phase 3.3, Layer 6)
pub use dispatch::{
    never_cancel, CancelFlag, ConfirmationChallenge, DispatchError, DispatchOutcome,
    DispatchRecord, Dispatcher,
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
