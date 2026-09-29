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
pub mod sandbox;
pub mod storage;
pub mod supervisor;
pub mod workflow;

// Re-export sandbox & process isolation engine (Phase 4.2, Layer 8)
pub use sandbox::{
    apply_profile1_seccomp, build_profile1_bpf_filter, create_directory_beneath,
    delete_tree_beneath, enter_profile1_confinement, fs_access_mask_for_abi,
    net_access_mask_for_abi, openat2_beneath, probe_landlock_abi, probe_landlock_errata,
    read_file_beneath, restrict_to_workspace, restrict_to_workspace_for_capability,
    scope_mask_for_abi, ConfinedWorkspace, FsAccessProfile, LandlockPathBeneathAttr,
    LandlockRulesetAttr, OpenHow, SandboxError, SockFilter, SockFprog, AUDIT_ARCH_X86_64,
    LANDLOCK_ACCESS_FS_EXECUTE, LANDLOCK_ACCESS_FS_IOCTL_DEV, LANDLOCK_ACCESS_FS_MAKE_BLOCK,
    LANDLOCK_ACCESS_FS_MAKE_CHAR, LANDLOCK_ACCESS_FS_MAKE_DIR, LANDLOCK_ACCESS_FS_MAKE_FIFO,
    LANDLOCK_ACCESS_FS_MAKE_REG, LANDLOCK_ACCESS_FS_MAKE_SOCK, LANDLOCK_ACCESS_FS_MAKE_SYM,
    LANDLOCK_ACCESS_FS_READ_DIR, LANDLOCK_ACCESS_FS_READ_FILE, LANDLOCK_ACCESS_FS_REFER,
    LANDLOCK_ACCESS_FS_REMOVE_DIR, LANDLOCK_ACCESS_FS_REMOVE_FILE, LANDLOCK_ACCESS_FS_TRUNCATE,
    LANDLOCK_ACCESS_FS_WRITE_FILE, LANDLOCK_MIN_APPROVED_ABI, PROFILE1_ALLOWED_SYSCALLS,
    PROFILE1_CRITICAL_FORBIDDEN_SYSCALLS, PROFILE1_DENIED_SYSCALLS, RESOLVE_BENEATH,
    RESOLVE_NO_MAGICLINKS, RESOLVE_NO_SYMLINKS, RESOLVE_NO_XDEV, SECCOMP_RET_ALLOW,
    SECCOMP_RET_ERRNO, SECCOMP_RET_KILL_PROCESS,
};

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
