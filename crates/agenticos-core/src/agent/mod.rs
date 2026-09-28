//! Layer 5: Global Agent Manager domain models and contracts.
//!
//! Aligned with Phase 2.0 specification, ADR-0002, ADR-0006, and ADR-0007.

pub mod assignment;
pub mod health;
pub mod identity;
pub mod lifecycle;
pub mod machine;
pub mod manager;
pub mod monitor;
pub mod observer;
pub mod policy;
pub mod recovery;

pub use assignment::{AssignmentId, AssignmentStatus, WorkAssignment};
pub use health::{AgentHealthState, AgentResourceMetrics, HeartbeatRecord};
pub use identity::{AgentId, AgentRecord, AgentScope, AgentType, AgentVersion, ProcessIdentity};
pub use lifecycle::AgentLifecycleState;
pub use machine::{AgentLifecycleEngine, AgentLifecycleError};
pub use manager::{
    AgentManagerError, AssignmentRequest, DefaultHealthEvaluator, DegradedEligibility,
    GlobalAgentManager, HealthEvaluator, ManagerConfig,
};
pub use monitor::HeartbeatMonitor;
pub use observer::{
    DefaultProcessObserver, LinuxProcfsObserver, MockProcessObserver, ProcessLiveness,
    ProcessObserver, UnknownProcessObserver,
};
pub use policy::RestartPolicy;
pub use recovery::{
    AgentFailureReason, AgentRecoveryOutcome, AssignmentFailureReason, ReconciliationReport,
};
