//! Layer 5: Global Agent Manager domain models and contracts.
//!
//! Aligned with Phase 2.0 specification, ADR-0002, ADR-0006, and ADR-0007.

pub mod assignment;
pub mod health;
pub mod identity;
pub mod lifecycle;
pub mod policy;

pub use assignment::{AssignmentId, AssignmentStatus, WorkAssignment};
pub use health::{AgentHealthState, AgentResourceMetrics, HeartbeatRecord};
pub use identity::{AgentId, AgentRecord, AgentScope, AgentType, AgentVersion, ProcessIdentity};
pub use lifecycle::AgentLifecycleState;
pub use policy::RestartPolicy;
