//! Formal identity and persistent domain model for agents in Layer 5 (Global Agent Manager).
//!
//! Aligned with Phase 2.0 specification, ADR-0002, ADR-0006, and ADR-0007.

use std::collections::BTreeSet;
use std::fmt;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use agenticos_contracts::{PrincipalContext, ProtocolVersion};

use crate::error::DomainError;
use super::lifecycle::AgentLifecycleState;
use super::policy::RestartPolicy;

/// Unique identifier for an agent instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AgentId(pub Uuid);

impl AgentId {
    /// Generates a fresh random `AgentId`.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Wraps an existing UUID into an `AgentId`.
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Returns the underlying UUID.
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for AgentId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Categorical classification of the agent.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum AgentType {
    /// System built-in agent type (e.g., "FileAgent", "MonitorAgent").
    Builtin(String),
    /// User or extension-defined specialized agent.
    Custom(String),
}

impl AgentType {
    /// Validates the agent type string (non-empty, no null bytes, reasonable length ceiling).
    pub fn validate(&self) -> Result<(), DomainError> {
        let name = match self {
            Self::Builtin(s) | Self::Custom(s) => s,
        };

        if name.trim().is_empty() {
            return Err(DomainError::InvalidAgentRecord {
                reason: "Agent type name cannot be empty",
            });
        }

        if name.contains('\0') {
            return Err(DomainError::InvalidAgentRecord {
                reason: "Agent type name cannot contain null bytes",
            });
        }

        if name.len() > 256 {
            return Err(DomainError::InvalidAgentRecord {
                reason: "Agent type name exceeds maximum length ceiling (256 bytes)",
            });
        }

        Ok(())
    }

    /// Returns the string representation of the agent type.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Builtin(s) | Self::Custom(s) => s.as_str(),
        }
    }
}

impl fmt::Display for AgentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Builtin(s) => write!(f, "builtin:{}", s),
            Self::Custom(s) => write!(f, "custom:{}", s),
        }
    }
}

/// Semantic version of the agent specification and implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl AgentVersion {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl Default for AgentVersion {
    fn default() -> Self {
        Self::new(1, 0, 0)
    }
}

impl fmt::Display for AgentVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Authorization and visibility scope of an agent instance.
///
/// Determines which principals may be served by this agent instance.
/// Note: Agent ownership (`owner`) represents provenance, whereas `scope` represents
/// execution eligibility.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum AgentScope {
    /// Dedicated to a single originating principal.
    Private(PrincipalContext),

    /// Available to any authenticated principal within the current local user session.
    SharedSession,

    /// System-wide shared agent accessible to authorized principals via policy.
    SystemWide,
}

impl AgentScope {
    /// Evaluates whether an originating principal is within the local structural scope of this agent.
    ///
    /// # ARCHITECTURAL SECURITY BOUNDARY (CRITICAL)
    /// - This method encodes **only local structural scope semantics** for candidate selection.
    /// - It is **NOT an authorization engine** and must **NOT become a replacement for Cedar policy**.
    /// - It does **NOT bypass Security Governor policy**.
    /// - Passing this scope check merely indicates that the agent instance is eligible to be
    ///   considered for assignment; every capability invocation by the assigned agent remains
    ///   subject to mandatory Cedar PBAC evaluation at the Layer 8 capability execution boundary.
    pub fn authorizes(&self, principal: &PrincipalContext) -> bool {
        match self {
            Self::Private(owner) => {
                owner.actor_id == principal.actor_id && owner.uid == principal.uid
            }
            Self::SharedSession => {
                // Shared within the local session: structurally accessible to callers in session
                true
            }
            Self::SystemWide => {
                // System-wide agents can serve any caller structurally; actual authorization
                // is strictly evaluated by Cedar policy in the Security Governor.
                true
            }
        }
    }
}

/// Host process identity disambiguation data.
///
/// Disambiguation uses the tuple `(pid, start_time_ticks, instance_nonce)` to distinguish
/// local process instances within an OS boot session and detect stale registrations across crashes.
///
/// # Architectural Boundary (CRITICAL)
/// - This tuple is strictly an **instance-disambiguation and lifecycle tracking data structure**.
/// - It is **NOT an authentication or attestation primitive**.
/// - Agent process authenticity is established by the approved IPC registration/handshake
///   mechanism and kernel-enforced peer credential verification from ADR-0002 (`SO_PEERCRED`
///   over local Unix Domain Sockets or private descriptor inheritance via `socketpair(2)`).
/// - The `instance_nonce` is a manager-issued token that identifies the manager-approved
///   instance session; it does NOT by itself authenticate an arbitrary connecting process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    /// Host OS process ID (ephemeral, assigned by OS).
    pub pid: Option<u32>,

    /// Process start time in clock ticks since system boot from `/proc/[pid]/stat` (field 22, starttime).
    /// Used by the manager to detect whether a PID has been recycled by the OS during a crash.
    pub start_time_ticks: Option<u64>,

    /// Manager-issued instance nonce identifying this approved agent instance session.
    pub instance_nonce: Uuid,

    /// Effective user ID owning the agent process.
    pub uid: u32,

    /// Effective group ID owning the agent process.
    pub gid: u32,

    /// Wall-clock timestamp (ms, UTC) when process was spawned.
    pub process_started_at_ms: Option<u64>,
}

impl ProcessIdentity {
    /// Constructs process identity for a registered agent that has not yet been spawned.
    pub fn unspawned(uid: u32, gid: u32) -> Self {
        Self {
            pid: None,
            start_time_ticks: None,
            instance_nonce: Uuid::new_v4(),
            uid,
            gid,
            process_started_at_ms: None,
        }
    }

    /// Constructs process identity for an actively running agent process.
    pub fn active(
        pid: u32,
        start_time_ticks: u64,
        instance_nonce: Uuid,
        uid: u32,
        gid: u32,
        process_started_at_ms: u64,
    ) -> Self {
        Self {
            pid: Some(pid),
            start_time_ticks: Some(start_time_ticks),
            instance_nonce,
            uid,
            gid,
            process_started_at_ms: Some(process_started_at_ms),
        }
    }

    /// Returns true if the process identity represents an actively spawned process.
    pub fn is_spawned(&self) -> bool {
        self.pid.is_some() && self.start_time_ticks.is_some()
    }
}

/// Authoritative persistent domain model for a registered agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRecord {
    /// Unique agent instance ID.
    pub agent_id: AgentId,

    /// Categorical classification of the agent.
    pub agent_type: AgentType,

    /// Implementation version of the agent.
    pub agent_version: AgentVersion,

    /// IPC communication protocol version supported by the agent.
    pub protocol_version: ProtocolVersion,

    /// Attested principal asserting ownership/registration authority (provenance).
    pub owner: PrincipalContext,

    /// Authorization scope governing which principals may be served by this agent.
    pub scope: AgentScope,

    /// Set of canonical capability identifiers this agent is qualified to execute.
    /// Example: `["fs.create_directory", "fs.read_file"]`.
    pub declared_capabilities: BTreeSet<String>,

    /// Host OS process identity tracking with PID recycling protection.
    pub process_identity: ProcessIdentity,

    /// Authoritative lifecycle state machine state.
    pub state: AgentLifecycleState,

    /// Policy governing automatic failure recovery and restart.
    pub restart_policy: RestartPolicy,

    /// Timestamp (ms since Unix epoch, UTC) when registration occurred.
    pub registered_at_ms: u64,

    /// Timestamp (ms since Unix epoch, UTC) of last authoritative state update.
    pub updated_at_ms: u64,
}

impl AgentRecord {
    /// Creates and validates a new `AgentRecord` in the `Registered` state.
    pub fn new(
        agent_type: AgentType,
        agent_version: AgentVersion,
        protocol_version: ProtocolVersion,
        owner: PrincipalContext,
        scope: AgentScope,
        declared_capabilities: BTreeSet<String>,
        restart_policy: RestartPolicy,
        registered_at_ms: u64,
    ) -> Result<Self, DomainError> {
        agent_type.validate()?;

        if declared_capabilities.is_empty() {
            return Err(DomainError::InvalidAgentRecord {
                reason: "Agent must declare at least one capability",
            });
        }

        for cap in &declared_capabilities {
            if cap.trim().is_empty() {
                return Err(DomainError::InvalidAgentRecord {
                    reason: "Declared capability identifier cannot be empty",
                });
            }
            if cap.contains('\0') {
                return Err(DomainError::InvalidAgentRecord {
                    reason: "Declared capability identifier cannot contain null bytes",
                });
            }
        }

        let process_identity = ProcessIdentity::unspawned(owner.uid, owner.gid);

        Ok(Self {
            agent_id: AgentId::new(),
            agent_type,
            agent_version,
            protocol_version,
            owner,
            scope,
            declared_capabilities,
            process_identity,
            state: AgentLifecycleState::Registered,
            restart_policy,
            registered_at_ms,
            updated_at_ms: registered_at_ms,
        })
    }

    /// Transitions the agent to a new lifecycle state.
    ///
    /// Rejects invalid transitions and mutations from terminal states.
    pub fn transition(
        &mut self,
        next: AgentLifecycleState,
        updated_at_ms: u64,
    ) -> Result<(), DomainError> {
        self.state.transition_to(next)?;
        self.updated_at_ms = updated_at_ms;
        Ok(())
    }

    /// Re-arms a terminal agent (`Stopped` or `Failed`) via explicit restart action.
    ///
    /// Evaluates restart policy, increments the retry counter, resets process identity
    /// with a fresh instance nonce, and advances state to `Starting`.
    pub fn restart(
        &mut self,
        next_instance_nonce: Uuid,
        restarted_at_ms: u64,
    ) -> Result<(), DomainError> {
        if !self.state.is_terminal() {
            return Err(DomainError::InvalidAgentRecord {
                reason: "Cannot restart an agent that is not in a terminal state (Stopped or Failed)",
            });
        }

        self.restart_policy.record_restart()?;

        self.process_identity = ProcessIdentity {
            pid: None,
            start_time_ticks: None,
            instance_nonce: next_instance_nonce,
            uid: self.owner.uid,
            gid: self.owner.gid,
            process_started_at_ms: None,
        };

        self.state = AgentLifecycleState::Starting;
        self.updated_at_ms = restarted_at_ms;
        Ok(())
    }
}
