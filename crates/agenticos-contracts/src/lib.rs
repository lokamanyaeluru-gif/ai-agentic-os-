//! Formal subsystem contracts and foundational types for AI Agentic OS.
//!
//! Aligned with ADR-0007 (Formal Contracts) and Phase 1.0 specification.

use serde::{Deserialize, Serialize};

/// Semantic protocol version representation (major.minor).
///
/// Baseline protocol version is 1.0. Minor increments indicate backward-compatible additions;
/// major increments indicate breaking changes requiring migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl ProtocolVersion {
    /// Baseline protocol version 1.0.
    pub const V1_0: Self = Self { major: 1, minor: 0 };

    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }
}

impl Default for ProtocolVersion {
    fn default() -> Self {
        Self::V1_0
    }
}

/// Principal context capturing caller identity.
///
/// In the Intent domain model, this represents provenance and user context carried with the request.
/// Transport security at the socket boundary (SO_PEERCRED) remains the authoritative verifier
/// of caller credentials; copied Intent principal data is never the ultimate security authority.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalContext {
    /// Canonical actor identifier string (e.g. "User::\"1000\"" or "Agent::\"worker\"").
    pub actor_id: String,

    /// Linux UID of the principal.
    pub uid: u32,

    /// Linux GID of the principal.
    pub gid: u32,
}

impl PrincipalContext {
    pub fn new(actor_id: impl Into<String>, uid: u32, gid: u32) -> Self {
        Self {
            actor_id: actor_id.into(),
            uid,
            gid,
        }
    }

    pub fn user(uid: u32, gid: u32) -> Self {
        Self {
            actor_id: format!("User::\"{}\"", uid),
            uid,
            gid,
        }
    }
}

/// Conceptual reference to a target resource.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceRef {
    /// Resource category/domain (e.g. "Path", "DBusService", "NetworkEndpoint", "Application").
    pub kind: String,

    /// Canonical resource identifier (e.g. file path, service name).
    pub identifier: String,
}

impl ResourceRef {
    pub fn new(kind: impl Into<String>, identifier: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            identifier: identifier.into(),
        }
    }

    pub fn path(identifier: impl Into<String>) -> Self {
        Self {
            kind: "Path".to_string(),
            identifier: identifier.into(),
        }
    }
}

/// Retry classification governed by supervisor/workflow (not client-asserted).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RetryClassification {
    /// The operation must never be retried automatically.
    Never,

    /// The operation is safe to retry on transient transport/timeout faults.
    Safe,

    /// The operation may be retried only if explicit preconditions/idempotency keys match.
    Conditional,
}

/// Standardized error classification codes per ADR-0007.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ErrorCode {
    // Client & Validation
    InvalidRequest,
    MalformedArguments,
    IncompatibleProtocolVersion,

    // Security & Policy
    PolicyDenied,
    ConfirmationRequired,
    InvalidApprovalToken,
    TokenReplayDetected,
    PeerAuthenticationFailed,

    // Execution & Sandbox
    CapabilityNotFound,
    SandboxInitializationFailed,
    CapabilityExecutionFailed,
    ResourceCeilingExceeded,

    // Lifecycle & Flow Control
    Timeout,
    Cancelled,
    DependencyFailed,
    StorageFailure,
    InternalError,
}

/// Structured error payload adhering to ADR-0007 formal contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorPayload {
    /// Standardized error classification code.
    pub code: ErrorCode,

    /// Human-readable explanation.
    pub message: String,

    /// Subsystem originating the error.
    pub source_component: String,

    /// Supervisor/workflow-governed retry classification.
    pub retry_classification: RetryClassification,

    /// Optional schema version governing structured details.
    pub details_schema_version: Option<u32>,

    /// Schema-validated structured details.
    pub details: Option<serde_json::Value>,
}

impl ErrorPayload {
    pub fn new(
        code: ErrorCode,
        message: impl Into<String>,
        source_component: impl Into<String>,
        retry_classification: RetryClassification,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            source_component: source_component.into(),
            retry_classification,
            details_schema_version: None,
            details: None,
        }
    }
}
