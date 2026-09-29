//! Supervisor error taxonomy adhering to ADR-0007 formal contract.

use agenticos_contracts::{ErrorCode, ErrorPayload, RetryClassification};
use thiserror::Error;

/// Formal error taxonomy for Layer 7 CapabilitySupervisor operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SupervisorError {
    /// Worker process failed to spawn at the OS level.
    #[error("Worker spawn failed: {0}")]
    SpawnFailed(String),

    /// Worker handshake failed (nonce mismatch, protocol mismatch, etc.).
    #[error("Worker handshake failed: {0}")]
    HandshakeFailed(String),

    /// IPC framing or transport failure across the Unix socketpair.
    #[error("IPC transport failure: {0}")]
    IpcFailed(String),

    /// Execution timed out exceeding the supervisor wall-clock limit.
    #[error("Worker execution timed out: elapsed {elapsed_ms}ms exceeded limit {limit_ms}ms")]
    Timeout { elapsed_ms: u64, limit_ms: u64 },

    /// Worker exited abnormally without protocol completion.
    #[error("Worker exited abnormally with code {exit_code:?}, signal {signal:?}")]
    AbnormalExit {
        exit_code: Option<i32>,
        signal: Option<i32>,
    },

    /// Worker was terminated by an unhandled OS signal.
    #[error("Worker terminated by signal: {0}")]
    SignalTermination(i32),

    /// Worker violated the framing or message sequencing protocol.
    #[error("Protocol violation: {0}")]
    ProtocolViolation(String),

    /// Worker credentials (SO_PEERCRED, PID, start_time_ticks) did not match expectations.
    #[error("Worker identity mismatch: {0}")]
    IdentityMismatch(String),

    /// Cleanup or reaping failed following worker termination.
    #[error("Worker cleanup failed: {0}")]
    CleanupFailed(String),

    /// Execution was cooperatively cancelled prior to or during execution.
    #[error("Worker execution was cancelled")]
    Cancelled,
}

impl SupervisorError {
    /// Maps the supervisor error into an ADR-0007 formal ErrorPayload.
    pub fn to_error_payload(&self) -> ErrorPayload {
        match self {
            Self::SpawnFailed(msg) => ErrorPayload::new(
                ErrorCode::SandboxInitializationFailed,
                msg.clone(),
                "CapabilitySupervisor",
                RetryClassification::Safe,
            ),
            Self::HandshakeFailed(msg) => ErrorPayload::new(
                ErrorCode::PeerAuthenticationFailed,
                msg.clone(),
                "CapabilitySupervisor",
                RetryClassification::Never,
            ),
            Self::IpcFailed(msg) => ErrorPayload::new(
                ErrorCode::InternalError,
                msg.clone(),
                "CapabilitySupervisor",
                RetryClassification::Safe,
            ),
            Self::Timeout {
                elapsed_ms,
                limit_ms,
            } => ErrorPayload::new(
                ErrorCode::Timeout,
                format!("Wall-clock execution limit exceeded: {elapsed_ms}ms >= {limit_ms}ms"),
                "CapabilitySupervisor",
                RetryClassification::Conditional,
            ),
            Self::AbnormalExit { exit_code, signal } => ErrorPayload::new(
                ErrorCode::CapabilityExecutionFailed,
                format!("Process exited unexpectedly (code: {exit_code:?}, signal: {signal:?})"),
                "CapabilitySupervisor",
                RetryClassification::Never,
            ),
            Self::SignalTermination(sig) => ErrorPayload::new(
                ErrorCode::CapabilityExecutionFailed,
                format!("Process terminated by signal {sig}"),
                "CapabilitySupervisor",
                RetryClassification::Never,
            ),
            Self::ProtocolViolation(msg) => ErrorPayload::new(
                ErrorCode::IncompatibleProtocolVersion,
                msg.clone(),
                "CapabilitySupervisor",
                RetryClassification::Never,
            ),
            Self::IdentityMismatch(msg) => ErrorPayload::new(
                ErrorCode::PeerAuthenticationFailed,
                msg.clone(),
                "CapabilitySupervisor",
                RetryClassification::Never,
            ),
            Self::CleanupFailed(msg) => ErrorPayload::new(
                ErrorCode::InternalError,
                msg.clone(),
                "CapabilitySupervisor",
                RetryClassification::Never,
            ),
            Self::Cancelled => ErrorPayload::new(
                ErrorCode::Cancelled,
                "Execution cancelled by caller",
                "CapabilitySupervisor",
                RetryClassification::Never,
            ),
        }
    }
}
