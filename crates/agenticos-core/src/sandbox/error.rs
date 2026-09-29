//! Sandbox and isolation error taxonomy.

use agenticos_contracts::{ErrorCode, ErrorPayload, RetryClassification};
use thiserror::Error;

/// Formal error taxonomy for Layer 8 Sandbox & Isolation operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SandboxError {
    /// PR_SET_NO_NEW_PRIVS failed to activate.
    #[error("Failed to enable PR_SET_NO_NEW_PRIVS: {0}")]
    NoNewPrivsFailed(String),

    /// Landlock is unsupported or ABI version is insufficient.
    #[error(
        "Landlock unsupported or ABI too old: discovered ABI {discovered}, required ABI {required}"
    )]
    LandlockAbiUnsupported { discovered: u32, required: u32 },

    /// Probing Landlock ABI failed at the kernel syscall level.
    #[error("Landlock ABI discovery probe failed: {0}")]
    LandlockProbeFailed(String),

    /// Landlock ruleset creation failed.
    #[error("Landlock ruleset creation failed: {0}")]
    LandlockRulesetCreationFailed(String),

    /// Adding Landlock rule failed.
    #[error("Landlock add rule failed: {0}")]
    LandlockAddRuleFailed(String),

    /// Restricting process credentials with Landlock ruleset failed.
    #[error("Landlock self restriction failed: {0}")]
    LandlockRestrictSelfFailed(String),

    /// Opening target path with openat2 failed.
    #[error("openat2 failed on path '{path}': {os_error}")]
    Openat2Failed { path: String, os_error: String },

    /// openat2 blocked a path traversal / escape attempt outside the workspace boundary (EXDEV).
    #[error("Path traversal escape attempt blocked on '{path}' (EXDEV)")]
    EscapeAttempt { path: String },

    /// openat2 blocked symlink resolution due to RESOLVE_NO_SYMLINKS (ELOOP).
    #[error("Symlink traversal blocked on '{path}' (ELOOP)")]
    SymlinkTraversalBlocked { path: String },

    /// Access denied by Landlock or filesystem permissions (EACCES/EPERM).
    #[error("Permission denied on path '{path}'")]
    PermissionDenied { path: String },

    /// Failed to compile or construct the Seccomp-BPF filter program.
    #[error("Seccomp filter construction failed: {0}")]
    SeccompFilterBuildFailed(String),

    /// Failed to install Seccomp filter into the kernel.
    #[error("Seccomp filter installation failed: {0}")]
    SeccompInstallationFailed(String),

    /// Failed to obtain workspace directory handle.
    #[error("Workspace path access failed: {0}")]
    WorkspaceAccessFailed(String),

    /// Capability invocation within sandbox failed.
    #[error("Capability invocation failed: {0}")]
    CapabilityExecutionFailed(String),

    /// Bubblewrap binary was not found at specified or probed locations.
    #[error("Bubblewrap executable not found: {0}")]
    BubblewrapNotFound(String),

    /// Bubblewrap binary is non-compliant with AgenticOS security baseline.
    #[error("Bubblewrap non-compliant with security baseline: {0}")]
    BubblewrapNonCompliant(String),

    /// Bubblewrap process execution failed.
    #[error("Bubblewrap execution failed: {0}")]
    BubblewrapExecutionFailed(String),

    /// Cgroup v2 resource control setup failed.
    #[error("Cgroup v2 resource control failed: {0}")]
    CgroupControlFailed(String),

    /// Container startup failed.
    #[error("Container startup failed: {0}")]
    ContainerStartupFailed(String),
}

impl SandboxError {
    /// Maps the sandbox error into an ADR-0007 formal ErrorPayload.
    pub fn to_error_payload(&self) -> ErrorPayload {
        match self {
            Self::NoNewPrivsFailed(_)
            | Self::LandlockAbiUnsupported { .. }
            | Self::LandlockProbeFailed(_)
            | Self::LandlockRulesetCreationFailed(_)
            | Self::LandlockAddRuleFailed(_)
            | Self::LandlockRestrictSelfFailed(_)
            | Self::SeccompFilterBuildFailed(_)
            | Self::SeccompInstallationFailed(_)
            | Self::BubblewrapNotFound(_)
            | Self::BubblewrapNonCompliant(_)
            | Self::BubblewrapExecutionFailed(_)
            | Self::CgroupControlFailed(_)
            | Self::ContainerStartupFailed(_) => ErrorPayload::new(
                ErrorCode::SandboxInitializationFailed,
                self.to_string(),
                "SandboxEngine",
                RetryClassification::Never,
            ),
            Self::EscapeAttempt { .. } | Self::SymlinkTraversalBlocked { .. } => ErrorPayload::new(
                ErrorCode::CapabilityExecutionFailed,
                self.to_string(),
                "SandboxEngine",
                RetryClassification::Never,
            ),
            Self::PermissionDenied { .. } => ErrorPayload::new(
                ErrorCode::PolicyDenied,
                self.to_string(),
                "SandboxEngine",
                RetryClassification::Never,
            ),
            Self::Openat2Failed { .. } | Self::WorkspaceAccessFailed(_) => ErrorPayload::new(
                ErrorCode::CapabilityExecutionFailed,
                self.to_string(),
                "SandboxEngine",
                RetryClassification::Safe,
            ),
            Self::CapabilityExecutionFailed(msg) => ErrorPayload::new(
                ErrorCode::CapabilityExecutionFailed,
                msg.clone(),
                "SandboxEngine",
                RetryClassification::Never,
            ),
        }
    }
}
