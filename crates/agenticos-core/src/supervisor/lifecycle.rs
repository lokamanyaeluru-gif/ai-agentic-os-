//! Worker lifecycle states and ephemeral execution records.

use crate::agent::AssignmentId;
use agenticos_contracts::ErrorPayload;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Monotonic lifecycle states of an ephemeral capability worker execution instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum WorkerLifecycleState {
    /// Process has been created at OS level with assigned PID.
    Spawned,

    /// Initial IPC protocol handshake and identity validation in progress.
    Handshaking,

    /// Handshake completed; capability execution payload dispatched and running.
    Running,

    /// Capability execution finished with a successful result.
    Completed,

    /// Capability execution failed or returned an execution error.
    Failed,

    /// Wall-clock execution timeout expired before completion.
    TimedOut,

    /// Execution was cancelled cooperatively by caller.
    Cancelled,

    /// Process was terminated via signal (SIGTERM or SIGKILL).
    Terminated,

    /// Process zombie has been reaped via waitid/waitpid.
    Reaped,
}

impl WorkerLifecycleState {
    /// Returns true if the state is terminal (execution cannot transition further).
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed
                | Self::Failed
                | Self::TimedOut
                | Self::Cancelled
                | Self::Terminated
                | Self::Reaped
        )
    }

    /// Returns true if the state indicates a failure condition.
    pub fn is_failure(&self) -> bool {
        matches!(self, Self::Failed | Self::TimedOut | Self::Terminated)
    }
}

/// Standardized failure classification for worker execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WorkerFailureReason {
    /// OS-level failure creating the child process or pipes.
    SpawnFailure,

    /// Protocol handshake, nonce exchange, or version mismatch.
    HandshakeFailure,

    /// Unix domain socket read/write/framing transport error.
    IpcFailure,

    /// Exceeded maximum wall-clock execution duration.
    Timeout,

    /// Non-zero exit code or sudden process exit before protocol completion.
    AbnormalExit,

    /// Terminated by an unhandled OS signal.
    SignalTermination,

    /// Message serialization, schema violation, or invalid sequencing.
    ProtocolViolation,

    /// SO_PEERCRED, PID, or start_time_ticks verification failure.
    IdentityMismatch,

    /// Process reaping or resource cleanup error.
    CleanupFailure,
}

/// Ephemeral record capturing a complete sandboxed worker execution instance.
///
/// Binds worker OS identity (PID, start_time_ticks, instance_nonce) to Layer 6
/// dispatch and Layer 5 assignment records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerExecutionRecord {
    /// Unique identifier for this specific execution attempt.
    pub execution_id: Uuid,

    /// Associated Layer 6 dispatch identifier.
    pub dispatch_id: Uuid,

    /// Associated Layer 5 work assignment identifier.
    pub assignment_id: AssignmentId,

    /// OS process identifier of the worker child.
    pub pid: u32,

    /// Boot ticks timestamp of child creation from /proc/[pid]/stat.
    pub start_time_ticks: u64,

    /// Ephemeral 128-bit instance nonce generated before fork.
    pub instance_nonce: Uuid,

    /// Final lifecycle state attained.
    pub lifecycle_state: WorkerLifecycleState,

    /// Failure classification if execution did not complete cleanly.
    pub failure_reason: Option<WorkerFailureReason>,

    /// Exit status code returned by the process if it exited voluntarily.
    pub exit_code: Option<i32>,

    /// Signal that caused termination if terminated by an OS signal.
    pub termination_signal: Option<i32>,

    /// Captured stdout bytes (bounded by rolling ring buffer, up to 64 KiB).
    pub stdout_capture: Vec<u8>,

    /// Captured stderr bytes (bounded by rolling ring buffer, up to 64 KiB).
    pub stderr_capture: Vec<u8>,

    /// Total execution duration in milliseconds.
    pub duration_ms: u64,

    /// Structured error details if a failure occurred.
    pub error: Option<ErrorPayload>,
}

impl WorkerExecutionRecord {
    /// Creates a new execution record representing a successful completion.
    #[allow(clippy::too_many_arguments)]
    pub fn success(
        execution_id: Uuid,
        dispatch_id: Uuid,
        assignment_id: AssignmentId,
        pid: u32,
        start_time_ticks: u64,
        instance_nonce: Uuid,
        stdout_capture: Vec<u8>,
        stderr_capture: Vec<u8>,
        duration_ms: u64,
    ) -> Self {
        Self {
            execution_id,
            dispatch_id,
            assignment_id,
            pid,
            start_time_ticks,
            instance_nonce,
            lifecycle_state: WorkerLifecycleState::Completed,
            failure_reason: None,
            exit_code: Some(0),
            termination_signal: None,
            stdout_capture,
            stderr_capture,
            duration_ms,
            error: None,
        }
    }

    /// Creates an execution record representing a failure.
    #[allow(clippy::too_many_arguments)]
    pub fn failure(
        execution_id: Uuid,
        dispatch_id: Uuid,
        assignment_id: AssignmentId,
        pid: u32,
        start_time_ticks: u64,
        instance_nonce: Uuid,
        state: WorkerLifecycleState,
        reason: WorkerFailureReason,
        exit_code: Option<i32>,
        termination_signal: Option<i32>,
        stdout_capture: Vec<u8>,
        stderr_capture: Vec<u8>,
        duration_ms: u64,
        error: Option<ErrorPayload>,
    ) -> Self {
        Self {
            execution_id,
            dispatch_id,
            assignment_id,
            pid,
            start_time_ticks,
            instance_nonce,
            lifecycle_state: state,
            failure_reason: Some(reason),
            exit_code,
            termination_signal,
            stdout_capture,
            stderr_capture,
            duration_ms,
            error,
        }
    }
}
