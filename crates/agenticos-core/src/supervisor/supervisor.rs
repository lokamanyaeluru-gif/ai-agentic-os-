//! Persistent Layer 7 CapabilitySupervisor orchestrating worker execution.

use super::error::SupervisorError;
use super::identity::verify_worker_identity;
use super::ipc::{
    receive_message, send_message, IpcMessage, DEFAULT_MAX_OUTPUT_SIZE, MAX_FRAME_SIZE,
};
use super::lifecycle::{WorkerExecutionRecord, WorkerFailureReason, WorkerLifecycleState};
use super::process::{spawn_worker_process, terminate_escalate};
use super::ring_buffer::RollingLogBuffer;
use crate::agent::observer::LinuxProcfsObserver;
use crate::agent::AssignmentId;
use crate::capability::ExecutionStatus;
use crate::dispatch::{DispatchOutcome, DispatchRecord};
use agenticos_contracts::ProtocolVersion;
use std::os::unix::io::RawFd;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Operational configuration for CapabilitySupervisor.
#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    pub default_timeout: Duration,
    pub max_timeout: Duration,
    pub grace_period: Duration,
    pub max_frame_bytes: usize,
    pub max_output_bytes: usize,
    pub log_buffer_capacity: usize,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            default_timeout: Duration::from_secs(30),
            max_timeout: Duration::from_secs(300),
            grace_period: Duration::from_millis(500),
            max_frame_bytes: MAX_FRAME_SIZE,
            max_output_bytes: DEFAULT_MAX_OUTPUT_SIZE,
            log_buffer_capacity: 64 * 1024,
        }
    }
}

/// Helper to set a descriptor to non-blocking mode.
fn set_nonblocking(fd: RawFd) -> Result<(), std::io::Error> {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Drains all available and EOF bytes from a pipe into the rolling buffer.
fn drain_pipe_to_eof(fd: RawFd, log: &mut RollingLogBuffer) {
    let mut buf = [0u8; 4096];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n > 0 {
            log.push(&buf[..n as usize]);
        } else if n == 0 {
            break;
        } else {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
    }
}

/// Persistent Layer 7 CapabilitySupervisor.
///
/// Orchestrates out-of-process worker lifecycle, bidirectional IPC framing,
/// identity verification, diagnostic stdio capture, and timeout escalation.
#[derive(Debug, Clone)]
pub struct CapabilitySupervisor {
    config: SupervisorConfig,
    proc_observer: LinuxProcfsObserver,
}

impl Default for CapabilitySupervisor {
    fn default() -> Self {
        Self::new(SupervisorConfig::default(), LinuxProcfsObserver::default())
    }
}

impl CapabilitySupervisor {
    /// Creates a new CapabilitySupervisor with the given configuration and observer.
    pub fn new(config: SupervisorConfig, proc_observer: LinuxProcfsObserver) -> Self {
        Self {
            config,
            proc_observer,
        }
    }

    /// Accessor for configuration.
    pub fn config(&self) -> &SupervisorConfig {
        &self.config
    }

    /// Executes a sandboxed worker closure through the complete supervisor lifecycle.
    ///
    /// Lifecycle progression:
    /// 1. Spawn worker child process with isolated stdio and IPC socket.
    /// 2. Close worker-assigned descriptors in Supervisor immediately.
    /// 3. Exchange and verify ProtocolVersion, 128-bit instance_nonce, and SO_PEERCRED.
    /// 4. Verify PID and start_time_ticks against host /proc/[pid]/stat.
    /// 5. Monitor execution with wall-clock timeout and drain stdout/stderr rolling buffers.
    /// 6. Collect final execution response and reap zombie cleanly.
    pub fn execute_worker<F>(
        &self,
        execution_id: Uuid,
        dispatch_id: Uuid,
        assignment_id: AssignmentId,
        timeout: Option<Duration>,
        child_entry: F,
    ) -> Result<WorkerExecutionRecord, SupervisorError>
    where
        F: FnOnce(RawFd, Uuid) -> i32 + Send + 'static,
    {
        self.execute_worker_with_request(
            execution_id,
            dispatch_id,
            assignment_id,
            "stub.execute".to_string(),
            serde_json::json!({}),
            timeout,
            child_entry,
        )
    }

    /// Executes a worker process with explicit capability ID and invocation arguments.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_worker_with_request<F>(
        &self,
        execution_id: Uuid,
        dispatch_id: Uuid,
        assignment_id: AssignmentId,
        capability_id: String,
        arguments: serde_json::Value,
        timeout: Option<Duration>,
        child_entry: F,
    ) -> Result<WorkerExecutionRecord, SupervisorError>
    where
        F: FnOnce(RawFd, Uuid) -> i32 + Send + 'static,
    {
        let wall_clock_limit = timeout
            .unwrap_or(self.config.default_timeout)
            .min(self.config.max_timeout);

        let start_time = Instant::now();

        // Step 1: Spawn worker process
        let handle = spawn_worker_process(child_entry)?;
        let child_pid = handle.pid;
        let expected_nonce = handle.instance_nonce;

        // Step 2: Set stdout/stderr pipe read ends to non-blocking for polling
        let _ = set_nonblocking(handle.stdout_pipe_read);
        let _ = set_nonblocking(handle.stderr_pipe_read);

        let mut stdout_log = RollingLogBuffer::new(self.config.log_buffer_capacity);
        let mut stderr_log = RollingLogBuffer::new(self.config.log_buffer_capacity);

        // Step 3: Perform Handshake & Identity Verification
        // Send HandshakeRequest
        let handshake_req = IpcMessage::HandshakeRequest {
            protocol_version: ProtocolVersion::V1_0,
            instance_nonce: expected_nonce,
        };

        if let Err(e) = send_message(handle.supervisor_ipc_fd, &handshake_req) {
            let (code, sig) = terminate_escalate(child_pid, self.config.grace_period)?;
            drain_pipe_to_eof(handle.stdout_pipe_read, &mut stdout_log);
            drain_pipe_to_eof(handle.stderr_pipe_read, &mut stderr_log);
            let reason = if sig.is_some() {
                WorkerFailureReason::SignalTermination
            } else if code.is_some() && code != Some(0) {
                WorkerFailureReason::AbnormalExit
            } else {
                WorkerFailureReason::IpcFailure
            };
            return Ok(WorkerExecutionRecord::failure(
                execution_id,
                dispatch_id,
                assignment_id,
                child_pid,
                0,
                expected_nonce,
                WorkerLifecycleState::Failed,
                reason,
                code,
                sig,
                stdout_log.as_bytes(),
                stderr_log.as_bytes(),
                start_time.elapsed().as_millis() as u64,
                Some(SupervisorError::IpcFailed(e.to_string()).to_error_payload()),
            ));
        }

        // Receive HandshakeResponse
        let handshake_resp =
            match receive_message(handle.supervisor_ipc_fd, self.config.max_frame_bytes) {
                Ok(msg) => msg,
                Err(e) => {
                    let (code, sig) = terminate_escalate(child_pid, self.config.grace_period)?;
                    let reason = if sig.is_some() {
                        WorkerFailureReason::SignalTermination
                    } else if code.is_some() && code != Some(0) {
                        WorkerFailureReason::AbnormalExit
                    } else {
                        WorkerFailureReason::HandshakeFailure
                    };
                    return Ok(WorkerExecutionRecord::failure(
                        execution_id,
                        dispatch_id,
                        assignment_id,
                        child_pid,
                        0,
                        expected_nonce,
                        WorkerLifecycleState::Failed,
                        reason,
                        code,
                        sig,
                        stdout_log.as_bytes(),
                        stderr_log.as_bytes(),
                        start_time.elapsed().as_millis() as u64,
                        Some(SupervisorError::HandshakeFailed(e.to_string()).to_error_payload()),
                    ));
                }
            };

        // Verify identity attributes
        let verified_ticks = match verify_worker_identity(
            handle.supervisor_ipc_fd,
            child_pid,
            expected_nonce,
            &handshake_resp,
            &self.proc_observer,
        ) {
            Ok(ticks) => ticks,
            Err(err) => {
                let (code, sig) = terminate_escalate(child_pid, self.config.grace_period)?;
                return Ok(WorkerExecutionRecord::failure(
                    execution_id,
                    dispatch_id,
                    assignment_id,
                    child_pid,
                    0,
                    expected_nonce,
                    WorkerLifecycleState::Failed,
                    WorkerFailureReason::IdentityMismatch,
                    code,
                    sig,
                    stdout_log.as_bytes(),
                    stderr_log.as_bytes(),
                    start_time.elapsed().as_millis() as u64,
                    Some(err.to_error_payload()),
                ));
            }
        };

        // Step 4: Dispatch Invocation Request
        let invocation_req = IpcMessage::InvocationRequest {
            dispatch_id,
            capability_id,
            arguments,
        };

        if let Err(e) = send_message(handle.supervisor_ipc_fd, &invocation_req) {
            let (code, sig) = terminate_escalate(child_pid, self.config.grace_period)?;
            drain_pipe_to_eof(handle.stdout_pipe_read, &mut stdout_log);
            drain_pipe_to_eof(handle.stderr_pipe_read, &mut stderr_log);
            let reason = if sig.is_some() {
                WorkerFailureReason::SignalTermination
            } else if code.is_some() && code != Some(0) {
                WorkerFailureReason::AbnormalExit
            } else {
                WorkerFailureReason::IpcFailure
            };
            return Ok(WorkerExecutionRecord::failure(
                execution_id,
                dispatch_id,
                assignment_id,
                child_pid,
                verified_ticks,
                expected_nonce,
                WorkerLifecycleState::Failed,
                reason,
                code,
                sig,
                stdout_log.as_bytes(),
                stderr_log.as_bytes(),
                start_time.elapsed().as_millis() as u64,
                Some(SupervisorError::IpcFailed(e.to_string()).to_error_payload()),
            ));
        }

        // Step 5: Multiplexed polling loop with timeout monitoring
        let mut read_buf = [0u8; 4096];
        let mut invocation_response: Option<IpcMessage> = None;
        let mut stdout_open = true;
        let mut stderr_open = true;

        while start_time.elapsed() < wall_clock_limit {
            let mut fds = [
                libc::pollfd {
                    fd: handle.supervisor_ipc_fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: if stdout_open {
                        handle.stdout_pipe_read
                    } else {
                        -1
                    },
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: if stderr_open {
                        handle.stderr_pipe_read
                    } else {
                        -1
                    },
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];

            let timeout_ms = 50.min(
                wall_clock_limit
                    .saturating_sub(start_time.elapsed())
                    .as_millis() as i32,
            );

            let ret =
                unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };

            if ret < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }

            // Drain stdout if data available
            if fds[1].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                loop {
                    let n = unsafe {
                        libc::read(
                            handle.stdout_pipe_read,
                            read_buf.as_mut_ptr() as *mut libc::c_void,
                            read_buf.len(),
                        )
                    };
                    if n > 0 {
                        stdout_log.push(&read_buf[..n as usize]);
                    } else if n == 0 {
                        stdout_open = false;
                        break;
                    } else {
                        break;
                    }
                }
            }

            // Drain stderr if data available
            if fds[2].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                loop {
                    let n = unsafe {
                        libc::read(
                            handle.stderr_pipe_read,
                            read_buf.as_mut_ptr() as *mut libc::c_void,
                            read_buf.len(),
                        )
                    };
                    if n > 0 {
                        stderr_log.push(&read_buf[..n as usize]);
                    } else if n == 0 {
                        stderr_open = false;
                        break;
                    } else {
                        break;
                    }
                }
            }

            // Read IPC message if available
            if fds[0].revents & libc::POLLIN != 0 {
                match receive_message(handle.supervisor_ipc_fd, self.config.max_output_bytes) {
                    Ok(msg) => {
                        invocation_response = Some(msg);
                        break;
                    }
                    Err(e) => {
                        let (code, sig) = terminate_escalate(child_pid, self.config.grace_period)?;
                        return Ok(WorkerExecutionRecord::failure(
                            execution_id,
                            dispatch_id,
                            assignment_id,
                            child_pid,
                            verified_ticks,
                            expected_nonce,
                            WorkerLifecycleState::Failed,
                            WorkerFailureReason::ProtocolViolation,
                            code,
                            sig,
                            stdout_log.as_bytes(),
                            stderr_log.as_bytes(),
                            start_time.elapsed().as_millis() as u64,
                            Some(
                                SupervisorError::ProtocolViolation(e.to_string())
                                    .to_error_payload(),
                            ),
                        ));
                    }
                }
            }

            // If IPC hung up before delivering response, break to handle abnormal exit
            if fds[0].revents & libc::POLLHUP != 0 {
                break;
            }
        }

        // Drain any remaining stdout/stderr bytes
        if stdout_open {
            loop {
                let n = unsafe {
                    libc::read(
                        handle.stdout_pipe_read,
                        read_buf.as_mut_ptr() as *mut libc::c_void,
                        read_buf.len(),
                    )
                };
                if n > 0 {
                    stdout_log.push(&read_buf[..n as usize]);
                } else {
                    break;
                }
            }
        }
        if stderr_open {
            loop {
                let n = unsafe {
                    libc::read(
                        handle.stderr_pipe_read,
                        read_buf.as_mut_ptr() as *mut libc::c_void,
                        read_buf.len(),
                    )
                };
                if n > 0 {
                    stderr_log.push(&read_buf[..n as usize]);
                } else {
                    break;
                }
            }
        }

        let elapsed = start_time.elapsed();

        // Step 6: Handle Response, Timeout, or Abnormal Exit
        if let Some(msg) = invocation_response {
            match msg {
                IpcMessage::InvocationResponse { status, error, .. } => {
                    let (exit_code, sig) = terminate_escalate(child_pid, self.config.grace_period)?;
                    drain_pipe_to_eof(handle.stdout_pipe_read, &mut stdout_log);
                    drain_pipe_to_eof(handle.stderr_pipe_read, &mut stderr_log);
                    let final_state = match status {
                        ExecutionStatus::Success => WorkerLifecycleState::Completed,
                        ExecutionStatus::Cancelled => WorkerLifecycleState::Cancelled,
                        _ => WorkerLifecycleState::Failed,
                    };
                    let failure_reason = if final_state.is_failure() {
                        Some(WorkerFailureReason::AbnormalExit)
                    } else {
                        None
                    };

                    Ok(WorkerExecutionRecord {
                        execution_id,
                        dispatch_id,
                        assignment_id,
                        pid: child_pid,
                        start_time_ticks: verified_ticks,
                        instance_nonce: expected_nonce,
                        lifecycle_state: final_state,
                        failure_reason,
                        exit_code,
                        termination_signal: sig,
                        stdout_capture: stdout_log.as_bytes(),
                        stderr_capture: stderr_log.as_bytes(),
                        duration_ms: elapsed.as_millis() as u64,
                        error,
                    })
                }
                other => {
                    let (exit_code, sig) = terminate_escalate(child_pid, self.config.grace_period)?;
                    drain_pipe_to_eof(handle.stdout_pipe_read, &mut stdout_log);
                    drain_pipe_to_eof(handle.stderr_pipe_read, &mut stderr_log);
                    Ok(WorkerExecutionRecord::failure(
                        execution_id,
                        dispatch_id,
                        assignment_id,
                        child_pid,
                        verified_ticks,
                        expected_nonce,
                        WorkerLifecycleState::Failed,
                        WorkerFailureReason::ProtocolViolation,
                        exit_code,
                        sig,
                        stdout_log.as_bytes(),
                        stderr_log.as_bytes(),
                        elapsed.as_millis() as u64,
                        Some(
                            SupervisorError::ProtocolViolation(format!(
                                "Unexpected IPC message: {:?}",
                                other
                            ))
                            .to_error_payload(),
                        ),
                    ))
                }
            }
        } else if elapsed >= wall_clock_limit {
            // Timeout expired
            let (exit_code, sig) = terminate_escalate(child_pid, self.config.grace_period)?;
            drain_pipe_to_eof(handle.stdout_pipe_read, &mut stdout_log);
            drain_pipe_to_eof(handle.stderr_pipe_read, &mut stderr_log);
            Ok(WorkerExecutionRecord::failure(
                execution_id,
                dispatch_id,
                assignment_id,
                child_pid,
                verified_ticks,
                expected_nonce,
                WorkerLifecycleState::TimedOut,
                WorkerFailureReason::Timeout,
                exit_code,
                sig,
                stdout_log.as_bytes(),
                stderr_log.as_bytes(),
                elapsed.as_millis() as u64,
                Some(
                    SupervisorError::Timeout {
                        elapsed_ms: elapsed.as_millis() as u64,
                        limit_ms: wall_clock_limit.as_millis() as u64,
                    }
                    .to_error_payload(),
                ),
            ))
        } else {
            // Abnormal child exit / crash
            let (exit_code, sig) = terminate_escalate(child_pid, self.config.grace_period)?;
            drain_pipe_to_eof(handle.stdout_pipe_read, &mut stdout_log);
            drain_pipe_to_eof(handle.stderr_pipe_read, &mut stderr_log);
            let reason = if sig.is_some() {
                WorkerFailureReason::SignalTermination
            } else {
                WorkerFailureReason::AbnormalExit
            };
            Ok(WorkerExecutionRecord::failure(
                execution_id,
                dispatch_id,
                assignment_id,
                child_pid,
                verified_ticks,
                expected_nonce,
                WorkerLifecycleState::Failed,
                reason,
                exit_code,
                sig,
                stdout_log.as_bytes(),
                stderr_log.as_bytes(),
                elapsed.as_millis() as u64,
                Some(
                    SupervisorError::AbnormalExit {
                        exit_code,
                        signal: sig,
                    }
                    .to_error_payload(),
                ),
            ))
        }
    }

    /// Executes a sandboxed worker associated with a terminal planned DispatchRecord.
    ///
    /// Validates that the record has outcome `DispatchOutcome::Planned` and binds the
    /// worker execution to the dispatch and assignment lineage.
    pub fn execute_dispatch_worker<F>(
        &self,
        dispatch: &DispatchRecord,
        timeout: Option<Duration>,
        child_entry: F,
    ) -> Result<WorkerExecutionRecord, SupervisorError>
    where
        F: FnOnce(RawFd, Uuid) -> i32 + Send + 'static,
    {
        if dispatch.outcome != DispatchOutcome::Planned {
            return Err(SupervisorError::ProtocolViolation(format!(
                "Cannot execute worker for non-Planned dispatch record: {:?}",
                dispatch.outcome
            )));
        }

        let execution_id = Uuid::new_v4();
        self.execute_worker(
            execution_id,
            dispatch.dispatch_id,
            dispatch.assignment_id,
            timeout,
            child_entry,
        )
    }
}
