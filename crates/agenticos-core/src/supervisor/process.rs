//! Worker process spawning, descriptor redirection, and termination escalation.

use super::error::SupervisorError;
use super::ipc::create_seqpacket_socketpair;
use std::os::unix::io::RawFd;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Active handle held by the Supervisor governing a spawned worker process.
#[derive(Debug)]
pub struct WorkerHandle {
    pub pid: u32,
    pub instance_nonce: Uuid,
    pub supervisor_ipc_fd: RawFd,
    pub stdout_pipe_read: RawFd,
    pub stderr_pipe_read: RawFd,
}

impl Drop for WorkerHandle {
    fn drop(&mut self) {
        // Ensure open supervisor descriptors are closed on drop
        unsafe {
            if self.supervisor_ipc_fd >= 0 {
                libc::close(self.supervisor_ipc_fd);
            }
            if self.stdout_pipe_read >= 0 {
                libc::close(self.stdout_pipe_read);
            }
            if self.stderr_pipe_read >= 0 {
                libc::close(self.stderr_pipe_read);
            }
        }
    }
}

impl WorkerHandle {
    /// Closes all managed file descriptors without reaping.
    pub fn close_descriptors(&mut self) {
        unsafe {
            if self.supervisor_ipc_fd >= 0 {
                libc::close(self.supervisor_ipc_fd);
                self.supervisor_ipc_fd = -1;
            }
            if self.stdout_pipe_read >= 0 {
                libc::close(self.stdout_pipe_read);
                self.stdout_pipe_read = -1;
            }
            if self.stderr_pipe_read >= 0 {
                libc::close(self.stderr_pipe_read);
                self.stderr_pipe_read = -1;
            }
        }
    }
}

/// Atomically closes all open file descriptors from `first_fd` upward.
pub fn close_range_above(first_fd: libc::c_uint) {
    // Attempt close_range syscall
    let res = unsafe { libc::syscall(libc::SYS_close_range, first_fd, !0u32, 0) };
    if res != 0 {
        // Fallback: iterate /proc/self/fd or probe standard file descriptor ceiling
        if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
            for entry in entries.flatten() {
                if let Ok(fd) = entry.file_name().to_string_lossy().parse::<libc::c_int>() {
                    if fd >= first_fd as libc::c_int {
                        unsafe { libc::close(fd) };
                    }
                }
            }
        } else {
            for fd in first_fd..4096 {
                unsafe { libc::close(fd as libc::c_int) };
            }
        }
    }
}

/// Creates a pipe with O_CLOEXEC set on both ends.
pub fn create_pipe() -> Result<(RawFd, RawFd), std::io::Error> {
    let mut fds = [0 as RawFd; 2];
    let res = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if res != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((fds[0], fds[1]))
}

/// Spawns a worker child process executing the given child entrypoint closure.
///
/// Strictly enforces the Phase 4.0 file descriptor lifecycle:
/// - In Child:
///   - FD 0 redirected to /dev/null
///   - FD 1 redirected to stdout_pipe_write
///   - FD 2 redirected to stderr_pipe_write
///   - FD 3 redirected to worker_ipc_fd
///   - Atomically closes all FDs >= 4 via `close_range(4, ~0U, 0)`
///   - Executes `child_entry(3, instance_nonce)`
///   - Calls `libc::_exit(code)`
/// - In Supervisor:
///   - **Immediately closes** `worker_ipc_fd`, `stdout_pipe_write`, `stderr_pipe_write`
///   - Retains exclusively `supervisor_ipc_fd`, `stdout_pipe_read`, `stderr_pipe_read`
pub fn spawn_worker_process<F>(child_entry: F) -> Result<WorkerHandle, SupervisorError>
where
    F: FnOnce(RawFd, Uuid) -> i32 + Send + 'static,
{
    let instance_nonce = Uuid::new_v4();

    // 1. Allocate IPC socketpair
    let (supervisor_ipc_fd, worker_ipc_fd) = create_seqpacket_socketpair().map_err(|e| {
        SupervisorError::SpawnFailed(format!("Failed to create IPC socketpair: {e}"))
    })?;

    // 2. Allocate diagnostic stdio pipes
    let (stdout_pipe_read, stdout_pipe_write) = create_pipe()
        .map_err(|e| SupervisorError::SpawnFailed(format!("Failed to create stdout pipe: {e}")))?;
    let (stderr_pipe_read, stderr_pipe_write) = create_pipe()
        .map_err(|e| SupervisorError::SpawnFailed(format!("Failed to create stderr pipe: {e}")))?;

    // 3. Fork worker process
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let err = std::io::Error::last_os_error();
        unsafe {
            libc::close(supervisor_ipc_fd);
            libc::close(worker_ipc_fd);
            libc::close(stdout_pipe_read);
            libc::close(stdout_pipe_write);
            libc::close(stderr_pipe_read);
            libc::close(stderr_pipe_write);
        }
        return Err(SupervisorError::SpawnFailed(format!(
            "fork() failed: {err}"
        )));
    }

    if pid == 0 {
        // --- CHILD PROCESS ---
        // Step A: Redirect stdin (FD 0) to /dev/null
        let dev_null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        if dev_null >= 0 {
            unsafe {
                libc::dup2(dev_null, 0);
                if dev_null > 0 {
                    libc::close(dev_null);
                }
            }
        }

        // Step B: Redirect stdout (FD 1) and stderr (FD 2)
        unsafe {
            libc::dup2(stdout_pipe_write, 1);
            libc::dup2(stderr_pipe_write, 2);
        }

        // Step C: Redirect IPC channel to FD 3
        unsafe {
            libc::dup2(worker_ipc_fd, 3);
        }

        // Step D: Atomically close all descriptors >= 4
        close_range_above(4);

        // Step E: Execute child logic and exit
        let exit_code = child_entry(3, instance_nonce);
        unsafe { libc::_exit(exit_code) };
    }

    // --- SUPERVISOR PROCESS ---
    // Mandatory immediate closure of worker-assigned descriptors
    unsafe {
        libc::close(worker_ipc_fd);
        libc::close(stdout_pipe_write);
        libc::close(stderr_pipe_write);
    }

    Ok(WorkerHandle {
        pid: pid as u32,
        instance_nonce,
        supervisor_ipc_fd,
        stdout_pipe_read,
        stderr_pipe_read,
    })
}

/// Tuple representing child process exit status: (optional exit code, optional termination signal).
pub type ProcessExitStatus = (Option<i32>, Option<i32>);

/// Reaps a child process by PID, extracting exit code and termination signal.
pub fn reap_child_process(
    pid: u32,
    blocking: bool,
) -> Result<Option<ProcessExitStatus>, SupervisorError> {
    let mut status: libc::c_int = 0;
    let flags = if blocking { 0 } else { libc::WNOHANG };

    let res = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, flags) };
    if res < 0 {
        let err = std::io::Error::last_os_error();
        return Err(SupervisorError::CleanupFailed(format!(
            "waitpid({pid}) failed: {err}"
        )));
    }

    if res == 0 {
        // Child is still running (non-blocking call)
        return Ok(None);
    }

    // Extract exit status or signal
    let (exit_code, signal) = if libc::WIFEXITED(status) {
        (Some(libc::WEXITSTATUS(status)), None)
    } else if libc::WIFSIGNALED(status) {
        (None, Some(libc::WTERMSIG(status)))
    } else {
        (None, None)
    };

    Ok(Some((exit_code, signal)))
}

/// Escalated process termination sequence: SIGTERM -> 500ms grace -> SIGKILL -> waitpid.
pub fn terminate_escalate(
    pid: u32,
    grace_period: Duration,
) -> Result<ProcessExitStatus, SupervisorError> {
    // 1. Send SIGTERM
    let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };

    let start = Instant::now();
    let poll_interval = Duration::from_millis(10);

    // 2. Wait up to grace_period for orderly termination
    while start.elapsed() < grace_period {
        if let Some(status) = reap_child_process(pid, false)? {
            return Ok(status);
        }
        std::thread::sleep(poll_interval);
    }

    // 3. Grace period expired: Send SIGKILL
    let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };

    // 4. Blocking waitpid to reap zombie
    let status = reap_child_process(pid, true)?.ok_or_else(|| {
        SupervisorError::CleanupFailed(format!("Failed to reap child {pid} after SIGKILL"))
    })?;

    Ok(status)
}

/// Helper function to execute a standard worker execution loop inside a spawned child process.
pub fn run_worker_loop<F>(ipc_fd: RawFd, expected_nonce: Uuid, handler: F) -> i32
where
    F: FnOnce(crate::supervisor::ipc::IpcMessage) -> crate::supervisor::ipc::IpcMessage,
{
    use crate::agent::observer::LinuxProcfsObserver;
    use crate::supervisor::identity::read_process_start_time_ticks;
    use crate::supervisor::ipc::{receive_message, send_message, IpcMessage, MAX_FRAME_SIZE};
    use agenticos_contracts::ProtocolVersion;

    // 1. Receive HandshakeRequest
    let req = match receive_message(ipc_fd, MAX_FRAME_SIZE) {
        Ok(msg) => msg,
        Err(_) => return 101,
    };

    let received_nonce = match req {
        IpcMessage::HandshakeRequest { instance_nonce, .. } => instance_nonce,
        _ => return 102,
    };

    if received_nonce != expected_nonce {
        return 103;
    }

    let my_pid = std::process::id();
    let observer = LinuxProcfsObserver::default();
    let my_ticks = read_process_start_time_ticks(my_pid, &observer).unwrap_or_default();

    // 2. Send HandshakeResponse
    let resp = IpcMessage::HandshakeResponse {
        protocol_version: ProtocolVersion::V1_0,
        instance_nonce: expected_nonce,
        pid: my_pid,
        start_time_ticks: my_ticks,
    };

    if send_message(ipc_fd, &resp).is_err() {
        return 104;
    }

    // 3. Receive InvocationRequest
    let inv_req = match receive_message(ipc_fd, MAX_FRAME_SIZE) {
        Ok(msg) => msg,
        Err(_) => return 105,
    };

    // 4. Execute capability logic
    let inv_resp = handler(inv_req);

    // 5. Send InvocationResponse
    if send_message(ipc_fd, &inv_resp).is_err() {
        return 106;
    }

    0
}
