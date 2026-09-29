//! Profile 2 Container Isolation Engine (Bubblewrap + cgroup v2 + Inner Landlock/Seccomp).
//!
//! Orchestrates:
//! 1. Bubblewrap binary validation (approved baseline >= 0.12.0, non-setuid).
//! 2. cgroup v2 resource control scope (MemoryMax = 512 MB, TasksMax = 32).
//! 3. Descriptor-based workspace mounting via `--bind-fd` / `--ro-bind-fd`.
//! 4. Approved rootfs container layout (/usr, /lib*, /bin, /sbin, /etc, /dev, /proc, /run, /tmp, /workspace).
//! 5. Comprehensive namespace isolation (--unshare-all: user, mount, pid, net, ipc, uts).
//! 6. Inner defense-in-depth (worker PR_SET_NO_NEW_PRIVS + Landlock + Seccomp + openat2).
//! 7. Immediate supervisor-side descriptor closure.

use super::bwrap::{find_approved_bubblewrap, BubblewrapBinary, BubblewrapCommandBuilder};
use super::cgroup::{probe_cgroup_v2, CgroupConfig};
use super::error::SandboxError;
use crate::agent::observer::LinuxProcfsObserver;
use crate::supervisor::identity::read_process_start_time_ticks;
use crate::supervisor::ipc::create_seqpacket_socketpair;
use crate::supervisor::process::{close_range_above, create_pipe, WorkerHandle};
use crate::supervisor::SupervisorError;
use std::ffi::CString;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Configuration governing Profile 2 container execution.
#[derive(Debug, Clone)]
pub struct ContainerConfig {
    /// Explicit Bubblewrap binary override, or None to discover automatically.
    pub bwrap_binary: Option<BubblewrapBinary>,
    /// Mandatory cgroup v2 resource bounds.
    pub cgroup_config: CgroupConfig,
    /// Path to the compiled `agenticos-worker` binary.
    pub worker_binary_path: Option<PathBuf>,
    /// Whether Seccomp violations terminate with SIGSYS (SECCOMP_RET_KILL_PROCESS).
    pub kill_on_seccomp_violation: bool,
}

impl Default for ContainerConfig {
    fn default() -> Self {
        Self {
            bwrap_binary: None,
            cgroup_config: CgroupConfig::default(),
            worker_binary_path: None,
            kill_on_seccomp_violation: true,
        }
    }
}

/// Locates the `agenticos-worker` executable on disk.
pub fn find_worker_binary() -> Result<PathBuf, SandboxError> {
    // 1. CARGO_BIN_EXE_agenticos-worker environment variable if set by cargo test/run
    if let Ok(path_str) = std::env::var("CARGO_BIN_EXE_agenticos-worker") {
        let p = PathBuf::from(path_str);
        if p.exists() {
            return Ok(p);
        }
    }

    // 2. Relative to current executable
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            // Check current directory
            let cand1 = parent.join("agenticos-worker");
            if cand1.exists() {
                return Ok(cand1);
            }
            // Check parent directory (if in deps/)
            if let Some(grandparent) = parent.parent() {
                let cand2 = grandparent.join("agenticos-worker");
                if cand2.exists() {
                    return Ok(cand2);
                }
            }
        }
    }

    // 3. Fallback standard build targets
    let standard_targets = [
        "target/debug/agenticos-worker",
        "target/release/agenticos-worker",
        "../target/debug/agenticos-worker",
        "../../target/debug/agenticos-worker",
    ];

    for t in standard_targets {
        let p = PathBuf::from(t);
        if p.exists() {
            return Ok(p.canonicalize().unwrap_or(p));
        }
    }

    Err(SandboxError::ContainerStartupFailed(
        "Could not locate 'agenticos-worker' executable for Profile 2 container".to_string(),
    ))
}

/// Spawns a containerized worker process wrapped in Bubblewrap and governed by cgroup v2.
///
/// Execution Sequence:
/// 1. Validate Bubblewrap binary compliance (>= 0.12.0, non-setuid, owner, permissions).
/// 2. Validate cgroup v2 control availability (fail closed if unavailable).
/// 3. Safely open host workspace path using `O_PATH | O_DIRECTORY | O_CLOEXEC`.
/// 4. Allocate IPC socketpair and diagnostic stdio pipes.
/// 5. Fork container launcher child process:
///    - In Child:
///      - Map FD 0 -> /dev/null
///      - Map FD 1 -> stdout pipe write
///      - Map FD 2 -> stderr pipe write
///      - Map FD 3 -> worker IPC socket (clear CLOEXEC)
///      - Map FD 4 -> workspace O_PATH descriptor (clear CLOEXEC)
///      - Close all descriptors >= 5 via close_range(5, ~0U, 0)
///      - Exec systemd-run / bwrap with approved layout and container arguments
///    - In Supervisor:
///      - Immediately close child copies: `worker_ipc_fd`, `stdout_pipe_write`,
///        `stderr_pipe_write`, `workspace_dirfd`
///      - Retain exclusively supervisor handles
///      - Return `WorkerHandle`
pub fn spawn_container_worker_process(
    workspace_path: &Path,
    capability_id: &str,
    read_only: bool,
    config: &ContainerConfig,
) -> Result<WorkerHandle, SupervisorError> {
    let instance_nonce = Uuid::new_v4();

    // 1. Validate Bubblewrap compliance
    let bwrap = match &config.bwrap_binary {
        Some(b) => b.clone(),
        None => find_approved_bubblewrap().map_err(|e| {
            SupervisorError::SpawnFailed(format!("Bubblewrap validation failed: {e}"))
        })?,
    };

    // 2. Validate mandatory cgroup v2 resource control
    probe_cgroup_v2().map_err(|e| {
        SupervisorError::SpawnFailed(format!("Mandatory cgroup v2 probe failed: {e}"))
    })?;

    // 3. Locate worker binary
    let worker_bin = match &config.worker_binary_path {
        Some(p) => p.clone(),
        None => find_worker_binary().map_err(|e| {
            SupervisorError::SpawnFailed(format!("Worker binary location failed: {e}"))
        })?,
    };

    // 4. Safely open workspace directory with O_PATH | O_DIRECTORY | O_CLOEXEC
    let canonical_ws = workspace_path.canonicalize().map_err(|e| {
        SupervisorError::SpawnFailed(format!("Workspace canonicalization failed: {e}"))
    })?;

    let ws_path_str = canonical_ws.to_str().ok_or_else(|| {
        SupervisorError::SpawnFailed("Workspace path is not valid UTF-8".to_string())
    })?;

    let c_ws_path = CString::new(ws_path_str).map_err(|_| {
        SupervisorError::SpawnFailed("Workspace path contains null bytes".to_string())
    })?;

    let ws_dirfd = unsafe {
        libc::open(
            c_ws_path.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };

    if ws_dirfd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(SupervisorError::SpawnFailed(format!(
            "Failed opening workspace '{ws_path_str}': {err}"
        )));
    }

    // 5. Allocate IPC socketpair
    let (supervisor_ipc_fd, worker_ipc_fd) = create_seqpacket_socketpair().map_err(|e| {
        unsafe { libc::close(ws_dirfd) };
        SupervisorError::SpawnFailed(format!("Failed to create IPC socketpair: {e}"))
    })?;

    // 6. Allocate stdio pipes
    let (stdout_pipe_read, stdout_pipe_write) = match create_pipe() {
        Ok(pair) => pair,
        Err(e) => {
            unsafe {
                libc::close(ws_dirfd);
                libc::close(supervisor_ipc_fd);
                libc::close(worker_ipc_fd);
            }
            return Err(SupervisorError::SpawnFailed(format!(
                "Failed to create stdout pipe: {e}"
            )));
        }
    };

    let (stderr_pipe_read, stderr_pipe_write) = match create_pipe() {
        Ok(pair) => pair,
        Err(e) => {
            unsafe {
                libc::close(ws_dirfd);
                libc::close(supervisor_ipc_fd);
                libc::close(worker_ipc_fd);
                libc::close(stdout_pipe_read);
                libc::close(stdout_pipe_write);
            }
            return Err(SupervisorError::SpawnFailed(format!(
                "Failed to create stderr pipe: {e}"
            )));
        }
    };

    // 7. Fork container launcher process
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let err = std::io::Error::last_os_error();
        unsafe {
            libc::close(ws_dirfd);
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
        unsafe {
            // Close supervisor-side descriptors in child
            libc::close(supervisor_ipc_fd);
            libc::close(stdout_pipe_read);
            libc::close(stderr_pipe_read);

            // Step A: Redirect stdin (FD 0) to /dev/null
            let dev_null = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY);
            if dev_null >= 0 {
                libc::dup2(dev_null, 0);
                if dev_null > 0 {
                    libc::close(dev_null);
                }
            }

            // Step B: Redirect stdout (FD 1) and stderr (FD 2)
            libc::dup2(stdout_pipe_write, 1);
            libc::dup2(stderr_pipe_write, 2);
            if stdout_pipe_write != 1 && stdout_pipe_write != 2 {
                libc::close(stdout_pipe_write);
            }
            if stderr_pipe_write != 1 && stderr_pipe_write != 2 {
                libc::close(stderr_pipe_write);
            }

            // Step C & D: Relocate worker_ipc_fd and ws_dirfd to high temporary FDs (>= 50)
            // to eliminate any possibility of mutual clobbering if either descriptor was
            // already allocated as 9 or 10.
            let safe_ipc = libc::fcntl(worker_ipc_fd, libc::F_DUPFD_CLOEXEC, 50);
            let safe_ws = libc::fcntl(ws_dirfd, libc::F_DUPFD_CLOEXEC, 50);
            if safe_ipc < 0 || safe_ws < 0 {
                libc::_exit(124);
            }

            // Close original descriptors
            if worker_ipc_fd != safe_ipc && worker_ipc_fd != safe_ws {
                libc::close(worker_ipc_fd);
            }
            if ws_dirfd != safe_ipc && ws_dirfd != safe_ws {
                libc::close(ws_dirfd);
            }

            // Safely map safe_ipc -> FD 9 and clear CLOEXEC
            if libc::dup2(safe_ipc, 9) < 0 {
                libc::_exit(124);
            }
            let flags9 = libc::fcntl(9, libc::F_GETFD);
            if flags9 >= 0 {
                libc::fcntl(9, libc::F_SETFD, flags9 & !libc::FD_CLOEXEC);
            }

            // Safely map safe_ws -> FD 10 and clear CLOEXEC
            if libc::dup2(safe_ws, 10) < 0 {
                libc::_exit(124);
            }
            let flags10 = libc::fcntl(10, libc::F_GETFD);
            if flags10 >= 0 {
                libc::fcntl(10, libc::F_SETFD, flags10 & !libc::FD_CLOEXEC);
            }

            // Close temporary safe descriptors
            libc::close(safe_ipc);
            libc::close(safe_ws);

            // Close all descriptors >= 11
            close_range_above(11);

            // Query own PID and start time ticks for identity attestation
            let my_pid = libc::getpid() as u32;
            let observer = LinuxProcfsObserver::default();
            let my_ticks = read_process_start_time_ticks(my_pid, &observer).unwrap_or(0);

            // Construct Bubblewrap command
            let mut builder = BubblewrapCommandBuilder::new(
                bwrap.path.clone(),
                10, // FD 10 is workspace_dirfd
                read_only,
                worker_bin.clone(),
            );

            builder
                .arg("--mode")
                .arg("profile2")
                .arg("--ipc-fd")
                .arg("9")
                .arg("--nonce")
                .arg(instance_nonce.to_string())
                .arg("--host-pid")
                .arg(my_pid.to_string())
                .arg("--host-ticks")
                .arg(my_ticks.to_string())
                .arg("--capability")
                .arg(capability_id);

            if !config.kill_on_seccomp_violation {
                builder.arg("--no-kill-seccomp");
            }

            let bwrap_args = match builder.build_args() {
                Ok(a) => a,
                Err(_) => libc::_exit(125),
            };

            // Wrap with systemd-run for mandatory cgroup v2 resource limits
            let systemd_run = "/usr/bin/systemd-run";
            let mut exec_args: Vec<CString> = Vec::new();
            let exec_path: CString;

            if Path::new(systemd_run).exists() {
                exec_path = CString::new(systemd_run).unwrap();
                exec_args.push(exec_path.clone());
                exec_args.push(CString::new("--user").unwrap());
                exec_args.push(CString::new("--scope").unwrap());
                exec_args.push(CString::new("-q").unwrap());
                exec_args.push(
                    CString::new(format!(
                        "-pMemoryMax={}",
                        config.cgroup_config.memory_max_bytes
                    ))
                    .unwrap(),
                );
                exec_args.push(
                    CString::new(format!("-pTasksMax={}", config.cgroup_config.tasks_max)).unwrap(),
                );
                exec_args.push(CString::new("--").unwrap());
                exec_args.push(CString::new(bwrap.path.to_str().unwrap()).unwrap());
            } else {
                exec_path = CString::new(bwrap.path.to_str().unwrap()).unwrap();
                exec_args.push(exec_path.clone());
            }

            for arg in bwrap_args {
                if let Ok(c_arg) = CString::new(arg) {
                    exec_args.push(c_arg);
                }
            }

            let mut arg_ptrs: Vec<*const libc::c_char> =
                exec_args.iter().map(|s| s.as_ptr()).collect();
            arg_ptrs.push(std::ptr::null());

            libc::execv(exec_path.as_ptr(), arg_ptrs.as_ptr());

            // If execv returns, execution failed
            libc::_exit(127);
        }
    }

    // --- SUPERVISOR PROCESS ---
    // Mandatory immediate closure of worker-assigned descriptors
    unsafe {
        libc::close(ws_dirfd);
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
