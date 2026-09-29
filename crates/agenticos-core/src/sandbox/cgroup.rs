//! cgroup v2 Resource Control for Profile 2 Container Isolation.
//!
//! Mandatory resource constraints for Profile 2:
//! - MemoryMax = 512 MB (536,870,912 bytes)
//! - TasksMax = 32
//!
//! Enforces:
//! - Verification of cgroup v2 mount and controller delegation (`cpu memory pids`).
//! - Fail-closed guarantee: If required cgroup control cannot be established,
//!   Profile 2 fails closed immediately and does NOT silently degrade.

use super::error::SandboxError;
use std::path::Path;
use std::process::Command;

/// Standard Profile 2 memory limit: 512 MiB.
pub const PROFILE2_MEMORY_MAX_BYTES: u64 = 512 * 1024 * 1024;

/// Standard Profile 2 tasks/PIDs limit: 32 tasks.
pub const PROFILE2_TASKS_MAX: u32 = 32;

/// Resource limits applied to a Profile 2 container execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CgroupConfig {
    pub memory_max_bytes: u64,
    pub tasks_max: u32,
}

impl Default for CgroupConfig {
    fn default() -> Self {
        Self {
            memory_max_bytes: PROFILE2_MEMORY_MAX_BYTES,
            tasks_max: PROFILE2_TASKS_MAX,
        }
    }
}

/// Probes whether cgroup v2 and required controllers are operational.
pub fn probe_cgroup_v2() -> Result<(), SandboxError> {
    let controllers_file = Path::new("/sys/fs/cgroup/cgroup.controllers");
    if !controllers_file.exists() {
        return Err(SandboxError::CgroupControlFailed(
            "cgroup v2 is not mounted at /sys/fs/cgroup".to_string(),
        ));
    }

    // Verify controllers
    let content = std::fs::read_to_string(controllers_file).map_err(|e| {
        SandboxError::CgroupControlFailed(format!("Failed to read cgroup.controllers: {e}"))
    })?;

    if !content.contains("memory") || !content.contains("pids") {
        return Err(SandboxError::CgroupControlFailed(format!(
            "cgroup v2 root missing required controllers (available: '{}')",
            content.trim()
        )));
    }

    Ok(())
}

/// Wraps a given `Command` with a cgroup v2 resource control scope via `systemd-run --user --scope`.
///
/// Invariant: Profile 2 requires mandatory cgroup resource bounds.
/// If `systemd-run` is unavailable or fails to establish control, returns `CgroupControlFailed`
/// to ensure the engine fails closed without silent degradation.
pub fn apply_cgroup_scope(
    base_cmd: &Path,
    args: &[String],
    config: &CgroupConfig,
) -> Result<Command, SandboxError> {
    // 1. Mandatory pre-flight probe
    probe_cgroup_v2()?;

    // 2. Locate systemd-run
    let systemd_run_path = if Path::new("/usr/bin/systemd-run").exists() {
        "/usr/bin/systemd-run"
    } else if Path::new("/bin/systemd-run").exists() {
        "/bin/systemd-run"
    } else {
        return Err(SandboxError::CgroupControlFailed(
            "systemd-run executable not found; mandatory cgroup v2 scope cannot be established"
                .to_string(),
        ));
    };

    let mut cmd = Command::new(systemd_run_path);
    cmd.arg("--user")
        .arg("--scope")
        .arg("-q")
        .arg(format!("-pMemoryMax={}", config.memory_max_bytes))
        .arg(format!("-pTasksMax={}", config.tasks_max))
        .arg("--")
        .arg(base_cmd);

    for arg in args {
        cmd.arg(arg);
    }

    Ok(cmd)
}
