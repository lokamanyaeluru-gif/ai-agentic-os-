//! Profile 1 (Low-Risk ReadOnly / Workspace-Restricted) Confinement Engine.
//!
//! Orchestrates the strict, deterministic security boundary:
//! 1. `PR_SET_NO_NEW_PRIVS`
//! 2. Workspace `O_PATH` acquisition
//! 3. Landlock filesystem containment
//! 4. Seccomp-BPF system call filtering
//! 5. Pre-opened descriptor hygiene

use super::error::SandboxError;
use super::landlock::restrict_to_workspace_for_capability;
use super::openat2::openat2_beneath;
use super::seccomp::apply_profile1_seccomp;
use std::ffi::CString;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};

/// Encapsulates an active, confined workspace session.
#[derive(Debug)]
pub struct ConfinedWorkspace {
    workspace_dirfd: RawFd,
    workspace_path: PathBuf,
}

impl ConfinedWorkspace {
    /// Returns the open directory descriptor identifying the workspace root.
    pub fn dirfd(&self) -> RawFd {
        self.workspace_dirfd
    }

    /// Returns the canonical path of the confined workspace.
    pub fn path(&self) -> &Path {
        &self.workspace_path
    }

    /// Safely opens a file located strictly beneath this confined workspace.
    pub fn open_file(&self, rel_path: &str, read_only: bool) -> Result<RawFd, SandboxError> {
        let flags = if read_only {
            libc::O_RDONLY
        } else {
            libc::O_RDWR
        };
        openat2_beneath(self.workspace_dirfd, rel_path, flags)
    }

    /// Safely reads the entire contents of a file located strictly beneath this workspace.
    pub fn read_file(&self, rel_path: &str, max_bytes: usize) -> Result<Vec<u8>, SandboxError> {
        super::openat2::read_file_beneath(self.workspace_dirfd, rel_path, max_bytes)
    }

    /// Safely creates a directory located strictly beneath this workspace.
    pub fn create_directory(&self, rel_path: &str) -> Result<(), SandboxError> {
        super::openat2::create_directory_beneath(self.workspace_dirfd, rel_path)
    }

    /// Safely deletes a file or directory tree located strictly beneath this workspace.
    pub fn delete_tree(&self, rel_path: &str) -> Result<(), SandboxError> {
        super::openat2::delete_tree_beneath(self.workspace_dirfd, rel_path)
    }
}

impl Drop for ConfinedWorkspace {
    fn drop(&mut self) {
        if self.workspace_dirfd >= 0 {
            unsafe { libc::close(self.workspace_dirfd) };
            self.workspace_dirfd = -1;
        }
    }
}

/// Applies Profile 1 confinement to the calling process for a specific capability.
///
/// Execution Sequence:
/// 1. `PR_SET_NO_NEW_PRIVS`: Enforces that no subsequent exec or privilege escalation can occur.
/// 2. Resolves and opens `workspace_path` with `O_PATH | O_DIRECTORY | O_CLOEXEC`.
/// 3. Installs Landlock ruleset restricting the process to `workspace_dirfd` with least-privilege capability profile.
/// 4. Installs Seccomp-BPF filter denying `execve`, `clone`, `fork`, `socket`, etc.
/// 5. Returns `ConfinedWorkspace` for subsequent `openat2` capability operations.
pub fn enter_profile1_confinement(
    workspace_path: &Path,
    capability_id: &str,
    kill_on_seccomp_violation: bool,
) -> Result<ConfinedWorkspace, SandboxError> {
    // Step 1: Set PR_SET_NO_NEW_PRIVS immediately
    let res = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if res != 0 {
        let err = std::io::Error::last_os_error();
        return Err(SandboxError::NoNewPrivsFailed(format!(
            "prctl(PR_SET_NO_NEW_PRIVS) failed: {err}"
        )));
    }

    // Step 2: Open workspace directory with O_PATH | O_DIRECTORY | O_CLOEXEC
    let canonical_path = workspace_path.canonicalize().map_err(|e| {
        SandboxError::WorkspaceAccessFailed(format!("Canonicalization failed: {e}"))
    })?;

    let path_str = canonical_path.to_str().ok_or_else(|| {
        SandboxError::WorkspaceAccessFailed("Path is not valid UTF-8".to_string())
    })?;

    let c_path = CString::new(path_str).map_err(|_| {
        SandboxError::WorkspaceAccessFailed("Path contains interior null bytes".to_string())
    })?;

    let workspace_dirfd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };

    if workspace_dirfd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(SandboxError::WorkspaceAccessFailed(format!(
            "Failed opening workspace '{path_str}': {err}"
        )));
    }

    // Step 3: Apply Landlock filesystem containment with capability-specific allowed mask
    if let Err(e) = restrict_to_workspace_for_capability(workspace_dirfd, capability_id) {
        unsafe { libc::close(workspace_dirfd) };
        return Err(e);
    }

    // Step 4: Apply Seccomp-BPF system call filter
    if let Err(e) = apply_profile1_seccomp(kill_on_seccomp_violation) {
        unsafe { libc::close(workspace_dirfd) };
        return Err(e);
    }

    Ok(ConfinedWorkspace {
        workspace_dirfd,
        workspace_path: canonical_path,
    })
}
