//! Linux openat2 syscall wrapper enforcing strict workspace containment.
//!
//! Enforces `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS` to prevent directory traversal
//! escapes (`..`), mount crossings, and symlink attacks.

use super::error::SandboxError;
use std::ffi::CString;
use std::os::unix::io::RawFd;

pub const SYS_OPENAT2: libc::c_long = 437;

// Flags for open_how.resolve
pub const RESOLVE_NO_XDEV: u64 = 0x01;
pub const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
pub const RESOLVE_NO_SYMLINKS: u64 = 0x04;
pub const RESOLVE_BENEATH: u64 = 0x08;
pub const RESOLVE_IN_ROOT: u64 = 0x10;

/// Linux struct open_how passed to openat2(2).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenHow {
    pub flags: u64,
    pub mode: u64,
    pub resolve: u64,
}

/// Opens a file relative to `dirfd` using `openat2` with strict resolution boundaries.
///
/// Enforces:
/// - `RESOLVE_BENEATH`: Prevents any traversal outside the directory root (`..`, absolute components).
/// - `RESOLVE_NO_SYMLINKS`: Completely blocks traversal through symbolic links.
/// - `O_CLOEXEC`: Guarantees descriptor hygiene across exec boundaries.
pub fn openat2_beneath(dirfd: RawFd, rel_path: &str, flags: i32) -> Result<RawFd, SandboxError> {
    if rel_path.is_empty() {
        return Err(SandboxError::Openat2Failed {
            path: rel_path.to_string(),
            os_error: "Relative path cannot be empty".to_string(),
        });
    }

    if rel_path.starts_with('/') {
        return Err(SandboxError::EscapeAttempt {
            path: rel_path.to_string(),
        });
    }

    let c_path = CString::new(rel_path).map_err(|_| SandboxError::Openat2Failed {
        path: rel_path.to_string(),
        os_error: "Path contains interior null bytes".to_string(),
    })?;

    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS,
    };

    let res = unsafe {
        libc::syscall(
            SYS_OPENAT2,
            dirfd,
            c_path.as_ptr(),
            &how as *const OpenHow as *const libc::c_void,
            std::mem::size_of::<OpenHow>() as libc::size_t,
        )
    };

    if res < 0 {
        let err = std::io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(libc::EXDEV) => Err(SandboxError::EscapeAttempt {
                path: rel_path.to_string(),
            }),
            Some(libc::ELOOP) => Err(SandboxError::SymlinkTraversalBlocked {
                path: rel_path.to_string(),
            }),
            Some(libc::EACCES) | Some(libc::EPERM) => Err(SandboxError::PermissionDenied {
                path: rel_path.to_string(),
            }),
            _ => Err(SandboxError::Openat2Failed {
                path: rel_path.to_string(),
                os_error: err.to_string(),
            }),
        };
    }

    Ok(res as RawFd)
}

/// Reads the contents of a file located beneath `dirfd` up to `max_bytes`.
pub fn read_file_beneath(
    dirfd: RawFd,
    rel_path: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, SandboxError> {
    let file_fd = openat2_beneath(dirfd, rel_path, libc::O_RDONLY)?;

    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut total_read = 0;

    loop {
        let to_read = (max_bytes - total_read).min(chunk.len());
        if to_read == 0 {
            break;
        }

        let n = unsafe { libc::read(file_fd, chunk.as_mut_ptr() as *mut libc::c_void, to_read) };

        if n < 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(file_fd) };
            return Err(SandboxError::CapabilityExecutionFailed(format!(
                "Failed reading '{rel_path}': {err}"
            )));
        }

        if n == 0 {
            break;
        }

        buf.extend_from_slice(&chunk[..n as usize]);
        total_read += n as usize;
    }

    unsafe { libc::close(file_fd) };
    Ok(buf)
}

/// Helper to unlink a file or empty directory beneath `dirfd`.
fn unlink_beneath(dirfd: RawFd, rel_path: &str, is_dir: bool) -> Result<(), SandboxError> {
    let path = std::path::Path::new(rel_path);
    let (parent_fd, leaf_name) = match (path.parent(), path.file_name()) {
        (Some(parent), Some(leaf)) if !parent.as_os_str().is_empty() => {
            let parent_str = parent.to_str().ok_or_else(|| {
                SandboxError::CapabilityExecutionFailed("Path is not UTF-8".to_string())
            })?;
            let p_fd = openat2_beneath(dirfd, parent_str, libc::O_PATH | libc::O_DIRECTORY)?;
            let l_str = leaf.to_str().ok_or_else(|| {
                unsafe { libc::close(p_fd) };
                SandboxError::CapabilityExecutionFailed("Leaf name is not UTF-8".to_string())
            })?;
            (Some(p_fd), l_str)
        }
        (_, Some(leaf)) => {
            let l_str = leaf.to_str().ok_or_else(|| {
                SandboxError::CapabilityExecutionFailed("Leaf name is not UTF-8".to_string())
            })?;
            (None, l_str)
        }
        _ => {
            return Err(SandboxError::CapabilityExecutionFailed(
                "Invalid path for unlink".to_string(),
            ));
        }
    };

    let target_dirfd = parent_fd.unwrap_or(dirfd);
    let c_leaf = CString::new(leaf_name).map_err(|_| {
        if let Some(fd) = parent_fd {
            unsafe { libc::close(fd) };
        }
        SandboxError::CapabilityExecutionFailed("Leaf name contains null bytes".to_string())
    })?;

    let flags = if is_dir { libc::AT_REMOVEDIR } else { 0 };
    let res = unsafe { libc::unlinkat(target_dirfd, c_leaf.as_ptr(), flags) };

    if let Some(fd) = parent_fd {
        unsafe { libc::close(fd) };
    }

    if res < 0 {
        let err = std::io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(libc::EACCES) | Some(libc::EPERM) => Err(SandboxError::PermissionDenied {
                path: rel_path.to_string(),
            }),
            Some(libc::EXDEV) => Err(SandboxError::EscapeAttempt {
                path: rel_path.to_string(),
            }),
            Some(libc::ELOOP) => Err(SandboxError::SymlinkTraversalBlocked {
                path: rel_path.to_string(),
            }),
            _ => Err(SandboxError::CapabilityExecutionFailed(format!(
                "unlinkat failed on '{rel_path}': {err}"
            ))),
        };
    }

    Ok(())
}

/// Creates a directory beneath `dirfd` enforcing path hygiene and isolation.
pub fn create_directory_beneath(dirfd: RawFd, rel_path: &str) -> Result<(), SandboxError> {
    if rel_path.is_empty() {
        return Err(SandboxError::CapabilityExecutionFailed(
            "Relative path cannot be empty".to_string(),
        ));
    }
    if rel_path.starts_with('/') {
        return Err(SandboxError::EscapeAttempt {
            path: rel_path.to_string(),
        });
    }

    let path = std::path::Path::new(rel_path);
    for component in path.components() {
        match component {
            std::path::Component::ParentDir
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_) => {
                return Err(SandboxError::EscapeAttempt {
                    path: rel_path.to_string(),
                });
            }
            _ => {}
        }
    }

    let (parent_fd, leaf_name) = match (path.parent(), path.file_name()) {
        (Some(parent), Some(leaf)) if !parent.as_os_str().is_empty() => {
            let parent_str = parent.to_str().ok_or_else(|| {
                SandboxError::CapabilityExecutionFailed("Path is not UTF-8".to_string())
            })?;
            let p_fd = openat2_beneath(dirfd, parent_str, libc::O_PATH | libc::O_DIRECTORY)?;
            let l_str = leaf.to_str().ok_or_else(|| {
                unsafe { libc::close(p_fd) };
                SandboxError::CapabilityExecutionFailed("Leaf name is not UTF-8".to_string())
            })?;
            (Some(p_fd), l_str)
        }
        (_, Some(leaf)) => {
            let l_str = leaf.to_str().ok_or_else(|| {
                SandboxError::CapabilityExecutionFailed("Leaf name is not UTF-8".to_string())
            })?;
            (None, l_str)
        }
        _ => {
            return Err(SandboxError::CapabilityExecutionFailed(
                "Invalid path for directory creation".to_string(),
            ));
        }
    };

    let target_dirfd = parent_fd.unwrap_or(dirfd);
    let c_leaf = CString::new(leaf_name).map_err(|_| {
        if let Some(fd) = parent_fd {
            unsafe { libc::close(fd) };
        }
        SandboxError::CapabilityExecutionFailed("Leaf name contains null bytes".to_string())
    })?;

    let res = unsafe { libc::mkdirat(target_dirfd, c_leaf.as_ptr(), 0o755) };

    if let Some(fd) = parent_fd {
        unsafe { libc::close(fd) };
    }

    if res < 0 {
        let err = std::io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(libc::EACCES) | Some(libc::EPERM) => Err(SandboxError::PermissionDenied {
                path: rel_path.to_string(),
            }),
            Some(libc::EXDEV) => Err(SandboxError::EscapeAttempt {
                path: rel_path.to_string(),
            }),
            Some(libc::ELOOP) => Err(SandboxError::SymlinkTraversalBlocked {
                path: rel_path.to_string(),
            }),
            _ => Err(SandboxError::CapabilityExecutionFailed(format!(
                "mkdirat failed on '{rel_path}': {err}"
            ))),
        };
    }

    Ok(())
}

/// Recursively deletes a file or directory tree strictly beneath `dirfd`.
pub fn delete_tree_beneath(dirfd: RawFd, rel_path: &str) -> Result<(), SandboxError> {
    if rel_path.is_empty() || rel_path == "." {
        return Err(SandboxError::CapabilityExecutionFailed(
            "Cannot delete workspace root or empty path".to_string(),
        ));
    }
    if rel_path.starts_with('/') {
        return Err(SandboxError::EscapeAttempt {
            path: rel_path.to_string(),
        });
    }

    let path = std::path::Path::new(rel_path);
    for component in path.components() {
        match component {
            std::path::Component::ParentDir
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_) => {
                return Err(SandboxError::EscapeAttempt {
                    path: rel_path.to_string(),
                });
            }
            _ => {}
        }
    }

    // Step 1: Open target with openat2 to ensure strict boundary and resolve_no_symlinks
    let target_fd = openat2_beneath(dirfd, rel_path, libc::O_PATH)?;

    let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
    let stat_res = unsafe { libc::fstat(target_fd, &mut stat_buf) };
    unsafe { libc::close(target_fd) };

    if stat_res < 0 {
        let err = std::io::Error::last_os_error();
        return Err(SandboxError::CapabilityExecutionFailed(format!(
            "fstat failed on '{rel_path}': {err}"
        )));
    }

    let is_dir = (stat_buf.st_mode & libc::S_IFMT) == libc::S_IFDIR;
    if !is_dir {
        // Plain file / socket / fifo: unlink directly
        return unlink_beneath(dirfd, rel_path, false);
    }

    // Step 2: Directory recursion: open directory with O_RDONLY | O_DIRECTORY
    let dir_fd = openat2_beneath(dirfd, rel_path, libc::O_RDONLY | libc::O_DIRECTORY)?;

    let dir_stream = unsafe { libc::fdopendir(dir_fd) };
    if dir_stream.is_null() {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(dir_fd) };
        return Err(SandboxError::CapabilityExecutionFailed(format!(
            "fdopendir failed on '{rel_path}': {err}"
        )));
    }

    let mut children = Vec::new();
    loop {
        let entry = unsafe { libc::readdir(dir_stream) };
        if entry.is_null() {
            break;
        }
        let entry_name_c = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
        let entry_name = match entry_name_c.to_str() {
            Ok(s) => s,
            Err(_) => continue,
        };
        if entry_name == "." || entry_name == ".." {
            continue;
        }
        children.push(format!("{rel_path}/{entry_name}"));
    }

    unsafe { libc::closedir(dir_stream) }; // Note: closedir closes dir_fd

    for child in children {
        delete_tree_beneath(dirfd, &child)?;
    }

    // Step 3: Remove empty directory
    unlink_beneath(dirfd, rel_path, true)
}
