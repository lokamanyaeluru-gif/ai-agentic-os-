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
