//! Linux Landlock LSM sandboxing primitives, ABI discovery, and ruleset builder.
//!
//! Provides strict runtime ABI discovery, errata probing, and forward-compatible
//! configuration for Linux Landlock (ABIs 1 through 7+).

use super::error::SandboxError;
use std::os::unix::io::RawFd;

// Syscall numbers on Linux x86_64
pub const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
pub const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
pub const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

// Flags for landlock_create_ruleset
pub const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1 << 0;
pub const LANDLOCK_CREATE_RULESET_ERRATA: libc::c_uint = 1 << 1;

// Rule types
pub const LANDLOCK_RULE_PATH_BENEATH: libc::c_uint = 1;

// Filesystem access rights (ABI 1)
pub const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
pub const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
pub const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
pub const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
pub const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
pub const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
pub const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
pub const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
pub const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
pub const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
pub const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
pub const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
pub const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;

// Filesystem access rights (ABI 2)
pub const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
pub const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;

// Filesystem access rights (ABI 5)
pub const LANDLOCK_ACCESS_FS_IOCTL_DEV: u64 = 1 << 15;

// Network access rights (ABI 4)
pub const LANDLOCK_ACCESS_NET_BIND_TCP: u64 = 1 << 0;
pub const LANDLOCK_ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;

// Scoped flags (ABI 6)
pub const LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
pub const LANDLOCK_SCOPE_SIGNAL: u64 = 1 << 1;

/// Minimum Landlock ABI required by AgenticOS security baseline.
pub const LANDLOCK_MIN_APPROVED_ABI: u32 = 1;

/// In-kernel Landlock ruleset attribute structure.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct LandlockRulesetAttr {
    pub handled_access_fs: u64,
    pub handled_access_net: u64,
    pub scoped: u64,
}

/// In-kernel Landlock path beneath rule attribute structure.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct LandlockPathBeneathAttr {
    pub allowed_access: u64,
    pub parent_fd: i32,
}

/// Probes the host kernel for its highest supported Landlock ABI version.
///
/// Fails closed if Landlock is unsupported (`ENOSYS`, `EOPNOTSUPP`) or disabled.
pub fn probe_landlock_abi() -> Result<u32, SandboxError> {
    let res = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<libc::c_void>(),
            0 as libc::size_t,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };

    if res < 0 {
        let err = std::io::Error::last_os_error();
        return Err(SandboxError::LandlockProbeFailed(format!(
            "landlock_create_ruleset probe failed: {err}"
        )));
    }

    let abi = res as u32;
    if abi < LANDLOCK_MIN_APPROVED_ABI {
        return Err(SandboxError::LandlockAbiUnsupported {
            discovered: abi,
            required: LANDLOCK_MIN_APPROVED_ABI,
        });
    }

    Ok(abi)
}

/// Probes the host kernel for Landlock errata bitmask if supported.
pub fn probe_landlock_errata() -> u32 {
    let res = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<libc::c_void>(),
            0 as libc::size_t,
            LANDLOCK_CREATE_RULESET_ERRATA,
        )
    };
    if res >= 0 {
        res as u32
    } else {
        0
    }
}

/// Calculates the handled filesystem access bitmask known to this build for a given ABI.
pub fn fs_access_mask_for_abi(abi: u32) -> u64 {
    if abi == 0 {
        return 0;
    }

    // ABI 1 rights (bits 0..=12)
    let mut mask = (1 << 13) - 1;

    // ABI 2+ adds REFER and TRUNCATE (bits 13..=14)
    if abi >= 2 {
        mask |= LANDLOCK_ACCESS_FS_REFER | LANDLOCK_ACCESS_FS_TRUNCATE;
    }

    // ABI 5+ adds IOCTL_DEV (bit 15)
    if abi >= 5 {
        mask |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
    }

    mask
}

/// Calculates the handled network access bitmask known to this build for a given ABI.
pub fn net_access_mask_for_abi(abi: u32) -> u64 {
    if abi >= 4 {
        LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP
    } else {
        0
    }
}

/// Calculates the handled scope isolation bitmask known to this build for a given ABI.
pub fn scope_mask_for_abi(abi: u32) -> u64 {
    if abi >= 6 {
        LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL
    } else {
        0
    }
}

/// Restricts the calling process to the given workspace directory descriptor using Landlock.
///
/// Implements the Phase 4.2 Profile 1 confinement contract:
/// 1. Probes kernel Landlock ABI version (fails closed if unavailable).
/// 2. Configures handled access rights for all known FS, Network, and Scope vectors supported by the ABI.
/// 3. Adds a `PATH_BENEATH` rule scoping allowed filesystem operations exclusively to `workspace_dirfd`.
/// 4. Enacts the restriction via `landlock_restrict_self`.
/// 5. Immediately closes the temporary ruleset descriptor.
pub fn restrict_to_workspace(workspace_dirfd: RawFd, read_only: bool) -> Result<(), SandboxError> {
    let abi = probe_landlock_abi()?;

    let handled_fs = fs_access_mask_for_abi(abi);
    let handled_net = net_access_mask_for_abi(abi);
    let handled_scope = scope_mask_for_abi(abi);

    // Size of struct passed to kernel depends on ABI feature presence
    let (attr, attr_size) = if abi >= 6 {
        (
            LandlockRulesetAttr {
                handled_access_fs: handled_fs,
                handled_access_net: handled_net,
                scoped: handled_scope,
            },
            std::mem::size_of::<LandlockRulesetAttr>(),
        )
    } else if abi >= 4 {
        (
            LandlockRulesetAttr {
                handled_access_fs: handled_fs,
                handled_access_net: handled_net,
                scoped: 0,
            },
            std::mem::size_of::<u64>() * 2, // handled_access_fs + handled_access_net
        )
    } else {
        (
            LandlockRulesetAttr {
                handled_access_fs: handled_fs,
                handled_access_net: 0,
                scoped: 0,
            },
            std::mem::size_of::<u64>(), // handled_access_fs only
        )
    };

    // 1. Create Ruleset
    let ruleset_fd = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            &attr as *const LandlockRulesetAttr as *const libc::c_void,
            attr_size as libc::size_t,
            0 as libc::c_uint,
        )
    };

    if ruleset_fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(SandboxError::LandlockRulesetCreationFailed(format!(
            "landlock_create_ruleset failed: {err}"
        )));
    }

    let ruleset_fd = ruleset_fd as RawFd;

    // 2. Add PATH_BENEATH rule for workspace directory
    let allowed_fs = if read_only {
        LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR
    } else {
        // ReadWrite: grant all supported FS rights except EXECUTE
        handled_fs & !LANDLOCK_ACCESS_FS_EXECUTE
    };

    let path_beneath = LandlockPathBeneathAttr {
        allowed_access: allowed_fs,
        parent_fd: workspace_dirfd,
    };

    let add_res = unsafe {
        libc::syscall(
            SYS_LANDLOCK_ADD_RULE,
            ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH,
            &path_beneath as *const LandlockPathBeneathAttr as *const libc::c_void,
            0 as libc::c_uint,
        )
    };

    if add_res != 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(ruleset_fd) };
        return Err(SandboxError::LandlockAddRuleFailed(format!(
            "landlock_add_rule failed: {err}"
        )));
    }

    // 3. Enforce Landlock ruleset on the calling process
    let restrict_res =
        unsafe { libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0 as libc::c_uint) };

    // 4. Immediately close ruleset descriptor to ensure clean FD hygiene
    unsafe { libc::close(ruleset_fd) };

    if restrict_res != 0 {
        let err = std::io::Error::last_os_error();
        return Err(SandboxError::LandlockRestrictSelfFailed(format!(
            "landlock_restrict_self failed: {err}"
        )));
    }

    Ok(())
}
