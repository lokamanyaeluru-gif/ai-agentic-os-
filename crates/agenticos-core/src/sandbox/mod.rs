//! Layer 8 Sandbox & Isolation Engine (Profile 1 Process Isolation & Profile 2 Container Isolation).
//!
//! Provides Landlock LSM access confinement, openat2 filesystem traversal prevention,
//! Seccomp-BPF system call filtering, Bubblewrap namespace isolation, and cgroup v2 resource control.

pub mod bwrap;
pub mod cgroup;
pub mod confinement;
pub mod container;
pub mod error;
pub mod landlock;
pub mod openat2;
pub mod seccomp;
pub mod worker;

pub use bwrap::{
    find_approved_bubblewrap, BubblewrapBinary, BubblewrapCommandBuilder, BubblewrapVersion,
    BWRAP_MIN_APPROVED_VERSION,
};
pub use cgroup::{probe_cgroup_v2, CgroupConfig, PROFILE2_MEMORY_MAX_BYTES, PROFILE2_TASKS_MAX};
pub use confinement::{enter_profile1_confinement, ConfinedWorkspace};
pub use container::{find_worker_binary, spawn_container_worker_process, ContainerConfig};
pub use error::SandboxError;
pub use landlock::{
    fs_access_mask_for_abi, net_access_mask_for_abi, probe_landlock_abi, probe_landlock_errata,
    restrict_to_workspace, restrict_to_workspace_for_capability, scope_mask_for_abi,
    FsAccessProfile, LandlockPathBeneathAttr, LandlockRulesetAttr, LANDLOCK_ACCESS_FS_EXECUTE,
    LANDLOCK_ACCESS_FS_IOCTL_DEV, LANDLOCK_ACCESS_FS_MAKE_BLOCK, LANDLOCK_ACCESS_FS_MAKE_CHAR,
    LANDLOCK_ACCESS_FS_MAKE_DIR, LANDLOCK_ACCESS_FS_MAKE_FIFO, LANDLOCK_ACCESS_FS_MAKE_REG,
    LANDLOCK_ACCESS_FS_MAKE_SOCK, LANDLOCK_ACCESS_FS_MAKE_SYM, LANDLOCK_ACCESS_FS_READ_DIR,
    LANDLOCK_ACCESS_FS_READ_FILE, LANDLOCK_ACCESS_FS_REFER, LANDLOCK_ACCESS_FS_REMOVE_DIR,
    LANDLOCK_ACCESS_FS_REMOVE_FILE, LANDLOCK_ACCESS_FS_TRUNCATE, LANDLOCK_ACCESS_FS_WRITE_FILE,
    LANDLOCK_MIN_APPROVED_ABI,
};
pub use openat2::{
    create_directory_beneath, delete_tree_beneath, openat2_beneath, read_file_beneath, OpenHow,
    RESOLVE_BENEATH, RESOLVE_NO_MAGICLINKS, RESOLVE_NO_SYMLINKS, RESOLVE_NO_XDEV,
};
pub use seccomp::{
    apply_profile1_seccomp, build_profile1_bpf_filter, SockFilter, SockFprog, AUDIT_ARCH_X86_64,
    PROFILE1_ALLOWED_SYSCALLS, PROFILE1_CRITICAL_FORBIDDEN_SYSCALLS, PROFILE1_DENIED_SYSCALLS,
    SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO, SECCOMP_RET_KILL_PROCESS,
};
pub use worker::{run_profile1_worker, run_profile2_worker};
