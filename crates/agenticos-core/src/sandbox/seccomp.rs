//! Linux Seccomp-BPF system call filtering for Profile 1 workers.
//!
//! Enforces:
//! - Architecture validation (`AUDIT_ARCH_X86_64`)
//! - Explicit denial of process creation (`fork`, `vfork`, `clone`, `clone3`, `execve`, `execveat`)
//! - Explicit denial of network creation (`socket`, `connect`, `bind`, `listen`, `accept`, `accept4`)
//! - Explicit denial of debugging, container escape, and kernel attack vectors (`ptrace`, `bpf`, `kexec_load`, etc.)
//! - Strict allowlist derived empirically from the compiled Rust worker runtime
//! - Configurable default action (`SECCOMP_RET_KILL_PROCESS` or `SECCOMP_RET_ERRNO(EPERM)`)

use super::error::SandboxError;

pub const SYS_SECCOMP: libc::c_long = 317;
pub const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;

pub const AUDIT_ARCH_X86_64: u32 = 0xc000003e;

// BPF opcodes and classes
pub const BPF_LD: u16 = 0x00;
pub const BPF_W: u16 = 0x00;
pub const BPF_ABS: u16 = 0x20;
pub const BPF_JMP: u16 = 0x05;
pub const BPF_JEQ: u16 = 0x10;
pub const BPF_K: u16 = 0x00;
pub const BPF_RET: u16 = 0x06;

// Seccomp return actions
pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;
pub const SECCOMP_RET_TRAP: u32 = 0x00030000;
pub const SECCOMP_RET_ERRNO: u32 = 0x00050000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;

/// Classical BPF instruction filter block.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

/// BPF program header passed to `seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog)`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SockFprog {
    pub len: u16,
    pub filter: *const SockFilter,
}

/// Explicit list of security-critical forbidden syscalls for Profile 1 capability workers.
///
/// Any attempt to invoke these syscalls results in immediate process termination
/// via `SECCOMP_RET_KILL_PROCESS` (Signal 31 `SIGSYS`).
pub const PROFILE1_CRITICAL_FORBIDDEN_SYSCALLS: &[i64] = &[
    libc::SYS_clone,           // 56 (process/thread creation)
    libc::SYS_fork,            // 57 (process creation)
    libc::SYS_vfork,           // 58 (process creation)
    libc::SYS_execve,          // 59 (binary execution)
    libc::SYS_ptrace,          // 101 (process tracing / injection)
    155,                       // pivot_root (root filesystem escape)
    161,                       // chroot (jail manipulation)
    165,                       // mount (filesystem mounting)
    166,                       // umount2 (filesystem unmounting)
    246,                       // kexec_load (kernel replacement)
    272,                       // unshare (namespace creation)
    308,                       // setns (namespace joining)
    libc::SYS_kexec_file_load, // 320
    libc::SYS_bpf,             // 321 (eBPF map/program injection)
    libc::SYS_execveat,        // 322 (binary execution)
    435,                       // clone3 (process creation)
    libc::SYS_socket,          // 41 (network socket creation)
    libc::SYS_connect,         // 42 (network connection)
    libc::SYS_accept,          // 43 (network incoming connection)
    libc::SYS_bind,            // 49 (network binding)
    libc::SYS_listen,          // 50 (network listening)
    288,                       // accept4 (network incoming connection)
];

/// Backward-compatible alias for PROFILE1_CRITICAL_FORBIDDEN_SYSCALLS.
pub const PROFILE1_DENIED_SYSCALLS: &[i64] = PROFILE1_CRITICAL_FORBIDDEN_SYSCALLS;

/// Empirically validated allowlist of syscalls required by the compiled Rust worker runtime
/// and approved Layer 8 capabilities (`fs.read_file`, `fs.create_directory`, `fs.delete_tree`).
pub const PROFILE1_ALLOWED_SYSCALLS: &[i64] = &[
    libc::SYS_read,              // 0
    libc::SYS_write,             // 1
    libc::SYS_close,             // 3
    libc::SYS_fstat,             // 5
    libc::SYS_poll,              // 7
    libc::SYS_lseek,             // 8
    libc::SYS_mmap,              // 9
    libc::SYS_mprotect,          // 10
    libc::SYS_munmap,            // 11
    libc::SYS_brk,               // 12
    libc::SYS_rt_sigaction,      // 13
    libc::SYS_rt_sigprocmask,    // 14
    libc::SYS_rt_sigreturn,      // 15
    libc::SYS_ioctl,             // 16
    libc::SYS_pread64,           // 17
    libc::SYS_pwrite64,          // 18
    libc::SYS_readv,             // 19
    libc::SYS_writev,            // 20
    libc::SYS_access,            // 21
    libc::SYS_sched_yield,       // 24
    libc::SYS_madvise,           // 28
    libc::SYS_dup,               // 32
    libc::SYS_dup2,              // 33
    libc::SYS_nanosleep,         // 35
    libc::SYS_getpid,            // 39
    libc::SYS_sendto,            // 44
    libc::SYS_recvfrom,          // 45
    libc::SYS_sendmsg,           // 46
    libc::SYS_recvmsg,           // 47
    libc::SYS_exit,              // 60
    libc::SYS_fcntl,             // 72
    libc::SYS_gettimeofday,      // 96
    libc::SYS_getuid,            // 102
    libc::SYS_getgid,            // 104
    libc::SYS_geteuid,           // 107
    libc::SYS_getegid,           // 108
    libc::SYS_sigaltstack,       // 131
    libc::SYS_prctl,             // 157
    libc::SYS_arch_prctl,        // 158
    libc::SYS_gettid,            // 186
    libc::SYS_futex,             // 202
    libc::SYS_sched_getaffinity, // 204
    libc::SYS_getdents64,        // 217 (directory enumeration for tree traversal)
    libc::SYS_set_tid_address,   // 218
    libc::SYS_clock_gettime,     // 228
    libc::SYS_clock_nanosleep,   // 230
    libc::SYS_exit_group,        // 231
    libc::SYS_tgkill,            // 234
    libc::SYS_openat,            // 257
    libc::SYS_mkdirat,           // 258 (directory creation for fs.create_directory)
    libc::SYS_newfstatat,        // 262
    libc::SYS_unlinkat,          // 263 (file/dir deletion for fs.delete_tree)
    libc::SYS_set_robust_list,   // 273
    libc::SYS_prlimit64,         // 302
    libc::SYS_seccomp,           // 317
    libc::SYS_getrandom,         // 318
    libc::SYS_statx,             // 332
    libc::SYS_rseq,              // 334
    436,                         // close_range
    437,                         // openat2
    444,                         // landlock_create_ruleset
    445,                         // landlock_add_rule
    446,                         // landlock_restrict_self
];

/// Constructs the BPF filter instructions for Profile 1.
pub fn build_profile1_bpf_filter(action_on_deny: u32) -> Vec<SockFilter> {
    // 1. Validate architecture: Load arch from offset 4
    let mut instructions = vec![
        SockFilter {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: 4, // offsetof(struct seccomp_data, arch)
        },
        // Check arch == AUDIT_ARCH_X86_64
        SockFilter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 1, // match -> skip the kill statement
            jf: 0, // no match -> execute next kill statement
            k: AUDIT_ARCH_X86_64,
        },
        // Kill immediately on architecture mismatch
        SockFilter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_KILL_PROCESS,
        },
        // 2. Load system call number: Load nr from offset 0
        SockFilter {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: 0, // offsetof(struct seccomp_data, nr)
        },
    ];

    // 3. Explicit security-critical forbidden syscalls: ALWAYS kill process
    for &denied_nr in PROFILE1_CRITICAL_FORBIDDEN_SYSCALLS {
        instructions.push(SockFilter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 0, // match -> fall through to return KILL_PROCESS
            jf: 1, // no match -> skip return
            k: denied_nr as u32,
        });
        instructions.push(SockFilter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_KILL_PROCESS,
        });
    }

    // 4. Allowed list: If matched, return SECCOMP_RET_ALLOW
    for &allowed_nr in PROFILE1_ALLOWED_SYSCALLS {
        instructions.push(SockFilter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 0, // match -> fall through to return ALLOW
            jf: 1, // no match -> skip return
            k: allowed_nr as u32,
        });
        instructions.push(SockFilter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        });
    }

    // 5. Default catch-all policy for unlisted/unknown syscalls
    instructions.push(SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: action_on_deny,
    });

    instructions
}

/// Installs the Profile 1 Seccomp-BPF filter on the calling thread.
///
/// - Security-critical forbidden syscalls (`execve`, `fork`, `socket`, `ptrace`, etc.) ALWAYS terminate the process immediately (`SECCOMP_RET_KILL_PROCESS`).
/// - Unlisted/unhandled syscalls are handled per `kill_on_violation`:
///   - `true` (default production policy): `SECCOMP_RET_KILL_PROCESS`.
///   - `false` (testing harness policy for unlisted syscalls): `SECCOMP_RET_ERRNO(EPERM)`.
///
/// Fails closed if the kernel rejects the filter.
pub fn apply_profile1_seccomp(kill_on_violation: bool) -> Result<(), SandboxError> {
    let action_on_deny = if kill_on_violation {
        SECCOMP_RET_KILL_PROCESS
    } else {
        SECCOMP_RET_ERRNO | (libc::EPERM as u32)
    };

    let filter = build_profile1_bpf_filter(action_on_deny);

    let prog = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };

    let res = unsafe {
        libc::syscall(
            SYS_SECCOMP,
            SECCOMP_SET_MODE_FILTER,
            0 as libc::c_uint,
            &prog as *const SockFprog as *const libc::c_void,
        )
    };

    if res != 0 {
        let err = std::io::Error::last_os_error();
        return Err(SandboxError::SeccompInstallationFailed(format!(
            "seccomp(SECCOMP_SET_MODE_FILTER) failed: {err}"
        )));
    }

    Ok(())
}
