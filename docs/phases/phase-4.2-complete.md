# Phase 4.2: Minimal Process Isolation Engine (Profile 1) — Completion Record

* **Document Version**: 4.2.1 (Post-Remediation)
* **Date**: 2026-09-29
* **Phase**: 4.2 Implementation
* **Status**: COMPLETE & VERIFIED
* **Architectural Baseline**: ADR-0001 through ADR-0007, `docs/architecture.md`, `docs/security.md`, `docs/threat-model.md`, Phase 4.0 Specification, Phase 4.1 Implementation, Phase 3.2 Capability Contracts.

---

## 1. Executive Summary

Phase 4.2 implements the **Minimal Process Isolation Engine (Profile 1: Low-Risk ReadOnly / Workspace-Restricted)** under Layer 8 Sandbox & Isolation. This establishes the first real, defense-in-depth Linux execution boundary for AgenticOS capabilities.

Capability execution is strictly prohibited inside the `CapabilitySupervisor`. Worker processes run in isolated child processes with immediate credential lockdown (`PR_SET_NO_NEW_PRIVS`), Linux Landlock LSM filesystem containment, `openat2` resolution boundaries (`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`), and Seccomp-BPF system call filtering denying process spawning (`fork`, `clone`, `execve`), network creation (`socket`), and debugging/escape vectors (`ptrace`, `bpf`).

All communication occurs over point-to-point `AF_UNIX` `SOCK_SEQPACKET` socketpairs with complete datagram integrity verification, rejecting truncated or trailing bytes.

---

## 2. Key Components Implemented

### 2.1 Out-of-Process Worker Engine (`crates/agenticos-core/src/sandbox/worker.rs`)
- `run_profile1_worker()`: Deterministic, out-of-process worker execution loop.
- **Immediate Invariant**: Calls `prctl(PR_SET_NO_NEW_PRIVS, 1)` immediately upon worker process entry.
- **Identity Handshake**: Responds to `CapabilitySupervisor` over FD 3 with verified `instance_nonce`, worker PID, and `start_time_ticks`.
- **Pre-Execution Confinement**: Applies `enter_profile1_confinement(workspace_path, &capability_id, kill_on_seccomp_violation)` before functional capability access.
- **Supported Layer 8 Capabilities**:
  - `fs.read_file`: Safely reads file contents via `ConfinedWorkspace::read_file()`.
  - `fs.create_directory`: Safely creates directories via `ConfinedWorkspace::create_directory()`.
  - `fs.delete_tree`: Safely removes files/directory trees via `ConfinedWorkspace::delete_tree()`.
- **Error Propagation**: Maps any sandboxing or execution violation to ADR-0007 formal `ErrorPayload` returned in `InvocationResponse`.

### 2.2 Linux Landlock LSM Sandboxing (`crates/agenticos-core/src/sandbox/landlock.rs`)
- **Runtime ABI Discovery**: Uses `landlock_create_ruleset` with `LANDLOCK_CREATE_RULESET_VERSION` to discover kernel ABI. Fails closed if Landlock is unsupported or ABI < 1. On host kernel (Linux 6.18 x86_64), discovers ABI 7.
- **Runtime Errata Discovery**: Uses `LANDLOCK_CREATE_RULESET_ERRATA` to probe kernel errata flags.
- **Handled Access Rights Completeness**:
  - `handled_access_fs`: Configures ALL 16 known filesystem access classes supported by the discovered ABI (`(1 << 16) - 1` = `0xFFFF` for ABI $\ge$ 5):
    `READ_FILE`, `READ_DIR`, `WRITE_FILE`, `EXECUTE`, `REMOVE_FILE`, `REMOVE_DIR`, `MAKE_CHAR`, `MAKE_DIR`, `MAKE_REG`, `MAKE_SOCK`, `MAKE_FIFO`, `MAKE_BLOCK`, `MAKE_SYM`, `REFER`, `TRUNCATE`, `IOCTL_DEV`.
  - Any access class in `handled_access_fs` that is not explicitly granted in the ruleset is **automatically intercepted and denied (`EACCES`)** by the kernel.
  - Network handled rights: `LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP` (ABI 4+).
  - Scope handled rights: `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL` (ABI 6+).
- **Capability-to-Landlock Allowed Rights Mapping**:
  - `fs.read_file`: Strictly allowed `READ_FILE | READ_DIR`.
  - `fs.create_directory`: Strictly allowed `READ_DIR | MAKE_DIR`.
  - `fs.delete_tree`: Strictly allowed `READ_DIR | REMOVE_DIR | REMOVE_FILE`.
  - `workspace.read_write`: Allowed standard read/write rights; strictly denies `EXECUTE`, `MAKE_CHAR`, `MAKE_BLOCK`, `MAKE_FIFO`, `MAKE_SOCK`, `MAKE_SYM`, `IOCTL_DEV`.
- **Descriptor Hygiene**: Ruleset descriptor is immediately closed (`close(ruleset_fd)`) upon `landlock_restrict_self`.

### 2.3 Strict Path Resolution via openat2 (`crates/agenticos-core/src/sandbox/openat2.rs`)
- Native Linux `openat2` wrapper using `struct open_how`.
- Resolution flags: `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`.
- Guarantees:
  - Traversal attempts (`..`) are blocked by the kernel returning `EXDEV` -> mapped to `SandboxError::EscapeAttempt`.
  - Symlink traversals are blocked by the kernel returning `ELOOP` -> mapped to `SandboxError::SymlinkTraversalBlocked`.
  - Absolute paths are rejected prior to syscall.
  - Automatically enforces `O_CLOEXEC` on all opened descriptors.
- `read_file_beneath()`: Safely reads files within size bounds up to `max_bytes`.
- `create_directory_beneath()`: Safely creates directory nodes beneath workspace descriptor using `mkdirat`.
- `delete_tree_beneath()`: Recursively deletes directory entries beneath workspace descriptor using `openat2`, `fstat`, `fdopendir`/`readdir`, and `unlinkat`.

### 2.4 Linux Seccomp-BPF Syscall Filtering (`crates/agenticos-core/src/sandbox/seccomp.rs`)
- **Architecture Validation**: Validates `AUDIT_ARCH_X86_64` (0xc000003e) as instructions 0–2; kills immediately on mismatch (`SECCOMP_RET_KILL_PROCESS`).
- **Critical Forbidden Syscalls**:
  - Syscalls: `execve`, `execveat`, `fork`, `vfork`, `clone3`, `clone`, `mount`, `umount2`, `pivot_root`, `chroot`, `unshare`, `setns`, `ptrace`, `bpf`, `kexec_load`, `kexec_file_load`, `socket`, `connect`, `bind`, `listen`, `accept`, `accept4`.
  - **Action**: Always `SECCOMP_RET_KILL_PROCESS` (Signal 31 `SIGSYS`). Zero ambiguity.
- **Empirical Allowlist**: Filter permits the exact set of runtime syscalls needed by the Rust worker runtime and approved Layer 8 capabilities (`openat2`, `close_range`, `landlock_*`, `poll`, `recvmsg`, `sendmsg`, `mkdirat`, `unlinkat`, `getdents64`, memory allocators, futexes).
- **Default Catch-All Action**: Fails closed with `SECCOMP_RET_KILL_PROCESS`.

### 2.5 Confinement Lifecycle & Pre-Opened FD Hygiene (`crates/agenticos-core/src/sandbox/confinement.rs`)
- Sequence:
  1. `PR_SET_NO_NEW_PRIVS`
  2. Resolves canonical workspace path and opens directory handle with `O_PATH | O_DIRECTORY | O_CLOEXEC`.
  3. Applies Landlock filesystem restriction to workspace handle with capability-specific allowed mask.
  4. Installs Seccomp-BPF system call filter.
  5. Returns RAII-managed `ConfinedWorkspace`.
- Pre-opened FD bypass defense: Supervisor closes worker-side FDs after spawn; child closes all descriptors $\ge 4$ via `close_range_above(4)`; worker receives NO functional data FDs from supervisor.

### 2.6 IPC Framing Regression Fix (`crates/agenticos-core/src/supervisor/ipc.rs`)
- Hardened `read_frame()` using `libc::recv` with `MSG_PEEK | MSG_TRUNC` to probe total pending datagram size.
- Strictly compares pending datagram bytes to `4 + declared_len`.
- Rejects packets containing trailing or undeclared bytes with `IpcError::DatagramLengthMismatch`.

---

## 3. Verification & Test Suite

The test suite in `crates/agenticos-core/tests/sandbox_tests.rs` includes 14 comprehensive security and unit tests:

1. `test_landlock_abi_discovery_and_masks`: Probes kernel Landlock ABI (verified ABI 7 on Linux 6.18) and validates capability allowed masks for `ReadFile`, `CreateDirectory`, and `DeleteTree`.
2. `test_openat2_beneath_happy_path`: Validates authorized read of workspace file.
3. `test_openat2_beneath_blocks_directory_traversal`: Verifies `..` and absolute paths trigger `EscapeAttempt` (`EXDEV`).
4. `test_openat2_beneath_blocks_symlinks`: Verifies symlinks trigger `SymlinkTraversalBlocked` (`ELOOP`).
5. `test_openat2_directory_creation_and_deletion`: Verifies `create_directory_beneath` and `delete_tree_beneath` work and block traversal.
6. `test_seccomp_bpf_filter_structure`: Inspects BPF instruction stream, architecture validation, and verifies critical forbidden syscalls are mapped to `SECCOMP_RET_KILL_PROCESS`.
7. `test_seccomp_critical_syscalls_kill_process_in_child`: Confirms `execve`, `socket`, and `fork` terminate the worker process with signal 31 (`SIGSYS`).
8. `test_landlock_filesystem_containment_in_child`: Verifies Landlock denies opening files outside workspace (e.g., `/etc/passwd` returns `EACCES`).
9. `test_landlock_handled_access_classes_are_strictly_denied`: Negative test verifying that ungranted handled access classes (`WRITE_FILE`, `MAKE_DIR`, `MAKE_REG`, `REMOVE_FILE`, `MAKE_SYM`) fail with `EACCES`.
10. `test_profile1_capability_read_file_complete_matrix`: Full matrix test for `fs.read_file`: allowed read succeeds, outside workspace fails (`EscapeAttempt`), symlink escape fails (`SymlinkTraversalBlocked`).
11. `test_profile1_capability_create_directory_complete_matrix`: Full matrix test for `fs.create_directory`: allowed mkdir succeeds, outside workspace fails (`EscapeAttempt`), symlink escape fails (`SymlinkTraversalBlocked`).
12. `test_profile1_capability_delete_tree_complete_matrix`: Full matrix test for `fs.delete_tree`: allowed deletion succeeds, outside workspace fails (`EscapeAttempt`), symlink escape fails (`SymlinkTraversalBlocked`).
13. `test_profile1_worker_inherited_fd_hygiene`: Confirms parent descriptors $\ge 4$ are closed in child, preventing pre-opened descriptor leaks.
14. `test_profile1_worker_unsupported_capability_fails`: Unsupported capability fails closed deterministically with `CapabilityExecutionFailed`.

### Workspace Test Results
- **Total Tests**: 359 tests (14 sandbox + 19 supervisor + 326 runtime/storage/policy/contracts/capability).
- **Status**: 359 passed; 0 failed.
- **Formatting**: `cargo fmt --all -- --check` clean.
- **Linting**: `cargo clippy --all-targets --all-features -- -D warnings` clean.
