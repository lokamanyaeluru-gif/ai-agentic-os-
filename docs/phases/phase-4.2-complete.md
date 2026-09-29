# Phase 4.2: Minimal Process Isolation Engine (Profile 1) — Completion Record

* **Document Version**: 4.2.0
* **Date**: 2026-09-29
* **Phase**: 4.2 Implementation
* **Status**: COMPLETE & VERIFIED
* **Architectural Baseline**: ADR-0001 through ADR-0007, `docs/architecture.md`, `docs/security.md`, `docs/threat-model.md`, Phase 4.0 Specification, Phase 4.1 Implementation.

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
- **Pre-Execution Confinement**: Applies `enter_profile1_confinement()` before functional capability access.
- **Safe Execution**: Dispatches requested capability (`fs.read_file`) strictly through `ConfinedWorkspace`.
- **Error Propagation**: Maps any sandboxing or execution violation to ADR-0007 formal `ErrorPayload` returned in `InvocationResponse`.

### 2.2 Linux Landlock LSM Sandboxing (`crates/agenticos-core/src/sandbox/landlock.rs`)
- **Runtime ABI Discovery**: Uses `landlock_create_ruleset` with `LANDLOCK_CREATE_RULESET_VERSION` to discover kernel ABI. Fails closed if Landlock is unsupported or ABI < 1. On host kernel (Linux 6.18 x86_64), discovers ABI 7.
- **Runtime Errata Discovery**: Uses `LANDLOCK_CREATE_RULESET_ERRATA` to probe kernel errata flags.
- **Forward-Compatible Capability Masks**:
  - ABI 1..=7 support: `fs_access_mask_for_abi`, `net_access_mask_for_abi`, `scope_mask_for_abi`.
  - Handles FS execution, read, write, truncate, refer, and ioctl rights.
  - Handles network TCP bind/connect rights (ABI 4+).
  - Handles scope isolation (abstract UNIX sockets, signals) (ABI 6+).
  - Preserves forward compatibility with future ABIs without guessing unapproved features.
- **Path-Beneath Rules**: Ruleset bounds filesystem access strictly to the workspace directory.
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

### 2.4 Linux Seccomp-BPF Syscall Filtering (`crates/agenticos-core/src/sandbox/seccomp.rs`)
- **Architecture Validation**: Validates `AUDIT_ARCH_X86_64` (0xc000003e) as instruction 0-2; kills immediately on mismatch (`SECCOMP_RET_KILL_PROCESS`).
- **Explicit Denials**: Explicitly blocks:
  - Process creation: `fork`, `vfork`, `clone`, `clone3`, `execve`, `execveat`.
  - Network creation: `socket`, `connect`, `bind`, `listen`, `accept`, `accept4`.
  - System modification: `ptrace`, `bpf`, `kexec_load`, `kexec_file_load`, `mount`, `umount2`, `chroot`, `pivot_root`, `unshare`, `setns`.
- **Empirical Allowlist**: Filter permits the exact set of runtime syscalls needed by the Rust worker runtime (including `openat2`, `close_range`, `landlock_*`, `poll`, `recvmsg`, `sendmsg`, `futex`, memory allocations).
- **Default Action**: Fails closed with `action_on_deny` (`SECCOMP_RET_KILL_PROCESS` or `SECCOMP_RET_ERRNO(EPERM)`).

### 2.5 Confinement Lifecycle & Pre-Opened FD Hygiene (`crates/agenticos-core/src/sandbox/confinement.rs`)
- Sequence:
  1. `PR_SET_NO_NEW_PRIVS`
  2. Resolves canonical workspace path and opens directory handle with `O_PATH | O_DIRECTORY | O_CLOEXEC`.
  3. Applies Landlock filesystem restriction to workspace handle.
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

1. `test_landlock_abi_discovery_and_masks`: Probes kernel Landlock ABI (verified ABI 7 on Linux 6.18) and validates feature bitmasks.
2. `test_openat2_beneath_happy_path`: Validates authorized read of workspace file.
3. `test_openat2_beneath_blocks_directory_traversal`: Verifies `..` and absolute paths trigger `EscapeAttempt` (`EXDEV`).
4. `test_openat2_beneath_blocks_symlinks`: Verifies symlinks trigger `SymlinkTraversalBlocked` (`ELOOP`).
5. `test_seccomp_bpf_filter_structure`: Inspects BPF instruction stream, architecture validation, and syscall coverage.
6. `test_seccomp_denied_syscalls_fail_with_eperm_in_child`: Confirms `socket`, `fork`, and `ptrace` return `EPERM` under Seccomp.
7. `test_seccomp_kill_on_violation`: Verifies denied syscall in kill mode results in immediate `SIGSYS` termination.
8. `test_landlock_filesystem_containment_in_child`: Verifies Landlock denies opening files outside workspace (e.g., `/etc/passwd` returns `EACCES`).
9. `test_profile1_worker_end_to_end_read_file_success`: Full supervisor integration test executing `fs.read_file` in confined worker.
10. `test_profile1_worker_escape_attempt_reported_to_supervisor`: Traversal attempt inside worker reported back to supervisor as `CapabilityExecutionFailed`.
11. `test_profile1_worker_symlink_blocked_reported_to_supervisor`: Symlink resolution attempt inside worker reported as `CapabilityExecutionFailed`.
12. `test_profile1_worker_non_existent_file_reported`: Non-existent file reported with appropriate OS error.
13. `test_profile1_worker_unsupported_capability_fails`: Unsupported capability fails closed deterministically.
14. `test_profile1_worker_inherited_fd_hygiene`: Confirms parent descriptors $\ge 4$ are closed in child, preventing pre-opened descriptor leaks.

### Workspace Test Results
- **Total Tests**: 359 tests (14 sandbox + 19 supervisor + 326 runtime/storage/policy/contracts/capability).
- **Status**: 359 passed; 0 failed.
- **Formatting**: `cargo fmt --all -- --check` clean.
- **Linting**: `cargo clippy --all-targets --all-features -- -D warnings` clean.
