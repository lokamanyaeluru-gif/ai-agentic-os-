# Phase 4.1: Supervisor Foundations, IPC Protocol & Process Lifecycle — Completion Record

* **Document Version**: 4.1.0
* **Date**: 2026-09-29
* **Phase**: 4.1 Implementation
* **Status**: COMPLETE & VERIFIED
* **Architectural Baseline**: ADR-0001 through ADR-0007, `docs/architecture.md`, `docs/security.md`, `docs/threat-model.md`, Phase 4.0 Specification, Phase 3.3 Implementation.

---

## 1. Executive Summary

Phase 4.1 implements the foundational execution harness for Layer 7 `CapabilitySupervisor`. This establishes the strict, out-of-process process lifecycle and inter-process communication (IPC) channel between the host supervisor and unprivileged worker processes.

Zero capability code executes inside the Supervisor. All execution happens in spawned child processes communicating over an unrouted, point-to-point `AF_UNIX` `SOCK_SEQPACKET` socketpair. Worker identity is authenticated via kernel credentials (`SO_PEERCRED`), 128-bit cryptographically secure instance nonces, and `/proc/[pid]/stat` process start times (`start_time_ticks`). Bounded 64 KiB rolling ring buffers capture diagnostic stdout and stderr with true EOF detection, and timeouts are enforced through a strict SIGTERM → 500ms grace → SIGKILL escalation ladder.

---

## 2. Key Components Implemented

### 2.1 CapabilitySupervisor (`crates/agenticos-core/src/supervisor/supervisor.rs`)
- Persistent Layer 7 supervisor that manages out-of-process worker execution.
- Configurable wall-clock timeouts (default 30s, maximum 300s) and grace periods (default 500ms).
- Multiplexed `libc::poll` loop monitoring `supervisor_ipc_fd`, `stdout_pipe_read`, and `stderr_pipe_read`.
- Bridges to Phase 3.3 `DispatchRecord` via `execute_dispatch_worker()`. Rejects non-`Planned` dispatches.

### 2.2 IPC Protocol & Framing (`crates/agenticos-core/src/supervisor/ipc.rs`)
- Transport: `AF_UNIX` `SOCK_SEQPACKET` via `libc::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0)`.
- Framing: 4-byte big-endian unsigned length prefix. Maximum frame size: 16 MiB (`16 * 1024 * 1024` bytes).
- Packet-Boundary Preservation: Uses `libc::recv(fd, buf, 4, MSG_PEEK)` to inspect packet length without consuming bytes, ensuring datagram boundaries in `SOCK_SEQPACKET` are preserved.
- Serde-backed typed messages (`IpcMessage`):
  - `HandshakeRequest { protocol_version, instance_nonce }`
  - `HandshakeResponse { protocol_version, instance_nonce, pid, start_time_ticks }`
  - `InvocationRequest { dispatch_id, capability_id, arguments }`
  - `InvocationResponse { dispatch_id, status, output, error }`
  - `Heartbeat { timestamp_ns }`

### 2.3 Worker Identity & Handshake (`crates/agenticos-core/src/supervisor/identity.rs`)
- `get_peer_credentials()`: Kernel-enforced caller PID/UID/GID via `getsockopt(..., SOL_SOCKET, SO_PEERCRED, ...)`.
- `read_process_start_time_ticks()`: Reads field 22 from `/proc/[pid]/stat` using `LinuxProcfsObserver`.
- `verify_worker_identity()`: Verifies that:
  1. The peer credentials match the expected process hierarchy.
  2. The worker returned the exact 128-bit `instance_nonce` minted prior to fork.
  3. The reported PID matches the child PID from `fork()`.
  4. The reported start time ticks match field 22 from `/proc/[pid]/stat`.

### 2.4 File Descriptor Lifecycle (`crates/agenticos-core/src/supervisor/process.rs`)
- **In Child**:
  - FD 0: Redirected to `/dev/null` (`libc::O_RDONLY`).
  - FD 1: Redirected to `stdout_pipe_write` via `dup2`.
  - FD 2: Redirected to `stderr_pipe_write` via `dup2`.
  - FD 3: Redirected to `worker_ipc_fd` via `dup2`.
  - Atomically closes all descriptors $\ge 4$ via `close_range_above(4)` (`SYS_close_range` or `/proc/self/fd` fallback).
- **In Supervisor**:
  - **Immediately closes** `worker_ipc_fd`, `stdout_pipe_write`, `stderr_pipe_write` upon successful `fork()`.
  - Retains strictly: `supervisor_ipc_fd`, `stdout_pipe_read`, `stderr_pipe_read`.

### 2.5 Diagnostics & Rolling Log Buffer (`crates/agenticos-core/src/supervisor/ring_buffer.rs`)
- `RollingLogBuffer`: Fixed-capacity in-memory buffer (default 64 KiB) using `VecDeque<u8>`.
- Rolling FIFO truncation: Keeps the most recent 64 KiB of diagnostic text if the worker exceeds capacity.
- `drain_pipe_to_eof()`: Non-blocking drain after child reap to ensure complete log capture up to true EOF.

### 2.6 Lifecycle States & Failure Taxonomy (`crates/agenticos-core/src/supervisor/lifecycle.rs`)
- `WorkerLifecycleState` (9 states): `Spawning`, `Handshaking`, `Ready`, `Executing`, `Completed`, `TimedOut`, `Terminating`, `Failed`, `Cancelled`.
- `WorkerFailureReason` (9 reasons): `SpawnFailure`, `HandshakeFailure`, `IdentityMismatch`, `ProtocolViolation`, `Timeout`, `AbnormalExit`, `SignalTermination`, `IpcFailure`, `InternalError`.
- Ephemeral execution record: `WorkerExecutionRecord` with complete execution metadata, output logs, exit code, termination signal, and structured error payload.

---

## 3. Verification & Test Suite

The test suite in `crates/agenticos-core/tests/supervisor_tests.rs` covers 18 end-to-end and unit test cases:
1. `test_successful_worker_spawn_and_handshake`: Full lifecycle with stdout capture and successful execution.
2. `test_handshake_nonce_mismatch_fails_closed`: Rejection when instance nonce does not match.
3. `test_handshake_pid_mismatch_fails_closed`: Rejection when worker reports wrong PID.
4. `test_handshake_start_time_mismatch_fails_closed`: Rejection when worker reports corrupted start time.
5. `test_so_peercred_validation`: Kernel credential inspection on socketpair.
6. `test_frame_over_16_mib_rejected`: Enforcement of 16 MiB maximum frame boundary.
7. `test_malformed_ipc_frame`: Rejection of corrupted/invalid JSON frames.
8. `test_truncated_frame`: Error handling when payload is shorter than declared length header.
9. `test_timeout_enforcement_and_termination`: Supervisor timeout terminates hung worker.
10. `test_sigterm_to_sigkill_escalation`: Escalation ladder kills uncooperative worker ignoring SIGTERM.
11. `test_stdout_and_stderr_capture_and_eof`: Multi-channel diagnostic stream capture.
12. `test_stdio_rolling_buffer_capacity_bounded`: FIFO rolling truncation test for 64 KiB buffer.
13. `test_worker_crash_abnormal_exit`: Correct classification of non-zero worker exit (`AbnormalExit`).
14. `test_worker_signal_crash_segfault`: Detection and reporting of signal-terminated child (`SignalTermination`).
15. `test_fd_cleanup_in_child_and_supervisor`: Verification of descriptor closure above FD 3.
16. `test_repeated_worker_executions`: Sequential execution clean state verification.
17. `test_concurrent_supervisor_executions`: Thread-safe concurrent supervisor execution runs.
18. `test_dispatch_record_integration`: Binding to Phase 3.3 planned `DispatchRecord`.

### Workspace Test Results
- Total Tests: 345 (18 supervisor + 327 runtime/storage/policy/contracts/capability).
- Status: 345 passed; 0 failed.
- Formatting: `cargo fmt --all -- --check` clean.
- Linting: `cargo clippy --all-targets --all-features -- -D warnings` clean.
