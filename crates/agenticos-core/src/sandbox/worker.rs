//! Dedicated out-of-process Profile 1 capability worker loop.
//!
//! Executes inside the spawned child process, enters confinement before capability
//! execution, safely processes requests via `openat2`, and communicates with the
//! CapabilitySupervisor over the inherited IPC socketpair (FD 3).

use super::confinement::enter_profile1_confinement;
use super::error::SandboxError;
use crate::agent::observer::LinuxProcfsObserver;
use crate::capability::ExecutionStatus;
use crate::supervisor::identity::read_process_start_time_ticks;
use crate::supervisor::ipc::{receive_message, send_message, IpcMessage, MAX_FRAME_SIZE};
use agenticos_contracts::ProtocolVersion;
use std::os::unix::io::RawFd;
use std::path::Path;
use uuid::Uuid;

/// Runs the standard Profile 1 capability worker event loop inside a spawned child process.
///
/// Execution order:
/// 1. Handshake with supervisor over `ipc_fd`.
/// 2. Receive capability invocation request.
/// 3. Enter Profile 1 confinement (PR_SET_NO_NEW_PRIVS -> Landlock -> Seccomp).
/// 4. Execute operation strictly inside confined workspace via openat2.
/// 5. Return invocation response to supervisor.
/// 6. Return exit code (0 on success).
pub fn run_profile1_worker(
    ipc_fd: RawFd,
    expected_nonce: Uuid,
    workspace_path: &Path,
    kill_on_seccomp_violation: bool,
) -> i32 {
    // Enforce PR_SET_NO_NEW_PRIVS immediately upon entering the worker process
    let res = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if res != 0 {
        return 100;
    }

    // 1. Receive HandshakeRequest
    let req = match receive_message(ipc_fd, MAX_FRAME_SIZE) {
        Ok(msg) => msg,
        Err(_) => return 101,
    };

    let received_nonce = match req {
        IpcMessage::HandshakeRequest { instance_nonce, .. } => instance_nonce,
        _ => return 102,
    };

    if received_nonce != expected_nonce {
        return 103;
    }

    let my_pid = std::process::id();
    let observer = LinuxProcfsObserver::default();
    let my_ticks = read_process_start_time_ticks(my_pid, &observer).unwrap_or_default();

    // 2. Send HandshakeResponse
    let resp = IpcMessage::HandshakeResponse {
        protocol_version: ProtocolVersion::V1_0,
        instance_nonce: expected_nonce,
        pid: my_pid,
        start_time_ticks: my_ticks,
    };

    if send_message(ipc_fd, &resp).is_err() {
        return 104;
    }

    // 3. Receive InvocationRequest
    let inv_req = match receive_message(ipc_fd, MAX_FRAME_SIZE) {
        Ok(msg) => msg,
        Err(_) => return 105,
    };

    let (dispatch_id, capability_id, arguments) = match inv_req {
        IpcMessage::InvocationRequest {
            dispatch_id,
            capability_id,
            arguments,
        } => (dispatch_id, capability_id, arguments),
        _ => return 106,
    };

    // 4. Enter Profile 1 Confinement configured with least-privilege capability profile
    let confined =
        match enter_profile1_confinement(workspace_path, &capability_id, kill_on_seccomp_violation)
        {
            Ok(c) => c,
            Err(err) => {
                let resp = IpcMessage::InvocationResponse {
                    dispatch_id,
                    status: ExecutionStatus::Failure,
                    output: None,
                    error: Some(err.to_error_payload()),
                };
                let _ = send_message(ipc_fd, &resp);
                return 107;
            }
        };

    // 5. Execute Capability inside Confinement
    let (status, output, error) = match capability_id.as_str() {
        "fs.read_file" => {
            let rel_path = arguments.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let max_bytes = arguments
                .get("max_bytes")
                .and_then(|v| v.as_u64())
                .unwrap_or(65536) as usize;

            match confined.read_file(rel_path, max_bytes) {
                Ok(bytes) => {
                    let content = String::from_utf8_lossy(&bytes).to_string();
                    (
                        ExecutionStatus::Success,
                        Some(serde_json::json!({ "content": content, "bytes_read": bytes.len() })),
                        None,
                    )
                }
                Err(err) => (ExecutionStatus::Failure, None, Some(err.to_error_payload())),
            }
        }
        "fs.create_directory" => {
            let rel_path = arguments.get("path").and_then(|v| v.as_str()).unwrap_or("");

            match confined.create_directory(rel_path) {
                Ok(()) => (
                    ExecutionStatus::Success,
                    Some(serde_json::json!({ "created": rel_path })),
                    None,
                ),
                Err(err) => (ExecutionStatus::Failure, None, Some(err.to_error_payload())),
            }
        }
        "fs.delete_tree" => {
            let rel_path = arguments.get("path").and_then(|v| v.as_str()).unwrap_or("");

            match confined.delete_tree(rel_path) {
                Ok(()) => (
                    ExecutionStatus::Success,
                    Some(serde_json::json!({ "deleted": rel_path })),
                    None,
                ),
                Err(err) => (ExecutionStatus::Failure, None, Some(err.to_error_payload())),
            }
        }
        other => {
            let err = SandboxError::CapabilityExecutionFailed(format!(
                "Unsupported capability in Profile 1 worker: '{other}'"
            ));
            (ExecutionStatus::Failure, None, Some(err.to_error_payload()))
        }
    };

    // 6. Send InvocationResponse
    let inv_resp = IpcMessage::InvocationResponse {
        dispatch_id,
        status,
        output,
        error,
    };

    if send_message(ipc_fd, &inv_resp).is_err() {
        return 108;
    }

    0
}

/// Runs the Profile 2 capability worker loop inside the Bubblewrap sandbox.
///
/// Execution order:
/// 1. Close all descriptors >= 4 to maintain strict FD hygiene.
/// 2. Enforce PR_SET_NO_NEW_PRIVS.
/// 3. Handshake with supervisor over `ipc_fd` (FD 3).
/// 4. Receive capability invocation request.
/// 5. Enter inner defense-in-depth confinement (Landlock + Seccomp) on `/workspace`.
/// 6. Execute operation strictly inside `/workspace` via `openat2`.
/// 7. Return invocation response to supervisor.
/// 8. Exit cleanly.
pub fn run_profile2_worker(
    ipc_fd: RawFd,
    expected_nonce: Uuid,
    host_pid: u32,
    host_ticks: u64,
    kill_on_seccomp_violation: bool,
) -> i32 {
    // 0. Enforce descriptor hygiene: close all descriptors above FD 3
    crate::supervisor::close_range_above(4);

    // 1. Enforce PR_SET_NO_NEW_PRIVS immediately
    let res = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if res != 0 {
        eprintln!("PR_SET_NO_NEW_PRIVS failed: {res}");
        return 100;
    }

    // 2. Receive HandshakeRequest
    let req = match receive_message(ipc_fd, MAX_FRAME_SIZE) {
        Ok(msg) => msg,
        Err(e) => {
            eprintln!("Receive HandshakeRequest failed: {e}");
            return 101;
        }
    };

    let received_nonce = match req {
        IpcMessage::HandshakeRequest { instance_nonce, .. } => instance_nonce,
        other => {
            eprintln!("Unexpected message during handshake: {other:?}");
            return 102;
        }
    };

    if received_nonce != expected_nonce {
        eprintln!("Nonce mismatch: received {received_nonce}, expected {expected_nonce}");
        return 103;
    }

    // 3. Send HandshakeResponse attesting identity
    let resp = IpcMessage::HandshakeResponse {
        protocol_version: ProtocolVersion::V1_0,
        instance_nonce: expected_nonce,
        pid: host_pid,
        start_time_ticks: host_ticks,
    };

    if let Err(e) = send_message(ipc_fd, &resp) {
        eprintln!("Send HandshakeResponse failed: {e}");
        return 104;
    }

    // 4. Receive InvocationRequest
    let inv_req = match receive_message(ipc_fd, MAX_FRAME_SIZE) {
        Ok(msg) => msg,
        Err(e) => {
            eprintln!("Receive InvocationRequest failed: {e}");
            return 105;
        }
    };

    let (dispatch_id, capability_id, arguments) = match inv_req {
        IpcMessage::InvocationRequest {
            dispatch_id,
            capability_id,
            arguments,
        } => (dispatch_id, capability_id, arguments),
        other => {
            eprintln!("Unexpected message instead of InvocationRequest: {other:?}");
            return 106;
        }
    };

    // 5. Enter Inner Defense-in-Depth Confinement (Landlock + Seccomp on /workspace)
    let workspace_path = Path::new("/workspace");
    let confined =
        match enter_profile1_confinement(workspace_path, &capability_id, kill_on_seccomp_violation)
        {
            Ok(c) => c,
            Err(err) => {
                eprintln!("enter_profile1_confinement failed: {err}");
                let resp = IpcMessage::InvocationResponse {
                    dispatch_id,
                    status: ExecutionStatus::Failure,
                    output: None,
                    error: Some(err.to_error_payload()),
                };
                let _ = send_message(ipc_fd, &resp);
                return 107;
            }
        };

    // 6. Execute Capability inside Confinement via openat2
    let (status, output, error) = match capability_id.as_str() {
        "fs.read_file" => {
            let rel_path = arguments.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let max_bytes = arguments
                .get("max_bytes")
                .and_then(|v| v.as_u64())
                .unwrap_or(65536) as usize;

            match confined.read_file(rel_path, max_bytes) {
                Ok(bytes) => {
                    let content = String::from_utf8_lossy(&bytes).to_string();
                    (
                        ExecutionStatus::Success,
                        Some(serde_json::json!({ "content": content, "bytes_read": bytes.len() })),
                        None,
                    )
                }
                Err(err) => (ExecutionStatus::Failure, None, Some(err.to_error_payload())),
            }
        }
        "fs.create_directory" => {
            let rel_path = arguments.get("path").and_then(|v| v.as_str()).unwrap_or("");

            match confined.create_directory(rel_path) {
                Ok(()) => (
                    ExecutionStatus::Success,
                    Some(serde_json::json!({ "created": rel_path })),
                    None,
                ),
                Err(err) => (ExecutionStatus::Failure, None, Some(err.to_error_payload())),
            }
        }
        "fs.delete_tree" => {
            let rel_path = arguments.get("path").and_then(|v| v.as_str()).unwrap_or("");

            match confined.delete_tree(rel_path) {
                Ok(()) => (
                    ExecutionStatus::Success,
                    Some(serde_json::json!({ "deleted": rel_path })),
                    None,
                ),
                Err(err) => (ExecutionStatus::Failure, None, Some(err.to_error_payload())),
            }
        }
        other => {
            let err = SandboxError::CapabilityExecutionFailed(format!(
                "Unsupported capability in Profile 2 container worker: '{other}'"
            ));
            (ExecutionStatus::Failure, None, Some(err.to_error_payload()))
        }
    };

    // 7. Send InvocationResponse
    let inv_resp = IpcMessage::InvocationResponse {
        dispatch_id,
        status,
        output,
        error,
    };

    if send_message(ipc_fd, &inv_resp).is_err() {
        return 108;
    }

    0
}
