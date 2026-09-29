use agenticos_contracts::{ErrorCode, ProtocolVersion};
use agenticos_core::agent::observer::LinuxProcfsObserver;
use agenticos_core::agent::AssignmentId;
use agenticos_core::capability::ExecutionStatus;
use agenticos_core::dispatch::{DispatchOutcome, DispatchRecord};
use agenticos_core::supervisor::{
    close_range_above, create_seqpacket_socketpair, get_peer_credentials, read_frame,
    read_process_start_time_ticks, receive_message, run_worker_loop, send_message, write_frame,
    CapabilitySupervisor, IpcError, IpcMessage, RollingLogBuffer, SupervisorConfig,
    SupervisorError, WorkerFailureReason, WorkerLifecycleState, MAX_FRAME_SIZE,
};
use std::time::Duration;
use uuid::Uuid;

fn make_test_supervisor(timeout_ms: u64, grace_ms: u64) -> CapabilitySupervisor {
    let config = SupervisorConfig {
        default_timeout: Duration::from_millis(timeout_ms),
        max_timeout: Duration::from_secs(300),
        grace_period: Duration::from_millis(grace_ms),
        max_frame_bytes: MAX_FRAME_SIZE,
        max_output_bytes: 4 * 1024 * 1024,
        log_buffer_capacity: 64 * 1024,
    };
    CapabilitySupervisor::new(config, LinuxProcfsObserver::default())
}

#[test]
fn test_successful_worker_spawn_and_handshake() {
    let supervisor = make_test_supervisor(5000, 500);
    let execution_id = Uuid::new_v4();
    let dispatch_id = Uuid::new_v4();
    let assignment_id = AssignmentId(Uuid::new_v4());

    let record = supervisor
        .execute_worker(
            execution_id,
            dispatch_id,
            assignment_id,
            None,
            |ipc_fd, nonce| {
                let msg = b"Worker started successfully\n";
                unsafe { libc::write(1, msg.as_ptr() as *const libc::c_void, msg.len()) };
                run_worker_loop(ipc_fd, nonce, |req| match req {
                    IpcMessage::InvocationRequest { dispatch_id, .. } => {
                        IpcMessage::InvocationResponse {
                            dispatch_id,
                            status: ExecutionStatus::Success,
                            output: Some(serde_json::json!({ "result": "computed_value" })),
                            error: None,
                        }
                    }
                    other => panic!("Unexpected request: {:?}", other),
                })
            },
        )
        .expect("Execution succeeded");

    assert_eq!(record.execution_id, execution_id);
    assert_eq!(record.dispatch_id, dispatch_id);
    assert_eq!(record.assignment_id, assignment_id);
    assert_eq!(record.lifecycle_state, WorkerLifecycleState::Completed);
    assert_eq!(record.exit_code, Some(0));
    assert!(record.pid > 0);
    assert!(record.start_time_ticks > 0);
    assert!(record.failure_reason.is_none());
    assert!(record.error.is_none());

    let stdout_str = String::from_utf8_lossy(&record.stdout_capture);
    assert!(stdout_str.contains("Worker started successfully"));
}

#[test]
fn test_handshake_nonce_mismatch_fails_closed() {
    let supervisor = make_test_supervisor(5000, 500);
    let execution_id = Uuid::new_v4();
    let dispatch_id = Uuid::new_v4();
    let assignment_id = AssignmentId(Uuid::new_v4());

    let record = supervisor
        .execute_worker(
            execution_id,
            dispatch_id,
            assignment_id,
            None,
            |ipc_fd, _nonce| {
                // Send bogus nonce
                let bogus_nonce = Uuid::new_v4();
                let my_pid = std::process::id();
                let observer = LinuxProcfsObserver::default();
                let my_ticks = read_process_start_time_ticks(my_pid, &observer).unwrap_or(0);

                let _ = receive_message(ipc_fd, MAX_FRAME_SIZE);
                let resp = IpcMessage::HandshakeResponse {
                    protocol_version: ProtocolVersion::V1_0,
                    instance_nonce: bogus_nonce,
                    pid: my_pid,
                    start_time_ticks: my_ticks,
                };
                let _ = send_message(ipc_fd, &resp);
                0
            },
        )
        .expect("Record generated");

    assert_eq!(record.lifecycle_state, WorkerLifecycleState::Failed);
    assert_eq!(
        record.failure_reason,
        Some(WorkerFailureReason::IdentityMismatch)
    );
    let err = record.error.expect("Error payload present");
    assert_eq!(err.code, ErrorCode::PeerAuthenticationFailed);
    assert!(err.message.contains("Instance nonce mismatch"));
}

#[test]
fn test_handshake_pid_mismatch_fails_closed() {
    let supervisor = make_test_supervisor(5000, 500);
    let execution_id = Uuid::new_v4();
    let dispatch_id = Uuid::new_v4();
    let assignment_id = AssignmentId(Uuid::new_v4());

    let record = supervisor
        .execute_worker(
            execution_id,
            dispatch_id,
            assignment_id,
            None,
            |ipc_fd, nonce| {
                let my_pid = std::process::id();
                let observer = LinuxProcfsObserver::default();
                let my_ticks = read_process_start_time_ticks(my_pid, &observer).unwrap_or(0);

                let _ = receive_message(ipc_fd, MAX_FRAME_SIZE);
                let resp = IpcMessage::HandshakeResponse {
                    protocol_version: ProtocolVersion::V1_0,
                    instance_nonce: nonce,
                    pid: my_pid + 9999, // Intentional PID spoof
                    start_time_ticks: my_ticks,
                };
                let _ = send_message(ipc_fd, &resp);
                0
            },
        )
        .expect("Record generated");

    assert_eq!(record.lifecycle_state, WorkerLifecycleState::Failed);
    assert_eq!(
        record.failure_reason,
        Some(WorkerFailureReason::IdentityMismatch)
    );
    let err = record.error.expect("Error payload present");
    assert_eq!(err.code, ErrorCode::PeerAuthenticationFailed);
    assert!(err.message.contains("Reported PID mismatch"));
}

#[test]
fn test_handshake_start_time_mismatch_fails_closed() {
    let supervisor = make_test_supervisor(5000, 500);
    let execution_id = Uuid::new_v4();
    let dispatch_id = Uuid::new_v4();
    let assignment_id = AssignmentId(Uuid::new_v4());

    let record = supervisor
        .execute_worker(
            execution_id,
            dispatch_id,
            assignment_id,
            None,
            |ipc_fd, nonce| {
                let my_pid = std::process::id();
                let _ = receive_message(ipc_fd, MAX_FRAME_SIZE);
                let resp = IpcMessage::HandshakeResponse {
                    protocol_version: ProtocolVersion::V1_0,
                    instance_nonce: nonce,
                    pid: my_pid,
                    start_time_ticks: 12345678, // Wrong ticks
                };
                let _ = send_message(ipc_fd, &resp);
                0
            },
        )
        .expect("Record generated");

    assert_eq!(record.lifecycle_state, WorkerLifecycleState::Failed);
    assert_eq!(
        record.failure_reason,
        Some(WorkerFailureReason::IdentityMismatch)
    );
    let err = record.error.expect("Error payload present");
    assert_eq!(err.code, ErrorCode::PeerAuthenticationFailed);
    assert!(err.message.contains("start_time_ticks mismatch"));
}

#[test]
fn test_so_peercred_validation() {
    let (parent_fd, child_fd) = create_seqpacket_socketpair().expect("socketpair created");

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");

    if pid == 0 {
        unsafe { libc::close(parent_fd) };
        std::thread::sleep(Duration::from_millis(50));
        unsafe {
            libc::close(child_fd);
            libc::_exit(0);
        }
    }

    unsafe { libc::close(child_fd) };
    let ucred = get_peer_credentials(parent_fd).expect("SO_PEERCRED retrieved");
    assert_eq!(ucred.pid as u32, unsafe { libc::getpid() as u32 });
    assert_eq!(ucred.uid, unsafe { libc::getuid() });
    assert_eq!(ucred.gid, unsafe { libc::getgid() });

    unsafe {
        libc::close(parent_fd);
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
    }
}

#[test]
fn test_malformed_ipc_frame() {
    let (parent_fd, child_fd) = create_seqpacket_socketpair().expect("socketpair created");

    // Write invalid JSON bytes
    write_frame(parent_fd, b"THIS_IS_NOT_VALID_JSON").expect("write frame succeeded");

    let res = receive_message(child_fd, MAX_FRAME_SIZE);
    assert!(matches!(res, Err(IpcError::Serialization(_))));

    unsafe {
        libc::close(parent_fd);
        libc::close(child_fd);
    }
}

#[test]
fn test_truncated_frame() {
    let (parent_fd, child_fd) = create_seqpacket_socketpair().expect("socketpair created");

    // Write length prefix claiming 100 bytes, but send only 10 bytes and close
    let declared_len: u32 = 100;
    let mut data = Vec::new();
    data.extend_from_slice(&declared_len.to_be_bytes());
    data.extend_from_slice(b"1234567890");

    unsafe {
        libc::write(parent_fd, data.as_ptr() as *const libc::c_void, data.len());
        libc::close(parent_fd);
    }

    let res = read_frame(child_fd, MAX_FRAME_SIZE);
    assert!(matches!(res, Err(IpcError::TruncatedPayload { .. })));

    unsafe {
        libc::close(child_fd);
    }
}

#[test]
fn test_frame_over_16_mib_rejected() {
    let (parent_fd, child_fd) = create_seqpacket_socketpair().expect("socketpair created");

    let oversized_len = (MAX_FRAME_SIZE + 1) as u32;
    unsafe {
        libc::write(
            parent_fd,
            oversized_len.to_be_bytes().as_ptr() as *const libc::c_void,
            4,
        );
    }

    let err = read_frame(child_fd, MAX_FRAME_SIZE).unwrap_err();
    match err {
        IpcError::FrameTooLarge(len) => assert_eq!(len, MAX_FRAME_SIZE + 1),
        other => panic!("Expected FrameTooLarge, got {:?}", other),
    }

    unsafe {
        libc::close(parent_fd);
        libc::close(child_fd);
    }
}

#[test]
fn test_stdout_and_stderr_capture_and_eof() {
    let supervisor = make_test_supervisor(5000, 500);
    let execution_id = Uuid::new_v4();
    let dispatch_id = Uuid::new_v4();
    let assignment_id = AssignmentId(Uuid::new_v4());

    let record = supervisor
        .execute_worker(
            execution_id,
            dispatch_id,
            assignment_id,
            None,
            |ipc_fd, nonce| {
                let out = b"Message on standard output from worker\n";
                let err = b"Diagnostic warning on standard error from worker\n";
                unsafe {
                    libc::write(1, out.as_ptr() as *const libc::c_void, out.len());
                    libc::write(2, err.as_ptr() as *const libc::c_void, err.len());
                }
                run_worker_loop(ipc_fd, nonce, |req| match req {
                    IpcMessage::InvocationRequest { dispatch_id, .. } => {
                        IpcMessage::InvocationResponse {
                            dispatch_id,
                            status: ExecutionStatus::Success,
                            output: None,
                            error: None,
                        }
                    }
                    other => panic!("Unexpected request: {:?}", other),
                })
            },
        )
        .expect("Execution succeeded");

    assert_eq!(record.lifecycle_state, WorkerLifecycleState::Completed);
    let stdout_text = String::from_utf8_lossy(&record.stdout_capture);
    let stderr_text = String::from_utf8_lossy(&record.stderr_capture);

    assert!(stdout_text.contains("Message on standard output from worker"));
    assert!(stderr_text.contains("Diagnostic warning on standard error from worker"));
}

#[test]
fn test_stdio_rolling_buffer_capacity_bounded() {
    let mut ring = RollingLogBuffer::new(100);
    let chunk = vec![b'x'; 60];
    ring.push(&chunk);
    ring.push(&chunk);

    assert_eq!(ring.len(), 100);
    assert_eq!(ring.total_bytes_received(), 120);
    assert!(ring.was_truncated());
}

#[test]
fn test_timeout_enforcement_and_termination() {
    let supervisor = make_test_supervisor(100, 200); // 100ms timeout
    let execution_id = Uuid::new_v4();
    let dispatch_id = Uuid::new_v4();
    let assignment_id = AssignmentId(Uuid::new_v4());

    let record = supervisor
        .execute_worker(
            execution_id,
            dispatch_id,
            assignment_id,
            Some(Duration::from_millis(100)),
            |ipc_fd, nonce| {
                run_worker_loop(ipc_fd, nonce, |_req| {
                    // Sleep to trigger timeout
                    std::thread::sleep(Duration::from_secs(5));
                    panic!("Should have been killed before this");
                })
            },
        )
        .expect("Execution handled");

    assert_eq!(record.lifecycle_state, WorkerLifecycleState::TimedOut);
    assert_eq!(record.failure_reason, Some(WorkerFailureReason::Timeout));
    let err = record.error.expect("Timeout error present");
    assert_eq!(err.code, ErrorCode::Timeout);
}

#[test]
fn test_sigterm_to_sigkill_escalation() {
    let supervisor = make_test_supervisor(100, 50); // 100ms timeout, 50ms grace
    let execution_id = Uuid::new_v4();
    let dispatch_id = Uuid::new_v4();
    let assignment_id = AssignmentId(Uuid::new_v4());

    let record = supervisor
        .execute_worker(
            execution_id,
            dispatch_id,
            assignment_id,
            Some(Duration::from_millis(100)),
            |ipc_fd, nonce| {
                // Ignore SIGTERM so supervisor is forced to escalate to SIGKILL
                unsafe {
                    libc::signal(libc::SIGTERM, libc::SIG_IGN);
                }
                run_worker_loop(ipc_fd, nonce, |_req| loop {
                    std::thread::sleep(Duration::from_millis(50));
                })
            },
        )
        .expect("Execution handled");

    assert_eq!(record.lifecycle_state, WorkerLifecycleState::TimedOut);
    assert_eq!(record.termination_signal, Some(libc::SIGKILL));
}

#[test]
fn test_worker_crash_abnormal_exit() {
    let supervisor = make_test_supervisor(5000, 500);
    let execution_id = Uuid::new_v4();
    let dispatch_id = Uuid::new_v4();
    let assignment_id = AssignmentId(Uuid::new_v4());

    let record = supervisor
        .execute_worker(
            execution_id,
            dispatch_id,
            assignment_id,
            None,
            |_ipc_fd, _nonce| {
                // Immediate crash with exit code 42
                unsafe { libc::_exit(42) };
            },
        )
        .expect("Execution handled");

    assert_eq!(record.lifecycle_state, WorkerLifecycleState::Failed);
    assert_eq!(
        record.failure_reason,
        Some(WorkerFailureReason::AbnormalExit)
    );
    assert_eq!(record.exit_code, Some(42));
}

#[test]
fn test_worker_signal_crash_segfault() {
    let supervisor = make_test_supervisor(5000, 500);
    let execution_id = Uuid::new_v4();
    let dispatch_id = Uuid::new_v4();
    let assignment_id = AssignmentId(Uuid::new_v4());

    let record = supervisor
        .execute_worker(
            execution_id,
            dispatch_id,
            assignment_id,
            None,
            |_ipc_fd, _nonce| {
                // Trigger SIGSEGV with default disposition
                unsafe {
                    libc::signal(libc::SIGSEGV, libc::SIG_DFL);
                    libc::raise(libc::SIGSEGV);
                };
                0
            },
        )
        .expect("Execution handled");

    assert_eq!(record.lifecycle_state, WorkerLifecycleState::Failed);
    assert_eq!(record.termination_signal, Some(libc::SIGSEGV));
}

#[test]
fn test_fd_cleanup_in_child_and_supervisor() {
    let (p1, p2) = create_seqpacket_socketpair().expect("socketpair created");
    assert!(p1 >= 0 && p2 >= 0);

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        close_range_above(p1 as u32);
        // p1 should now be closed in child
        let res = unsafe { libc::close(p1) };
        let exit_code = if res == -1 { 0 } else { 1 };
        unsafe { libc::_exit(exit_code) };
    }

    let mut status = 0;
    let res = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert!(res > 0);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);

    unsafe {
        libc::close(p1);
        libc::close(p2);
    }
}

#[test]
fn test_repeated_worker_executions() {
    let supervisor = make_test_supervisor(5000, 500);
    let mut pids = Vec::new();

    for i in 0..5 {
        let execution_id = Uuid::new_v4();
        let dispatch_id = Uuid::new_v4();
        let assignment_id = AssignmentId(Uuid::new_v4());

        let record = supervisor
            .execute_worker(
                execution_id,
                dispatch_id,
                assignment_id,
                None,
                move |ipc_fd, nonce| {
                    run_worker_loop(ipc_fd, nonce, |req| match req {
                        IpcMessage::InvocationRequest { dispatch_id, .. } => {
                            IpcMessage::InvocationResponse {
                                dispatch_id,
                                status: ExecutionStatus::Success,
                                output: Some(serde_json::json!({ "iteration": i })),
                                error: None,
                            }
                        }
                        other => panic!("Unexpected request: {:?}", other),
                    })
                },
            )
            .expect("Execution succeeded");

        assert_eq!(record.lifecycle_state, WorkerLifecycleState::Completed);
        pids.push(record.pid);
    }

    assert_eq!(pids.len(), 5);
}

#[test]
fn test_concurrent_supervisor_executions() {
    let supervisor = std::sync::Arc::new(make_test_supervisor(5000, 500));
    let mut handles = Vec::new();

    for i in 0..4 {
        let sup = std::sync::Arc::clone(&supervisor);
        let handle = std::thread::spawn(move || {
            let execution_id = Uuid::new_v4();
            let dispatch_id = Uuid::new_v4();
            let assignment_id = AssignmentId(Uuid::new_v4());

            sup.execute_worker(
                execution_id,
                dispatch_id,
                assignment_id,
                None,
                move |ipc_fd, nonce| {
                    run_worker_loop(ipc_fd, nonce, |req| match req {
                        IpcMessage::InvocationRequest { dispatch_id, .. } => {
                            IpcMessage::InvocationResponse {
                                dispatch_id,
                                status: ExecutionStatus::Success,
                                output: Some(serde_json::json!({ "thread_index": i })),
                                error: None,
                            }
                        }
                        other => panic!("Unexpected request: {:?}", other),
                    })
                },
            )
            .expect("Thread execution succeeded")
        });
        handles.push(handle);
    }

    for handle in handles {
        let record = handle.join().expect("Thread joined cleanly");
        assert_eq!(record.lifecycle_state, WorkerLifecycleState::Completed);
    }
}

#[test]
fn test_dispatch_record_integration() {
    let supervisor = make_test_supervisor(5000, 500);

    // 1. Create a planned DispatchRecord
    let planned_dispatch = DispatchRecord {
        dispatch_id: Uuid::new_v4(),
        assignment_id: AssignmentId(Uuid::new_v4()),
        correlation_id: Uuid::new_v4(),
        workflow_id: Uuid::new_v4(),
        step_id: Uuid::new_v4(),
        agent_id: agenticos_core::agent::AgentId(Uuid::new_v4()),
        outcome: DispatchOutcome::Planned,
        request_id: Uuid::new_v4(),
        decision_ref: None,
        binding_hash: Some([1u8; 32]),
        plan_hash: Some([2u8; 32]),
        declared_preconditions: Vec::new(),
        declared_postconditions: Vec::new(),
        confirmation: None,
        error: None,
    };

    let record = supervisor
        .execute_dispatch_worker(&planned_dispatch, None, |ipc_fd, nonce| {
            run_worker_loop(ipc_fd, nonce, |req| match req {
                IpcMessage::InvocationRequest { dispatch_id, .. } => {
                    IpcMessage::InvocationResponse {
                        dispatch_id,
                        status: ExecutionStatus::Success,
                        output: Some(serde_json::json!({ "dispatched": true })),
                        error: None,
                    }
                }
                other => panic!("Unexpected request: {:?}", other),
            })
        })
        .expect("Dispatch worker execution succeeded");

    assert_eq!(record.dispatch_id, planned_dispatch.dispatch_id);
    assert_eq!(record.assignment_id, planned_dispatch.assignment_id);
    assert_eq!(record.lifecycle_state, WorkerLifecycleState::Completed);

    // 2. Verify non-Planned dispatch record is rejected
    let denied_dispatch = DispatchRecord {
        outcome: DispatchOutcome::Denied,
        ..planned_dispatch
    };

    let err = supervisor
        .execute_dispatch_worker(&denied_dispatch, None, |_ipc_fd, _nonce| 0)
        .unwrap_err();

    assert!(matches!(err, SupervisorError::ProtocolViolation(_)));
}
