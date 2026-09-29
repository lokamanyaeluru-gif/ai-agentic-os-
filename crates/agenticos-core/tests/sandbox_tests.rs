use agenticos_contracts::ErrorCode;
use agenticos_core::agent::observer::LinuxProcfsObserver;
use agenticos_core::agent::AssignmentId;
use agenticos_core::sandbox::{
    apply_profile1_seccomp, build_profile1_bpf_filter, fs_access_mask_for_abi,
    net_access_mask_for_abi, openat2_beneath, probe_landlock_abi, probe_landlock_errata,
    read_file_beneath, restrict_to_workspace, run_profile1_worker, scope_mask_for_abi,
    SandboxError, AUDIT_ARCH_X86_64, LANDLOCK_MIN_APPROVED_ABI, PROFILE1_ALLOWED_SYSCALLS,
    PROFILE1_DENIED_SYSCALLS, SECCOMP_RET_ERRNO, SECCOMP_RET_KILL_PROCESS,
};
use agenticos_core::supervisor::{
    reap_child_process, spawn_worker_process, CapabilitySupervisor, SupervisorConfig,
    WorkerFailureReason, WorkerLifecycleState, MAX_FRAME_SIZE,
};
use std::ffi::CString;
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::symlink;
use std::time::Duration;
use tempfile::tempdir;
use uuid::Uuid;

fn make_test_supervisor() -> CapabilitySupervisor {
    let config = SupervisorConfig {
        default_timeout: Duration::from_secs(5),
        max_timeout: Duration::from_secs(30),
        grace_period: Duration::from_millis(500),
        max_frame_bytes: MAX_FRAME_SIZE,
        max_output_bytes: 4 * 1024 * 1024,
        log_buffer_capacity: 64 * 1024,
    };
    CapabilitySupervisor::new(config, LinuxProcfsObserver::default())
}

#[test]
fn test_landlock_abi_discovery_and_masks() {
    let abi = probe_landlock_abi().expect("Host kernel must support Landlock");
    assert!(
        abi >= LANDLOCK_MIN_APPROVED_ABI,
        "Discovered ABI {abi} must be >= {LANDLOCK_MIN_APPROVED_ABI}"
    );

    let errata = probe_landlock_errata();
    println!("Probed Landlock ABI: {abi}, Errata: 0x{errata:x}");

    // Test feature bitmasks for ABIs
    let fs_mask_1 = fs_access_mask_for_abi(1);
    assert_eq!(fs_mask_1, (1 << 13) - 1);

    let fs_mask_2 = fs_access_mask_for_abi(2);
    assert_eq!(fs_mask_2, (1 << 15) - 1);

    let fs_mask_5 = fs_access_mask_for_abi(5);
    assert_eq!(fs_mask_5, (1 << 16) - 1);

    // Forward compatibility check: unknown higher ABIs still include known bits
    let fs_mask_10 = fs_access_mask_for_abi(10);
    assert_eq!(fs_mask_10, (1 << 16) - 1);

    assert_eq!(net_access_mask_for_abi(3), 0);
    assert!(net_access_mask_for_abi(4) > 0);

    assert_eq!(scope_mask_for_abi(5), 0);
    assert!(scope_mask_for_abi(6) > 0);
}

#[test]
fn test_openat2_beneath_happy_path() {
    let dir = tempdir().expect("Create tempdir");
    let file_path = dir.path().join("test.txt");
    {
        let mut f = File::create(&file_path).expect("Create test file");
        f.write_all(b"Hello sandboxed world!")
            .expect("Write content");
    }

    let c_dir = CString::new(dir.path().to_str().unwrap()).unwrap();
    let dirfd = unsafe {
        libc::open(
            c_dir.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    assert!(dirfd >= 0, "Opened dirfd");

    let fd = openat2_beneath(dirfd, "test.txt", libc::O_RDONLY)
        .expect("openat2_beneath succeeds for child file");
    assert!(fd >= 0);
    unsafe { libc::close(fd) };

    let content = read_file_beneath(dirfd, "test.txt", 1024).expect("read_file_beneath");
    assert_eq!(content, b"Hello sandboxed world!");

    unsafe { libc::close(dirfd) };
}

#[test]
fn test_openat2_beneath_blocks_directory_traversal() {
    let dir = tempdir().expect("Create tempdir");
    let c_dir = CString::new(dir.path().to_str().unwrap()).unwrap();
    let dirfd = unsafe {
        libc::open(
            c_dir.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    assert!(dirfd >= 0);

    // Escape via ../
    let res = openat2_beneath(dirfd, "../outside.txt", libc::O_RDONLY);
    match res {
        Err(SandboxError::EscapeAttempt { path }) => {
            assert_eq!(path, "../outside.txt");
        }
        other => panic!("Expected EscapeAttempt error, got: {:?}", other),
    }

    // Escape via absolute path
    let res = openat2_beneath(dirfd, "/etc/passwd", libc::O_RDONLY);
    match res {
        Err(SandboxError::EscapeAttempt { path }) => {
            assert_eq!(path, "/etc/passwd");
        }
        other => panic!("Expected EscapeAttempt error, got: {:?}", other),
    }

    unsafe { libc::close(dirfd) };
}

#[test]
fn test_openat2_beneath_blocks_symlinks() {
    let dir = tempdir().expect("Create tempdir");
    let target_path = dir.path().join("real.txt");
    File::create(&target_path)
        .unwrap()
        .write_all(b"data")
        .unwrap();

    let symlink_path = dir.path().join("sym_internal.txt");
    symlink("real.txt", &symlink_path).expect("Create symlink");

    let escape_symlink = dir.path().join("sym_escape.txt");
    symlink("/etc/passwd", &escape_symlink).expect("Create escape symlink");

    let c_dir = CString::new(dir.path().to_str().unwrap()).unwrap();
    let dirfd = unsafe {
        libc::open(
            c_dir.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    assert!(dirfd >= 0);

    // Symlink internal
    let res = openat2_beneath(dirfd, "sym_internal.txt", libc::O_RDONLY);
    match res {
        Err(SandboxError::SymlinkTraversalBlocked { path }) => {
            assert_eq!(path, "sym_internal.txt");
        }
        other => panic!("Expected SymlinkTraversalBlocked, got: {:?}", other),
    }

    // Symlink external
    let res = openat2_beneath(dirfd, "sym_escape.txt", libc::O_RDONLY);
    match res {
        Err(SandboxError::SymlinkTraversalBlocked { .. })
        | Err(SandboxError::EscapeAttempt { .. }) => {}
        other => panic!(
            "Expected SymlinkTraversalBlocked or EscapeAttempt, got: {:?}",
            other
        ),
    }

    unsafe { libc::close(dirfd) };
}

#[test]
fn test_seccomp_bpf_filter_structure() {
    let filter = build_profile1_bpf_filter(SECCOMP_RET_ERRNO | (libc::EPERM as u32));
    assert!(
        filter.len() > 50,
        "Filter must have sufficient instructions for denied and allowed syscalls"
    );

    // Instruction 0 loads arch
    assert_eq!(filter[0].k, 4);
    // Instruction 1 checks AUDIT_ARCH_X86_64
    assert_eq!(filter[1].k, AUDIT_ARCH_X86_64);
    // Instruction 2 kills on mismatch
    assert_eq!(filter[2].k, SECCOMP_RET_KILL_PROCESS);

    // Denied syscalls are in filter
    for &denied in PROFILE1_DENIED_SYSCALLS {
        assert!(
            filter.iter().any(|inst| inst.k == denied as u32),
            "Filter must contain denied syscall {denied}"
        );
    }

    // Allowed syscalls are in filter
    for &allowed in PROFILE1_ALLOWED_SYSCALLS {
        assert!(
            filter.iter().any(|inst| inst.k == allowed as u32),
            "Filter must contain allowed syscall {allowed}"
        );
    }
}

#[test]
fn test_seccomp_denied_syscalls_fail_with_eperm_in_child() {
    let handle = spawn_worker_process(|_ipc_fd, _nonce| {
        // Step 1: Set PR_SET_NO_NEW_PRIVS
        let res = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if res != 0 {
            return 1;
        }

        // Step 2: Install Seccomp filter with EPERM on violation
        if apply_profile1_seccomp(false).is_err() {
            return 2;
        }

        // Test 1: socket creation must return EPERM
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        if sock >= 0 {
            unsafe { libc::close(sock) };
            return 3; // FAILED: socket was permitted
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EPERM) {
            return 4; // FAILED: expected EPERM
        }

        // Test 2: fork / clone must return EPERM
        let fork_res = unsafe { libc::syscall(libc::SYS_fork) };
        if fork_res >= 0 {
            return 5; // FAILED: fork succeeded
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EPERM) {
            return 6;
        }

        // Test 3: ptrace must return EPERM
        let ptrace_res = unsafe { libc::syscall(libc::SYS_ptrace, 0, 0, 0, 0) };
        if ptrace_res >= 0 {
            return 7;
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EPERM) {
            return 8;
        }

        // Test 4: allowed syscalls like getpid must still work
        let pid = unsafe { libc::getpid() };
        if pid <= 0 {
            return 9;
        }

        0 // SUCCESS
    })
    .expect("Spawn worker process");

    let (exit_code, signal) = reap_child_process(handle.pid, true)
        .expect("Reap child")
        .expect("Status");

    assert_eq!(signal, None);
    assert_eq!(
        exit_code,
        Some(0),
        "Child executed seccomp tests and exited with 0"
    );
}

#[test]
fn test_seccomp_kill_on_violation() {
    let handle = spawn_worker_process(|_ipc_fd, _nonce| {
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        apply_profile1_seccomp(true).unwrap();

        // Trigger denied syscall in KILL mode -> kernel terminates process immediately with SIGSYS
        unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        0
    })
    .expect("Spawn worker process");

    let (exit_code, signal) = reap_child_process(handle.pid, true)
        .expect("Reap child")
        .expect("Status");

    // Process was killed by SIGSYS (signal 31)
    assert_eq!(signal, Some(31));
    assert_eq!(exit_code, None);
}

#[test]
fn test_landlock_filesystem_containment_in_child() {
    let dir = tempdir().expect("Create tempdir");
    let allowed_file = dir.path().join("workspace_file.txt");
    File::create(&allowed_file)
        .unwrap()
        .write_all(b"permitted content")
        .unwrap();

    let workspace_path = dir.path().to_path_buf();

    let handle = spawn_worker_process(move |_ipc_fd, _nonce| {
        // 1. PR_SET_NO_NEW_PRIVS
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };

        // 2. Open workspace dirfd
        let c_path = CString::new(workspace_path.to_str().unwrap()).unwrap();
        let dirfd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if dirfd < 0 {
            return 1;
        }

        // 3. Restrict with Landlock
        if restrict_to_workspace(dirfd, true).is_err() {
            unsafe { libc::close(dirfd) };
            return 2;
        }

        // 4. Attempt to open file outside workspace (e.g. /etc/passwd or /tmp)
        let outside = CString::new("/etc/passwd").unwrap();
        let outside_fd = unsafe { libc::open(outside.as_ptr(), libc::O_RDONLY) };
        if outside_fd >= 0 {
            unsafe {
                libc::close(outside_fd);
                libc::close(dirfd);
            }
            return 3; // FAILED: Landlock allowed access to /etc/passwd!
        }

        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EACCES) {
            unsafe { libc::close(dirfd) };
            return 4; // Expected EACCES from Landlock
        }

        // 5. Access inside workspace must still succeed
        let in_file = CString::new("workspace_file.txt").unwrap();
        let in_fd = unsafe { libc::openat(dirfd, in_file.as_ptr(), libc::O_RDONLY) };
        if in_fd < 0 {
            unsafe { libc::close(dirfd) };
            return 5;
        }

        unsafe {
            libc::close(in_fd);
            libc::close(dirfd);
        }

        0 // SUCCESS
    })
    .expect("Spawn worker");

    let (exit_code, signal) = reap_child_process(handle.pid, true)
        .expect("Reap child")
        .expect("Status");

    assert_eq!(signal, None);
    assert_eq!(
        exit_code,
        Some(0),
        "Landlock strictly confined process to workspace"
    );
}

#[test]
fn test_profile1_worker_end_to_end_read_file_success() {
    let dir = tempdir().expect("Create tempdir");
    let test_file = dir.path().join("data.json");
    File::create(&test_file)
        .unwrap()
        .write_all(b"{\"key\": \"valuable_agent_data\"}")
        .unwrap();

    let supervisor = make_test_supervisor();
    let execution_id = Uuid::new_v4();
    let dispatch_id = Uuid::new_v4();
    let assignment_id = AssignmentId(Uuid::new_v4());
    let workspace_path = dir.path().to_path_buf();

    let record = supervisor
        .execute_worker_with_request(
            execution_id,
            dispatch_id,
            assignment_id,
            "fs.read_file".to_string(),
            serde_json::json!({ "path": "data.json", "max_bytes": 4096 }),
            Some(Duration::from_secs(5)),
            move |ipc_fd, nonce| run_profile1_worker(ipc_fd, nonce, &workspace_path, true, false),
        )
        .expect("Execution succeeded");

    assert_eq!(record.execution_id, execution_id);
    assert_eq!(record.dispatch_id, dispatch_id);
    assert_eq!(record.lifecycle_state, WorkerLifecycleState::Completed);
    assert_eq!(record.exit_code, Some(0));
    assert!(record.error.is_none());
}

#[test]
fn test_profile1_worker_escape_attempt_reported_to_supervisor() {
    let dir = tempdir().expect("Create tempdir");
    let supervisor = make_test_supervisor();
    let execution_id = Uuid::new_v4();
    let dispatch_id = Uuid::new_v4();
    let assignment_id = AssignmentId(Uuid::new_v4());
    let workspace_path = dir.path().to_path_buf();

    let record = supervisor
        .execute_worker_with_request(
            execution_id,
            dispatch_id,
            assignment_id,
            "fs.read_file".to_string(),
            serde_json::json!({ "path": "../outside.txt", "max_bytes": 4096 }),
            Some(Duration::from_secs(5)),
            move |ipc_fd, nonce| run_profile1_worker(ipc_fd, nonce, &workspace_path, true, false),
        )
        .expect("Worker execution");

    assert_eq!(record.lifecycle_state, WorkerLifecycleState::Failed);
    assert_eq!(
        record.failure_reason,
        Some(WorkerFailureReason::AbnormalExit)
    );
    assert!(record.error.is_some());
    let err = record.error.unwrap();
    assert_eq!(err.code, ErrorCode::CapabilityExecutionFailed);
    assert!(err
        .message
        .contains("Path traversal escape attempt blocked"));
}

#[test]
fn test_profile1_worker_symlink_blocked_reported_to_supervisor() {
    let dir = tempdir().expect("Create tempdir");
    let real_file = dir.path().join("real.txt");
    File::create(&real_file)
        .unwrap()
        .write_all(b"secret")
        .unwrap();

    let sym_file = dir.path().join("sym.txt");
    symlink("real.txt", &sym_file).expect("Create symlink");

    let supervisor = make_test_supervisor();
    let execution_id = Uuid::new_v4();
    let dispatch_id = Uuid::new_v4();
    let assignment_id = AssignmentId(Uuid::new_v4());
    let workspace_path = dir.path().to_path_buf();

    let record = supervisor
        .execute_worker_with_request(
            execution_id,
            dispatch_id,
            assignment_id,
            "fs.read_file".to_string(),
            serde_json::json!({ "path": "sym.txt", "max_bytes": 4096 }),
            Some(Duration::from_secs(5)),
            move |ipc_fd, nonce| run_profile1_worker(ipc_fd, nonce, &workspace_path, true, false),
        )
        .expect("Worker execution");

    assert_eq!(record.lifecycle_state, WorkerLifecycleState::Failed);
    assert!(record.error.is_some());
    let err = record.error.unwrap();
    assert_eq!(err.code, ErrorCode::CapabilityExecutionFailed);
    assert!(err.message.contains("Symlink traversal blocked"));
}

#[test]
fn test_profile1_worker_non_existent_file_reported() {
    let dir = tempdir().expect("Create tempdir");
    let supervisor = make_test_supervisor();
    let execution_id = Uuid::new_v4();
    let dispatch_id = Uuid::new_v4();
    let assignment_id = AssignmentId(Uuid::new_v4());
    let workspace_path = dir.path().to_path_buf();

    let record = supervisor
        .execute_worker_with_request(
            execution_id,
            dispatch_id,
            assignment_id,
            "fs.read_file".to_string(),
            serde_json::json!({ "path": "does_not_exist.txt", "max_bytes": 4096 }),
            Some(Duration::from_secs(5)),
            move |ipc_fd, nonce| run_profile1_worker(ipc_fd, nonce, &workspace_path, true, false),
        )
        .expect("Worker execution");

    assert_eq!(record.lifecycle_state, WorkerLifecycleState::Failed);
    assert!(record.error.is_some());
    let err = record.error.unwrap();
    assert_eq!(err.code, ErrorCode::CapabilityExecutionFailed);
    assert!(err.message.contains("openat2 failed"));
}

#[test]
fn test_profile1_worker_unsupported_capability_fails() {
    let dir = tempdir().expect("Create tempdir");
    let supervisor = make_test_supervisor();
    let execution_id = Uuid::new_v4();
    let dispatch_id = Uuid::new_v4();
    let assignment_id = AssignmentId(Uuid::new_v4());
    let workspace_path = dir.path().to_path_buf();

    let record = supervisor
        .execute_worker_with_request(
            execution_id,
            dispatch_id,
            assignment_id,
            "unsupported.action".to_string(),
            serde_json::json!({}),
            Some(Duration::from_secs(5)),
            move |ipc_fd, nonce| run_profile1_worker(ipc_fd, nonce, &workspace_path, true, false),
        )
        .expect("Worker execution");

    assert_eq!(record.lifecycle_state, WorkerLifecycleState::Failed);
    assert!(record.error.is_some());
    let err = record.error.unwrap();
    assert_eq!(err.code, ErrorCode::CapabilityExecutionFailed);
    assert!(err
        .message
        .contains("Unsupported capability in Profile 1 worker"));
}

#[test]
fn test_profile1_worker_inherited_fd_hygiene() {
    // Open a sensitive file in the parent test process to simulate a leaked FD
    let sensitive_file = tempdir().expect("Sensitive dir");
    let secret_path = sensitive_file.path().join("parent_secret.txt");
    File::create(&secret_path)
        .unwrap()
        .write_all(b"super_secret_parent_data")
        .unwrap();

    let c_path = CString::new(secret_path.to_str().unwrap()).unwrap();
    let raw_fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY) };
    assert!(raw_fd >= 0, "Opened raw_fd");
    let parent_fd = unsafe { libc::fcntl(raw_fd, libc::F_DUPFD, 10) };
    unsafe { libc::close(raw_fd) };
    assert!(parent_fd >= 10, "Parent FD is >= 10");

    // Spawn a worker process and verify that close_range_above(4) in spawn_worker_process
    // closed this descriptor in the child
    let handle = spawn_worker_process(move |_ipc_fd, _nonce| {
        // Attempting to read from parent_fd must fail with EBADF because close_range_above(4) closed it
        let mut buf = [0u8; 16];
        let n = unsafe { libc::read(parent_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n >= 0 {
            return 1; // FAILED: Leaked parent FD was still open!
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EBADF) {
            return 2; // Expected EBADF
        }

        0 // SUCCESS
    })
    .expect("Spawn worker");

    unsafe { libc::close(parent_fd) };

    let (exit_code, signal) = reap_child_process(handle.pid, true)
        .expect("Reap child")
        .expect("Status");

    assert_eq!(signal, None);
    assert_eq!(
        exit_code,
        Some(0),
        "Inherited FD hygiene confirmed: FD >= 4 closed"
    );
}
