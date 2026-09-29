use agenticos_contracts::ErrorCode;
use agenticos_core::agent::observer::LinuxProcfsObserver;
use agenticos_core::agent::AssignmentId;
use agenticos_core::sandbox::{
    apply_profile1_seccomp, build_profile1_bpf_filter, create_directory_beneath,
    delete_tree_beneath, fs_access_mask_for_abi, net_access_mask_for_abi, openat2_beneath,
    probe_landlock_abi, probe_landlock_errata, read_file_beneath, restrict_to_workspace,
    run_profile1_worker, scope_mask_for_abi, FsAccessProfile, SandboxError, AUDIT_ARCH_X86_64,
    LANDLOCK_ACCESS_FS_MAKE_DIR, LANDLOCK_ACCESS_FS_MAKE_REG, LANDLOCK_ACCESS_FS_READ_DIR,
    LANDLOCK_ACCESS_FS_READ_FILE, LANDLOCK_ACCESS_FS_REMOVE_DIR, LANDLOCK_ACCESS_FS_REMOVE_FILE,
    LANDLOCK_ACCESS_FS_WRITE_FILE, LANDLOCK_MIN_APPROVED_ABI, PROFILE1_ALLOWED_SYSCALLS,
    PROFILE1_CRITICAL_FORBIDDEN_SYSCALLS, SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO,
    SECCOMP_RET_KILL_PROCESS,
};
use agenticos_core::supervisor::{
    reap_child_process, spawn_worker_process, CapabilitySupervisor, SupervisorConfig,
    WorkerLifecycleState, MAX_FRAME_SIZE,
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

    // Forward compatibility check: unknown higher ABIs still include all 16 known bits
    let fs_mask_10 = fs_access_mask_for_abi(10);
    assert_eq!(fs_mask_10, (1 << 16) - 1);

    assert_eq!(net_access_mask_for_abi(3), 0);
    assert!(net_access_mask_for_abi(4) > 0);

    assert_eq!(scope_mask_for_abi(5), 0);
    assert!(scope_mask_for_abi(6) > 0);

    // Test capability-specific allowed masks
    let handled_fs = fs_access_mask_for_abi(abi);

    let read_mask = FsAccessProfile::ReadFile.allowed_mask(handled_fs);
    assert_eq!(
        read_mask,
        LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR
    );
    assert_eq!(read_mask & LANDLOCK_ACCESS_FS_WRITE_FILE, 0);
    assert_eq!(read_mask & LANDLOCK_ACCESS_FS_MAKE_DIR, 0);
    assert_eq!(read_mask & LANDLOCK_ACCESS_FS_REMOVE_FILE, 0);

    let mkdir_mask = FsAccessProfile::CreateDirectory.allowed_mask(handled_fs);
    assert_eq!(
        mkdir_mask,
        LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_MAKE_DIR
    );
    assert_eq!(mkdir_mask & LANDLOCK_ACCESS_FS_READ_FILE, 0);
    assert_eq!(mkdir_mask & LANDLOCK_ACCESS_FS_WRITE_FILE, 0);
    assert_eq!(mkdir_mask & LANDLOCK_ACCESS_FS_REMOVE_DIR, 0);

    let del_mask = FsAccessProfile::DeleteTree.allowed_mask(handled_fs);
    assert_eq!(
        del_mask,
        LANDLOCK_ACCESS_FS_READ_DIR
            | LANDLOCK_ACCESS_FS_REMOVE_DIR
            | LANDLOCK_ACCESS_FS_REMOVE_FILE
    );
    assert_eq!(del_mask & LANDLOCK_ACCESS_FS_WRITE_FILE, 0);
    assert_eq!(del_mask & LANDLOCK_ACCESS_FS_MAKE_DIR, 0);
    assert_eq!(del_mask & LANDLOCK_ACCESS_FS_MAKE_REG, 0);
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
fn test_openat2_directory_creation_and_deletion() {
    let dir = tempdir().expect("Create tempdir");
    let c_dir = CString::new(dir.path().to_str().unwrap()).unwrap();
    let dirfd = unsafe {
        libc::open(
            c_dir.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    assert!(dirfd >= 0);

    // Create directory
    create_directory_beneath(dirfd, "sub_dir").expect("create_directory");
    assert!(dir.path().join("sub_dir").is_dir());

    // Create file inside directory
    let child_path = dir.path().join("sub_dir").join("file.txt");
    File::create(&child_path)
        .unwrap()
        .write_all(b"sub_content")
        .unwrap();

    // Delete tree
    delete_tree_beneath(dirfd, "sub_dir").expect("delete_tree");
    assert!(!dir.path().join("sub_dir").exists());

    // Negative tests for create_directory
    assert!(matches!(
        create_directory_beneath(dirfd, "../outside"),
        Err(SandboxError::EscapeAttempt { .. })
    ));
    assert!(matches!(
        create_directory_beneath(dirfd, "/tmp/bad"),
        Err(SandboxError::EscapeAttempt { .. })
    ));

    // Negative tests for delete_tree
    assert!(matches!(
        delete_tree_beneath(dirfd, "."),
        Err(SandboxError::CapabilityExecutionFailed(_))
    ));
    assert!(matches!(
        delete_tree_beneath(dirfd, "../outside"),
        Err(SandboxError::EscapeAttempt { .. })
    ));

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

    // Critical forbidden syscalls are in filter and mapped strictly to SECCOMP_RET_KILL_PROCESS
    for &denied in PROFILE1_CRITICAL_FORBIDDEN_SYSCALLS {
        let rel_idx = filter[4..]
            .iter()
            .position(|inst| inst.k == denied as u32)
            .unwrap_or_else(|| panic!("Filter must contain denied syscall {denied}"));
        let idx = 4 + rel_idx;
        assert_eq!(
            filter[idx + 1].k,
            SECCOMP_RET_KILL_PROCESS,
            "Denied syscall {denied} must return SECCOMP_RET_KILL_PROCESS"
        );
    }

    // Allowed syscalls are in filter and mapped to SECCOMP_RET_ALLOW
    for &allowed in PROFILE1_ALLOWED_SYSCALLS {
        let rel_idx = filter[4..]
            .iter()
            .position(|inst| inst.k == allowed as u32)
            .unwrap_or_else(|| panic!("Filter must contain allowed syscall {allowed}"));
        let idx = 4 + rel_idx;
        assert_eq!(
            filter[idx + 1].k,
            SECCOMP_RET_ALLOW,
            "Allowed syscall {allowed} must return SECCOMP_RET_ALLOW"
        );
    }
}

#[test]
fn test_seccomp_critical_syscalls_kill_process_in_child() {
    // 1. execve triggers SECCOMP_RET_KILL_PROCESS (SIGSYS = 31)
    let handle = spawn_worker_process(|_ipc_fd, _nonce| {
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        apply_profile1_seccomp(true).unwrap();

        let path = CString::new("/bin/ls").unwrap();
        let argv = [path.as_ptr(), std::ptr::null()];
        unsafe { libc::execve(path.as_ptr(), argv.as_ptr(), [std::ptr::null()].as_ptr()) };
        0
    })
    .expect("Spawn worker");

    let (exit_code, signal) = reap_child_process(handle.pid, true)
        .expect("Reap child")
        .expect("Status");
    assert_eq!(signal, Some(31), "execve must be killed with SIGSYS");
    assert_eq!(exit_code, None);

    // 2. socket triggers SECCOMP_RET_KILL_PROCESS (SIGSYS = 31)
    let handle = spawn_worker_process(|_ipc_fd, _nonce| {
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        apply_profile1_seccomp(true).unwrap();

        unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        0
    })
    .expect("Spawn worker");

    let (exit_code, signal) = reap_child_process(handle.pid, true)
        .expect("Reap child")
        .expect("Status");
    assert_eq!(signal, Some(31), "socket must be killed with SIGSYS");
    assert_eq!(exit_code, None);

    // 3. fork triggers SECCOMP_RET_KILL_PROCESS (SIGSYS = 31)
    let handle = spawn_worker_process(|_ipc_fd, _nonce| {
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        apply_profile1_seccomp(true).unwrap();

        unsafe { libc::syscall(libc::SYS_fork) };
        0
    })
    .expect("Spawn worker");

    let (exit_code, signal) = reap_child_process(handle.pid, true)
        .expect("Reap child")
        .expect("Status");
    assert_eq!(signal, Some(31), "fork must be killed with SIGSYS");
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

        // 3. Restrict with Landlock for ReadFile profile
        if restrict_to_workspace(dirfd, FsAccessProfile::ReadFile).is_err() {
            unsafe { libc::close(dirfd) };
            return 2;
        }

        // 4. Attempt to open file outside workspace (e.g. /etc/passwd)
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
fn test_landlock_handled_access_classes_are_strictly_denied() {
    let dir = tempdir().expect("Create tempdir");
    let target_file = dir.path().join("target.txt");
    File::create(&target_file)
        .unwrap()
        .write_all(b"immutable")
        .unwrap();

    let workspace_path = dir.path().to_path_buf();

    let handle = spawn_worker_process(move |_ipc_fd, _nonce| {
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };

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

        // Restrict with Landlock for ReadFile: ONLY READ_FILE and READ_DIR are allowed.
        // ALL other 14 filesystem access classes are in handled_fs and MUST be denied!
        if restrict_to_workspace(dirfd, FsAccessProfile::ReadFile).is_err() {
            unsafe { libc::close(dirfd) };
            return 2;
        }

        // Negative 1: WRITE_FILE must fail with EACCES
        let f_c = CString::new("target.txt").unwrap();
        let write_fd = unsafe { libc::openat(dirfd, f_c.as_ptr(), libc::O_WRONLY) };
        if write_fd >= 0 {
            unsafe { libc::close(write_fd) };
            return 3; // FAILED: write was permitted!
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EACCES) {
            return 4;
        }

        // Negative 2: MAKE_DIR must fail with EACCES
        let d_c = CString::new("new_folder").unwrap();
        let mkdir_res = unsafe { libc::mkdirat(dirfd, d_c.as_ptr(), 0o755) };
        if mkdir_res == 0 {
            return 5; // FAILED: mkdir was permitted!
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EACCES) {
            return 6;
        }

        // Negative 3: MAKE_REG (O_CREAT) must fail with EACCES
        let new_f_c = CString::new("created.txt").unwrap();
        let creat_fd = unsafe {
            libc::openat(
                dirfd,
                new_f_c.as_ptr(),
                libc::O_CREAT | libc::O_WRONLY,
                0o644,
            )
        };
        if creat_fd >= 0 {
            unsafe { libc::close(creat_fd) };
            return 7; // FAILED: file creation was permitted!
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EACCES) {
            return 8;
        }

        // Negative 4: REMOVE_FILE must fail with EACCES
        let rm_res = unsafe { libc::unlinkat(dirfd, f_c.as_ptr(), 0) };
        if rm_res == 0 {
            return 9; // FAILED: unlink was permitted!
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EACCES) {
            return 10;
        }

        // Negative 5: MAKE_SYM (symlink creation) must fail with EACCES
        let sym_target = CString::new("target.txt").unwrap();
        let sym_link = CString::new("sym_link").unwrap();
        let sym_res = unsafe { libc::symlinkat(sym_target.as_ptr(), dirfd, sym_link.as_ptr()) };
        if sym_res == 0 {
            return 11; // FAILED: symlink creation was permitted!
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EACCES) {
            return 12;
        }

        // Positive check: READ_FILE succeeds
        let read_fd = unsafe { libc::openat(dirfd, f_c.as_ptr(), libc::O_RDONLY) };
        if read_fd < 0 {
            return 13;
        }
        unsafe { libc::close(read_fd) };

        unsafe { libc::close(dirfd) };
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
        "Handled access rights were strictly denied"
    );
}

#[test]
fn test_profile1_capability_read_file_complete_matrix() {
    let dir = tempdir().expect("Create tempdir");
    let test_file = dir.path().join("data.json");
    File::create(&test_file)
        .unwrap()
        .write_all(b"{\"key\": \"valuable_agent_data\"}")
        .unwrap();

    let sym_file = dir.path().join("sym.json");
    symlink("data.json", &sym_file).expect("Create symlink");

    let supervisor = make_test_supervisor();
    let workspace_path = dir.path().to_path_buf();

    // 1. Allowed operation succeeds
    let record = supervisor
        .execute_worker_with_request(
            Uuid::new_v4(),
            Uuid::new_v4(),
            AssignmentId(Uuid::new_v4()),
            "fs.read_file".to_string(),
            serde_json::json!({ "path": "data.json", "max_bytes": 4096 }),
            Some(Duration::from_secs(5)),
            {
                let wp = workspace_path.clone();
                move |ipc_fd, nonce| run_profile1_worker(ipc_fd, nonce, &wp, true)
            },
        )
        .expect("Worker execution");
    assert_eq!(record.lifecycle_state, WorkerLifecycleState::Completed);
    assert_eq!(record.exit_code, Some(0));

    // 2. Operation outside workspace fails
    let record = supervisor
        .execute_worker_with_request(
            Uuid::new_v4(),
            Uuid::new_v4(),
            AssignmentId(Uuid::new_v4()),
            "fs.read_file".to_string(),
            serde_json::json!({ "path": "../outside.txt", "max_bytes": 4096 }),
            Some(Duration::from_secs(5)),
            {
                let wp = workspace_path.clone();
                move |ipc_fd, nonce| run_profile1_worker(ipc_fd, nonce, &wp, true)
            },
        )
        .expect("Worker execution");
    assert_eq!(record.lifecycle_state, WorkerLifecycleState::Failed);
    assert!(record.error.unwrap().message.contains("escape attempt"));

    // 3. Symlink escape fails
    let record = supervisor
        .execute_worker_with_request(
            Uuid::new_v4(),
            Uuid::new_v4(),
            AssignmentId(Uuid::new_v4()),
            "fs.read_file".to_string(),
            serde_json::json!({ "path": "sym.json", "max_bytes": 4096 }),
            Some(Duration::from_secs(5)),
            {
                let wp = workspace_path.clone();
                move |ipc_fd, nonce| run_profile1_worker(ipc_fd, nonce, &wp, true)
            },
        )
        .expect("Worker execution");
    assert_eq!(record.lifecycle_state, WorkerLifecycleState::Failed);
    assert!(record
        .error
        .unwrap()
        .message
        .contains("Symlink traversal blocked"));
}

#[test]
fn test_profile1_capability_create_directory_complete_matrix() {
    let dir = tempdir().expect("Create tempdir");
    let supervisor = make_test_supervisor();
    let workspace_path = dir.path().to_path_buf();

    // 1. Allowed operation succeeds
    let record = supervisor
        .execute_worker_with_request(
            Uuid::new_v4(),
            Uuid::new_v4(),
            AssignmentId(Uuid::new_v4()),
            "fs.create_directory".to_string(),
            serde_json::json!({ "path": "new_dir" }),
            Some(Duration::from_secs(5)),
            {
                let wp = workspace_path.clone();
                move |ipc_fd, nonce| run_profile1_worker(ipc_fd, nonce, &wp, true)
            },
        )
        .expect("Worker execution");
    assert_eq!(record.lifecycle_state, WorkerLifecycleState::Completed);
    assert!(dir.path().join("new_dir").is_dir());

    // 2. Operation outside workspace fails
    let record = supervisor
        .execute_worker_with_request(
            Uuid::new_v4(),
            Uuid::new_v4(),
            AssignmentId(Uuid::new_v4()),
            "fs.create_directory".to_string(),
            serde_json::json!({ "path": "../outside_dir" }),
            Some(Duration::from_secs(5)),
            {
                let wp = workspace_path.clone();
                move |ipc_fd, nonce| run_profile1_worker(ipc_fd, nonce, &wp, true)
            },
        )
        .expect("Worker execution");
    assert_eq!(record.lifecycle_state, WorkerLifecycleState::Failed);
    assert!(record.error.unwrap().message.contains("escape attempt"));

    // 3. Symlink traversal fails
    let sym_dest = dir.path().join("sym_dir_link");
    symlink("new_dir", &sym_dest).expect("symlink");

    let record = supervisor
        .execute_worker_with_request(
            Uuid::new_v4(),
            Uuid::new_v4(),
            AssignmentId(Uuid::new_v4()),
            "fs.create_directory".to_string(),
            serde_json::json!({ "path": "sym_dir_link/sub" }),
            Some(Duration::from_secs(5)),
            {
                let wp = workspace_path.clone();
                move |ipc_fd, nonce| run_profile1_worker(ipc_fd, nonce, &wp, true)
            },
        )
        .expect("Worker execution");
    assert_eq!(record.lifecycle_state, WorkerLifecycleState::Failed);
    assert!(record
        .error
        .unwrap()
        .message
        .contains("Symlink traversal blocked"));
}

#[test]
fn test_profile1_capability_delete_tree_complete_matrix() {
    let dir = tempdir().expect("Create tempdir");
    let target_dir = dir.path().join("to_delete");
    std::fs::create_dir(&target_dir).unwrap();
    File::create(target_dir.join("leaf.txt"))
        .unwrap()
        .write_all(b"bye")
        .unwrap();

    let supervisor = make_test_supervisor();
    let workspace_path = dir.path().to_path_buf();

    // 1. Allowed operation succeeds
    let record = supervisor
        .execute_worker_with_request(
            Uuid::new_v4(),
            Uuid::new_v4(),
            AssignmentId(Uuid::new_v4()),
            "fs.delete_tree".to_string(),
            serde_json::json!({ "path": "to_delete" }),
            Some(Duration::from_secs(5)),
            {
                let wp = workspace_path.clone();
                move |ipc_fd, nonce| run_profile1_worker(ipc_fd, nonce, &wp, true)
            },
        )
        .expect("Worker execution");
    assert_eq!(record.lifecycle_state, WorkerLifecycleState::Completed);
    assert!(!dir.path().join("to_delete").exists());

    // 2. Operation outside workspace fails
    let record = supervisor
        .execute_worker_with_request(
            Uuid::new_v4(),
            Uuid::new_v4(),
            AssignmentId(Uuid::new_v4()),
            "fs.delete_tree".to_string(),
            serde_json::json!({ "path": "../outside" }),
            Some(Duration::from_secs(5)),
            {
                let wp = workspace_path.clone();
                move |ipc_fd, nonce| run_profile1_worker(ipc_fd, nonce, &wp, true)
            },
        )
        .expect("Worker execution");
    assert_eq!(record.lifecycle_state, WorkerLifecycleState::Failed);
    assert!(record.error.unwrap().message.contains("escape attempt"));

    // 3. Symlink traversal fails
    let dummy_file = dir.path().join("dummy.txt");
    File::create(&dummy_file).unwrap();
    let sym_target = dir.path().join("sym_dummy");
    symlink("dummy.txt", &sym_target).expect("symlink");

    let record = supervisor
        .execute_worker_with_request(
            Uuid::new_v4(),
            Uuid::new_v4(),
            AssignmentId(Uuid::new_v4()),
            "fs.delete_tree".to_string(),
            serde_json::json!({ "path": "sym_dummy" }),
            Some(Duration::from_secs(5)),
            {
                let wp = workspace_path.clone();
                move |ipc_fd, nonce| run_profile1_worker(ipc_fd, nonce, &wp, true)
            },
        )
        .expect("Worker execution");
    assert_eq!(record.lifecycle_state, WorkerLifecycleState::Failed);
    assert!(record
        .error
        .unwrap()
        .message
        .contains("Symlink traversal blocked"));
}

#[test]
fn test_profile1_worker_inherited_fd_hygiene() {
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

    let handle = spawn_worker_process(move |_ipc_fd, _nonce| {
        let mut buf = [0u8; 16];
        let n = unsafe { libc::read(parent_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n >= 0 {
            return 1;
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EBADF) {
            return 2;
        }

        0
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
            move |ipc_fd, nonce| run_profile1_worker(ipc_fd, nonce, &workspace_path, true),
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
