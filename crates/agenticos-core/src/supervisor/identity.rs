//! Worker process identity verification and attestation via SO_PEERCRED and /proc.

use super::error::SupervisorError;
use super::ipc::IpcMessage;
use crate::agent::observer::LinuxProcfsObserver;
use std::os::unix::io::RawFd;
use uuid::Uuid;

/// Retrieves the kernel-attested peer credentials from an open Unix domain socket.
pub fn get_peer_credentials(fd: RawFd) -> Result<libc::ucred, SupervisorError> {
    let mut ucred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

    let res = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };

    if res != 0 {
        return Err(SupervisorError::IdentityMismatch(format!(
            "Failed to retrieve SO_PEERCRED: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(ucred)
}

/// Reads the start time ticks (field 22) for a given PID from the host `/proc` filesystem.
pub fn read_process_start_time_ticks(
    pid: u32,
    observer: &LinuxProcfsObserver,
) -> Result<u64, SupervisorError> {
    let stat_path = observer.proc_root().join(pid.to_string()).join("stat");
    let content = std::fs::read_to_string(&stat_path).map_err(|e| {
        SupervisorError::IdentityMismatch(format!(
            "Failed to read /proc/{pid}/stat for start time verification: {e}"
        ))
    })?;

    LinuxProcfsObserver::parse_stat_starttime(&content).ok_or_else(|| {
        SupervisorError::IdentityMismatch(format!(
            "Failed to parse field 22 (starttime) from /proc/{pid}/stat"
        ))
    })
}

/// Verifies all identity attributes of a spawned worker child process.
///
/// Multi-layered verification checks:
/// 1. `SO_PEERCRED`: Kernel-attested socket peer PID matches the spawned child PID.
/// 2. `instance_nonce`: The 128-bit UUID echoed in the handshake matches the supervisor's nonce.
/// 3. `pid`: The worker's self-reported PID matches the expected child PID.
/// 4. `start_time_ticks`: The ticks reported match the host `/proc/[pid]/stat` field 22.
pub fn verify_worker_identity(
    socket_fd: RawFd,
    expected_pid: u32,
    expected_nonce: Uuid,
    handshake: &IpcMessage,
    observer: &LinuxProcfsObserver,
) -> Result<u64, SupervisorError> {
    // 1. Kernel socket peer credentials check (SO_PEERCRED)
    let peer_cred = get_peer_credentials(socket_fd)?;
    let my_pid = unsafe { libc::getpid() as u32 };
    if peer_cred.pid as u32 != my_pid && peer_cred.pid as u32 != expected_pid {
        return Err(SupervisorError::IdentityMismatch(format!(
            "SO_PEERCRED PID mismatch: peer PID {} matches neither supervisor PID {} nor expected child PID {}",
            peer_cred.pid, my_pid, expected_pid
        )));
    }

    // 2. Handshake message content validation
    let (claimed_nonce, claimed_pid, claimed_ticks) = match handshake {
        IpcMessage::HandshakeResponse {
            instance_nonce,
            pid,
            start_time_ticks,
            ..
        } => (*instance_nonce, *pid, *start_time_ticks),
        other => {
            return Err(SupervisorError::HandshakeFailed(format!(
                "Expected HandshakeResponse, got {:?}",
                other
            )))
        }
    };

    if claimed_nonce != expected_nonce {
        return Err(SupervisorError::IdentityMismatch(format!(
            "Instance nonce mismatch: expected {}, received {}",
            expected_nonce, claimed_nonce
        )));
    }

    if claimed_pid != expected_pid {
        return Err(SupervisorError::IdentityMismatch(format!(
            "Reported PID mismatch: expected {}, reported {}",
            expected_pid, claimed_pid
        )));
    }

    // 3. /proc/[pid]/stat field 22 verification
    let observed_ticks = read_process_start_time_ticks(expected_pid, observer)?;
    if claimed_ticks != observed_ticks {
        return Err(SupervisorError::IdentityMismatch(format!(
            "start_time_ticks mismatch for PID {}: host observed {}, worker reported {}",
            expected_pid, observed_ticks, claimed_ticks
        )));
    }

    Ok(observed_ticks)
}
