//! Unix domain socketpair IPC transport and framing adhering to ADR-0007 §2.

use crate::capability::ExecutionStatus;
use agenticos_contracts::{ErrorPayload, ProtocolVersion};
use serde::{Deserialize, Serialize};
use std::os::unix::io::RawFd;
use thiserror::Error;
use uuid::Uuid;

/// Maximum permissible transport frame size: 16 MiB (ADR-0007 §2.2).
pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// Default capability invocation output ceiling: 4 MiB (Phase 4.0 specification).
pub const DEFAULT_MAX_OUTPUT_SIZE: usize = 4 * 1024 * 1024;

/// IPC transport and framing errors.
#[derive(Debug, Error)]
pub enum IpcError {
    #[error("I/O error during IPC: {0}")]
    Io(#[from] std::io::Error),

    #[error("Frame length {0} exceeds maximum permissible ceiling of {MAX_FRAME_SIZE} bytes")]
    FrameTooLarge(usize),

    #[error("Premature EOF encountered while reading 4-byte length prefix")]
    TruncatedHeader,

    #[error(
        "Premature EOF while reading payload: expected {expected} bytes, received {received} bytes"
    )]
    TruncatedPayload { expected: usize, received: usize },

    #[error(
        "Datagram length mismatch: declared {declared} bytes, but datagram has {actual} bytes"
    )]
    DatagramLengthMismatch { declared: usize, actual: usize },

    #[error("IPC connection closed cleanly by peer")]
    ConnectionClosed,

    #[error("JSON serialization/deserialization failure: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Invalid UTF-8 payload: {0}")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),
}

/// Strongly typed IPC messages exchanged between CapabilitySupervisor and Worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload", deny_unknown_fields)]
pub enum IpcMessage {
    /// Initial handshake request sent from Supervisor to Worker.
    HandshakeRequest {
        protocol_version: ProtocolVersion,
        instance_nonce: Uuid,
    },

    /// Handshake response returned by Worker to Supervisor.
    HandshakeResponse {
        protocol_version: ProtocolVersion,
        instance_nonce: Uuid,
        pid: u32,
        start_time_ticks: u64,
    },

    /// Capability invocation payload dispatched from Supervisor to Worker.
    InvocationRequest {
        dispatch_id: Uuid,
        capability_id: String,
        arguments: serde_json::Value,
    },

    /// Execution result payload returned from Worker to Supervisor.
    InvocationResponse {
        dispatch_id: Uuid,
        status: ExecutionStatus,
        output: Option<serde_json::Value>,
        error: Option<ErrorPayload>,
    },

    /// Liveness verification ping.
    Ping { nonce: u64 },

    /// Liveness verification pong.
    Pong { nonce: u64 },
}

/// Allocates a connected, bi-directional Unix domain socketpair with SOCK_SEQPACKET and SOCK_CLOEXEC.
pub fn create_seqpacket_socketpair() -> Result<(RawFd, RawFd), IpcError> {
    let mut fds = [0 as RawFd; 2];
    let res = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if res != 0 {
        return Err(IpcError::Io(std::io::Error::last_os_error()));
    }
    Ok((fds[0], fds[1]))
}

/// Writes a length-prefixed frame to the given descriptor adhering to ADR-0007 §2.
///
/// Encodes a 4-byte big-endian length prefix followed by the exact payload bytes.
pub fn write_frame(fd: RawFd, payload: &[u8]) -> Result<(), IpcError> {
    if payload.len() > MAX_FRAME_SIZE {
        return Err(IpcError::FrameTooLarge(payload.len()));
    }

    let len_prefix = (payload.len() as u32).to_be_bytes();
    let mut buffer = Vec::with_capacity(4 + payload.len());
    buffer.extend_from_slice(&len_prefix);
    buffer.extend_from_slice(payload);

    let mut written = 0;
    while written < buffer.len() {
        let n = unsafe {
            libc::write(
                fd,
                buffer[written..].as_ptr() as *const libc::c_void,
                buffer.len() - written,
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(IpcError::Io(err));
        }
        if n == 0 {
            return Err(IpcError::ConnectionClosed);
        }
        written += n as usize;
    }

    Ok(())
}

/// Reads a length-prefixed frame from the given descriptor adhering to ADR-0007 §2.
///
/// Validates that the declared length does not exceed `max_size` (bounded by MAX_FRAME_SIZE),
/// reads the exact payload, and returns the payload byte vector.
pub fn read_frame(fd: RawFd, max_size: usize) -> Result<Vec<u8>, IpcError> {
    let ceiling = max_size.min(MAX_FRAME_SIZE);

    // 1. Peek 4-byte big-endian length prefix and probe total datagram length via MSG_PEEK | MSG_TRUNC
    let mut len_buf = [0u8; 4];
    let actual_datagram_len: usize;
    loop {
        let n = unsafe {
            libc::recv(
                fd,
                len_buf.as_mut_ptr() as *mut libc::c_void,
                4,
                libc::MSG_PEEK | libc::MSG_TRUNC,
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(IpcError::Io(err));
        }
        if n == 0 {
            return Err(IpcError::ConnectionClosed);
        }
        if n < 4 {
            let mut discard = [0u8; 4];
            let _ =
                unsafe { libc::recv(fd, discard.as_mut_ptr() as *mut libc::c_void, n as usize, 0) };
            return Err(IpcError::TruncatedHeader);
        }
        actual_datagram_len = n as usize;
        break;
    }

    let declared_len = u32::from_be_bytes(len_buf) as usize;
    if declared_len > ceiling || actual_datagram_len > 4 + ceiling {
        let mut discard = [0u8; 4];
        let _ = unsafe { libc::recv(fd, discard.as_mut_ptr() as *mut libc::c_void, 4, 0) };
        return Err(IpcError::FrameTooLarge(
            declared_len.max(actual_datagram_len.saturating_sub(4)),
        ));
    }

    // Verify exact datagram length matches declared 4-byte header + payload (ADR-0007 regression check)
    let expected_total_len = 4 + declared_len;
    if actual_datagram_len != expected_total_len {
        let mut discard = vec![0u8; actual_datagram_len];
        let _ = unsafe {
            libc::recv(
                fd,
                discard.as_mut_ptr() as *mut libc::c_void,
                actual_datagram_len,
                0,
            )
        };
        return Err(IpcError::DatagramLengthMismatch {
            declared: declared_len,
            actual: actual_datagram_len.saturating_sub(4),
        });
    }

    // 2. Read full packet (4 bytes header + declared_len bytes payload)
    let mut full_buf = vec![0u8; expected_total_len];
    let mut read_bytes = 0;
    while read_bytes < expected_total_len {
        let n = unsafe {
            libc::recv(
                fd,
                full_buf[read_bytes..].as_mut_ptr() as *mut libc::c_void,
                expected_total_len - read_bytes,
                0,
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(IpcError::Io(err));
        }
        if n == 0 {
            return Err(IpcError::TruncatedPayload {
                expected: declared_len,
                received: read_bytes.saturating_sub(4),
            });
        }
        read_bytes += n as usize;
    }

    Ok(full_buf[4..].to_vec())
}

/// Serializes and sends an IpcMessage across the descriptor.
pub fn send_message(fd: RawFd, message: &IpcMessage) -> Result<(), IpcError> {
    let json_bytes = serde_json::to_vec(message)?;
    write_frame(fd, &json_bytes)
}

/// Reads and deserializes an IpcMessage from the descriptor.
pub fn receive_message(fd: RawFd, max_size: usize) -> Result<IpcMessage, IpcError> {
    let payload = read_frame(fd, max_size)?;
    let message: IpcMessage = serde_json::from_slice(&payload)?;
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socketpair_roundtrip() {
        let (fd_a, fd_b) = create_seqpacket_socketpair().expect("socketpair created");

        let msg = IpcMessage::HandshakeRequest {
            protocol_version: ProtocolVersion::V1_0,
            instance_nonce: Uuid::new_v4(),
        };

        send_message(fd_a, &msg).expect("send succeeded");
        let received = receive_message(fd_b, MAX_FRAME_SIZE).expect("recv succeeded");

        assert_eq!(msg, received);

        unsafe {
            libc::close(fd_a);
            libc::close(fd_b);
        }
    }

    #[test]
    fn test_frame_too_large_rejected() {
        let (fd_a, fd_b) = create_seqpacket_socketpair().expect("socketpair created");

        let oversized_len = (MAX_FRAME_SIZE + 1) as u32;
        let len_bytes = oversized_len.to_be_bytes();
        let n = unsafe { libc::write(fd_a, len_bytes.as_ptr() as *const libc::c_void, 4) };
        assert_eq!(n, 4);

        let err = read_frame(fd_b, MAX_FRAME_SIZE).unwrap_err();
        match err {
            IpcError::FrameTooLarge(len) => assert_eq!(len, MAX_FRAME_SIZE + 1),
            other => panic!("Expected FrameTooLarge, got {:?}", other),
        }

        unsafe {
            libc::close(fd_a);
            libc::close(fd_b);
        }
    }
}
