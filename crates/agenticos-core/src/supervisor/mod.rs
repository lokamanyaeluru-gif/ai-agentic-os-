//! Layer 7 CapabilitySupervisor and Sandboxed Worker Foundations.
//!
//! Provides the out-of-process execution harness, bidirectional IPC framing (ADR-0007),
//! SO_PEERCRED worker identity verification, deterministic descriptor hygiene,
//! bounded diagnostic stdio capture, and timeout escalation.

pub mod error;
pub mod identity;
pub mod ipc;
pub mod lifecycle;
pub mod process;
pub mod ring_buffer;
#[allow(clippy::module_inception)]
pub mod supervisor;

pub use error::SupervisorError;
pub use identity::{get_peer_credentials, read_process_start_time_ticks, verify_worker_identity};
pub use ipc::{
    create_seqpacket_socketpair, read_frame, receive_message, send_message, write_frame, IpcError,
    IpcMessage, DEFAULT_MAX_OUTPUT_SIZE, MAX_FRAME_SIZE,
};
pub use lifecycle::{WorkerExecutionRecord, WorkerFailureReason, WorkerLifecycleState};
pub use process::{
    close_range_above, create_pipe, reap_child_process, run_worker_loop, spawn_worker_process,
    terminate_escalate, WorkerHandle,
};
pub use ring_buffer::{RollingLogBuffer, DEFAULT_LOG_BUFFER_CAPACITY};
pub use supervisor::{CapabilitySupervisor, SupervisorConfig};
