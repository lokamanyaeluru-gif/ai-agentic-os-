//! Process observation abstraction for Layer 5 (Global Agent Manager).
//!
//! Provides traits and implementations for observing host OS process liveness
//! and detecting stale agent registrations and PID recycling using actual host evidence.
//!
//! # Architectural Boundary (CRITICAL)
//! - Process observation is strictly an **instance-disambiguation and lifecycle tracking mechanism**.
//! - It is **NOT an authentication or attestation primitive**.
//! - Agent process authenticity is established by the approved IPC registration/handshake
//!   mechanism and kernel-enforced peer credential verification from ADR-0002 (`SO_PEERCRED`
//!   over local Unix Domain Sockets or private descriptor inheritance via `socketpair(2)`).
//! - Production implementations must NEVER invent "Dead" merely because the manager restarted.
//! - A process may be marked `Dead` only when the observer has actual host evidence that
//!   the process no longer exists.
//! - When host evidence is unavailable, the observer must report `Unknown`.
//! - `Unknown` must be fail-closed for recovery: no state mutations, no assignment failures,
//!   and no restart retry consumption.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

use crate::agent::identity::ProcessIdentity;

/// Observed status of a host OS process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProcessLiveness {
    /// Agent has not been spawned yet (no PID or start time ticks recorded).
    Unspawned,

    /// Process is alive and verified with matching `start_time_ticks`.
    Alive,

    /// Process is dead (actual host evidence confirms the PID no longer exists).
    Dead,

    /// PID exists on host, but belongs to a different process (`start_time_ticks` mismatch).
    /// Indicates the host OS recycled the PID following an earlier process termination.
    Recycled { observed_ticks: u64 },

    /// Process liveness could not be definitively determined from host evidence.
    Unknown,
}

impl ProcessLiveness {
    /// Returns true if the process is confirmed alive.
    pub const fn is_alive(&self) -> bool {
        matches!(self, Self::Alive)
    }

    /// Returns true if the process has terminated or was recycled by the host OS.
    pub const fn is_dead_or_recycled(&self) -> bool {
        matches!(self, Self::Dead | Self::Recycled { .. })
    }

    /// Returns true if process liveness is unknown.
    pub const fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}

/// Narrow abstraction for observing host OS process liveness.
///
/// Follows ADR-0002 and Phase 2.0 specifications:
/// Disambiguation uses the tuple `(pid, start_time_ticks, instance_nonce)` to distinguish
/// local process instances within an OS boot session and detect stale registrations across crashes.
pub trait ProcessObserver: Send + Sync {
    /// Determines the liveness of the process described by the given `ProcessIdentity`.
    fn check_liveness(&self, identity: &ProcessIdentity) -> ProcessLiveness;
}

/// Genuine read-only Linux procfs process observer.
///
/// Inspects `/proc/[pid]/stat` to verify that the process exists on the host and that
/// field 22 (`starttime` in clock ticks since boot) matches `start_time_ticks`.
///
/// Zero writable/general filesystem operations outside the authoritative SQLite registry.
/// The production process observer performs read-only procfs observation of `/proc/[pid]/stat`.
#[derive(Debug, Clone)]
pub struct LinuxProcfsObserver {
    proc_root: PathBuf,
}

impl Default for LinuxProcfsObserver {
    fn default() -> Self {
        Self {
            proc_root: PathBuf::from("/proc"),
        }
    }
}

impl LinuxProcfsObserver {
    /// Creates a new `LinuxProcfsObserver` pointing to the standard `/proc` filesystem.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an observer pointing to a custom procfs root path (useful for deterministic tests).
    pub fn with_proc_root(proc_root: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
        }
    }

    /// Returns the active procfs root path.
    pub fn proc_root(&self) -> &Path {
        &self.proc_root
    }

    /// Parses field 22 (`starttime`) from `/proc/[pid]/stat` content.
    ///
    /// The `comm` field (field 2) can contain spaces and parentheses. The standard robust parser
    /// finds the last `')'` character and splits the remainder by whitespace.
    /// Field 3 (`state`) is index 0; field 22 (`starttime`) is index 19.
    pub fn parse_stat_starttime(stat_content: &str) -> Option<u64> {
        let after_comm = stat_content.rfind(')')?;
        let rest = &stat_content[after_comm + 1..];
        let fields: Vec<&str> = rest.split_whitespace().collect();
        fields.get(19)?.parse::<u64>().ok()
    }
}

impl ProcessObserver for LinuxProcfsObserver {
    fn check_liveness(&self, identity: &ProcessIdentity) -> ProcessLiveness {
        let (pid, expected_ticks) = match (identity.pid, identity.start_time_ticks) {
            (Some(p), Some(t)) => (p, t),
            _ => return ProcessLiveness::Unspawned,
        };

        let stat_path = self.proc_root.join(pid.to_string()).join("stat");
        match std::fs::read_to_string(&stat_path) {
            Ok(content) => match Self::parse_stat_starttime(&content) {
                Some(observed_ticks) => {
                    if observed_ticks == expected_ticks {
                        ProcessLiveness::Alive
                    } else {
                        ProcessLiveness::Recycled { observed_ticks }
                    }
                }
                None => ProcessLiveness::Unknown,
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Actual host evidence that the PID no longer exists
                ProcessLiveness::Dead
            }
            Err(_) => {
                // Permission denied, I/O error, or transient failure -> fail closed
                ProcessLiveness::Unknown
            }
        }
    }
}

/// Default production process observer.
///
/// On Linux, inspects the real host `/proc` filesystem read-only to verify process existence
/// and match `start_time_ticks` against field 22 of `/proc/[pid]/stat`.
///
/// On non-Linux platforms or when host evidence cannot be accessed, returns `ProcessLiveness::Unknown`
/// so that startup reconciliation fails closed non-destructively without inventing process death.
#[derive(Debug, Clone, Default)]
pub struct DefaultProcessObserver {
    #[cfg(target_os = "linux")]
    inner: LinuxProcfsObserver,
}

impl DefaultProcessObserver {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ProcessObserver for DefaultProcessObserver {
    fn check_liveness(&self, identity: &ProcessIdentity) -> ProcessLiveness {
        if !identity.is_spawned() {
            return ProcessLiveness::Unspawned;
        }

        #[cfg(target_os = "linux")]
        {
            self.inner.check_liveness(identity)
        }

        #[cfg(not(target_os = "linux"))]
        {
            ProcessLiveness::Unknown
        }
    }
}

/// Explicit fail-closed observer that returns `ProcessLiveness::Unknown` for any spawned process.
///
/// Used to verify fail-closed non-destructive startup recovery behavior.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnknownProcessObserver;

impl UnknownProcessObserver {
    pub const fn new() -> Self {
        Self
    }
}

impl ProcessObserver for UnknownProcessObserver {
    fn check_liveness(&self, identity: &ProcessIdentity) -> ProcessLiveness {
        if !identity.is_spawned() {
            ProcessLiveness::Unspawned
        } else {
            ProcessLiveness::Unknown
        }
    }
}

/// Deterministic mock process observer for test suites and simulations.
///
/// Allows configuring known live processes with `(pid, start_time_ticks)`,
/// simulating process death, PID recycling, unspawned states, and unknown host states.
#[derive(Debug, Default)]
pub struct MockProcessObserver {
    /// Map of PID -> observed start_time_ticks for currently alive processes.
    live_processes: RwLock<HashMap<u32, u64>>,
    /// Set of PIDs configured to return `ProcessLiveness::Unknown`.
    unknown_pids: RwLock<HashSet<u32>>,
}

impl MockProcessObserver {
    /// Creates a new empty mock process observer.
    pub fn new() -> Self {
        Self {
            live_processes: RwLock::new(HashMap::new()),
            unknown_pids: RwLock::new(HashSet::new()),
        }
    }

    /// Registers a process as alive with its observed `start_time_ticks`.
    pub fn register_process(&self, pid: u32, start_time_ticks: u64) {
        self.unknown_pids
            .write()
            .expect("unknown_pids lock poisoned")
            .remove(&pid);
        self.live_processes
            .write()
            .expect("live_processes lock poisoned")
            .insert(pid, start_time_ticks);
    }

    /// Removes a process, simulating process termination.
    pub fn terminate_process(&self, pid: u32) {
        self.live_processes
            .write()
            .expect("live_processes lock poisoned")
            .remove(&pid);
        self.unknown_pids
            .write()
            .expect("unknown_pids lock poisoned")
            .remove(&pid);
    }

    /// Simulates PID recycling by changing the `start_time_ticks` of an existing PID.
    pub fn recycle_pid(&self, pid: u32, new_start_time_ticks: u64) {
        self.unknown_pids
            .write()
            .expect("unknown_pids lock poisoned")
            .remove(&pid);
        self.live_processes
            .write()
            .expect("live_processes lock poisoned")
            .insert(pid, new_start_time_ticks);
    }

    /// Configures a PID to report `ProcessLiveness::Unknown`.
    pub fn set_unknown(&self, pid: u32) {
        self.live_processes
            .write()
            .expect("live_processes lock poisoned")
            .remove(&pid);
        self.unknown_pids
            .write()
            .expect("unknown_pids lock poisoned")
            .insert(pid);
    }

    /// Clears all recorded processes.
    pub fn clear(&self) {
        self.live_processes
            .write()
            .expect("live_processes lock poisoned")
            .clear();
        self.unknown_pids
            .write()
            .expect("unknown_pids lock poisoned")
            .clear();
    }
}

impl ProcessObserver for MockProcessObserver {
    fn check_liveness(&self, identity: &ProcessIdentity) -> ProcessLiveness {
        let (pid, expected_ticks) = match (identity.pid, identity.start_time_ticks) {
            (Some(p), Some(t)) => (p, t),
            _ => return ProcessLiveness::Unspawned,
        };

        if self
            .unknown_pids
            .read()
            .expect("unknown_pids lock poisoned")
            .contains(&pid)
        {
            return ProcessLiveness::Unknown;
        }

        let map = self
            .live_processes
            .read()
            .expect("live_processes lock poisoned");

        match map.get(&pid) {
            Some(&observed_ticks) => {
                if observed_ticks == expected_ticks {
                    ProcessLiveness::Alive
                } else {
                    ProcessLiveness::Recycled { observed_ticks }
                }
            }
            None => ProcessLiveness::Dead,
        }
    }
}
