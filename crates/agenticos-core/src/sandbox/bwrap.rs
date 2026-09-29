//! Bubblewrap executable validation, baseline compliance verification, and command layout engine.
//!
//! Enforces:
//! - Approved security floor: Bubblewrap >= 0.12.0 (rejection of Category C: CVE-2026-87766 and CVE-2026-41163).
//! - Non-setuid invariant: binary must never have S_ISUID / S_ISGID set.
//! - Ownership & permissions: owned by root or invoking user; non-world-writable.
//! - Approved container filesystem layout (/usr, /lib*, /bin, /sbin, /etc, /dev, /proc, /run, /tmp, /workspace).
//! - Full namespace isolation: unshare user, mount, pid, net, ipc, uts.
//! - Descriptor-based workspace mounting via `--bind-fd` / `--ro-bind-fd`.

use super::error::SandboxError;
use std::fmt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Approved minimum security baseline version for Bubblewrap in AgenticOS.
pub const BWRAP_MIN_APPROVED_VERSION: BubblewrapVersion = BubblewrapVersion {
    major: 0,
    minor: 12,
    patch: 0,
};

/// SemVer representation for Bubblewrap version parsing and comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BubblewrapVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl fmt::Display for BubblewrapVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl BubblewrapVersion {
    /// Parses a version string like "bubblewrap 0.13.0\n" or "0.12.0".
    pub fn parse(s: &str) -> Option<Self> {
        let clean = s.trim();
        let version_part = if let Some(stripped) = clean.strip_prefix("bubblewrap") {
            stripped.trim()
        } else {
            clean
        };

        let mut parts = version_part.split('.');
        let major = parts.next()?.parse::<u32>().ok()?;
        let minor = parts.next()?.parse::<u32>().ok()?;
        let patch_str = parts.next()?.split('-').next()?;
        let patch = patch_str.parse::<u32>().ok()?;

        Some(BubblewrapVersion {
            major,
            minor,
            patch,
        })
    }

    /// Returns true if this version meets or exceeds the approved AgenticOS baseline (>= 0.12.0).
    pub fn is_compliant(&self) -> bool {
        *self >= BWRAP_MIN_APPROVED_VERSION
    }

    /// Evaluates known CVE exposure for this version.
    pub fn cve_status(&self) -> &'static str {
        if *self
            < (BubblewrapVersion {
                major: 0,
                minor: 11,
                patch: 2,
            })
        {
            "Category C: Vulnerable to CVE-2026-41163 (privilege escalation via ptrace) and CVE-2026-87766 (link resolution sandbox escape)"
        } else if *self < BWRAP_MIN_APPROVED_VERSION {
            "Category C: Vulnerable to CVE-2026-87766 (improper link resolution during mount destination resolution / Flatpak regression drop)"
        } else {
            "Approved Baseline: CVE-2026-41163 and CVE-2026-87766 verified resolved"
        }
    }
}

/// Metadata and validation proof of an approved Bubblewrap binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BubblewrapBinary {
    pub path: PathBuf,
    pub version: BubblewrapVersion,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

impl BubblewrapBinary {
    /// Validates an executable against the strict AgenticOS security rules.
    pub fn validate<P: AsRef<Path>>(path: P) -> Result<Self, SandboxError> {
        let p = path.as_ref();
        if !p.exists() {
            return Err(SandboxError::BubblewrapNotFound(format!(
                "Executable does not exist at '{}'",
                p.display()
            )));
        }

        let meta = std::fs::metadata(p).map_err(|e| {
            SandboxError::BubblewrapNotFound(format!(
                "Failed to stat executable '{}': {e}",
                p.display()
            ))
        })?;

        if !meta.is_file() {
            return Err(SandboxError::BubblewrapNonCompliant(format!(
                "Path '{}' is not a regular file",
                p.display()
            )));
        }

        let mode = meta.mode();
        let uid = meta.uid();
        let gid = meta.gid();

        // 1. Mandatory Non-Setuid Invariant
        let is_setuid = (mode & libc::S_ISUID) != 0;
        let is_setgid = (mode & libc::S_ISGID) != 0;
        if is_setuid || is_setgid {
            return Err(SandboxError::BubblewrapNonCompliant(format!(
                "Binary '{}' has setuid (0o{:o}) or setgid bit set; only unprivileged non-setuid mode is permitted",
                p.display(),
                mode
            )));
        }

        // 2. Non-World-Writable Invariant
        if (mode & 0o002) != 0 {
            return Err(SandboxError::BubblewrapNonCompliant(format!(
                "Binary '{}' is world-writable (mode 0o{:o})",
                p.display(),
                mode
            )));
        }

        // 3. Ownership Invariant (Must be owned by root or running UID)
        let running_uid = unsafe { libc::geteuid() };
        if uid != 0 && uid != running_uid {
            return Err(SandboxError::BubblewrapNonCompliant(format!(
                "Binary '{}' owner UID {} is neither root (0) nor invoking user ({running_uid})",
                p.display(),
                uid
            )));
        }

        // 4. Version and CVE Mitigation Probe
        let output = Command::new(p).arg("--version").output().map_err(|e| {
            SandboxError::BubblewrapExecutionFailed(format!(
                "Failed to execute '{} --version': {e}",
                p.display()
            ))
        })?;

        if !output.status.success() {
            return Err(SandboxError::BubblewrapExecutionFailed(format!(
                "'{} --version' exited with non-zero status {:?}",
                p.display(),
                output.status.code()
            )));
        }

        let stdout_str = String::from_utf8_lossy(&output.stdout);
        let version = BubblewrapVersion::parse(&stdout_str).ok_or_else(|| {
            SandboxError::BubblewrapNonCompliant(format!(
                "Could not parse Bubblewrap version string from '{}': '{stdout_str}'",
                p.display()
            ))
        })?;

        if !version.is_compliant() {
            return Err(SandboxError::BubblewrapNonCompliant(format!(
                "Bubblewrap binary '{}' version {} is below required baseline {} (Status: {})",
                p.display(),
                version,
                BWRAP_MIN_APPROVED_VERSION,
                version.cve_status()
            )));
        }

        Ok(BubblewrapBinary {
            path: p.to_path_buf(),
            version,
            mode,
            uid,
            gid,
        })
    }
}

/// Discovers an approved Bubblewrap binary by checking candidate paths in order.
pub fn find_approved_bubblewrap() -> Result<BubblewrapBinary, SandboxError> {
    let mut candidates = Vec::new();

    // 1. Explicit environment override
    if let Ok(env_path) = std::env::var("AGENTICOS_BWRAP_PATH") {
        candidates.push(PathBuf::from(env_path));
    }

    // 2. User-local binary
    if let Ok(home) = std::env::var("HOME") {
        candidates.push(PathBuf::from(home).join(".local/bin/bwrap"));
    }

    // 3. System paths
    candidates.push(PathBuf::from("/usr/local/bin/bwrap"));
    candidates.push(PathBuf::from("/usr/bin/bwrap"));

    let mut last_rejection = None;
    for cand in candidates {
        if cand.exists() {
            match BubblewrapBinary::validate(&cand) {
                Ok(approved) => return Ok(approved),
                Err(err) => last_rejection = Some(err),
            }
        }
    }

    Err(last_rejection.unwrap_or_else(|| {
        SandboxError::BubblewrapNotFound(
            "No Bubblewrap executable found in candidate paths".to_string(),
        )
    }))
}

/// Builder configuring Bubblewrap container layout and isolation boundaries.
#[derive(Debug)]
pub struct BubblewrapCommandBuilder {
    pub bwrap_bin: PathBuf,
    pub workspace_fd: RawFd,
    pub read_only_workspace: bool,
    pub worker_binary_path: PathBuf,
    pub worker_args: Vec<String>,
}

impl BubblewrapCommandBuilder {
    pub fn new(
        bwrap_bin: PathBuf,
        workspace_fd: RawFd,
        read_only_workspace: bool,
        worker_binary_path: PathBuf,
    ) -> Self {
        Self {
            bwrap_bin,
            workspace_fd,
            read_only_workspace,
            worker_binary_path,
            worker_args: Vec::new(),
        }
    }

    pub fn arg<S: Into<String>>(&mut self, arg: S) -> &mut Self {
        self.worker_args.push(arg.into());
        self
    }

    /// Constructs the complete argument list for `bwrap`.
    ///
    /// Layout:
    /// - `--unshare-all` (unshare user, mount, pid, net, ipc, uts)
    /// - `--die-with-parent`
    /// - `--new-session`
    /// - `--tmpfs /`
    /// - `--ro-bind /usr /usr`
    /// - `--symlink usr/lib /lib`
    /// - `--symlink usr/lib64 /lib64` (if /lib64 exists on host)
    /// - `--symlink usr/bin /bin`
    /// - `--symlink usr/sbin /sbin`
    /// - `--ro-bind /etc /etc`
    /// - `--dev /dev`
    /// - `--proc /proc`
    /// - `--tmpfs /run`
    /// - `--tmpfs /tmp`
    /// - `--dir /workspace`
    /// - `--bind-fd <fd> /workspace` (or `--ro-bind-fd`)
    /// - `--dir /app`
    /// - `--ro-bind <worker_bin> /app/agenticos-worker`
    /// - `/app/agenticos-worker <args...>`
    pub fn build_args(&self) -> Result<Vec<String>, SandboxError> {
        // Explicitly reject --not-a-security-boundary
        for arg in &self.worker_args {
            if arg.contains("--not-a-security-boundary") {
                return Err(SandboxError::BubblewrapNonCompliant(
                    "Profile 2 explicitly rejects --not-a-security-boundary".to_string(),
                ));
            }
        }

        let mut args = vec![
            // 1. Full namespace isolation & lifecycle flags
            "--unshare-all".to_string(),
            "--die-with-parent".to_string(),
            "--new-session".to_string(),
            // 2. Container root filesystem layout
            "--tmpfs".to_string(),
            "/".to_string(),
            "--ro-bind".to_string(),
            "/usr".to_string(),
            "/usr".to_string(),
            "--symlink".to_string(),
            "usr/lib".to_string(),
            "/lib".to_string(),
        ];

        if Path::new("/lib64").exists() {
            args.push("--symlink".to_string());
            args.push("usr/lib64".to_string());
            args.push("/lib64".to_string());
        }

        args.push("--symlink".to_string());
        args.push("usr/bin".to_string());
        args.push("/bin".to_string());

        args.push("--symlink".to_string());
        args.push("usr/sbin".to_string());
        args.push("/sbin".to_string());

        args.push("--ro-bind".to_string());
        args.push("/etc".to_string());
        args.push("/etc".to_string());

        args.push("--dev".to_string());
        args.push("/dev".to_string());

        args.push("--proc".to_string());
        args.push("/proc".to_string());

        args.push("--tmpfs".to_string());
        args.push("/run".to_string());

        args.push("--tmpfs".to_string());
        args.push("/tmp".to_string());

        // 3. Workspace mount via descriptor
        args.push("--dir".to_string());
        args.push("/workspace".to_string());

        if self.read_only_workspace {
            args.push("--ro-bind-fd".to_string());
        } else {
            args.push("--bind-fd".to_string());
        }
        args.push(self.workspace_fd.to_string());
        args.push("/workspace".to_string());

        // 4. Worker binary mount
        args.push("--dir".to_string());
        args.push("/app".to_string());

        args.push("--ro-bind".to_string());
        args.push(self.worker_binary_path.to_string_lossy().to_string());
        args.push("/app/agenticos-worker".to_string());

        // 5. Worker execution command
        args.push("/app/agenticos-worker".to_string());
        for a in &self.worker_args {
            args.push(a.clone());
        }

        Ok(args)
    }
}
