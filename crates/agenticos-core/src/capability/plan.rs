//! Sandbox construction plans: deterministic, data-only builders plus the
//! validation gate (`validate()`).
//!
//! A `SandboxConstructionPlan` describes confinement without applying it:
//! no `bwrap` invocation, no Landlock/seccomp syscalls, no namespace or
//! cgroup writes. Plans that fail `validate()` are unrepresentable
//! downstream — a future launcher must refuse them.
//!
//! Fixture data below (seccomp example sets, argv vocabulary, sensitivity
//! lists, numeric defaults) reproduces ADR-0003's *documented examples* and
//! is labeled NON-NORMATIVE throughout. Allowlist contents, version pins,
//! ABI policy, and numeric ceilings for real capabilities remain TBD.

use super::binding::InvocationBinding;
use super::error::CapabilityError;
use super::manifest::{CapabilityManifest, RiskTier, SandboxProfile};
use crate::policy::canonical::{canonical_json_bytes, sha256};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Container mount target constants (container-side layout, ADR-0003 P2).
const TARGET_WORK: &str = "/work";
const TARGET_USR: &str = "/usr";
const TARGET_LIB: &str = "/lib";
const TARGET_TMP: &str = "/tmp";
const TARGET_DEV: &str = "/dev";
const TARGET_ROOT: &str = "/";

/// Fixed `bwrap` argv vocabulary (literals). Anything else must be a
/// `{SCOPE:<label>}` reference or the manifest-declared purpose binary.
const BWRAP_VOCAB: &[&str] = &[
    "bwrap",
    "--unshare-all",
    "--unshare-net",
    "--unshare-pid",
    "--unshare-ipc",
    "--unshare-uts",
    "--ro-bind",
    "--bind",
    "--tmpfs",
    "--dev",
    "/usr",
    "/lib",
    "/tmp",
    "/dev",
    "/",
    TARGET_WORK,
    "--",
];

/// Shell names banned from any exec-visible plan string (full token match).
const SHELL_TOKENS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "fish",
    "powershell",
    "cmd",
    "cmd.exe",
];

/// Sensitive host paths that must never appear in plan strings
/// (NON-NORMATIVE list drawn from the threat-model blacklisted paths).
const SENSITIVE_SUBSTRINGS: &[&str] = &[
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/passwd",
    "/root",
    "/boot",
    ".ssh",
    ".gnupg",
];

/// Default task ceiling (NON-NORMATIVE: ADR-0003 Profile 2 example value).
pub const DEFAULT_TASKS_MAX: u32 = 32;
/// Default fd-pass buffer bound (NON-NORMATIVE implementation default).
pub const DEFAULT_FD_BUFFER_BYTES: u64 = 65_536;

/// NON-NORMATIVE fixture seccomp sets reproducing ADR-0003's documented
/// Profile 1 example enumeration. Test data for future profiles, never
/// compiled or installed here.
const PROFILE1_ALLOW: &[&str] = &[
    "brk", "close", "fstat", "lseek", "mmap", "read", "recvmsg", "sendmsg",
];
const PROFILE1_DENY: &[&str] = &[
    "bind", "bpf", "clone", "clone3", "connect", "execve", "execveat", "fork", "ptrace", "socket",
];

/// NON-NORMATIVE fixture seccomp sets for Profile 2: Profile 1 plus
/// purpose-binary execution, denying kernel attack vectors. Fixture data.
const PROFILE2_ALLOW_EXTRA: &[&str] = &["execve", "execveat", "open", "openat", "stat", "write"];
const PROFILE2_DENY: &[&str] = &["bpf", "kexec_load", "ptrace"];

/// Mount source: scope labels are symbolic (Decision 4); the rest are
/// fixed container-layout constants. No host paths appear.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum MountSource {
    ScopeLabel(String),
    SystemLibs,
    Tmpfs,
    DevMinimal,
}

/// Mount access mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MountMode {
    ReadOnly,
    ReadWrite,
}

/// One container mount entry (data only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MountEntry {
    pub source: MountSource,
    pub target: String,
    pub mode: MountMode,
}

/// Landlock rights as an opaque, valueless enum (no invented mask values;
/// numeric sourcing deferred to UAPI definitions in a future phase).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LandlockRights {
    ReadFile,
    ReadDir,
    WriteFile,
    WriteDir,
    MakeDir,
    Rename,
    Delete,
    Truncate,
}

/// One Landlock rule entry: scope label plus rights (data only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LandlockRule {
    pub scope: String,
    pub rights: Vec<LandlockRights>,
}

/// seccomp allow/deny name lists (sorted; fixture data, never installed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeccompData {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

/// Namespace unshare set (data only; Profile 2 sets all five).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnshareSet {
    pub mount: bool,
    pub pid: bool,
    pub net: bool,
    pub ipc: bool,
    pub uts: bool,
}

/// Resource ceilings (bounded data; exact values TBD, enforcement deferred).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ceilings {
    pub memory_bytes: u64,
    pub cpu_quota_percent: u32,
    pub tasks_max: u32,
    pub wall_time_ms: u64,
}

/// Descriptor-passing intent (future `SCM_RIGHTS`; nothing passed here).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FdPlan {
    pub socketpair: bool,
    pub bounded_buffer_bytes: u64,
    pub scm_rights: Vec<String>,
}

/// Exec argument reference: request field or hygiene-checked literal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ExecArg {
    RequestField(String),
    Literal(String),
}

/// Purpose-binary execution description (data only, never spawned).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecPlan {
    pub binary: String,
    pub args: Vec<ExecArg>,
}

/// Validated sandbox construction plan (data only — never applied).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxConstructionPlan {
    pub plan_id: Uuid,
    pub binding_hash: [u8; 32],
    pub profile: SandboxProfile,
    /// Capability risk tier (drives tier-precise validation: Tier 0 plans
    /// are read-only; Tier 1 plans may additionally carry write-file).
    pub risk_tier: RiskTier,
    /// Scope labels covered by this plan (sorted; validation universe).
    pub scope_labels: Vec<String>,
    pub mounts: Vec<MountEntry>,
    pub landlock_rules: Vec<LandlockRule>,
    pub seccomp: SeccompData,
    pub unshare: UnshareSet,
    pub ceilings: Ceilings,
    pub fd_plan: FdPlan,
    pub env_allowlist: Vec<String>,
    pub no_new_privs: bool,
    pub exec: Option<ExecPlan>,
    /// Profile 2 argv (`Some`) or Profile 1 (`None`, direct worker).
    pub bwrap_argv: Option<BwrapArgv>,
    pub plan_hash: [u8; 32],
}

/// Validated Bubblewrap argument vector (data only, never executed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BwrapArgv(pub Vec<String>);

/// Build a validated construction plan for a bound invocation.
///
/// Profile selection is exactly `(risk_tier → profile)`; builders are pure
/// and deterministic. Provenance (binary == manifest declaration) is
/// checked here; hygiene is re-checked by `validate()`.
pub fn build_plan(
    binding: &InvocationBinding,
    manifest: &CapabilityManifest,
) -> Result<SandboxConstructionPlan, CapabilityError> {
    let rejected = |reason: &str| CapabilityError::PlanRejected {
        reason: reason.to_string(),
    };
    let expected_profile = match manifest.risk_tier {
        RiskTier::Tier0 | RiskTier::Tier1 => SandboxProfile::Profile1,
        RiskTier::Tier2 | RiskTier::Tier3 => SandboxProfile::Profile2,
        RiskTier::Tier4 => {
            return Err(rejected("Tier 4 capabilities are never plannable"));
        }
    };
    if manifest.sandbox_profile != expected_profile {
        return Err(rejected("manifest profile disagrees with risk tier"));
    }
    let mut scope_labels: Vec<String> = binding
        .resolved
        .matched_read_scopes
        .iter()
        .chain(binding.resolved.matched_write_scopes.iter())
        .cloned()
        .collect();
    scope_labels.sort();
    scope_labels.dedup();

    let writable = manifest.risk_tier != RiskTier::Tier0;
    let mounts = build_mounts(&scope_labels, writable, manifest.sandbox_profile);
    let landlock_rules = build_landlock_rules(&scope_labels, writable);
    let seccomp = fixture_seccomp_data(manifest.sandbox_profile);
    let unshare = match manifest.sandbox_profile {
        SandboxProfile::Profile1 => UnshareSet {
            mount: false,
            pid: false,
            net: false,
            ipc: false,
            uts: false,
        },
        SandboxProfile::Profile2 => UnshareSet {
            mount: true,
            pid: true,
            net: true,
            ipc: true,
            uts: true,
        },
    };
    let ceilings = Ceilings {
        memory_bytes: binding.resolved.max_memory_bytes,
        cpu_quota_percent: binding.resolved.max_cpu_quota_percent,
        tasks_max: DEFAULT_TASKS_MAX,
        wall_time_ms: binding.resolved.max_wall_time_ms,
    };
    if ceilings.wall_time_ms == 0 {
        return Err(rejected("wall_time_ms must be non-zero"));
    }
    let exec = match manifest.purpose_binary.clone() {
        None => None,
        Some(binary) => {
            let mut args = Vec::new();
            // Fixture convention: the `{path}` request field feeds the
            // purpose binary. Field names are hygiene-checked below.
            if manifest.input_schema.get("properties").is_some() {
                args.push(ExecArg::RequestField("path".to_string()));
            }
            Some(ExecPlan { binary, args })
        }
    };
    if let Some(plan_exec) = &exec {
        validate_exec_args(plan_exec)?;
    }
    let bwrap_argv = match manifest.sandbox_profile {
        SandboxProfile::Profile1 => None,
        SandboxProfile::Profile2 => Some(build_bwrap_argv(&scope_labels, writable, exec.as_ref())),
    };
    let plan_id = Uuid::new_v4();
    let plan_hash = plan_content_hash(
        plan_id,
        &binding.binding_hash,
        manifest,
        &mounts,
        &landlock_rules,
        &seccomp,
        &unshare,
        &ceilings,
        &bwrap_argv,
    )
    .map_err(|reason| CapabilityError::InternalError { reason })?;
    let plan = SandboxConstructionPlan {
        plan_id,
        binding_hash: binding.binding_hash,
        profile: manifest.sandbox_profile,
        risk_tier: manifest.risk_tier,
        scope_labels,
        mounts,
        landlock_rules,
        seccomp,
        unshare,
        ceilings,
        fd_plan: FdPlan {
            socketpair: true,
            bounded_buffer_bytes: DEFAULT_FD_BUFFER_BYTES,
            scm_rights: Vec::new(),
        },
        env_allowlist: Vec::new(),
        no_new_privs: true,
        exec,
        bwrap_argv,
        plan_hash,
    };
    validate(&plan)?;
    Ok(plan)
}

fn build_mounts(
    scope_labels: &[String],
    writable: bool,
    profile: SandboxProfile,
) -> Vec<MountEntry> {
    let mut mounts = Vec::new();
    if profile == SandboxProfile::Profile2 {
        mounts.push(MountEntry {
            source: MountSource::Tmpfs,
            target: TARGET_ROOT.to_string(),
            mode: MountMode::ReadOnly,
        });
        mounts.push(MountEntry {
            source: MountSource::SystemLibs,
            target: TARGET_USR.to_string(),
            mode: MountMode::ReadOnly,
        });
        mounts.push(MountEntry {
            source: MountSource::SystemLibs,
            target: TARGET_LIB.to_string(),
            mode: MountMode::ReadOnly,
        });
        mounts.push(MountEntry {
            source: MountSource::Tmpfs,
            target: TARGET_TMP.to_string(),
            mode: MountMode::ReadWrite,
        });
        mounts.push(MountEntry {
            source: MountSource::DevMinimal,
            target: TARGET_DEV.to_string(),
            mode: MountMode::ReadOnly,
        });
    }
    let mode = if writable {
        MountMode::ReadWrite
    } else {
        MountMode::ReadOnly
    };
    for label in scope_labels {
        mounts.push(MountEntry {
            source: MountSource::ScopeLabel(label.clone()),
            target: TARGET_WORK.to_string(),
            mode,
        });
    }
    mounts
}

fn build_landlock_rules(scope_labels: &[String], writable: bool) -> Vec<LandlockRule> {
    let mut rights = vec![LandlockRights::ReadFile, LandlockRights::ReadDir];
    if writable {
        rights.push(LandlockRights::WriteFile);
    }
    rights.sort_by_key(|right| *right as u8);
    scope_labels
        .iter()
        .map(|scope| LandlockRule {
            scope: scope.clone(),
            rights: rights.clone(),
        })
        .collect()
}

/// NON-NORMATIVE fixture seccomp tables (documented ADR-0003 example sets).
fn fixture_seccomp_data(profile: SandboxProfile) -> SeccompData {
    let mut allow: Vec<String> = PROFILE1_ALLOW.iter().map(|s| s.to_string()).collect();
    let mut deny: Vec<String> = PROFILE1_DENY.iter().map(|s| s.to_string()).collect();
    if profile == SandboxProfile::Profile2 {
        allow.extend(PROFILE2_ALLOW_EXTRA.iter().map(|s| s.to_string()));
        deny.retain(|name| name != "execve" && name != "execveat");
        deny.extend(PROFILE2_DENY.iter().map(|s| s.to_string()));
    }
    allow.sort();
    allow.dedup();
    deny.sort();
    deny.dedup();
    SeccompData { allow, deny }
}

fn build_bwrap_argv(scope_labels: &[String], writable: bool, exec: Option<&ExecPlan>) -> BwrapArgv {
    let mut argv = vec![
        "bwrap".to_string(),
        "--unshare-all".to_string(),
        "--unshare-net".to_string(),
        "--unshare-pid".to_string(),
        "--unshare-ipc".to_string(),
        "--unshare-uts".to_string(),
        "--ro-bind".to_string(),
        TARGET_USR.to_string(),
        TARGET_USR.to_string(),
        "--ro-bind".to_string(),
        TARGET_LIB.to_string(),
        TARGET_LIB.to_string(),
        "--tmpfs".to_string(),
        TARGET_TMP.to_string(),
        "--dev".to_string(),
        TARGET_DEV.to_string(),
    ];
    let bind_flag = if writable { "--bind" } else { "--ro-bind" };
    for label in scope_labels {
        argv.push(bind_flag.to_string());
        argv.push(format!("{{SCOPE:{label}}}"));
        argv.push(TARGET_WORK.to_string());
    }
    argv.push("--".to_string());
    if let Some(plan_exec) = exec {
        argv.push(plan_exec.binary.clone());
    }
    BwrapArgv(argv)
}

fn validate_exec_args(exec: &ExecPlan) -> Result<(), CapabilityError> {
    let rejected = |reason: String| CapabilityError::PlanRejected { reason };
    if exec.binary.is_empty() {
        return Err(rejected("exec binary must not be empty".to_string()));
    }
    for arg in &exec.args {
        match arg {
            ExecArg::RequestField(name) => {
                if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    return Err(rejected(format!("invalid arg field reference '{name}'")));
                }
            }
            ExecArg::Literal(value) => {
                if value.bytes().any(|b| !b.is_ascii_graphic() && b != b' ') || value.contains('\0')
                {
                    return Err(rejected("exec literal contains unsafe bytes".to_string()));
                }
                for meta in ['|', ';', '&', '$', '`', '(', ')', '<', '>'] {
                    if value.contains(meta) {
                        return Err(rejected("exec literal contains metacharacters".to_string()));
                    }
                }
            }
        }
    }
    Ok(())
}

/// Validate a construction plan (the gate future launchers must enforce).
///
/// Rules reference fixed vocabularies and the plan's own scope labels;
/// nothing here interprets host state.
pub fn validate(plan: &SandboxConstructionPlan) -> Result<(), CapabilityError> {
    let rejected = |reason: String| CapabilityError::PlanRejected { reason };
    if !plan.no_new_privs {
        return Err(rejected("no_new_privs must be true".to_string()));
    }
    if plan.ceilings.wall_time_ms == 0 {
        return Err(rejected("wall_time_ms must be non-zero".to_string()));
    }
    if plan.fd_plan.bounded_buffer_bytes == 0 {
        return Err(rejected("fd buffer bound must be non-zero".to_string()));
    }
    for entry in &plan.mounts {
        check_plan_string(&entry.target, "mount target")?;
        if let MountSource::ScopeLabel(label) = &entry.source {
            if !plan.scope_labels.iter().any(|scope| scope == label) {
                return Err(rejected(format!(
                    "mount references unknown scope '{label}'"
                )));
            }
            check_plan_string(label, "mount scope")?;
        }
    }
    for rule in &plan.landlock_rules {
        if !plan.scope_labels.iter().any(|scope| scope == &rule.scope) {
            return Err(rejected(format!(
                "landlock rule references unknown scope '{}'",
                rule.scope
            )));
        }
        // Tier-precise least privilege: Tier 0 is read-only; Tier 1 may
        // additionally carry write-file (non-destructive writes never gain
        // structural rights). Higher tiers live under Profile 2.
        let allowed = match plan.risk_tier {
            RiskTier::Tier0 => &[LandlockRights::ReadFile, LandlockRights::ReadDir][..],
            _ => &[
                LandlockRights::ReadFile,
                LandlockRights::ReadDir,
                LandlockRights::WriteFile,
            ][..],
        };
        if rule.rights.iter().any(|right| !allowed.contains(right)) {
            return Err(rejected(
                "landlock rights exceed tier allowance".to_string(),
            ));
        }
    }
    if plan.profile == SandboxProfile::Profile1
        && plan
            .seccomp
            .allow
            .iter()
            .any(|name| name == "execve" || name == "execveat")
    {
        return Err(rejected(
            "Profile 1 seccomp data must not allow execve".to_string(),
        ));
    }
    // Network backstop is structural: the argv vocabulary contains no
    // network-sharing flags (only `--unshare-net`), and dual authorization
    // was already enforced at binding intersection time.
    if let Some(argv) = &plan.bwrap_argv {
        validate_bwrap_argv(argv, &plan.scope_labels, plan.exec.as_ref())?;
    } else if plan.profile == SandboxProfile::Profile2 {
        return Err(rejected("Profile 2 plans require bwrap_argv".to_string()));
    }
    if let Some(exec) = &plan.exec {
        validate_exec_args(exec)?;
        check_plan_string(&exec.binary, "exec binary")?;
    }
    for name in &plan.env_allowlist {
        if name.contains('\0') || name.contains('=') {
            return Err(rejected("env entry contains NUL or '='".to_string()));
        }
    }
    Ok(())
}

/// Validate Bubblewrap argv data: fixed vocabulary plus `{SCOPE:<label>}`
/// references drawn from the plan's scope labels, plus the plan's own
/// manifest-declared purpose binary (provenance checked at build time,
/// hygiene re-checked here); no shells, no sensitive paths, no unlisted
/// flags.
fn validate_bwrap_argv(
    argv: &BwrapArgv,
    scope_labels: &[String],
    exec: Option<&ExecPlan>,
) -> Result<(), CapabilityError> {
    let rejected = |reason: String| CapabilityError::PlanRejected { reason };
    if argv.0.is_empty() || argv.0[0] != "bwrap" {
        return Err(rejected("bwrap argv must start with 'bwrap'".to_string()));
    }
    for entry in &argv.0 {
        if BWRAP_VOCAB.contains(&entry.as_str()) {
            continue;
        }
        if let Some(label) = entry
            .strip_prefix("{SCOPE:")
            .and_then(|rest| rest.strip_suffix('}'))
        {
            if !label.is_empty() && scope_labels.iter().any(|scope| scope == label) {
                check_plan_string(label, "scope reference")?;
                continue;
            }
            return Err(rejected(format!("unknown scope reference '{entry}'")));
        }
        // The manifest-declared purpose binary trails "--"; provenance was
        // established at build time, hygiene is enforced here.
        if let Some(plan_exec) = exec {
            if entry == &plan_exec.binary {
                check_plan_string(entry, "argv entry")?;
                continue;
            }
        }
        // Anything else is outside the fixed vocabulary: reject even if
        // hygienic, so unlisted flags can never slip into a valid plan.
        check_plan_string(entry, "argv entry")?;
        return Err(rejected(format!(
            "argv entry outside fixed vocabulary: '{entry}'"
        )));
    }
    Ok(())
}

/// Hygiene for any plan string: no NUL, no shell tokens as path components,
/// no sensitive host-path substrings.
fn check_plan_string(value: &str, what: &str) -> Result<(), CapabilityError> {
    if value.contains('\0') {
        return Err(CapabilityError::PlanRejected {
            reason: format!("{what} contains NUL byte"),
        });
    }
    for component in value.split('/') {
        if SHELL_TOKENS.contains(&component) {
            return Err(CapabilityError::PlanRejected {
                reason: format!("{what} references a shell interpreter"),
            });
        }
    }
    for sensitive in SENSITIVE_SUBSTRINGS {
        if value.contains(sensitive) {
            return Err(CapabilityError::PlanRejected {
                reason: format!("{what} references a sensitive host path"),
            });
        }
    }
    Ok(())
}

/// Plan content hash: SHA-256 over the JCS canonical encoding
/// (Decision 2 — the Phase 3.1 mechanism, no new scheme).
#[allow(clippy::too_many_arguments)]
fn plan_content_hash(
    plan_id: Uuid,
    binding_hash: &[u8; 32],
    manifest: &CapabilityManifest,
    mounts: &[MountEntry],
    landlock_rules: &[LandlockRule],
    seccomp: &SeccompData,
    unshare: &UnshareSet,
    ceilings: &Ceilings,
    bwrap_argv: &Option<BwrapArgv>,
) -> Result<[u8; 32], String> {
    let value = serde_json::json!({
        "domain": "agenticos-sandbox-plan/v1",
        "plan_id": plan_id,
        "binding_hash": binding_hash.to_vec(),
        "manifest_ref": format!("{}@{}", manifest.capability_id, manifest.capability_schema_version),
        "profile": format!("{:?}", manifest.sandbox_profile),
        "mounts": serde_json::to_value(mounts).map_err(|e| format!("{e}"))?,
        "landlock_rules": serde_json::to_value(landlock_rules).map_err(|e| format!("{e}"))?,
        "seccomp": serde_json::to_value(seccomp).map_err(|e| format!("{e}"))?,
        "unshare": serde_json::to_value(unshare).map_err(|e| format!("{e}"))?,
        "ceilings": serde_json::to_value(ceilings).map_err(|e| format!("{e}"))?,
        "bwrap_argv": bwrap_argv.as_ref().map(|argv| &argv.0),
    });
    canonical_json_bytes(&value)
        .map(|bytes| sha256(&bytes))
        .map_err(|e| format!("{e}"))
}
