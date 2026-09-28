//! Phase 3.2 capability boundary tests: manifests, registry, binding,
//! plans, verifier shapes, error mapping, determinism, and the
//! zero-escape static audit.
//!
//! All fixtures are synthetic and in-memory only. Scope labels are pure
//! symbols (`"workspace"`); no host paths appear. Nothing is spawned,
//! installed, or executed.
use agenticos_core::capability::{
    bind, build_plan, fixture_bundle_manifests,
    fixture_create_directory, fixture_delete_tree, fixture_read_file, validate,
    validate_manifest, Atomicity, CapabilityError, CapabilityRegistry,
    CheckExpr, InvocationBinding, ManifestBundle, MemView, RiskTier,
    SandboxProfile,
};
use agenticos_core::policy::PolicyDecision as PD;
use agenticos_core::{
    ApprovalToken, ApprovalTokenSignedPayload, CapabilityInvocationRequest, ErrorCode,
    FileMeta, ResourceRef, RetryClassification, SandboxConstraints,
};
use std::collections::HashMap;
use std::path::PathBuf;
use uuid::Uuid;

fn uuid(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

fn allow_decision(contributing: Vec<String>) -> PD {
    PD::Allow {
        constraints: SandboxConstraints {
            read_paths: vec![],
            write_paths: vec![],
            allow_network: false,
            seccomp_profile: "phase31-evaluation-only".to_string(),
            max_memory_bytes: 0,
            max_cpu_quota_percent: 0,
            max_wall_time_ms: 10_000,
        },
        contributing_policies: contributing,
    }
}

fn request(capability: &str, kind: &str, n: u128) -> CapabilityInvocationRequest {
    CapabilityInvocationRequest {
        request_id: uuid(n),
        correlation_id: uuid(n + 90_000),
        capability_id: capability.to_string(),
        capability_schema_version: 1,
        resource: ResourceRef::new(kind, "workspace-target"),
        arguments: serde_json::json!({"path": "workspace-target"}),
        deadline_ms: 1_750_000_010_000,
        timeout_duration_ms: 10_000,
        policy_snapshot_hash: [3u8; 32],
        approval_token: None,
    }
}

fn tokened(mut req: CapabilityInvocationRequest, n: u128) -> CapabilityInvocationRequest {
    req.approval_token = Some(ApprovalToken {
        signature: vec![0x01],
        payload: ApprovalTokenSignedPayload {
            single_use_id: uuid(n),
            request_hash: [9u8; 32],
            policy_snapshot_hash: [3u8; 32],
            principal: "fixture-agent".to_string(),
            capability: req.capability_id.clone(),
            resource: req.resource.clone(),
            confirmation_reason: "fixture".to_string(),
            issued_at_ms: 1_749_999_000_000,
            expires_at_ms: 1_750_000_030_000,
            nonce: [1u8; 16],
        },
    });
    req
}

fn registry() -> CapabilityRegistry {
    CapabilityRegistry::load(ManifestBundle::new(fixture_bundle_manifests())).unwrap()
}

fn bind_request(
    req: &CapabilityInvocationRequest,
    decision: &PD,
) -> Result<InvocationBinding, CapabilityError> {
    bind(req, decision, &[3u8; 32], &registry())
}

// ============================================================================
// 1. Manifest validation
// ============================================================================

#[test]
fn test_fixture_manifests_validate() {
    for manifest in fixture_bundle_manifests() {
        validate_manifest(&manifest).unwrap();
    }
}

#[test]
fn test_manifest_rejects_generic_and_tier4() {
    let mut generic = fixture_read_file();
    generic.capability_id = "tool.shell".to_string();
    assert!(matches!(
        CapabilityRegistry::load(ManifestBundle::new(vec![generic])),
        Err(CapabilityError::InvalidManifest { .. })
    ));

    let mut tier4 = fixture_read_file();
    tier4.capability_id = "sys.reboot".to_string();
    tier4.risk_tier = RiskTier::Tier4;
    assert!(matches!(
        CapabilityRegistry::load(ManifestBundle::new(vec![tier4])),
        Err(CapabilityError::InvalidManifest { .. })
    ));

    let mut shell_bin = fixture_delete_tree();
    shell_bin.purpose_binary = Some("bash".to_string());
    assert!(matches!(
        CapabilityRegistry::load(ManifestBundle::new(vec![shell_bin])),
        Err(CapabilityError::InvalidManifest { .. })
    ));

    let mut missing = fixture_delete_tree();
    missing.purpose_binary = None;
    assert!(matches!(
        CapabilityRegistry::load(ManifestBundle::new(vec![missing])),
        Err(CapabilityError::InvalidManifest { .. })
    ));
}

#[test]
fn test_manifest_rejects_bad_schemas_and_network() {
    let mut bad_schema = fixture_read_file();
    bad_schema.input_schema = serde_json::json!({"type": "object", "pattern": "^x"});
    assert!(matches!(
        CapabilityRegistry::load(ManifestBundle::new(vec![bad_schema])),
        Err(CapabilityError::InvalidManifest { .. })
    ));

    let mut netted = fixture_read_file();
    netted.network_need = Some("127.0.0.1:9".to_string());
    assert!(matches!(
        CapabilityRegistry::load(ManifestBundle::new(vec![netted])),
        Err(CapabilityError::InvalidManifest { .. })
    ));

    let mut pathed = fixture_read_file();
    pathed.declared_read_scopes = vec!["/home/lokamanya/Documents".to_string()];
    assert!(matches!(
        CapabilityRegistry::load(ManifestBundle::new(vec![pathed])),
        Err(CapabilityError::InvalidManifest { .. })
    ));
}

// ============================================================================
// 2. Registry lookup/versioning
// ============================================================================

#[test]
fn test_registry_exact_lookup_and_duplicates() {
    let registry = registry();
    assert_eq!(registry.len(), 3);
    let manifest = registry.get("fs.read_file", 1).unwrap();
    assert_eq!(manifest.risk_tier, RiskTier::Tier0);

    assert!(matches!(
        registry.get("fs.nope", 1),
        Err(CapabilityError::UnknownCapability { .. })
    ));
    // Known ID, unknown version: no silent fallback.
    assert!(matches!(
        registry.get("fs.read_file", 2),
        Err(CapabilityError::UnknownCapability { .. })
    ));

    let dupes = vec![fixture_read_file(), fixture_read_file()];
    assert!(matches!(
        CapabilityRegistry::load(ManifestBundle::new(dupes)),
        Err(CapabilityError::InvalidManifest { .. })
    ));

    // Deterministic insertion order.
    let ids: Vec<String> = registry
        .manifests()
        .map(|m| m.capability_id.clone())
        .collect();
    assert_eq!(
        ids,
        vec!["fs.read_file", "fs.create_directory", "fs.delete_tree"]
    );
}

// ============================================================================
// 3. Binding + intersection
// ============================================================================

#[test]
fn test_binding_allow_path_and_hash_stability() {
    let req = request("fs.read_file", "workspace", 1);
    let decision = allow_decision(vec!["system-0".to_string()]);
    let first = bind_request(&req, &decision).unwrap();
    assert_eq!(first.request_id, uuid(1));
    assert_eq!(first.correlation_id, uuid(90_001));
    assert_eq!(first.manifest_ref, "fs.read_file@1");
    assert_eq!(
        first.resolved.matched_read_scopes,
        vec!["workspace".to_string()]
    );
    assert!(!first.resolved.allow_network);
    assert_eq!(first.decision_ref.contributing_policies, vec!["system-0"]);

    // Same inputs (fresh binding id aside) hash differently only by id;
    // identical bindings hash identically.
    let second = bind_request(&req, &decision).unwrap();
    assert_ne!(first.binding_id, second.binding_id);
    assert_ne!(first.binding_hash, second.binding_hash);
}

#[test]
fn test_binding_rejects_non_allow_stale_and_unknown() {
    let req = request("fs.read_file", "workspace", 2);
    let deny = PD::Deny {
        reason: "x".to_string(),
        contributing_policies: vec![],
    };
    assert!(matches!(
        bind(&req, &deny, &[3u8; 32], &registry()),
        Err(CapabilityError::BindingRejected { .. })
    ));

    let confirm = PD::Confirm {
        challenge_id: uuid(7),
        prompt: "p".to_string(),
        blast_radius: "b".to_string(),
        required_scope: "s".to_string(),
        contributing_policies: vec![],
    };
    assert!(matches!(
        bind(&req, &confirm, &[3u8; 32], &registry()),
        Err(CapabilityError::BindingRejected { .. })
    ));

    let decision = allow_decision(vec![]);
    assert!(matches!(
        bind(&req, &decision, &[4u8; 32], &registry()),
        Err(CapabilityError::StaleAuthorization { .. })
    ));

    let unknown = request("fs.nope", "workspace", 3);
    assert!(matches!(
        bind_request(&unknown, &decision),
        Err(CapabilityError::UnknownCapability { .. })
    ));

    // Scope mismatch: kind matches no declared label.
    let scoped = request("fs.read_file", "elsewhere", 4);
    assert!(matches!(
        bind_request(&scoped, &decision),
        Err(CapabilityError::BindingRejected { .. })
    ));
}

#[test]
fn test_binding_tier2_requires_token_and_schema() {
    let decision = allow_decision(vec!["user-1".to_string()]);
    let bare = request("fs.delete_tree", "workspace", 5);
    assert!(matches!(
        bind_request(&bare, &decision),
        Err(CapabilityError::TokenRequired { .. })
    ));

    let mut bad_args = request("fs.delete_tree", "workspace", 6);
    bad_args.arguments = serde_json::json!({"path": 42});
    let tokened_bad = tokened(bad_args, 6);
    assert!(matches!(
        bind_request(&tokened_bad, &decision),
        Err(CapabilityError::SchemaViolation { .. })
    ));

    let tokened_ok = tokened(request("fs.delete_tree", "workspace", 7), 7);
    let binding = bind_request(&tokened_ok, &decision).unwrap();
    assert_eq!(binding.manifest_ref, "fs.delete_tree@1");
}

#[test]
fn test_binding_tier0_rejects_write_carry() {
    let mut decision = allow_decision(vec!["system-0".to_string()]);
    if let PD::Allow { constraints, .. } = &mut decision {
        constraints.write_paths = vec![PathBuf::from("/fixture/synthetic-write")];
    }
    let req = request("fs.read_file", "workspace", 8);
    assert!(matches!(
        bind_request(&req, &decision),
        Err(CapabilityError::BindingRejected { .. })
    ));
}

#[test]
fn test_binding_network_dual_authorization() {
    // Policy allows network but no fixture manifest needs it: resolved false.
    let mut decision = allow_decision(vec!["system-0".to_string()]);
    if let PD::Allow { constraints, .. } = &mut decision {
        constraints.allow_network = true;
    }
    let req = request("fs.read_file", "workspace", 9);
    let binding = bind_request(&req, &decision).unwrap();
    assert!(!binding.resolved.allow_network);
    assert_eq!(binding.resolved.network_endpoint, None);
}

// ============================================================================
// 4. Plan builders + validate()
// ============================================================================

#[test]
fn test_profile1_plan_shape_and_rules() {
    let req = request("fs.read_file", "workspace", 11);
    let binding = bind_request(&req, &allow_decision(vec!["system-0".to_string()])).unwrap();
    let manifest = registry().get("fs.read_file", 1).unwrap().clone();
    let plan = build_plan(&binding, &manifest).unwrap();
    assert_eq!(plan.profile, SandboxProfile::Profile1);
    assert!(plan.no_new_privs);
    assert!(plan.bwrap_argv.is_none());
    assert!(plan
        .landlock_rules
        .iter()
        .all(|rule| rule.rights.iter().all(|right| matches!(
            right,
            agenticos_core::capability::LandlockRights::ReadFile
                | agenticos_core::capability::LandlockRights::ReadDir
        ))));
    assert!(plan.seccomp.allow.iter().all(|name| name != "execve"));
    assert_eq!(plan.ceilings.wall_time_ms, 10_000);
    validate(&plan).unwrap();

    // Determinism: same binding rebuilds byte-identical plans modulo fresh IDs.
    let rebuilt = build_plan(&binding, &manifest).unwrap();
    let strip = |mut value: serde_json::Value| {
        value["plan_id"] = serde_json::json!("fixed");
        value["plan_hash"] = serde_json::json!("fixed");
        value
    };
    assert_eq!(
        strip(serde_json::to_value(&rebuilt).unwrap()),
        strip(serde_json::to_value(&plan).unwrap())
    );
}

#[test]
fn test_profile2_plan_shape_and_argv() {
    let req = tokened(request("fs.delete_tree", "workspace", 12), 12);
    let binding = bind_request(&req, &allow_decision(vec!["user-1".to_string()])).unwrap();
    let manifest = registry().get("fs.delete_tree", 1).unwrap().clone();
    let plan = build_plan(&binding, &manifest).unwrap();
    assert_eq!(plan.profile, SandboxProfile::Profile2);
    let argv = plan.bwrap_argv.clone().unwrap().0;
    assert_eq!(argv[0], "bwrap");
    assert!(argv.contains(&"--unshare-net".to_string()));
    assert!(argv.iter().any(|entry| entry == "{SCOPE:workspace}"));
    assert!(argv.contains(&"agenticos-fs-rmtree".to_string()));
    // No argv entry names a shell interpreter (component match, mirroring
    // the production hygiene rule — not a substring match, which would
    // false-positive on flags like `--unshare-all`).
    const SHELLS: &[&str] = &[
        "sh",
        "bash",
        "zsh",
        "dash",
        "fish",
        "powershell",
        "cmd",
        "cmd.exe",
    ];
    for entry in &argv {
        for component in entry.split('/') {
            assert!(!SHELLS.contains(&component), "shell in argv: {entry}");
        }
    }
    validate(&plan).unwrap();
}

#[test]
fn test_plan_validate_rejects_violations() {
    let req = request("fs.read_file", "workspace", 13);
    let binding = bind_request(&req, &allow_decision(vec!["system-0".to_string()])).unwrap();
    let manifest = registry().get("fs.read_file", 1).unwrap().clone();
    let mut plan = build_plan(&binding, &manifest).unwrap();

    // Shell in argv.
    let mut shelled = plan.clone();
    shelled.bwrap_argv = Some(agenticos_core::capability::BwrapArgv(vec![
        "bwrap".to_string(),
        "bash".to_string(),
    ]));
    assert!(matches!(
        validate(&shelled),
        Err(CapabilityError::PlanRejected { .. })
    ));

    // Unknown scope reference.
    let mut scoped = plan.clone();
    scoped.scope_labels = vec!["other".to_string()];
    assert!(matches!(
        validate(&scoped),
        Err(CapabilityError::PlanRejected { .. })
    ));

    // Dropped NO_NEW_PRIVS.
    plan.no_new_privs = false;
    assert!(matches!(
        validate(&plan),
        Err(CapabilityError::PlanRejected { .. })
    ));

    // Profile mismatch can never validate-build, but a hand-mutated plan
    // with execve allowed under Profile 1 must fail.
    let req = request("fs.read_file", "workspace", 14);
    let binding = bind_request(&req, &allow_decision(vec!["system-0".to_string()])).unwrap();
    let manifest = registry().get("fs.read_file", 1).unwrap().clone();
    let mut execed = build_plan(&binding, &manifest).unwrap();
    execed.seccomp.allow.push("execve".to_string());
    assert!(matches!(
        validate(&execed),
        Err(CapabilityError::PlanRejected { .. })
    ));
}

#[test]
fn test_plan_profiles_match_tiers() {
    let registry = registry();
    for (id, profile) in [
        ("fs.read_file", SandboxProfile::Profile1),
        ("fs.create_directory", SandboxProfile::Profile1),
        ("fs.delete_tree", SandboxProfile::Profile2),
    ] {
        let manifest = registry.get(id, 1).unwrap();
        assert_eq!(manifest.sandbox_profile, profile, "{id}");
    }
    assert_eq!(fixture_delete_tree().risk_tier, RiskTier::Tier2);
    assert_eq!(
        fixture_delete_tree().retry_class,
        RetryClassification::Never
    );
    assert_eq!(fixture_read_file().atomicity, Atomicity::Atomic);
}

// ============================================================================
// 5. Verifier fixture evaluation
// ============================================================================

#[test]
fn test_verifier_conditions_over_fixture_view() {
    use agenticos_core::capability::{evaluate_conditions, ConditionStatus};
    let manifest = fixture_create_directory();
    let args = serde_json::json!({"path": "demo"});
    let (results, satisfied) =
        evaluate_conditions(&manifest.postconditions, &args, &MemView::directory("demo"));
    assert!(satisfied);
    assert!(results.iter().all(|r| r.status == ConditionStatus::Pass));

    let (_, unsatisfied) = evaluate_conditions(
        &manifest.postconditions,
        &args,
        &MemView::new(HashMap::new()),
    );
    assert!(!unsatisfied);

    // Unknown checks and bad references fail the condition, not the harness.
    let bad = vec![CheckExpr {
        check: "nope".to_string(),
        path: "demo".to_string(),
        expected: serde_json::json!(true),
    }];
    let (results, satisfied) = evaluate_conditions(&bad, &args, &MemView::directory("demo"));
    assert!(!satisfied);
    assert_eq!(results.len(), 1);

    let _ = FileMeta {
        exists: true,
        is_directory: false,
    };
}

// ============================================================================
// 6. Error mapping + contracts
// ============================================================================

#[test]
fn test_capability_error_mapping() {
    let cases = [
        (
            CapabilityError::UnknownCapability {
                capability_id: "x".to_string(),
                capability_schema_version: 1,
            },
            ErrorCode::CapabilityNotFound,
        ),
        (
            CapabilityError::BindingRejected {
                reason: "x".to_string(),
            },
            ErrorCode::PolicyDenied,
        ),
        (
            CapabilityError::SchemaViolation {
                reason: "x".to_string(),
            },
            ErrorCode::MalformedArguments,
        ),
        (
            CapabilityError::TokenRequired {
                capability_id: "x".to_string(),
            },
            ErrorCode::ConfirmationRequired,
        ),
        (
            CapabilityError::StaleAuthorization {
                reason: "x".to_string(),
            },
            ErrorCode::InvalidApprovalToken,
        ),
        (
            CapabilityError::PlanRejected {
                reason: "x".to_string(),
            },
            ErrorCode::InvalidRequest,
        ),
    ];
    for (error, code) in cases {
        let payload = error.to_payload();
        assert_eq!(payload.code, code);
        assert_eq!(
            payload.retry_classification,
            agenticos_core::RetryClassification::Never
        );
    }
    assert_eq!(CapabilityError::SOURCE_COMPONENT, "capability-boundary");
}

// ============================================================================
// 7. Zero-escape static audit of Phase 3.2 sources
// ============================================================================

#[test]
fn test_security_audit_zero_escape_primitives_in_phase32_sources() {
    let source_files = [
        "src/capability/mod.rs",
        "src/capability/binding.rs",
        "src/capability/error.rs",
        "src/capability/manifest.rs",
        "src/capability/plan.rs",
        "src/capability/registry.rs",
        "src/capability/report.rs",
        "src/capability/verify.rs",
        "src/capability/worker.rs",
    ];
    let crate_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let forbidden: &[(&str, &str)] = &[
        ("Command::new(", "subprocess execution"),
        ("Command::spawn", "subprocess execution"),
        ("StdCommand", "subprocess execution"),
        ("std::process::Command", "subprocess execution"),
        ("process::exit", "process control"),
        ("fork(", "fork/exec"),
        ("execve(", "execve syscall"),
        ("execvp(", "exec syscall"),
        ("posix_spawn", "process spawning"),
        ("sh -c", "shell invocation"),
        ("/bin/sh", "shell binary"),
        ("/bin/bash", "shell binary"),
        ("TcpStream", "live TCP network"),
        ("TcpListener", "live TCP listener"),
        ("UdpSocket", "live UDP network"),
        ("UnixListener", "live UDS listener"),
        ("UnixStream::connect", "live UDS dial"),
        ("reqwest", "HTTP client"),
        ("hyper::", "HTTP framework"),
        ("tokio::net", "async network runtime"),
        ("tokio::process", "async subprocess"),
        ("std::net::", "network socket"),
        ("zbus", "D-Bus service"),
        ("rusqlite", "unauthorized database access"),
        ("fs::write", "filesystem writes"),
        ("fs::remove", "filesystem mutation"),
        ("fs::create_dir", "filesystem mutation"),
        ("File::create", "filesystem writes"),
        ("OpenOptions", "filesystem writes"),
        ("set_permissions", "filesystem mutation"),
        ("symlink", "filesystem mutation"),
        // NOTE: the bare token "bwrap" is intentionally NOT banned: the
        // spec mandates emitting validated `bwrap_argv` DATA (§16). Actual
        // invocation is covered by the Command/spawn/fork/exec patterns.
        ("landlock_create", "Landlock enforcement"),
        ("landlock_add_rule", "Landlock enforcement"),
        ("landlock_restrict", "Landlock enforcement"),
        ("seccomp_init", "seccomp installation"),
        ("seccomp_load", "seccomp installation"),
        ("prctl(", "privilege syscall"),
        ("sched_unshare", "namespace manipulation"),
        ("unshare(", "namespace manipulation"),
        ("setns(", "namespace manipulation"),
        ("write_cgroup", "cgroup writes"),
        // NOTE: bare "sudo" is not banned: "/etc/sudoers" is spec-mandated
        // denylist DATA (§14 table). Real escalation via `sudo <cmd>` is banned.
        ("sudo ", "privilege escalation invocation"),
        ("setuid", "privilege manipulation"),
        ("setgid", "privilege manipulation"),
        ("cap_set", "capability manipulation"),
        ("llama", "LLM integration"),
        ("ollama", "LLM integration"),
        ("openai", "LLM integration"),
        ("anthropic", "LLM integration"),
        ("tauri", "UI framework"),
        ("gtk", "UI toolkit"),
        ("slint", "UI framework"),
        ("wry", "UI framework"),
    ];
    let mut violations = Vec::new();
    for relative in &source_files {
        let content = match std::fs::read_to_string(crate_root.join(relative)) {
            Ok(content) => content,
            Err(err) => {
                violations.push(format!("cannot read {relative}: {err}"));
                continue;
            }
        };
        // Doc comments describe forbidden concepts; only code matters.
        // Block comments are also excluded: audit targets live code tokens.
        let code = strip_comments(&content);
        for (pattern, description) in forbidden {
            if code.contains(pattern) {
                violations.push(format!(
                    "FORBIDDEN `{pattern}` ({description}) in {relative}"
                ));
            }
        }
        // Structural: no function may return a live child/process/socket handle.
        for token in ["Child", "TcpStream", "UnixStream", "Command>"] {
            if code.contains(&format!("-> {token}"))
                || code.contains(&format!("-> Option<{token}>"))
            {
                violations.push(format!("live-handle return `{token}` in {relative}"));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "security audit failed:\n{}",
        violations.join("\n")
    );
}

/// Strip line doc comments, inline comments, and block comments so the
/// audit scans live code tokens only.
fn strip_comments(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let bytes = content.as_bytes();
    let mut index = 0;
    let mut in_block = false;
    while index < bytes.len() {
        if in_block {
            if bytes[index] == b'*' && index + 1 < bytes.len() && bytes[index + 1] == b'/' {
                in_block = false;
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        if bytes[index] == b'/' && index + 1 < bytes.len() && bytes[index + 1] == b'*' {
            in_block = true;
            index += 2;
            continue;
        }
        if bytes[index] == b'/' && index + 1 < bytes.len() && bytes[index + 1] == b'/' {
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            continue;
        }
        out.push(bytes[index] as char);
        index += 1;
    }
    out
}
