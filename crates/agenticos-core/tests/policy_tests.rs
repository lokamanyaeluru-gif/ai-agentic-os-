//! Phase 3.1 policy plane tests: validation, canonicalization, bundles,
//! snapshots, decision semantics, token shapes, determinism, error mapping,
//! and the zero-execution static audit.
//!
//! All fixtures are synthetic and in-memory only. No synthetic principal is
//! ever persisted as production state; no host mutation occurs.

use agenticos_core::policy::{
    compute_request_hash, ApprovalToken, ApprovalTokenSignedPayload, CapabilityInvocationRequest,
    PolicyBundleSource, PolicyDecision, PolicyEngine, PolicyError,
};
use agenticos_core::{ErrorCode, PrincipalContext, ResourceRef, RetryClassification};
use uuid::Uuid;

/// Fixed supervisor clock for deterministic tests.
const NOW_MS: u64 = 1_750_000_000_000;

fn principal() -> PrincipalContext {
    PrincipalContext::new("fixture-agent", 1000, 1000)
}

fn uuid(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

fn read_permit() -> String {
    "permit(principal, action == Action::\"invoke\", resource) when { context.capability_id == \"fs.read_file\" };".to_string()
}

fn mkdir_permit() -> String {
    "permit(principal, action == Action::\"invoke\", resource) when { context.capability_id == \"fs.create_directory\" };".to_string()
}

fn system_forbid() -> String {
    "forbid(principal, action == Action::\"invoke\", resource) when { context.resource_kind == \"System\" };".to_string()
}

fn delete_confirm_permit() -> String {
    [
        "@confirm(\"true\")",
        "@confirm_prompt(\"Delete the target resource?\")",
        "@blast_radius(\"destructive_filesystem\")",
        "permit(principal, action == Action::\"invoke\", resource) when { context.capability_id == \"fs.delete\" };",
    ]
    .join("\n")
}

fn base_bundle(version: &str) -> PolicyBundleSource {
    PolicyBundleSource {
        version: version.to_string(),
        system_policies: vec![read_permit(), system_forbid()],
        user_policies: vec![mkdir_permit(), delete_confirm_permit()],
        session_policies: vec![],
    }
}

fn request(
    capability: &str,
    kind: &str,
    id: &str,
    engine: &PolicyEngine,
    n: u128,
) -> CapabilityInvocationRequest {
    CapabilityInvocationRequest {
        request_id: uuid(n),
        correlation_id: uuid(n + 10_000),
        capability_id: capability.to_string(),
        capability_schema_version: 1,
        resource: ResourceRef::new(kind, id),
        arguments: serde_json::json!({"path": id}),
        deadline_ms: NOW_MS + 10_000,
        timeout_duration_ms: 10_000,
        policy_snapshot_hash: engine.active().hash,
        approval_token: None,
    }
}

fn fixture_token(
    engine: &PolicyEngine,
    req: &CapabilityInvocationRequest,
    n: u128,
) -> ApprovalToken {
    let mut bound = req.clone();
    bound.approval_token = None;
    let subject = bound.approval_subject();
    let request_hash = compute_request_hash(&subject).expect("hash computes");
    ApprovalToken {
        // Signature bytes are opaque in Phase 3.1 (algorithm TBD) and are
        // never verified; structural binding is what the tests exercise.
        signature: vec![0xAA, 0xBB],
        payload: ApprovalTokenSignedPayload {
            single_use_id: uuid(n),
            request_hash,
            policy_snapshot_hash: engine.active().hash,
            principal: principal().actor_id,
            capability: req.capability_id.clone(),
            resource: req.resource.clone(),
            confirmation_reason: "Delete the target resource?".to_string(),
            issued_at_ms: NOW_MS - 1_000,
            expires_at_ms: NOW_MS + 30_000,
            nonce: [7u8; 16],
        },
    }
}

// ============================================================================
// 1. Request validation
// ============================================================================

#[test]
fn test_request_validation_rejects_malformed_inputs() {
    let engine = PolicyEngine::from_source(&base_bundle("v1")).unwrap();
    let mut req = request("fs.read_file", "Path", "a.txt", &engine, 1);
    assert!(engine.evaluate(&req, &principal(), NOW_MS).is_ok());

    req = request("", "Path", "a.txt", &engine, 2);
    assert!(matches!(
        engine.evaluate(&req, &principal(), NOW_MS),
        Err(PolicyError::InvalidRequest { .. })
    ));

    req = request("fs.read_file", "Path", "a.txt", &engine, 3);
    req.timeout_duration_ms = 0;
    assert!(matches!(
        engine.evaluate(&req, &principal(), NOW_MS),
        Err(PolicyError::InvalidRequest { .. })
    ));

    req = request("fs.read_file", "Path", "a\0b", &engine, 4);
    assert!(matches!(
        engine.evaluate(&req, &principal(), NOW_MS),
        Err(PolicyError::InvalidRequest { .. })
    ));

    let bad_actor = PrincipalContext::new("", 1000, 1000);
    let req = request("fs.read_file", "Path", "a.txt", &engine, 5);
    assert!(matches!(
        engine.evaluate(&req, &bad_actor, NOW_MS),
        Err(PolicyError::InvalidRequest { .. })
    ));
}

// ============================================================================
// 2. Hashing semantics
// ============================================================================

#[test]
fn test_request_hash_deterministic_and_sensitive() {
    let engine = PolicyEngine::from_source(&base_bundle("v1")).unwrap();
    let req = request("fs.read_file", "Path", "a.txt", &engine, 11);
    let h1 = compute_request_hash(&req.approval_subject()).unwrap();
    let h2 = compute_request_hash(&req.approval_subject()).unwrap();
    assert_eq!(h1, h2);

    let mut other = req.clone();
    other.arguments = serde_json::json!({"path": "b.txt"});
    let h3 = compute_request_hash(&other.approval_subject()).unwrap();
    assert_ne!(h1, h3);

    // ApprovalSubject excludes the token: attaching a token is hash-neutral.
    let mut with_token = req.clone();
    with_token.approval_token = Some(fixture_token(&engine, &req, 99));
    assert_eq!(
        h1,
        compute_request_hash(&with_token.approval_subject()).unwrap()
    );
}

// ============================================================================
// 3. Bundle loading + snapshots + rollback
// ============================================================================

#[test]
fn test_bundle_rejects_bad_version_and_syntax() {
    let mut bad = base_bundle("");
    assert!(matches!(
        PolicyEngine::from_source(&bad),
        Err(PolicyError::BundleRejected { .. })
    ));

    bad = base_bundle("v1");
    bad.system_policies = vec!["permit(principal, action, resource".to_string()];
    assert!(matches!(
        PolicyEngine::from_source(&bad),
        Err(PolicyError::BundleRejected { .. })
    ));
}

#[test]
fn test_bundle_rejects_schema_violations() {
    // `Action::"bogus"` is not declared by the fixture schema.
    let mut bad = base_bundle("v1");
    bad.user_policies
        .push("permit(principal, action == Action::\"bogus\", resource);".to_string());
    assert!(matches!(
        PolicyEngine::from_source(&bad),
        Err(PolicyError::BundleRejected { .. })
    ));
}

#[test]
fn test_snapshot_activation_and_rollback() {
    let engine = PolicyEngine::from_source(&base_bundle("v1")).unwrap();
    let h1 = engine.active().hash;

    let h2 = engine.load_and_activate(&base_bundle("v2")).unwrap();
    assert_ne!(h1, h2);
    assert_eq!(engine.active().version, "v2");
    assert_eq!(engine.retained_versions(), vec!["v1".to_string()]);

    // Rejected candidate keeps the active snapshot.
    let mut bad = base_bundle("v3");
    bad.system_policies = vec!["forbid(principal,".to_string()];
    assert!(engine.load_and_activate(&bad).is_err());
    assert_eq!(engine.active().hash, h2);

    let back = engine.rollback_to_version("v1").unwrap();
    assert_eq!(back, h1);
    assert_eq!(engine.active().version, "v1");

    assert!(matches!(
        engine.rollback_to_version("v9"),
        Err(PolicyError::UnknownSnapshot { .. })
    ));
}

#[test]
fn test_rollback_selection_deterministic_with_duplicate_versions() {
    // Even if duplicate version labels somehow enter the retained pool,
    // rollback must deterministically select the oldest matching snapshot:
    // repeated rollbacks from a fresh engine state must agree bit-for-bit.
    fn run_once() -> ([u8; 32], String) {
        let engine = PolicyEngine::from_source(&base_bundle("v1")).unwrap();
        // v2a and v2b share the version label but differ in content.
        let mut v2a = base_bundle("v2");
        v2a.user_policies.pop();
        let mut v2b = base_bundle("v2");
        v2b.user_policies.clear();
        engine.load_and_activate(&v2a).unwrap();
        engine.load_and_activate(&v2b).unwrap();
        let hash = engine.rollback_to_version("v2").unwrap();
        let req = request("fs.read_file", "Path", "a.txt", &engine, 61);
        let (decision, _) = engine.evaluate(&req, &principal(), NOW_MS).unwrap();
        (hash, format!("{decision:?}"))
    }
    let first = run_once();
    for _ in 0..8 {
        assert_eq!(run_once(), first);
    }
    // The oldest duplicate wins: v2a still permits directory creation while
    // v2b (which dropped all user policies) would deny it.
    let engine = PolicyEngine::from_source(&base_bundle("v1")).unwrap();
    let mut v2a = base_bundle("v2");
    v2a.user_policies.pop();
    let mut v2b = base_bundle("v2");
    v2b.user_policies.clear();
    engine.load_and_activate(&v2a).unwrap();
    engine.load_and_activate(&v2b).unwrap();
    engine.rollback_to_version("v2").unwrap();
    let req = request("fs.create_directory", "Path", "demo", &engine, 62);
    let (decision, _) = engine.evaluate(&req, &principal(), NOW_MS).unwrap();
    assert!(
        matches!(decision, PolicyDecision::Allow { .. }),
        "oldest duplicate (v2a) must serve, got {decision:?}"
    );
}

#[test]
fn test_snapshot_hash_stable_across_rebuilds() {
    let a = PolicyEngine::from_source(&base_bundle("v1")).unwrap();
    let b = PolicyEngine::from_source(&base_bundle("v1")).unwrap();
    assert_eq!(a.active().hash, b.active().hash);
}

// ============================================================================
// 4. Default-deny + forbid-overrides + session restriction
// ============================================================================

#[test]
fn test_default_deny_without_permit() {
    let engine = PolicyEngine::from_source(&base_bundle("v1")).unwrap();
    let req = request("fs.unknown_xyz", "Path", "x", &engine, 21);
    let (decision, audit) = engine.evaluate(&req, &principal(), NOW_MS).unwrap();
    match decision {
        PolicyDecision::Deny { reason, .. } => assert_eq!(reason, "DefaultDenyNoMatchingPermit"),
        other => panic!("expected DENY, got {other:?}"),
    }
    assert_eq!(audit.decision, "DENY");
    assert!(!audit.confirmation_required);
}

#[test]
fn test_system_forbid_dominates_user_permit() {
    // fs.create_directory is user-permitted, but resource kind System is
    // system-forbidden: the forbid must win with system attribution.
    let engine = PolicyEngine::from_source(&base_bundle("v1")).unwrap();
    let req = request("fs.create_directory", "System", "/etc/x", &engine, 22);
    let (decision, _) = engine.evaluate(&req, &principal(), NOW_MS).unwrap();
    match decision {
        PolicyDecision::Deny {
            reason,
            contributing_policies,
        } => {
            assert!(reason.contains("system"), "reason: {reason}");
            assert!(contributing_policies
                .iter()
                .any(|p| p.starts_with("system-")));
        }
        other => panic!("expected DENY, got {other:?}"),
    }
}

#[test]
fn test_session_forbid_restricts_base_allow() {
    let mut bundle = base_bundle("v1");
    bundle.session_policies = vec![
        "forbid(principal, action == Action::\"invoke\", resource) when { context.resource_kind == \"Scratch\" };"
            .to_string(),
    ];
    let engine = PolicyEngine::from_source(&bundle).unwrap();
    let req = request("fs.read_file", "Scratch", "tmp", &engine, 23);
    let (decision, _) = engine.evaluate(&req, &principal(), NOW_MS).unwrap();
    match decision {
        PolicyDecision::Deny {
            contributing_policies,
            ..
        } => assert!(contributing_policies
            .iter()
            .any(|p| p.starts_with("session-"))),
        other => panic!("expected DENY, got {other:?}"),
    }
}

#[test]
fn test_session_permit_cannot_expand_base_deny() {
    let mut bundle = base_bundle("v1");
    bundle.session_policies = vec![
        "permit(principal, action == Action::\"invoke\", resource) when { context.capability_id == \"fs.superuser\" };"
            .to_string(),
    ];
    let engine = PolicyEngine::from_source(&bundle).unwrap();
    let req = request("fs.superuser", "Path", "x", &engine, 24);
    let (decision, _) = engine.evaluate(&req, &principal(), NOW_MS).unwrap();
    assert!(matches!(decision, PolicyDecision::Deny { .. }));
}

// ============================================================================
// 5. CONFIRM detection + precedence + malformed metadata
// ============================================================================

#[test]
fn test_confirm_without_token_issues_challenge() {
    let engine = PolicyEngine::from_source(&base_bundle("v1")).unwrap();
    let req = request("fs.delete", "Path", "old.txt", &engine, 31);
    let (decision, audit) = engine.evaluate(&req, &principal(), NOW_MS).unwrap();
    match decision {
        PolicyDecision::Confirm {
            prompt,
            blast_radius,
            required_scope,
            contributing_policies,
            ..
        } => {
            assert_eq!(prompt, "Delete the target resource?");
            assert_eq!(blast_radius, "destructive_filesystem");
            assert_eq!(required_scope, "fs.delete");
            assert!(contributing_policies.iter().any(|p| p.starts_with("user-")));
        }
        other => panic!("expected CONFIRM, got {other:?}"),
    }
    assert_eq!(audit.decision, "CONFIRM");
    assert!(audit.confirmation_required);
}

#[test]
fn test_confirm_precedence_over_plain_permit() {
    // A plain system permit for fs.delete must NOT waive the user-tier
    // @confirm requirement.
    let mut bundle = base_bundle("v1");
    bundle.system_policies.push(
        "permit(principal, action == Action::\"invoke\", resource) when { context.capability_id == \"fs.delete\" };"
            .to_string(),
    );
    let engine = PolicyEngine::from_source(&bundle).unwrap();
    let req = request("fs.delete", "Path", "old.txt", &engine, 32);
    let (decision, _) = engine.evaluate(&req, &principal(), NOW_MS).unwrap();
    assert!(matches!(decision, PolicyDecision::Confirm { .. }));
}

#[test]
fn test_malformed_confirm_value_fails_closed() {
    let mut bundle = base_bundle("v1");
    bundle.user_policies.push(
        [
            "@confirm(\"yes\")",
            "@confirm_prompt(\"???\")",
            "permit(principal, action == Action::\"invoke\", resource) when { context.capability_id == \"fs.read_file\" };",
        ]
        .join("\n"),
    );
    let engine = PolicyEngine::from_source(&bundle).unwrap();
    // Bundle loads (annotation values are opaque to Cedar); evaluation DENYs.
    let req = request("fs.read_file", "Path", "a.txt", &engine, 33);
    let (decision, _) = engine.evaluate(&req, &principal(), NOW_MS).unwrap();
    match decision {
        PolicyDecision::Deny { reason, .. } => assert!(reason.contains("malformed")),
        other => panic!("expected DENY, got {other:?}"),
    }
}

#[test]
fn test_confirm_without_prompt_fails_closed() {
    let mut bundle = base_bundle("v1");
    bundle.user_policies.push(
        [
            "@confirm(\"true\")",
            "permit(principal, action == Action::\"invoke\", resource) when { context.capability_id == \"fs.read_file\" };",
        ]
        .join("\n"),
    );
    let engine = PolicyEngine::from_source(&bundle).unwrap();
    let req = request("fs.read_file", "Path", "a.txt", &engine, 34);
    let (decision, _) = engine.evaluate(&req, &principal(), NOW_MS).unwrap();
    assert!(matches!(decision, PolicyDecision::Deny { .. }));
}

// ============================================================================
// 6. Token structural binding
// ============================================================================

#[test]
fn test_valid_token_binding_yields_allow_and_single_use() {
    let engine = PolicyEngine::from_source(&base_bundle("v1")).unwrap();
    let mut req = request("fs.delete", "Path", "old.txt", &engine, 41);
    req.approval_token = Some(fixture_token(&engine, &req, 41));
    let (decision, audit) = engine.evaluate(&req, &principal(), NOW_MS).unwrap();
    match decision {
        PolicyDecision::Allow {
            contributing_policies,
            ..
        } => {
            assert!(!contributing_policies.is_empty());
        }
        other => panic!("expected ALLOW, got {other:?}"),
    }
    assert_eq!(audit.decision, "ALLOW");
    assert_eq!(audit.approval_token_id, Some(uuid(41)));

    // Replay of the same token is rejected.
    let err = engine.evaluate(&req, &principal(), NOW_MS).unwrap_err();
    assert!(matches!(err, PolicyError::TokenReplayDetected));
}

#[test]
fn test_token_mismatch_shapes_rejected() {
    let engine = PolicyEngine::from_source(&base_bundle("v1")).unwrap();
    let mut req = request("fs.delete", "Path", "old.txt", &engine, 42);

    // Tampered arguments invalidate the request hash.
    let mut tampered = req.clone();
    tampered.approval_token = Some(fixture_token(&engine, &req, 42));
    tampered.arguments = serde_json::json!({"path": "other.txt"});
    assert!(matches!(
        engine.evaluate(&tampered, &principal(), NOW_MS),
        Err(PolicyError::InvalidApprovalToken { .. })
    ));

    // Wrong principal binding.
    let other = PrincipalContext::new("intruder", 1000, 1000);
    req.approval_token = Some(fixture_token(&engine, &req, 43));
    assert!(matches!(
        engine.evaluate(&req, &other, NOW_MS),
        Err(PolicyError::InvalidApprovalToken { .. })
    ));

    // Expired token.
    let mut expired = request("fs.delete", "Path", "old.txt", &engine, 44);
    let mut token = fixture_token(&engine, &expired, 44);
    token.payload.expires_at_ms = NOW_MS - 1;
    token.payload.issued_at_ms = NOW_MS - 60_000;
    expired.approval_token = Some(token);
    assert!(matches!(
        engine.evaluate(&expired, &principal(), NOW_MS),
        Err(PolicyError::InvalidApprovalToken { .. })
    ));

    // Snapshot mismatch invalidates the token: mint under v1, rotate to
    // v2, then present the v1-bound token (§11 invalidation rule).
    let engine_v1 = PolicyEngine::from_source(&base_bundle("v1")).unwrap();
    let req_v1 = request("fs.delete", "Path", "old.txt", &engine_v1, 46);
    let token_v1 = fixture_token(&engine_v1, &req_v1, 46);
    let mut carried = req_v1.clone();
    carried.approval_token = Some(token_v1);
    engine_v1.load_and_activate(&base_bundle("v2")).unwrap();
    assert!(matches!(
        engine_v1.evaluate(&carried, &principal(), NOW_MS),
        Err(PolicyError::InvalidApprovalToken { .. })
    ));
}

// ============================================================================
// 7. Determinism + lineage + error mapping
// ============================================================================

#[test]
fn test_deterministic_decisions_and_lineage() {
    let engine = PolicyEngine::from_source(&base_bundle("v1")).unwrap();
    let req = request("fs.read_file", "Path", "a.txt", &engine, 51);
    let (d1, a1) = engine.evaluate(&req, &principal(), NOW_MS).unwrap();
    let (d2, a2) = engine.evaluate(&req, &principal(), NOW_MS).unwrap();
    assert_eq!(d1, d2);
    assert_eq!(a1, a2);
    assert_eq!(a1.request_id, uuid(51));
    assert_eq!(a1.correlation_id, uuid(10_051));
    assert_eq!(a1.principal, "fixture-agent");
    assert_eq!(a1.action, "fs.read_file");
    assert_eq!(a1.active_snapshot_version, "v1");
    assert_eq!(a1.request_snapshot_hash, a1.active_snapshot_hash);
}

#[test]
fn test_error_payload_mapping() {
    let denied = PolicyError::PolicyDenied {
        reason: "x".to_string(),
        contributing_policies: vec![],
    };
    let payload = denied.to_payload();
    assert_eq!(payload.code, ErrorCode::PolicyDenied);
    assert_eq!(payload.retry_classification, RetryClassification::Never);

    let confirm = PolicyError::ConfirmationRequired {
        reason: "x".to_string(),
        contributing_policies: vec![],
    };
    assert_eq!(confirm.to_payload().code, ErrorCode::ConfirmationRequired);

    let replay = PolicyError::TokenReplayDetected.to_payload();
    assert_eq!(replay.code, ErrorCode::TokenReplayDetected);

    let internal = PolicyError::InternalError {
        reason: "x".to_string(),
    }
    .to_payload();
    assert_eq!(internal.code, ErrorCode::InternalError);
}

// ============================================================================
// 8. Zero-execution static audit of Phase 3.1 sources
// ============================================================================

/// Scans Phase 3.1 production sources for forbidden constructs.
///
/// Forbidden: subprocess/shell (`Command::new`, `fork`, `execve`,
/// `std::process`), live network (`TcpStream`, `TcpListener`, `UdpSocket`,
/// `reqwest`, `hyper`, `tokio::net`), IPC daemons (`UnixListener`,
/// `zbus`, `dbus`), sandbox enforcement (`bwrap`, `landlock`, `seccomp`,
/// `unshare`, `cgroup`), LLM/network clients, UI toolkits.
#[test]
fn test_security_audit_zero_forbidden_primitives_in_phase31_sources() {
    let source_files = [
        "src/policy/mod.rs",
        "src/policy/audit.rs",
        "src/policy/bundle.rs",
        "src/policy/canonical.rs",
        "src/policy/error.rs",
        "src/policy/evaluate.rs",
        "src/policy/request.rs",
        "src/policy/snapshot.rs",
    ];
    let crate_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let forbidden: &[(&str, &str)] = &[
        ("Command::new(", "subprocess execution"),
        ("std::process::Command", "subprocess execution"),
        ("process::exit", "process control"),
        ("fork(", "fork/exec"),
        ("execve(", "execve syscall"),
        ("sh -c", "shell invocation"),
        ("/bin/sh", "shell binary"),
        ("/bin/bash", "shell binary"),
        ("TcpStream", "live TCP network"),
        ("TcpListener", "live TCP listener"),
        ("UdpSocket", "live UDP network"),
        ("UnixListener", "live UDS listener"),
        ("reqwest", "HTTP client"),
        ("hyper::", "HTTP framework"),
        ("tokio::net", "async network runtime"),
        ("zbus", "D-Bus service"),
        ("dbus", "D-Bus service"),
        ("bwrap", "sandbox launcher"),
        ("landlock", "sandbox enforcement"),
        // NOTE: the spec-mandated `SandboxConstraints.seccomp_profile`
        // *data field* (§15) is permitted; only enforcement APIs are banned.
        ("seccomp::", "sandbox enforcement API"),
        ("libseccomp", "sandbox enforcement library"),
        ("SeccompFilter", "sandbox enforcement API"),
        ("unshare", "namespace manipulation"),
        ("cgroup", "cgroup manipulation"),
        ("sudo", "privilege escalation"),
        ("setuid", "privilege manipulation"),
        ("llama", "LLM integration"),
        ("ollama", "LLM integration"),
        ("openai", "LLM integration"),
        ("tauri", "UI framework"),
        ("gtk", "UI toolkit"),
        ("slint", "UI framework"),
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
        // Skip doc-comment mentions of forbidden concepts: only code matters.
        let code: String = content
            .lines()
            .filter(|line| {
                let trimmed = line.trim_start();
                !(trimmed.starts_with("//!") || trimmed.starts_with("///"))
            })
            .collect::<Vec<_>>()
            .join("\n");
        for (pattern, description) in forbidden {
            if code.contains(pattern) {
                violations.push(format!(
                    "FORBIDDEN `{pattern}` ({description}) in {relative}"
                ));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "security audit failed:\n{}",
        violations.join("\n")
    );
}
