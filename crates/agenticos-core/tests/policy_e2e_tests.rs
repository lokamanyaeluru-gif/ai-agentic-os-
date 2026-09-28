//! Phase 3.0 §23 end-to-end acceptance: synthetic fixtures A–D, bundle
//! rejection/rollback continuity, lineage, and the full-run zero-execution
//! assertion.
//!
//! Fixtures are synthetic and in-memory only. No directory is created, no
//! capability runs, no worker spawns: verification stops at the dispatch
//! boundary with `WorkAssignment`-free `CapabilityInvocationRequest`
//! evaluation records.

use agenticos_core::policy::{
    compute_request_hash, ApprovalToken, ApprovalTokenSignedPayload, CapabilityInvocationRequest,
    PolicyBundleSource, PolicyDecision, PolicyEngine,
};
use agenticos_core::{PrincipalContext, ResourceRef};
use uuid::Uuid;

const NOW_MS: u64 = 1_750_000_000_000;

fn principal() -> PrincipalContext {
    PrincipalContext::new("fixture-agent", 1000, 1000)
}

fn uuid(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

/// Shared fixture bundle: autonomous workspace reads, autonomous scratch
/// directory creation, system-kind forbid, confirmed deletions.
fn fixture_bundle(version: &str) -> PolicyBundleSource {
    PolicyBundleSource {
        version: version.to_string(),
        system_policies: vec![
            "permit(principal, action == Action::\"invoke\", resource) when { context.capability_id == \"fs.read_file\" };"
                .to_string(),
            "forbid(principal, action == Action::\"invoke\", resource) when { context.resource_kind == \"System\" };"
                .to_string(),
        ],
        user_policies: vec![
            "permit(principal, action == Action::\"invoke\", resource) when { context.capability_id == \"fs.create_directory\" };"
                .to_string(),
            [
                "@confirm(\"true\")",
                "@confirm_prompt(\"Recursively delete the workspace directory?\")",
                "@blast_radius(\"destructive_filesystem\")",
                "permit(principal, action == Action::\"invoke\", resource) when { context.capability_id == \"fs.delete_tree\" };",
            ]
            .join("\n"),
        ],
        session_policies: vec![],
    }
}

fn fixture_request(
    engine: &PolicyEngine,
    capability: &str,
    kind: &str,
    id: &str,
    n: u128,
) -> CapabilityInvocationRequest {
    CapabilityInvocationRequest {
        request_id: uuid(n),
        correlation_id: uuid(n + 50_000),
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

fn bound_token(engine: &PolicyEngine, req: &CapabilityInvocationRequest, n: u128) -> ApprovalToken {
    let request_hash = compute_request_hash(&req.approval_subject()).unwrap();
    ApprovalToken {
        // Opaque in Phase 3.1 (algorithm TBD); never verified.
        signature: vec![0x01],
        payload: ApprovalTokenSignedPayload {
            single_use_id: uuid(n),
            request_hash,
            policy_snapshot_hash: engine.active().hash,
            principal: principal().actor_id,
            capability: req.capability_id.clone(),
            resource: req.resource.clone(),
            confirmation_reason: "Recursively delete the workspace directory?".to_string(),
            issued_at_ms: NOW_MS - 1_000,
            expires_at_ms: NOW_MS + 30_000,
            nonce: [3u8; 16],
        },
    }
}

// ============================================================================
// Fixture A — autonomous workspace read → ALLOW
// ============================================================================

#[test]
fn test_e2e_fixture_a_workspace_read_allow() {
    let engine = PolicyEngine::from_source(&fixture_bundle("v1")).unwrap();
    let req = fixture_request(&engine, "fs.read_file", "Path", "notes.txt", 101);
    let (decision, audit) = engine.evaluate(&req, &principal(), NOW_MS).unwrap();
    match decision {
        PolicyDecision::Allow {
            constraints,
            contributing_policies,
        } => {
            assert!(!constraints.allow_network);
            assert_eq!(constraints.max_wall_time_ms, 10_000);
            assert!(constraints.read_paths.is_empty() && constraints.write_paths.is_empty());
            assert!(!contributing_policies.is_empty());
        }
        other => panic!("fixture A must ALLOW, got {other:?}"),
    }
    assert_eq!(audit.decision, "ALLOW");
    assert_eq!(audit.request_id, uuid(101));
    assert_eq!(audit.correlation_id, uuid(50_101));
    assert_eq!(audit.approval_token_id, None);
    assert_eq!(audit.request_snapshot_hash, audit.active_snapshot_hash);

    // The audit shape round-trips as strict JSON (deny_unknown_fields).
    let json = serde_json::to_string(&audit).unwrap();
    let back: agenticos_core::policy::PolicyAuditRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(back, audit);
}

// ============================================================================
// Fixture B — system-kind write forbidden despite user permit → DENY
// ============================================================================

#[test]
fn test_e2e_fixture_b_system_write_deny() {
    let engine = PolicyEngine::from_source(&fixture_bundle("v1")).unwrap();
    // fs.create_directory is user-permitted, but System kind is forbidden.
    let req = fixture_request(&engine, "fs.create_directory", "System", "svc", 102);
    let (decision, audit) = engine.evaluate(&req, &principal(), NOW_MS).unwrap();
    match decision {
        PolicyDecision::Deny {
            reason,
            contributing_policies,
        } => {
            assert!(reason.contains("system"), "reason: {reason}");
            assert_eq!(contributing_policies.len(), 1);
            assert!(contributing_policies[0].starts_with("system-"));
        }
        other => panic!("fixture B must DENY, got {other:?}"),
    }
    assert_eq!(audit.decision, "DENY");
}

// ============================================================================
// Fixture C — destructive mutation without token → CONFIRM, no constraints
// ============================================================================

#[test]
fn test_e2e_fixture_c_destructive_confirm() {
    let engine = PolicyEngine::from_source(&fixture_bundle("v1")).unwrap();
    let req = fixture_request(&engine, "fs.delete_tree", "Path", "scratch/old", 103);
    let (decision, audit) = engine.evaluate(&req, &principal(), NOW_MS).unwrap();
    match decision {
        PolicyDecision::Confirm {
            prompt,
            blast_radius,
            required_scope,
            contributing_policies,
            ..
        } => {
            assert_eq!(prompt, "Recursively delete the workspace directory?");
            assert_eq!(blast_radius, "destructive_filesystem");
            assert_eq!(required_scope, "fs.delete_tree");
            assert_eq!(contributing_policies.len(), 1);
        }
        other => panic!("fixture C must CONFIRM, got {other:?}"),
    }
    assert_eq!(audit.decision, "CONFIRM");
    assert!(audit.confirmation_required);
}

// ============================================================================
// Fixture C + bound token → ALLOW path, still zero execution
// ============================================================================

#[test]
fn test_e2e_fixture_c_with_token_allow_path() {
    let engine = PolicyEngine::from_source(&fixture_bundle("v1")).unwrap();
    let mut req = fixture_request(&engine, "fs.delete_tree", "Path", "scratch/old", 104);
    req.approval_token = Some(bound_token(&engine, &req, 104));
    let (decision, audit) = engine.evaluate(&req, &principal(), NOW_MS).unwrap();
    assert!(
        matches!(decision, PolicyDecision::Allow { .. }),
        "got {decision:?}"
    );
    assert_eq!(audit.decision, "ALLOW");
    assert_eq!(audit.approval_token_id, Some(uuid(104)));
    // No directory was created, removed, or touched: the engine performs
    // zero host I/O by construction (see full-run assertion below).
}

// ============================================================================
// Bundle rejection continuity + rollback determinism
// ============================================================================

#[test]
fn test_e2e_rejected_bundle_keeps_serving_fixtures() {
    let engine = PolicyEngine::from_source(&fixture_bundle("v1")).unwrap();
    let before_a = engine
        .evaluate(
            &fixture_request(&engine, "fs.read_file", "Path", "notes.txt", 105),
            &principal(),
            NOW_MS,
        )
        .unwrap()
        .0;
    let mut bad = fixture_bundle("v2-broken");
    bad.user_policies = vec!["permit(principal,".to_string()];
    assert!(engine.load_and_activate(&bad).is_err());
    let after_a = engine
        .evaluate(
            &fixture_request(&engine, "fs.read_file", "Path", "notes.txt", 105),
            &principal(),
            NOW_MS,
        )
        .unwrap()
        .0;
    assert_eq!(before_a, after_a);
}

#[test]
fn test_e2e_rollback_restores_prior_behavior() {
    let engine = PolicyEngine::from_source(&fixture_bundle("v1")).unwrap();
    // v2 revokes autonomous reads.
    let mut v2 = fixture_bundle("v2");
    v2.system_policies = vec![
        "forbid(principal, action == Action::\"invoke\", resource) when { context.resource_kind == \"System\" };"
            .to_string(),
    ];
    engine.load_and_activate(&v2).unwrap();
    let denied = engine
        .evaluate(
            &fixture_request(&engine, "fs.read_file", "Path", "notes.txt", 106),
            &principal(),
            NOW_MS,
        )
        .unwrap()
        .0;
    assert!(matches!(denied, PolicyDecision::Deny { .. }));

    engine.rollback_to_version("v1").unwrap();
    let allowed = engine
        .evaluate(
            &fixture_request(&engine, "fs.read_file", "Path", "notes.txt", 106),
            &principal(),
            NOW_MS,
        )
        .unwrap()
        .0;
    assert!(matches!(allowed, PolicyDecision::Allow { .. }));
}

// ============================================================================
// Full-run assertion: zero execution primitives, full lineage
// ============================================================================

#[test]
fn test_e2e_full_run_zero_execution_and_lineage() {
    let engine = PolicyEngine::from_source(&fixture_bundle("v1")).unwrap();
    let cases = [
        ("fs.read_file", "Path", "a.txt", 201u128),
        ("fs.create_directory", "Path", "demo", 202u128),
        ("fs.delete_tree", "Path", "scratch/old", 203u128),
    ];
    for (capability, kind, id, n) in cases {
        let req = fixture_request(&engine, capability, kind, id, n);
        let (decision, audit) = engine.evaluate(&req, &principal(), NOW_MS).unwrap();
        // Every path terminates in a typed decision with lineage intact.
        assert_eq!(audit.request_id, uuid(n));
        assert_eq!(audit.correlation_id, uuid(n + 50_000));
        assert_eq!(audit.action, capability);
        assert_eq!(audit.resource_kind, kind);
        assert_eq!(audit.resource_id, id);
        assert_eq!(audit.active_snapshot_version, "v1");
        match decision {
            PolicyDecision::Allow { .. } => assert_eq!(audit.decision, "ALLOW"),
            PolicyDecision::Deny { .. } => assert_eq!(audit.decision, "DENY"),
            PolicyDecision::Confirm { .. } => assert_eq!(audit.decision, "CONFIRM"),
        }
    }

    // Zero host side effects by construction: the policy plane opens no
    // databases, spawns no processes, and dials no sockets. The static
    // source audit in policy_tests.rs enforces this on every run; here we
    // assert the behavioral corollary — repeated evaluation is pure.
    let req = fixture_request(&engine, "fs.read_file", "Path", "a.txt", 204);
    let first = engine.evaluate(&req, &principal(), NOW_MS).unwrap();
    let second = engine.evaluate(&req, &principal(), NOW_MS).unwrap();
    assert_eq!(first, second);
}
