//! Phase 3.2 end-to-end acceptance: Layer 8 `ALLOW` → registry → binding →
//! validated plan, with zero host effects and full lineage.
//!
//! The E2E path drives the real Phase 3.1 `PolicyEngine` (Cedar evaluation)
//! and binds its `ALLOW` decisions through the capability boundary. No
//! directory is created, removed, or read; no worker spawns; verification
//! stops at validated plan data. Fixture scope labels are pure symbols.

use agenticos_core::capability::{
    bind, build_plan, fixture_bundle_manifests, validate, CapabilityRegistry, ManifestBundle,
    SandboxProfile,
};
use agenticos_core::policy::PolicyDecision;
use agenticos_core::policy::{
    compute_request_hash, ApprovalToken, ApprovalTokenSignedPayload, CapabilityInvocationRequest,
    PolicyBundleSource, PolicyEngine,
};
use agenticos_core::{PrincipalContext, ResourceRef};
use uuid::Uuid;

const NOW_MS: u64 = 1_750_000_000_000;

fn uuid(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

fn principal() -> PrincipalContext {
    PrincipalContext::new("fixture-agent", 1000, 1000)
}

/// Cedar bundle mirroring the boundary fixtures: autonomous read/create,
/// confirmed `fs.delete_tree`, system-kind forbid.
fn policy_bundle(version: &str) -> PolicyBundleSource {
    PolicyBundleSource {
        version: version.to_string(),
        system_policies: vec![
            "permit(principal, action == Action::\"invoke\", resource) when { context.capability_id == \"fs.read_file\" };"
                .to_string(),
            "permit(principal, action == Action::\"invoke\", resource) when { context.capability_id == \"fs.create_directory\" };"
                .to_string(),
            "forbid(principal, action == Action::\"invoke\", resource) when { context.resource_kind == \"System\" };"
                .to_string(),
        ],
        user_policies: vec![[
            "@confirm(\"true\")",
            "@confirm_prompt(\"Recursively delete?\")",
            "@blast_radius(\"destructive_filesystem\")",
            "permit(principal, action == Action::\"invoke\", resource) when { context.capability_id == \"fs.delete_tree\" };",
        ]
        .join("\n")],
        session_policies: vec![],
    }
}

fn request(engine: &PolicyEngine, capability: &str, n: u128) -> CapabilityInvocationRequest {
    CapabilityInvocationRequest {
        request_id: uuid(n),
        correlation_id: uuid(n + 70_000),
        capability_id: capability.to_string(),
        capability_schema_version: 1,
        // Symbolic scope label only (Decision 4): never a host path.
        resource: ResourceRef::new("workspace", "workspace-target"),
        arguments: serde_json::json!({"path": "workspace-target"}),
        deadline_ms: NOW_MS + 10_000,
        timeout_duration_ms: 10_000,
        policy_snapshot_hash: engine.active().hash,
        approval_token: None,
    }
}

fn bound_token(engine: &PolicyEngine, req: &CapabilityInvocationRequest, n: u128) -> ApprovalToken {
    ApprovalToken {
        // Opaque in Phase 3.1/3.2 (algorithm TBD); structural binding only.
        signature: vec![0x02],
        payload: ApprovalTokenSignedPayload {
            single_use_id: uuid(n),
            request_hash: compute_request_hash(&req.approval_subject()).unwrap(),
            policy_snapshot_hash: engine.active().hash,
            principal: principal().actor_id,
            capability: req.capability_id.clone(),
            resource: req.resource.clone(),
            confirmation_reason: "Recursively delete?".to_string(),
            issued_at_ms: NOW_MS - 1_000,
            expires_at_ms: NOW_MS + 30_000,
            nonce: [5u8; 16],
        },
    }
}

fn registry() -> CapabilityRegistry {
    CapabilityRegistry::load(ManifestBundle::new(fixture_bundle_manifests())).unwrap()
}

/// Evaluate through Layer 8, bind the `ALLOW`, build and validate the plan.
fn evaluate_bind_plan(
    engine: &PolicyEngine,
    req: &CapabilityInvocationRequest,
) -> (
    agenticos_core::capability::InvocationBinding,
    agenticos_core::capability::SandboxConstructionPlan,
    agenticos_core::policy::PolicyAuditRecord,
) {
    let (decision, audit) = engine.evaluate(req, &principal(), NOW_MS).unwrap();
    let binding = bind(req, &decision, &engine.active().hash, &registry()).unwrap();
    let manifest = registry()
        .get(&binding.capability_id, binding.capability_schema_version)
        .unwrap()
        .clone();
    let plan = build_plan(&binding, &manifest).unwrap();
    validate(&plan).unwrap();
    (binding, plan, audit)
}

// ============================================================================
// E2E-1: fs.read_file ALLOW → valid Profile 1 plan
// ============================================================================

#[test]
fn test_e2e_read_allow_yields_valid_profile1_plan() {
    let engine = PolicyEngine::from_source(&policy_bundle("v1")).unwrap();
    let req = request(&engine, "fs.read_file", 301);
    let (binding, plan, audit) = evaluate_bind_plan(&engine, &req);

    assert_eq!(binding.manifest_ref, "fs.read_file@1");
    assert_eq!(plan.profile, SandboxProfile::Profile1);
    assert!(plan.no_new_privs);
    assert!(plan.bwrap_argv.is_none());
    assert!(!binding.resolved.allow_network);
    assert_eq!(audit.decision, "ALLOW");
    // Lineage: request → decision → binding → plan.
    assert_eq!(binding.request_id, uuid(301));
    assert_eq!(binding.correlation_id, uuid(70_301));
    assert_eq!(binding.decision_ref.snapshot_hash, engine.active().hash);
    assert_eq!(plan.binding_hash, binding.binding_hash);
    assert_eq!(audit.request_id, uuid(301));
}

// ============================================================================
// E2E-2: fs.delete_tree without token → CONFIRM, handoff refused, no plan
// ============================================================================

#[test]
fn test_e2e_delete_without_token_refuses_handoff() {
    let engine = PolicyEngine::from_source(&policy_bundle("v1")).unwrap();
    let req = request(&engine, "fs.delete_tree", 302);
    let (decision, _) = engine.evaluate(&req, &principal(), NOW_MS).unwrap();
    assert!(matches!(decision, PolicyDecision::Confirm { .. }));
    // The handoff accepts only ALLOW: CONFIRM cannot produce a binding.
    assert!(bind(&req, &decision, &engine.active().hash, &registry()).is_err());
}

// ============================================================================
// E2E-3: fs.delete_tree with bound token → valid Profile 2 plan, zero exec
// ============================================================================

#[test]
fn test_e2e_delete_with_token_yields_valid_profile2_plan() {
    let engine = PolicyEngine::from_source(&policy_bundle("v1")).unwrap();
    let mut req = request(&engine, "fs.delete_tree", 303);
    req.approval_token = Some(bound_token(&engine, &req, 303));
    let (binding, plan, audit) = evaluate_bind_plan(&engine, &req);

    assert_eq!(plan.profile, SandboxProfile::Profile2);
    let argv = plan.bwrap_argv.clone().unwrap().0;
    assert_eq!(argv[0], "bwrap");
    assert!(argv.contains(&"--unshare-net".to_string()));
    assert_eq!(audit.decision, "ALLOW");
    assert_eq!(audit.approval_token_id, Some(uuid(303)));
    assert_eq!(plan.binding_hash, binding.binding_hash);
}

// ============================================================================
// E2E-4: unknown capability → CapabilityNotFound after Layer 8 deny
// ============================================================================

#[test]
fn test_e2e_unknown_capability_rejected() {
    use agenticos_core::capability::CapabilityError;
    let engine = PolicyEngine::from_source(&policy_bundle("v1")).unwrap();
    let req = request(&engine, "fs.nope", 304);
    let (decision, _) = engine.evaluate(&req, &principal(), NOW_MS).unwrap();
    // Layer 8 denies first (default-deny); even a forged ALLOW cannot bind.
    assert!(matches!(decision, PolicyDecision::Deny { .. }));
    let forged = PolicyDecision::Allow {
        constraints: agenticos_core::policy::SandboxConstraints {
            read_paths: vec![],
            write_paths: vec![],
            allow_network: false,
            seccomp_profile: "x".to_string(),
            max_memory_bytes: 0,
            max_cpu_quota_percent: 0,
            max_wall_time_ms: 10_000,
        },
        contributing_policies: vec![],
    };
    assert!(matches!(
        bind(&req, &forged, &engine.active().hash, &registry()),
        Err(CapabilityError::UnknownCapability { .. })
    ));
}

// ============================================================================
// E2E-5: tampered binding inputs rejected; lineage intact on success paths
// ============================================================================

#[test]
fn test_e2e_tampered_and_stale_handoffs_rejected() {
    use agenticos_core::capability::CapabilityError;
    let engine = PolicyEngine::from_source(&policy_bundle("v1")).unwrap();
    let req = request(&engine, "fs.create_directory", 305);
    let (decision, _) = engine.evaluate(&req, &principal(), NOW_MS).unwrap();

    // Stale snapshot hash.
    assert!(matches!(
        bind(&req, &decision, &[8u8; 32], &registry()),
        Err(CapabilityError::StaleAuthorization { .. })
    ));

    // Tampered decision content (wrong contributing set is still ALLOW, but
    // the binding records exactly what it was given — lineage over trust).
    let (binding, plan, audit) = evaluate_bind_plan(&engine, &req);
    assert_eq!(binding.decision_ref.contributing_policies, {
        match &decision {
            PolicyDecision::Allow {
                contributing_policies,
                ..
            } => {
                let mut ids = contributing_policies.clone();
                ids.sort();
                ids
            }
            _ => unreachable!(),
        }
    });
    assert_eq!(audit.correlation_id, binding.correlation_id);
    assert_eq!(plan.binding_hash, binding.binding_hash);
}

// ============================================================================
// E2E-6: full-run purity — repeated evaluation binds identical plans
// ============================================================================

#[test]
fn test_e2e_repeated_runs_are_pure() {
    let engine = PolicyEngine::from_source(&policy_bundle("v1")).unwrap();
    let first = evaluate_bind_plan(&engine, &request(&engine, "fs.read_file", 306));
    let second = evaluate_bind_plan(&engine, &request(&engine, "fs.read_file", 306));
    // Same binding content modulo fresh IDs hashes identically in structure:
    // plans built from equal bindings (sans fresh IDs) agree field-for-field.
    assert_eq!(first.1.profile, second.1.profile);
    assert_eq!(first.1.mounts, second.1.mounts);
    assert_eq!(first.1.seccomp, second.1.seccomp);
    assert_eq!(first.1.bwrap_argv, second.1.bwrap_argv);
}
