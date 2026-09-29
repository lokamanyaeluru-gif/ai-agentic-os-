//! Phase 3.3 end-to-end acceptance: Phase 1 submit → manager assignment →
//! dispatch → validated plan, with zero host effects and full lineage.
//!
//! The demo input traverses the real Intent → Goal → Workflow chain. The
//! assignment step is then constructed with the symbolic `"workspace"`
//! scope label (Decision 3): the Phase 1 planner predates the Phase 3.2
//! scope vocabulary and emits `kind: "Path"`, which no fixture scope
//! matches. Lineage (correlation, workflow IDs) stays genuinely
//! end-to-end; only the unmapped scope label is adapted, and the reason is
//! asserted, not hidden: the planner's own capability choice is verified
//! first. No directory is created, read, or removed; no worker spawns.

use agenticos_core::capability::{fixture_bundle_manifests, CapabilityRegistry, ManifestBundle};
use agenticos_core::dispatch::{never_cancel, CancelFlag, DispatchOutcome, Dispatcher};
use agenticos_core::policy::{PolicyBundleSource, PolicyEngine};
use agenticos_core::{
    AgentId, AgentLifecycleState, AgentRecord, AgentRegistryStore, AgentScope, AgentType,
    AgentVersion, AssignmentRequest, AssignmentStatus, GlobalAgentManager, GoalStore, IntentStore,
    Phase1Runtime, PrincipalContext, ProcessIdentity, ProtocolVersion, ResourceRef, RestartPolicy,
    RetryClassification, StepExecutionState, SubmitRequest, WorkflowStep, WorkflowStore,
};
use std::collections::BTreeSet;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tempfile::TempDir;
use uuid::Uuid;

const NOW: u64 = 1_750_000_000_000;

fn principal() -> PrincipalContext {
    PrincipalContext::user(1000, 1000)
}

fn harness() -> (
    TempDir,
    Phase1Runtime,
    GlobalAgentManager,
    PolicyEngine,
    CapabilityRegistry,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let phase1 = Phase1Runtime::new(
        IntentStore::open(dir.path().join("intents.db")).unwrap(),
        GoalStore::open(dir.path().join("goals.db")).unwrap(),
        WorkflowStore::open(dir.path().join("workflows.db")).unwrap(),
    );
    let store = AgentRegistryStore::open(dir.path().join("agent_registry.db")).unwrap();
    let manager = GlobalAgentManager::new(store);
    let policy = PolicyEngine::from_source(&PolicyBundleSource {
        version: "v1".to_string(),
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
    })
    .unwrap();
    let registry =
        CapabilityRegistry::load(ManifestBundle::new(fixture_bundle_manifests())).unwrap();
    (dir, phase1, manager, policy, registry)
}

fn make_agent(id_seed: u128, capabilities: &[&str]) -> AgentRecord {
    let mut caps = BTreeSet::new();
    for c in capabilities {
        caps.insert(c.to_string());
    }
    AgentRecord {
        agent_id: AgentId::from_uuid(Uuid::from_u128(id_seed)),
        agent_type: AgentType::Builtin("TestAgent".to_string()),
        agent_version: AgentVersion::new(1, 0, 0),
        protocol_version: ProtocolVersion::V1_0,
        owner: principal(),
        scope: AgentScope::SystemWide,
        declared_capabilities: caps,
        process_identity: ProcessIdentity::unspawned(1000, 1000),
        state: AgentLifecycleState::Ready,
        restart_policy: RestartPolicy::Never,
        registered_at_ms: 1_000_000,
        updated_at_ms: 1_000_000,
    }
}

/// Assignment step in the fixture scope vocabulary. The capability comes
/// from the caller (in the demo test: verified against the real planner
/// output first); the kind is the symbolic fixture label.
fn workspace_step(capability: &str) -> WorkflowStep {
    WorkflowStep {
        step_id: Uuid::new_v4(),
        step_index: 0,
        capability_id: capability.to_string(),
        capability_schema_version: 1,
        resource: ResourceRef::new("workspace", "workspace-target"),
        arguments: serde_json::json!({"path": "workspace-target"}),
        dependency_step_ids: Vec::new(),
        state: StepExecutionState::Created,
        retry_classification: RetryClassification::Never,
        timeout_duration_ms: 30_000,
    }
}

fn submit_demo(phase1: &Phase1Runtime, correlation: Uuid) -> agenticos_core::Phase1Result {
    phase1
        .submit(SubmitRequest {
            raw_input: "Create a project folder called demo".to_string(),
            principal: principal(),
            correlation_id: correlation,
            idempotency_key: None,
            created_at_ms: NOW,
        })
        .expect("phase 1 submit")
}

fn cancel_flag() -> CancelFlag {
    Arc::new(AtomicBool::new(false))
}

// ============================================================================
// E2E-1: demo traversal to Planned + Ready with full lineage
// ============================================================================

#[test]
fn test_e2e_demo_submit_assign_dispatch_plan() {
    let (_dir, phase1, manager, policy, registry) = harness();
    let agent = make_agent(101, &["fs.create_directory"]);
    let agent_id = agent.agent_id;
    manager.register_agent(&agent).unwrap();

    let correlation = Uuid::from_u128(7001);
    let result = submit_demo(&phase1, correlation);
    // The real planner chooses the capability: keep it honestly in the loop.
    let planned_capability = result.workflow.steps[0].capability_id.clone();
    assert_eq!(planned_capability, "fs.create_directory");

    let assignment = manager
        .assign_step(&AssignmentRequest::new(
            result.workflow.correlation_id,
            Uuid::from_u128(7002),
            principal(),
            result.workflow.workflow_id,
            workspace_step(&planned_capability),
            NOW,
        ))
        .unwrap();

    let record = Dispatcher::new(&manager, &policy, &registry).dispatch(
        &assignment.assignment_id,
        NOW,
        &never_cancel(),
    );
    assert_eq!(record.outcome, DispatchOutcome::Planned);
    // Lineage preserved across all four planes.
    assert_eq!(record.correlation_id, correlation);
    assert_eq!(record.workflow_id, result.workflow.workflow_id);
    assert_eq!(record.request_id, assignment.request_id);
    assert!(record.binding_hash.is_some() && record.plan_hash.is_some());
    let dec = record.decision_ref.as_ref().expect("decision_ref present");
    assert_eq!(dec.contributing_policies, vec!["system-1"]);
    assert_eq!(
        manager
            .get_assignment(&assignment.assignment_id)
            .unwrap()
            .unwrap()
            .status,
        AssignmentStatus::Completed
    );
    assert_eq!(
        manager.get_agent(&agent_id).unwrap().unwrap().state,
        AgentLifecycleState::Ready
    );
}

// ============================================================================
// E2E-2..6: terminal branches, each released with lineage intact
// ============================================================================

#[test]
fn test_e2e_denied_releases_agent() {
    let (_dir, _phase1, manager, policy, registry) = harness();
    let agent = make_agent(102, &["fs.read_file"]);
    let agent_id = agent.agent_id;
    manager.register_agent(&agent).unwrap();
    let mut step = workspace_step("fs.read_file");
    step.resource = ResourceRef::new("System", "workspace-target");
    let assignment = manager
        .assign_step(&AssignmentRequest::new(
            Uuid::from_u128(7101),
            Uuid::from_u128(7102),
            principal(),
            Uuid::from_u128(7103),
            step,
            NOW,
        ))
        .unwrap();
    let record = Dispatcher::new(&manager, &policy, &registry).dispatch(
        &assignment.assignment_id,
        NOW,
        &never_cancel(),
    );
    assert_eq!(record.outcome, DispatchOutcome::Denied);
    assert_eq!(record.correlation_id, Uuid::from_u128(7101));
    assert_eq!(
        manager.get_agent(&agent_id).unwrap().unwrap().state,
        AgentLifecycleState::Ready
    );
}

#[test]
fn test_e2e_confirm_pending_never_upgrades() {
    let (_dir, _phase1, manager, policy, registry) = harness();
    let agent = make_agent(103, &["fs.delete_tree"]);
    manager.register_agent(&agent).unwrap();
    let assignment = manager
        .assign_step(&AssignmentRequest::new(
            Uuid::from_u128(7201),
            Uuid::from_u128(7202),
            principal(),
            Uuid::from_u128(7203),
            workspace_step("fs.delete_tree"),
            NOW,
        ))
        .unwrap();
    let record = Dispatcher::new(&manager, &policy, &registry).dispatch(
        &assignment.assignment_id,
        NOW,
        &never_cancel(),
    );
    assert_eq!(record.outcome, DispatchOutcome::ConfirmPending);
    assert!(record.confirmation.is_some());
    assert!(record.binding_hash.is_none() && record.plan_hash.is_none());
}

#[test]
fn test_e2e_unknown_capability_failed() {
    let (_dir, _phase1, manager, policy, registry) = harness();
    manager
        .register_agent(&make_agent(104, &["fs.nope"]))
        .unwrap();
    let assignment = manager
        .assign_step(&AssignmentRequest::new(
            Uuid::from_u128(7301),
            Uuid::from_u128(7302),
            principal(),
            Uuid::from_u128(7303),
            workspace_step("fs.nope"),
            NOW,
        ))
        .unwrap();
    let record = Dispatcher::new(&manager, &policy, &registry).dispatch(
        &assignment.assignment_id,
        NOW,
        &never_cancel(),
    );
    assert_eq!(record.outcome, DispatchOutcome::Failed);
}

#[test]
fn test_e2e_scope_mismatch_failed() {
    let (_dir, _phase1, manager, policy, registry) = harness();
    manager
        .register_agent(&make_agent(105, &["fs.read_file"]))
        .unwrap();
    let mut step = workspace_step("fs.read_file");
    step.resource = ResourceRef::new("elsewhere", "workspace-target");
    let assignment = manager
        .assign_step(&AssignmentRequest::new(
            Uuid::from_u128(7401),
            Uuid::from_u128(7402),
            principal(),
            Uuid::from_u128(7403),
            step,
            NOW,
        ))
        .unwrap();
    let record = Dispatcher::new(&manager, &policy, &registry).dispatch(
        &assignment.assignment_id,
        NOW,
        &never_cancel(),
    );
    assert_eq!(record.outcome, DispatchOutcome::Failed);
}

#[test]
fn test_e2e_snapshot_rotation_changes_verdict() {
    let (_dir, _phase1, manager, policy, registry) = harness();
    manager
        .register_agent(&make_agent(106, &["fs.read_file"]))
        .unwrap();
    let dispatcher = Dispatcher::new(&manager, &policy, &registry);
    let first = manager
        .assign_step(&AssignmentRequest::new(
            Uuid::from_u128(7501),
            Uuid::from_u128(7502),
            principal(),
            Uuid::from_u128(7503),
            workspace_step("fs.read_file"),
            NOW,
        ))
        .unwrap();
    let record = dispatcher.dispatch(&first.assignment_id, NOW, &never_cancel());
    assert_eq!(record.outcome, DispatchOutcome::Planned);
    // Rotate the bundle: revoke autonomous reads. The next dispatch reads
    // the fresh snapshot and denies — no stale service, no downgrade.
    policy
        .load_and_activate(&PolicyBundleSource {
            version: "v2".to_string(),
            system_policies: vec![
                "forbid(principal, action == Action::\"invoke\", resource) when { context.resource_kind == \"System\" };"
                    .to_string(),
            ],
            user_policies: vec![],
            session_policies: vec![],
        })
        .unwrap();
    let second = manager
        .assign_step(&AssignmentRequest::new(
            Uuid::from_u128(7511),
            Uuid::from_u128(7512),
            principal(),
            Uuid::from_u128(7513),
            workspace_step("fs.read_file"),
            NOW,
        ))
        .unwrap();
    let record = dispatcher.dispatch(&second.assignment_id, NOW, &never_cancel());
    assert_eq!(record.outcome, DispatchOutcome::Denied);
}

#[test]
fn test_e2e_cancel_injected_releases_agent() {
    let (_dir, _phase1, manager, policy, registry) = harness();
    let agent = make_agent(107, &["fs.read_file"]);
    let agent_id = agent.agent_id;
    manager.register_agent(&agent).unwrap();
    let assignment = manager
        .assign_step(&AssignmentRequest::new(
            Uuid::from_u128(7601),
            Uuid::from_u128(7602),
            principal(),
            Uuid::from_u128(7603),
            workspace_step("fs.read_file"),
            NOW,
        ))
        .unwrap();
    let flag = cancel_flag();
    flag.store(true, Ordering::SeqCst);
    let record = Dispatcher::new(&manager, &policy, &registry).dispatch(
        &assignment.assignment_id,
        NOW,
        &flag,
    );
    assert_eq!(record.outcome, DispatchOutcome::Cancelled);
    assert_eq!(
        manager.get_agent(&agent_id).unwrap().unwrap().state,
        AgentLifecycleState::Ready
    );
}

// ============================================================================
// E2E-7: purity — identical setups agree modulo fresh IDs
// ============================================================================

#[test]
fn test_e2e_repeated_runs_are_pure() {
    let (_dir, _phase1, manager, policy, registry) = harness();
    manager
        .register_agent(&make_agent(108, &["fs.create_directory"]))
        .unwrap();
    let dispatcher = Dispatcher::new(&manager, &policy, &registry);
    let run = |n: u128| {
        let assignment = manager
            .assign_step(&AssignmentRequest::new(
                Uuid::from_u128(n),
                Uuid::from_u128(n + 1),
                principal(),
                Uuid::from_u128(n + 2),
                workspace_step("fs.create_directory"),
                NOW,
            ))
            .unwrap();
        dispatcher.dispatch(&assignment.assignment_id, NOW, &never_cancel())
    };
    // Same agent serves both runs (released Ready after the first).
    let first = run(7701);
    let second = run(7711);
    assert_eq!(first.outcome, second.outcome);
    assert_eq!(first.decision_ref, second.decision_ref);
    assert_eq!(first.error, second.error);
    assert_ne!(first.dispatch_id, second.dispatch_id);
}
