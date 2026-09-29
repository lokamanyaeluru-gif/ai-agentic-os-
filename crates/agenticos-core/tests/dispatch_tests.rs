//! Phase 3.3 dispatch unit tests: synthesis, claims, cancellation,
//! terminal mapping, honesty, determinism, error mapping, zero-escape audit.
//!
//! All fixtures are synthetic and in-memory (SQLite stores live in test
//! tempdirs only). Scope labels are pure symbols (`"workspace"`); no host
//! paths appear. Nothing is spawned, installed, or executed.

use agenticos_core::capability::{fixture_bundle_manifests, CapabilityRegistry, ManifestBundle};
use agenticos_core::dispatch::{
    never_cancel, CancelFlag, ConfirmationChallenge, DispatchError, DispatchOutcome, Dispatcher,
};
use agenticos_core::policy::{PolicyBundleSource, PolicyEngine};
use agenticos_core::{
    AgentId, AgentLifecycleState, AgentRecord, AgentRegistryStore, AgentScope, AgentType,
    AgentVersion, AssignmentId, AssignmentRequest, AssignmentStatus, ErrorCode, GlobalAgentManager,
    PrincipalContext, ProcessIdentity, ProtocolVersion, ResourceRef, RestartPolicy,
    RetryClassification, StepExecutionState, WorkflowStep,
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

fn temp_manager() -> (TempDir, GlobalAgentManager) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("agent_registry.db");
    let store = AgentRegistryStore::open(&path).expect("open registry store");
    (dir, GlobalAgentManager::new(store))
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

fn make_step(capability: &str, kind: &str, timeout_ms: u64) -> WorkflowStep {
    WorkflowStep {
        step_id: Uuid::new_v4(),
        step_index: 0,
        capability_id: capability.to_string(),
        capability_schema_version: 1,
        resource: ResourceRef::new(kind, "workspace-target"),
        arguments: serde_json::json!({"path": "workspace-target"}),
        dependency_step_ids: Vec::new(),
        state: StepExecutionState::Created,
        retry_classification: RetryClassification::Never,
        timeout_duration_ms: timeout_ms,
    }
}

fn assign(
    manager: &GlobalAgentManager,
    step: WorkflowStep,
    workflow_id: Uuid,
    ts: u64,
) -> agenticos_core::WorkAssignment {
    let request = AssignmentRequest::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        principal(),
        workflow_id,
        step,
        ts,
    );
    manager.assign_step(&request).expect("assign_step")
}

fn policy_engine() -> PolicyEngine {
    PolicyEngine::from_source(&PolicyBundleSource {
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
    .expect("policy engine")
}

fn registry() -> CapabilityRegistry {
    CapabilityRegistry::load(ManifestBundle::new(fixture_bundle_manifests()))
        .expect("fixture registry")
}

fn dispatcher<'a>(
    manager: &'a GlobalAgentManager,
    policy: &'a PolicyEngine,
    registry: &'a CapabilityRegistry,
) -> Dispatcher<'a> {
    Dispatcher::new(manager, policy, registry)
}

fn cancel_flag() -> CancelFlag {
    Arc::new(AtomicBool::new(false))
}

fn agent_state(manager: &GlobalAgentManager, agent: AgentId) -> AgentLifecycleState {
    manager
        .get_agent(&agent)
        .expect("get agent")
        .expect("agent present")
        .state
}

// ============================================================================
// 1. Synthesis contract
// ============================================================================

#[test]
fn test_synthesis_field_mapping_and_deadline() {
    use agenticos_core::dispatch::synthesize;
    let (_dir, manager) = temp_manager();
    manager
        .register_agent(&make_agent(1, &["fs.read_file"]))
        .unwrap();
    let assignment = assign(
        &manager,
        make_step("fs.read_file", "workspace", 30_000),
        Uuid::from_u128(900),
        NOW,
    );
    let engine = policy_engine();
    let request = synthesize::synthesize(&assignment, &engine.active().hash, &registry()).unwrap();
    assert_eq!(request.request_id, assignment.request_id);
    assert_eq!(request.correlation_id, assignment.correlation_id);
    assert_eq!(request.capability_id, "fs.read_file");
    assert_eq!(request.capability_schema_version, 1);
    assert_eq!(request.resource.kind, "workspace");
    assert_eq!(request.arguments, assignment.arguments);
    assert_eq!(request.timeout_duration_ms, 30_000);
    assert_eq!(request.deadline_ms, NOW + 30_000);
    assert_eq!(request.policy_snapshot_hash, engine.active().hash);
    assert!(request.approval_token.is_none());
}

#[test]
fn test_synthesis_deadline_saturates_on_overflow() {
    use agenticos_core::dispatch::synthesize;
    use agenticos_core::WorkAssignment;
    let assignment = WorkAssignment::new(
        Uuid::from_u128(1),
        Uuid::from_u128(2),
        principal(),
        Uuid::from_u128(3),
        Uuid::from_u128(4),
        AgentId::from_uuid(Uuid::from_u128(5)),
        "fs.read_file",
        serde_json::json!({"path": "x"}),
        ResourceRef::new("workspace", "x"),
        u64::MAX - 5,
        30,
    )
    .unwrap();
    let engine = policy_engine();
    let request = synthesize::synthesize(&assignment, &engine.active().hash, &registry()).unwrap();
    assert_eq!(request.deadline_ms, u64::MAX);
}

#[test]
fn test_version_resolution_zero_and_many() {
    use agenticos_core::dispatch::synthesize::resolve_schema_version;
    let empty = CapabilityRegistry::load(ManifestBundle::new(vec![])).unwrap();
    assert!(matches!(
        resolve_schema_version("fs.read_file", &empty),
        Err(DispatchError::SynthesisConflict { .. })
    ));
    let mut two = fixture_bundle_manifests();
    let mut second = two[0].clone();
    second.capability_schema_version = 2;
    two.push(second);
    let multi = CapabilityRegistry::load(ManifestBundle::new(two)).unwrap();
    assert!(matches!(
        resolve_schema_version("fs.read_file", &multi),
        Err(DispatchError::SynthesisConflict { .. })
    ));
    assert_eq!(resolve_schema_version("fs.read_file", &registry()), Ok(1));
}

// ============================================================================
// 2. Claim guards
// ============================================================================

#[test]
fn test_claim_unknown_assignment_fails_without_state_touch() {
    let (_dir, manager) = temp_manager();
    let engine = policy_engine();
    let registry = registry();
    let record = dispatcher(&manager, &engine, &registry).dispatch(
        &AssignmentId::from_uuid(Uuid::from_u128(4242)),
        NOW,
        &never_cancel(),
    );
    assert_eq!(record.outcome, DispatchOutcome::Failed);
    let error = record.error.expect("error attached");
    assert_eq!(error.code, ErrorCode::InvalidRequest);
}

#[test]
fn test_claim_terminal_redispatch_refused() {
    let (_dir, manager) = temp_manager();
    manager
        .register_agent(&make_agent(11, &["fs.read_file"]))
        .unwrap();
    let engine = policy_engine();
    let registry = registry();
    let dispatcher = dispatcher(&manager, &engine, &registry);
    let assignment = assign(
        &manager,
        make_step("fs.read_file", "workspace", 30_000),
        Uuid::from_u128(901),
        NOW,
    );
    let first = dispatcher.dispatch(&assignment.assignment_id, NOW, &never_cancel());
    assert_eq!(first.outcome, DispatchOutcome::Planned);
    // Second dispatch of the now-terminal assignment fails closed.
    let second = dispatcher.dispatch(&assignment.assignment_id, NOW, &never_cancel());
    assert_eq!(second.outcome, DispatchOutcome::Failed);
    let error = second.error.expect("error attached");
    assert_eq!(error.code, ErrorCode::InvalidRequest);
    // Manager state untouched by the refused re-dispatch.
    let stored = manager
        .get_assignment(&assignment.assignment_id)
        .unwrap()
        .unwrap();
    assert_eq!(stored.status, AssignmentStatus::Completed);
}

// ============================================================================
// 3. Cancellation checkpoints
// ============================================================================

#[test]
fn test_cancel_before_claim_releases_agent() {
    let (_dir, manager) = temp_manager();
    let agent = make_agent(21, &["fs.read_file"]);
    let agent_id = agent.agent_id;
    manager.register_agent(&agent).unwrap();
    let engine = policy_engine();
    let registry = registry();
    let assignment = assign(
        &manager,
        make_step("fs.read_file", "workspace", 30_000),
        Uuid::from_u128(902),
        NOW,
    );
    let flag = cancel_flag();
    flag.store(true, Ordering::SeqCst);
    let record =
        dispatcher(&manager, &engine, &registry).dispatch(&assignment.assignment_id, NOW, &flag);
    assert_eq!(record.outcome, DispatchOutcome::Cancelled);
    assert!(record.error.is_none());
    let stored = manager
        .get_assignment(&assignment.assignment_id)
        .unwrap()
        .unwrap();
    assert_eq!(stored.status, AssignmentStatus::Cancelled);
    assert_eq!(agent_state(&manager, agent_id), AgentLifecycleState::Ready);
}

#[test]
fn test_cancel_checkpoints_present_at_all_stages() {
    // Post-claim checkpoints cannot be triggered deterministically through
    // the public API in a single call (a pre-set flag always fires the
    // pre-claim checkpoint first, by design). This structural test pins
    // their existence: exactly one check per stage — before claim, before
    // synthesis, before evaluation submission, before binding.
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/dispatch/dispatch.rs"),
    )
    .expect("read dispatch.rs");
    let checkpoints = source.matches("is_cancelled(cancel)").count();
    assert_eq!(
        checkpoints, 4,
        "expected 4 cooperative cancel checkpoints, found {checkpoints}"
    );
}

#[test]
fn test_claim_guard_precedes_cancel_check() {
    // A terminal assignment with a set flag fails closed on the claim guard
    // (Failed/ClaimRejected), not Cancelled: there is nothing to cancel,
    // and guards run before cancel checks by design.
    let (_dir, manager) = temp_manager();
    let agent = make_agent(23, &["fs.read_file"]);
    let agent_id = agent.agent_id;
    manager.register_agent(&agent).unwrap();
    let engine = policy_engine();
    let registry = registry();
    let assignment = assign(
        &manager,
        make_step("fs.read_file", "workspace", 30_000),
        Uuid::from_u128(904),
        NOW,
    );
    manager
        .start_assignment(&assignment.assignment_id, NOW)
        .unwrap();
    let flag = cancel_flag();
    flag.store(true, Ordering::SeqCst);
    let record =
        dispatcher(&manager, &engine, &registry).dispatch(&assignment.assignment_id, NOW, &flag);
    assert_eq!(record.outcome, DispatchOutcome::Failed);
    let stored = manager
        .get_assignment(&assignment.assignment_id)
        .unwrap()
        .unwrap();
    assert_eq!(stored.status, AssignmentStatus::InProgress);
    // Dispatch never owned the claim, so it released nothing: the agent
    // stays Running and the manager guard is untouched.
    assert_eq!(
        agent_state(&manager, agent_id),
        AgentLifecycleState::Running
    );
}

// ============================================================================
// 4. Terminal mapping + release on every path
// ============================================================================

#[test]
fn test_terminal_mapping_and_release() {
    // Planned.
    let (_dir, manager) = temp_manager();
    let agent_id = AgentId::from_uuid(Uuid::from_u128(31));
    let mut agent = make_agent(
        31,
        &["fs.read_file", "fs.create_directory", "fs.delete_tree"],
    );
    agent.agent_id = agent_id;
    manager.register_agent(&agent).unwrap();
    let engine = policy_engine();
    let registry = registry();
    let dispatcher = dispatcher(&manager, &engine, &registry);

    let planned = assign(
        &manager,
        make_step("fs.create_directory", "workspace", 30_000),
        Uuid::from_u128(910),
        NOW,
    );
    let record = dispatcher.dispatch(&planned.assignment_id, NOW, &never_cancel());
    assert_eq!(record.outcome, DispatchOutcome::Planned);
    assert!(record.binding_hash.is_some() && record.plan_hash.is_some());
    let dec = record.decision_ref.as_ref().expect("decision_ref present");
    assert_eq!(dec.contributing_policies, vec!["system-1"]);
    assert_eq!(
        manager
            .get_assignment(&planned.assignment_id)
            .unwrap()
            .unwrap()
            .status,
        AssignmentStatus::Completed
    );

    // Denied (system-kind forbid).
    let denied = assign(
        &manager,
        make_step("fs.read_file", "System", 30_000),
        Uuid::from_u128(911),
        NOW,
    );
    let record = dispatcher.dispatch(&denied.assignment_id, NOW, &never_cancel());
    assert_eq!(record.outcome, DispatchOutcome::Denied);
    assert!(record.error.is_some());
    assert_eq!(
        manager
            .get_assignment(&denied.assignment_id)
            .unwrap()
            .unwrap()
            .status,
        AssignmentStatus::Failed
    );

    // ConfirmPending (delete_tree, no token minted by construction).
    let confirm = assign(
        &manager,
        make_step("fs.delete_tree", "workspace", 30_000),
        Uuid::from_u128(912),
        NOW,
    );
    let record = dispatcher.dispatch(&confirm.assignment_id, NOW, &never_cancel());
    assert_eq!(record.outcome, DispatchOutcome::ConfirmPending);
    let challenge: ConfirmationChallenge = record.confirmation.clone().expect("challenge attached");
    assert!(!challenge.prompt.is_empty());
    assert_eq!(
        manager
            .get_assignment(&confirm.assignment_id)
            .unwrap()
            .unwrap()
            .status,
        AssignmentStatus::Failed
    );
    assert_eq!(agent_state(&manager, agent_id), AgentLifecycleState::Ready);
}

#[test]
fn test_failed_synthesis_releases_agent() {
    let (_dir, manager) = temp_manager();
    let agent_id = AgentId::from_uuid(Uuid::from_u128(32));
    let mut agent = make_agent(32, &["fs.nope"]);
    agent.agent_id = agent_id;
    manager.register_agent(&agent).unwrap();
    let engine = policy_engine();
    let registry = registry();
    let assignment = assign(
        &manager,
        make_step("fs.nope", "workspace", 30_000),
        Uuid::from_u128(913),
        NOW,
    );
    let record = dispatcher(&manager, &engine, &registry).dispatch(
        &assignment.assignment_id,
        NOW,
        &never_cancel(),
    );
    assert_eq!(record.outcome, DispatchOutcome::Failed);
    assert_eq!(
        manager
            .get_assignment(&assignment.assignment_id)
            .unwrap()
            .unwrap()
            .status,
        AssignmentStatus::Failed
    );
    assert_eq!(agent_state(&manager, agent_id), AgentLifecycleState::Ready);
}

// ============================================================================
// 5. Honesty, determinism, error mapping
// ============================================================================

#[test]
fn test_preconditions_recorded_verbatim_never_evaluated() {
    let (_dir, manager) = temp_manager();
    manager
        .register_agent(&make_agent(41, &["fs.create_directory"]))
        .unwrap();
    let engine = policy_engine();
    let registry = registry();
    let assignment = assign(
        &manager,
        make_step("fs.create_directory", "workspace", 30_000),
        Uuid::from_u128(914),
        NOW,
    );
    let record = dispatcher(&manager, &engine, &registry).dispatch(
        &assignment.assignment_id,
        NOW,
        &never_cancel(),
    );
    assert_eq!(record.outcome, DispatchOutcome::Planned);
    let manifest = registry.get("fs.create_directory", 1).unwrap();
    assert_eq!(record.declared_preconditions, manifest.preconditions);
    assert_eq!(record.declared_postconditions, manifest.postconditions);
    // No evaluated results exist anywhere on the record.
    let json = serde_json::to_value(&record).unwrap();
    assert!(json.get("is_satisfied").is_none());
    assert!(json.get("condition_results").is_none());
}

#[test]
fn test_determinism_modulo_fresh_ids() {
    let run_once = |seed: u128| {
        let (_dir, manager) = temp_manager();
        manager
            .register_agent(&make_agent(seed, &["fs.read_file"]))
            .unwrap();
        let engine = policy_engine();
        let registry = registry();
        let assignment = assign(
            &manager,
            make_step("fs.read_file", "workspace", 30_000),
            Uuid::from_u128(915),
            NOW,
        );
        dispatcher(&manager, &engine, &registry).dispatch(
            &assignment.assignment_id,
            NOW,
            &never_cancel(),
        )
    };
    let first = run_once(51);
    let second = run_once(52);
    assert_eq!(first.outcome, second.outcome);
    assert_eq!(first.decision_ref, second.decision_ref);
    assert_eq!(first.error, second.error);
    assert_eq!(first.declared_preconditions, second.declared_preconditions);
    // Fresh IDs/hashes differ by construction (uniqueness, not nondeterminism).
    assert_ne!(first.dispatch_id, second.dispatch_id);
    assert_ne!(first.binding_hash, second.binding_hash);
}

#[test]
fn test_dispatch_error_mapping() {
    let conflict = DispatchError::SynthesisConflict {
        reason: "x".to_string(),
    }
    .to_payload();
    assert_eq!(conflict.code, ErrorCode::InvalidRequest);
    assert_eq!(conflict.retry_classification, RetryClassification::Never);
    let claim = DispatchError::ClaimRejected {
        reason: "x".to_string(),
    }
    .to_payload();
    assert_eq!(claim.code, ErrorCode::InvalidRequest);
    assert_eq!(DispatchError::SOURCE_COMPONENT, "dispatch-consumer");
}

// ============================================================================
// 6. Zero-escape static audit of Phase 3.3 sources
// ============================================================================

#[test]
fn test_security_audit_zero_escape_primitives_in_phase33_sources() {
    let source_files = [
        "src/dispatch/mod.rs",
        "src/dispatch/dispatch.rs",
        "src/dispatch/error.rs",
        "src/dispatch/record.rs",
        "src/dispatch/synthesize.rs",
    ];
    let crate_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let forbidden: &[(&str, &str)] = &[
        ("Command::new(", "subprocess execution"),
        ("Command::spawn", "subprocess execution"),
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
        ("thread::sleep", "timing-based wait"),
        ("thread::spawn", "background thread"),
        ("std::fs::", "filesystem I/O"),
        ("fs::write", "filesystem writes"),
        ("fs::read", "filesystem reads"),
        ("File::create", "filesystem writes"),
        ("OpenOptions", "filesystem writes"),
        ("zbus", "D-Bus service"),
        ("rusqlite", "unauthorized database access"),
        ("bwrap", "sandbox launcher invocation"),
        ("landlock_create", "Landlock enforcement"),
        ("seccomp_init", "seccomp installation"),
        ("prctl(", "privilege syscall"),
        ("unshare(", "namespace manipulation"),
        ("setns(", "namespace manipulation"),
        ("sudo", "privilege escalation"),
        ("setuid", "privilege manipulation"),
        ("setgid", "privilege manipulation"),
        ("llama", "LLM integration"),
        ("ollama", "LLM integration"),
        ("openai", "LLM integration"),
        ("anthropic", "LLM integration"),
        ("prompt_template", "reasoning loop"),
        ("system_prompt", "reasoning loop"),
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
        let code = strip_comments(&content);
        for (pattern, description) in forbidden {
            if code.contains(pattern) {
                violations.push(format!(
                    "FORBIDDEN `{pattern}` ({description}) in {relative}"
                ));
            }
        }
        for token in ["Child", "TcpStream", "UnixStream", "JoinHandle", "File"] {
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

/// Strip line/block comments so the audit scans live code tokens only.
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
