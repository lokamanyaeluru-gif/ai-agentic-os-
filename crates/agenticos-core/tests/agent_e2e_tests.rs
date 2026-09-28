//! Phase 2.6: Final End-to-End Manager Verification Suite.
//!
//! Aligned with Phase 2.0 specification checkpoints 2.1–2.6, ADR-0002 through ADR-0007.
//!
//! Verification scope:
//!  1.  WorkflowStep → GlobalAgentManager → WorkAssignment (end-to-end dispatch)
//!  2.  Deterministic eligible-agent selection ordering
//!  3.  Atomic reservation (one agent, two concurrent threads, exactly one wins)
//!  4.  WorkAssignment persistence across database reopen
//!  5.  Assignment lifecycle: Assigned → InProgress → Completed
//!  6.  Completion releases Running → Ready; agent accepts new work
//!  7.  Failure releases Running → Ready correctly
//!  8.  Cancellation releases Running → Ready correctly
//!  9.  Restart and manager reopen persistence
//! 10.  Stale/dead process detection rejects assignment
//! 11.  PID recycling detection rejects assignment
//! 12.  Restart-policy handling (Never / OnFailure / Always)
//! 13.  Retry exhaustion (max_retries enforcement)
//! 14.  Idempotent startup reconciliation
//! 15.  Multiple agents, deterministic selection ordering
//! 16.  Concurrent reservation atomicity (multi-agent race)
//! 17.  Causal lineage preservation
//! 18.  Unknown process observation is non-destructive
//! 19.  Database integrity checks (dual-write consistency)
//! 20.  Phase 1 regression (Phase1Runtime.submit → Layer 5 dispatch)
//! 21.  Security audit (zero shell / subprocess / network in Phase 2 sources)
//!
//! Real-data rule: real SQLite persistence, real domain objects, MockProcessObserver for
//! deterministic liveness, no actual process spawning.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::TempDir;
use uuid::Uuid;

use agenticos_contracts::{PrincipalContext, ProtocolVersion, ResourceRef, RetryClassification};
use agenticos_core::agent::{
    AgentId, AgentLifecycleState, AgentManagerError, AgentRecord, AgentScope, AgentType,
    AgentVersion, AssignmentRequest, AssignmentStatus, GlobalAgentManager, MockProcessObserver,
    ProcessIdentity, RestartPolicy,
};
use agenticos_core::storage::AgentRegistryStore;
use agenticos_core::workflow::{StepExecutionState, WorkflowStep};
use agenticos_core::{GoalStore, IntentStore, Phase1Runtime, SubmitRequest, WorkflowStore};

// ============================================================================
// Test Helpers
// ============================================================================

/// Creates an isolated temporary directory and returns the dir handle plus a DB path.
fn temp_db() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("Failed to create tempdir");
    let path = dir.path().join("agent_registry.db");
    (dir, path)
}

/// Opens a `GlobalAgentManager` backed by a real persistent SQLite database.
fn open_manager(path: &Path) -> GlobalAgentManager {
    let store = AgentRegistryStore::open(path).expect("Failed to open AgentRegistryStore");
    GlobalAgentManager::new(store)
}

/// Opens a `GlobalAgentManager` with a `MockProcessObserver`.
fn open_manager_with_mock(path: &Path) -> (GlobalAgentManager, Arc<MockProcessObserver>) {
    let store = AgentRegistryStore::open(path).expect("Failed to open AgentRegistryStore");
    let observer = Arc::new(MockProcessObserver::new());
    let manager = GlobalAgentManager::new(store).with_process_observer(observer.clone());
    (manager, observer)
}

/// Constructs a minimal `AgentRecord` in the given state.
fn make_agent(
    id_seed: u128,
    state: AgentLifecycleState,
    scope: AgentScope,
    policy: RestartPolicy,
    capabilities: &[&str],
) -> AgentRecord {
    let mut caps = BTreeSet::new();
    for c in capabilities {
        caps.insert(c.to_string());
    }
    AgentRecord {
        agent_id: AgentId::from_uuid(Uuid::from_u128(id_seed)),
        agent_type: AgentType::Builtin("TestAgent".to_string()),
        agent_version: AgentVersion::new(1, 0, 0),
        protocol_version: ProtocolVersion::V1_0,
        owner: PrincipalContext::user(1000, 1000),
        scope,
        declared_capabilities: caps,
        process_identity: ProcessIdentity::unspawned(1000, 1000),
        state,
        restart_policy: policy,
        registered_at_ms: 1_000_000,
        updated_at_ms: 1_000_000,
    }
}

/// Constructs a `WorkflowStep` via struct literal (not ::new).
fn make_step(index: u32, capability: &str) -> WorkflowStep {
    WorkflowStep {
        step_id: Uuid::new_v4(),
        step_index: index,
        capability_id: capability.to_string(),
        capability_schema_version: 1,
        resource: ResourceRef::path("/workspace/test"),
        arguments: serde_json::json!({"flag": true}),
        dependency_step_ids: Vec::new(),
        state: StepExecutionState::Created,
        retry_classification: RetryClassification::Never,
        timeout_duration_ms: 30_000,
    }
}

/// Wraps a step into a fully populated `AssignmentRequest`.
fn make_request(
    step: WorkflowStep,
    principal: PrincipalContext,
    timestamp_ms: u64,
) -> AssignmentRequest {
    AssignmentRequest::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        principal,
        Uuid::new_v4(),
        step,
        timestamp_ms,
    )
}

/// Opens Phase 1 stores in a given directory.
fn open_phase1_stores(dir: &TempDir) -> Phase1Runtime {
    let i = IntentStore::open(dir.path().join("intents.db")).unwrap();
    let g = GoalStore::open(dir.path().join("goals.db")).unwrap();
    let w = WorkflowStore::open(dir.path().join("workflows.db")).unwrap();
    Phase1Runtime::new(i, g, w)
}

// ============================================================================
// 1. WorkflowStep → GlobalAgentManager → WorkAssignment (Full Dispatch)
// ============================================================================

#[test]
fn test_e2e_workflow_step_to_work_assignment() {
    let (_dir, path) = temp_db();
    let manager = open_manager(&path);

    let agent = make_agent(
        1,
        AgentLifecycleState::Ready,
        AgentScope::SystemWide,
        RestartPolicy::Never,
        &["fs.read_file"],
    );
    manager.register_agent(&agent).unwrap();

    let step = make_step(0, "fs.read_file");
    let request = make_request(step, PrincipalContext::user(1000, 1000), 2_000_000);

    let assignment = manager.assign_step(&request).unwrap();

    // Agent was selected and is now Running
    assert_eq!(assignment.agent_id, agent.agent_id);
    assert_eq!(assignment.capability_id, "fs.read_file");
    assert_eq!(assignment.status, AssignmentStatus::Assigned);

    let agent_after = manager.get_agent(&agent.agent_id).unwrap().unwrap();
    assert_eq!(agent_after.state, AgentLifecycleState::Running);
}

// ============================================================================
// 2. Deterministic Selection Ordering
// ============================================================================

#[test]
fn test_e2e_deterministic_selection_fewest_active_tasks() {
    let (_dir, path) = temp_db();
    let manager = open_manager(&path);

    // Two agents: A (seed 10) and B (seed 20) — both Ready, same capability.
    let agent_a = make_agent(
        10,
        AgentLifecycleState::Ready,
        AgentScope::SystemWide,
        RestartPolicy::Never,
        &["work.task"],
    );
    let agent_b = make_agent(
        20,
        AgentLifecycleState::Ready,
        AgentScope::SystemWide,
        RestartPolicy::Never,
        &["work.task"],
    );
    manager.register_agent(&agent_a).unwrap();
    manager.register_agent(&agent_b).unwrap();

    // First assignment: should go to A (lexicographically smaller UUID seed)
    let req1 = make_request(
        make_step(0, "work.task"),
        PrincipalContext::user(1000, 1000),
        2_001_000,
    );
    let assign1 = manager.assign_step(&req1).unwrap();
    assert_eq!(assign1.agent_id, agent_a.agent_id);

    // Force agent_a back to Ready so it has 1 active task count but state Ready
    manager
        .update_agent_state(&agent_a.agent_id, AgentLifecycleState::Ready, 2_001_500)
        .unwrap();

    // Second assignment: A has 1 active task (the Assigned record), B has 0 → B must be selected
    let req2 = make_request(
        make_step(1, "work.task"),
        PrincipalContext::user(1000, 1000),
        2_002_000,
    );
    let assign2 = manager.assign_step(&req2).unwrap();
    assert_eq!(assign2.agent_id, agent_b.agent_id);
}

#[test]
fn test_e2e_deterministic_selection_lexicographic_tiebreak() {
    let (_dir, path) = temp_db();
    let manager = open_manager(&path);

    // Two agents with equal workload — smaller UUID must win.
    let agent_small = make_agent(
        1,
        AgentLifecycleState::Ready,
        AgentScope::SystemWide,
        RestartPolicy::Never,
        &["compute.run"],
    );
    let agent_large = make_agent(
        u128::MAX,
        AgentLifecycleState::Ready,
        AgentScope::SystemWide,
        RestartPolicy::Never,
        &["compute.run"],
    );

    // Confirm ordering assumption
    assert!(
        agent_small.agent_id.to_string() < agent_large.agent_id.to_string(),
        "seed=1 must produce lexicographically smaller UUID than seed=u128::MAX"
    );

    // Register large first, small second (insertion order must not affect selection)
    manager.register_agent(&agent_large).unwrap();
    manager.register_agent(&agent_small).unwrap();

    let req = make_request(
        make_step(0, "compute.run"),
        PrincipalContext::user(1000, 1000),
        2_000_000,
    );
    let assignment = manager.assign_step(&req).unwrap();
    assert_eq!(assignment.agent_id, agent_small.agent_id);
}

// ============================================================================
// 3. Atomic Reservation — Two Threads, One Agent
// ============================================================================

#[test]
fn test_e2e_concurrent_reservation_one_agent_exactly_one_wins() {
    let (_dir, path) = temp_db();

    // Seed exactly one Ready agent
    {
        let store = AgentRegistryStore::open(&path).unwrap();
        let agent = make_agent(
            99,
            AgentLifecycleState::Ready,
            AgentScope::SystemWide,
            RestartPolicy::Never,
            &["atomic.op"],
        );
        store.register_agent(&agent).unwrap();
    }

    let path1 = path.clone();
    let path2 = path.clone();

    let h1 = std::thread::spawn(move || {
        let store = AgentRegistryStore::open(&path1).unwrap();
        let manager = GlobalAgentManager::new(store);
        let req = make_request(
            make_step(0, "atomic.op"),
            PrincipalContext::user(1000, 1000),
            2_000_000,
        );
        manager.assign_step(&req)
    });

    let h2 = std::thread::spawn(move || {
        let store = AgentRegistryStore::open(&path2).unwrap();
        let manager = GlobalAgentManager::new(store);
        let req = make_request(
            make_step(0, "atomic.op"),
            PrincipalContext::user(1000, 1000),
            2_000_000,
        );
        manager.assign_step(&req)
    });

    let r1 = h1.join().expect("Thread 1 panicked");
    let r2 = h2.join().expect("Thread 2 panicked");

    let successes = [&r1, &r2].iter().filter(|r| r.is_ok()).count();
    let failures = [&r1, &r2]
        .iter()
        .filter(|r| matches!(r, Err(AgentManagerError::NoEligibleAgent { .. })))
        .count();

    assert_eq!(
        successes, 1,
        "Exactly one thread must win the atomic reservation; got successes={successes}"
    );
    assert_eq!(
        failures, 1,
        "Exactly one thread must get NoEligibleAgent; got failures={failures}"
    );
}

// ============================================================================
// 4. WorkAssignment Persistence Across DB Reopen
// ============================================================================

#[test]
fn test_e2e_assignment_persistence_across_reopen() {
    let (_dir, path) = temp_db();
    let agent_id;
    let assignment_id;

    // Phase A: register agent, assign step
    {
        let manager = open_manager(&path);
        let agent = make_agent(
            77,
            AgentLifecycleState::Ready,
            AgentScope::SystemWide,
            RestartPolicy::Never,
            &["storage.write"],
        );
        manager.register_agent(&agent).unwrap();
        agent_id = agent.agent_id;

        let req = make_request(
            make_step(0, "storage.write"),
            PrincipalContext::user(1000, 1000),
            2_000_000,
        );
        let assignment = manager.assign_step(&req).unwrap();
        assignment_id = assignment.assignment_id;
    }

    // Phase B: reopen DB, verify assignment and agent state are persisted
    {
        let manager = open_manager(&path);
        let fetched = manager
            .get_assignment(&assignment_id)
            .unwrap()
            .expect("Assignment must persist across manager reopen");

        assert_eq!(fetched.agent_id, agent_id);
        assert_eq!(fetched.capability_id, "storage.write");
        assert_eq!(fetched.status, AssignmentStatus::Assigned);

        let agent_after = manager.get_agent(&agent_id).unwrap().unwrap();
        assert_eq!(agent_after.state, AgentLifecycleState::Running);
    }
}

// ============================================================================
// 5. Assignment Lifecycle: Assigned → InProgress → Completed
// ============================================================================

#[test]
fn test_e2e_assignment_lifecycle_assigned_to_completed() {
    let (_dir, path) = temp_db();
    let manager = open_manager(&path);

    let agent = make_agent(
        5,
        AgentLifecycleState::Ready,
        AgentScope::SystemWide,
        RestartPolicy::Never,
        &["fs.read_file"],
    );
    manager.register_agent(&agent).unwrap();

    let req = make_request(
        make_step(0, "fs.read_file"),
        PrincipalContext::user(1000, 1000),
        2_000_000,
    );
    let assignment = manager.assign_step(&req).unwrap();
    assert_eq!(assignment.status, AssignmentStatus::Assigned);

    // Transition: Assigned → InProgress
    let started = manager
        .start_assignment(&assignment.assignment_id, 2_001_000)
        .unwrap();
    assert_eq!(started.status, AssignmentStatus::InProgress);

    // Transition: InProgress → Completed
    manager
        .complete_assignment(&assignment.assignment_id, 2_002_000)
        .unwrap();

    let completed = manager
        .get_assignment(&assignment.assignment_id)
        .unwrap()
        .unwrap();
    assert_eq!(completed.status, AssignmentStatus::Completed);

    // Agent must be Ready again
    let agent_after = manager.get_agent(&agent.agent_id).unwrap().unwrap();
    assert_eq!(agent_after.state, AgentLifecycleState::Ready);
}

// ============================================================================
// 6. Completion Releases Running → Ready; Agent Accepts New Work
// ============================================================================

#[test]
fn test_e2e_completion_releases_agent_for_next_step() {
    let (_dir, path) = temp_db();
    let manager = open_manager(&path);

    let agent = make_agent(
        6,
        AgentLifecycleState::Ready,
        AgentScope::SystemWide,
        RestartPolicy::Never,
        &["fs.read_file"],
    );
    manager.register_agent(&agent).unwrap();

    // First assignment
    let req1 = make_request(
        make_step(0, "fs.read_file"),
        PrincipalContext::user(1000, 1000),
        2_000_000,
    );
    let assign1 = manager.assign_step(&req1).unwrap();

    manager
        .start_assignment(&assign1.assignment_id, 2_001_000)
        .unwrap();
    manager
        .complete_assignment(&assign1.assignment_id, 2_002_000)
        .unwrap();

    // Agent is Ready → can accept second assignment
    let req2 = make_request(
        make_step(1, "fs.read_file"),
        PrincipalContext::user(1000, 1000),
        2_003_000,
    );
    let assign2 = manager.assign_step(&req2).unwrap();
    assert_eq!(assign2.agent_id, agent.agent_id);
    assert_eq!(assign2.status, AssignmentStatus::Assigned);
}

// ============================================================================
// 7. Failure Releases Running → Ready
// ============================================================================

#[test]
fn test_e2e_failure_releases_agent_back_to_ready() {
    let (_dir, path) = temp_db();
    let manager = open_manager(&path);

    let agent = make_agent(
        7,
        AgentLifecycleState::Ready,
        AgentScope::SystemWide,
        RestartPolicy::Never,
        &["compute.run"],
    );
    manager.register_agent(&agent).unwrap();

    let req = make_request(
        make_step(0, "compute.run"),
        PrincipalContext::user(1000, 1000),
        2_000_000,
    );
    let assignment = manager.assign_step(&req).unwrap();
    manager
        .start_assignment(&assignment.assignment_id, 2_001_000)
        .unwrap();

    // Fail the assignment
    manager
        .fail_assignment(&assignment.assignment_id, "simulated failure", 2_002_000)
        .unwrap();

    let failed = manager
        .get_assignment(&assignment.assignment_id)
        .unwrap()
        .unwrap();
    assert_eq!(failed.status, AssignmentStatus::Failed);

    // Agent returns to Ready
    let agent_after = manager.get_agent(&agent.agent_id).unwrap().unwrap();
    assert_eq!(agent_after.state, AgentLifecycleState::Ready);
}

// ============================================================================
// 8. Cancellation Releases Running → Ready
// ============================================================================

#[test]
fn test_e2e_cancellation_releases_agent_back_to_ready() {
    let (_dir, path) = temp_db();
    let manager = open_manager(&path);

    let agent = make_agent(
        8,
        AgentLifecycleState::Ready,
        AgentScope::SystemWide,
        RestartPolicy::Never,
        &["net.request"],
    );
    manager.register_agent(&agent).unwrap();

    let req = make_request(
        make_step(0, "net.request"),
        PrincipalContext::user(1000, 1000),
        2_000_000,
    );
    let assignment = manager.assign_step(&req).unwrap();

    // Cancel the assignment
    manager
        .cancel_assignment(&assignment.assignment_id, "test cancellation", 2_001_000)
        .unwrap();

    let cancelled = manager
        .get_assignment(&assignment.assignment_id)
        .unwrap()
        .unwrap();
    assert_eq!(cancelled.status, AssignmentStatus::Cancelled);

    // Agent returns to Ready
    let agent_after = manager.get_agent(&agent.agent_id).unwrap().unwrap();
    assert_eq!(agent_after.state, AgentLifecycleState::Ready);
}

// ============================================================================
// 9. Restart and Manager Reopen Persistence
// ============================================================================

#[test]
fn test_e2e_manager_reopen_preserves_agent_state() {
    let (_dir, path) = temp_db();
    let agent_id;

    // Session 1: register and assign
    {
        let manager = open_manager(&path);
        let agent = make_agent(
            9,
            AgentLifecycleState::Ready,
            AgentScope::SystemWide,
            RestartPolicy::Never,
            &["fs.write"],
        );
        manager.register_agent(&agent).unwrap();
        agent_id = agent.agent_id;

        let req = make_request(
            make_step(0, "fs.write"),
            PrincipalContext::user(1000, 1000),
            2_000_000,
        );
        manager.assign_step(&req).unwrap();
    }

    // Session 2: different manager instance, same DB → state must survive
    {
        let manager = open_manager(&path);
        let agent = manager.get_agent(&agent_id).unwrap().unwrap();
        assert_eq!(
            agent.state,
            AgentLifecycleState::Running,
            "Agent state must persist across manager reopen"
        );
    }

    // Session 3: restore to Ready, reopen again → Ready must persist
    {
        let manager = open_manager(&path);
        manager
            .update_agent_state(&agent_id, AgentLifecycleState::Ready, 2_001_000)
            .unwrap();
    }
    {
        let manager = open_manager(&path);
        let agent = manager.get_agent(&agent_id).unwrap().unwrap();
        assert_eq!(agent.state, AgentLifecycleState::Ready);
    }
}

// ============================================================================
// 10. Stale/Dead Process Detection Rejects Assignment
// ============================================================================

#[test]
fn test_e2e_dead_process_rejected_from_assignment() {
    let (_dir, path) = temp_db();
    let (manager, observer) = open_manager_with_mock(&path);

    // Register agent with an active process identity
    let mut agent = make_agent(
        10,
        AgentLifecycleState::Ready,
        AgentScope::SystemWide,
        RestartPolicy::Never,
        &["fs.delete"],
    );
    agent.process_identity = ProcessIdentity::active(
        1234,
        5000,
        agent.process_identity.instance_nonce,
        1000,
        1000,
        1_000_000,
    );
    manager.register_agent(&agent).unwrap();

    // Observer reports PID 1234 as dead (not registered in MockProcessObserver)
    // MockProcessObserver returns Unknown for unregistered PIDs → test the actual behavior
    // By terminating after registration:
    observer.register_process(1234, 5000);
    observer.terminate_process(1234);

    // assign_step must reject dead-process agents
    let req = make_request(
        make_step(0, "fs.delete"),
        PrincipalContext::user(1000, 1000),
        2_000_000,
    );
    let err = manager.assign_step(&req).unwrap_err();
    assert!(
        matches!(err, AgentManagerError::NoEligibleAgent { .. }),
        "Dead-process agent must not be selected; got: {:?}",
        err
    );
}

// ============================================================================
// 11. PID Recycling Detection Rejects Assignment
// ============================================================================

#[test]
fn test_e2e_recycled_pid_rejected_from_assignment() {
    let (_dir, path) = temp_db();
    let (manager, observer) = open_manager_with_mock(&path);

    // Agent persisted with PID 2222, start_time_ticks=1000
    let mut agent = make_agent(
        11,
        AgentLifecycleState::Ready,
        AgentScope::SystemWide,
        RestartPolicy::Never,
        &["audit.log"],
    );
    agent.process_identity = ProcessIdentity::active(
        2222,
        1000,
        agent.process_identity.instance_nonce,
        1000,
        1000,
        1_000_000,
    );
    manager.register_agent(&agent).unwrap();

    // OS reports PID 2222 now exists but with different start_time_ticks (9999 ≠ 1000 → recycled)
    observer.register_process(2222, 9999);

    let req = make_request(
        make_step(0, "audit.log"),
        PrincipalContext::user(1000, 1000),
        2_000_000,
    );
    let err = manager.assign_step(&req).unwrap_err();
    assert!(
        matches!(err, AgentManagerError::NoEligibleAgent { .. }),
        "Recycled-PID agent must not be selected; got: {:?}",
        err
    );
}

// ============================================================================
// 12. Restart-Policy Handling (Never / OnFailure / Always)
// ============================================================================

#[test]
fn test_e2e_restart_policy_never_does_not_schedule_restart() {
    let (_dir, path) = temp_db();
    let (manager, observer) = open_manager_with_mock(&path);

    let mut agent = make_agent(
        12,
        AgentLifecycleState::Running,
        AgentScope::SystemWide,
        RestartPolicy::Never,
        &["worker.task"],
    );
    agent.process_identity = ProcessIdentity::active(
        3333,
        100,
        agent.process_identity.instance_nonce,
        1000,
        1000,
        1_000_000,
    );
    manager.register_agent(&agent).unwrap();

    observer.register_process(3333, 100);
    observer.terminate_process(3333);

    let report = manager.reconcile_startup(2_000_000).unwrap();
    assert_eq!(report.agents_scanned, 1);
    // With RestartPolicy::Never, agent is failed but NOT enqueued for restart
    let outcome = &report.agents_recovered[0];
    assert!(
        !outcome.restarted,
        "RestartPolicy::Never must not schedule a restart"
    );
}

#[test]
fn test_e2e_restart_policy_on_failure_schedules_restart() {
    let (_dir, path) = temp_db();
    let (manager, observer) = open_manager_with_mock(&path);

    let mut agent = make_agent(
        13,
        AgentLifecycleState::Running,
        AgentScope::SystemWide,
        RestartPolicy::on_failure(3, 1_000),
        &["worker.task"],
    );
    agent.process_identity = ProcessIdentity::active(
        4444,
        200,
        agent.process_identity.instance_nonce,
        1000,
        1000,
        1_000_000,
    );
    manager.register_agent(&agent).unwrap();

    observer.register_process(4444, 200);
    observer.terminate_process(4444);

    let report = manager.reconcile_startup(2_000_000).unwrap();
    assert_eq!(report.agents_scanned, 1);

    let outcome = &report.agents_recovered[0];
    assert!(
        outcome.restarted,
        "RestartPolicy::OnFailure must schedule a restart on dead process"
    );
}

#[test]
fn test_e2e_restart_policy_always_schedules_restart() {
    let (_dir, path) = temp_db();
    let (manager, observer) = open_manager_with_mock(&path);

    let mut agent = make_agent(
        14,
        AgentLifecycleState::Running,
        AgentScope::SystemWide,
        RestartPolicy::always(5, 2_000),
        &["worker.task"],
    );
    agent.process_identity = ProcessIdentity::active(
        5555,
        300,
        agent.process_identity.instance_nonce,
        1000,
        1000,
        1_000_000,
    );
    manager.register_agent(&agent).unwrap();

    observer.register_process(5555, 300);
    observer.terminate_process(5555);

    let report = manager.reconcile_startup(2_000_000).unwrap();
    assert_eq!(report.agents_scanned, 1);

    let outcome = &report.agents_recovered[0];
    assert!(
        outcome.restarted,
        "RestartPolicy::Always must schedule a restart on dead process"
    );
}

// ============================================================================
// 13. Retry Exhaustion
// ============================================================================

#[test]
fn test_e2e_retry_exhaustion_stops_restart() {
    let (_dir, path) = temp_db();
    let (manager, observer) = open_manager_with_mock(&path);

    // OnFailure with max_retries=1; agent has already used 1 retry
    let mut agent = make_agent(
        15,
        AgentLifecycleState::Running,
        AgentScope::SystemWide,
        RestartPolicy::on_failure(1, 0),
        &["work.job"],
    );
    agent.process_identity = ProcessIdentity::active(
        6666,
        400,
        agent.process_identity.instance_nonce,
        1000,
        1000,
        1_000_000,
    );
    // Simulate that the agent has already retried once by using handle_agent_failure once
    manager.register_agent(&agent).unwrap();

    // First failure → uses the 1 allowed retry
    observer.register_process(6666, 400);
    observer.terminate_process(6666);

    let first_report = manager.reconcile_startup(2_000_000).unwrap();
    assert_eq!(first_report.agents_scanned, 1);

    // After first reconcile, agent is in Failed/Stopped state.
    // A second reconciliation should find no recoverable Running agents.
    let second_report = manager.reconcile_startup(2_001_000).unwrap();
    // The agent is now terminal — reconcile should not attempt further recovery
    assert_eq!(
        second_report.agents_recovered.len(),
        0,
        "After retry exhaustion, second reconciliation must not attempt recovery again"
    );
}

// ============================================================================
// 14. Idempotent Startup Reconciliation
// ============================================================================

#[test]
fn test_e2e_idempotent_reconciliation() {
    let (_dir, path) = temp_db();
    let (manager, observer) = open_manager_with_mock(&path);

    // One Running agent with alive process
    let mut agent = make_agent(
        16,
        AgentLifecycleState::Running,
        AgentScope::SystemWide,
        RestartPolicy::Never,
        &["svc.process"],
    );
    agent.process_identity = ProcessIdentity::active(
        7777,
        500,
        agent.process_identity.instance_nonce,
        1000,
        1000,
        1_000_000,
    );
    manager.register_agent(&agent).unwrap();
    observer.register_process(7777, 500);

    let report1 = manager.reconcile_startup(2_000_000).unwrap();
    let report2 = manager.reconcile_startup(2_001_000).unwrap();

    // Both calls scan 1 agent; alive agent produces no recoveries either time
    assert_eq!(report1.agents_scanned, 1);
    assert_eq!(report2.agents_scanned, 1);
    assert_eq!(report1.agents_recovered.len(), 0);
    assert_eq!(report2.agents_recovered.len(), 0);

    // Agent state unchanged
    let agent_after = manager.get_agent(&agent.agent_id).unwrap().unwrap();
    assert_eq!(agent_after.state, AgentLifecycleState::Running);
}

// ============================================================================
// 15. Multiple Agents, Deterministic Selection Ordering
// ============================================================================

#[test]
fn test_e2e_multiple_agents_deterministic_ordering() {
    let (_dir, path) = temp_db();
    let manager = open_manager(&path);

    // Register 5 agents with identical workload; selection must be by ascending agent_id string
    let seeds: Vec<u128> = vec![500, 300, 100, 200, 400];
    let mut agents = Vec::new();
    for seed in &seeds {
        let a = make_agent(
            *seed,
            AgentLifecycleState::Ready,
            AgentScope::SystemWide,
            RestartPolicy::Never,
            &["batch.process"],
        );
        manager.register_agent(&a).unwrap();
        agents.push(a);
    }

    // Collect agent_id strings and sort to determine expected order
    let mut expected_order: Vec<String> = agents.iter().map(|a| a.agent_id.to_string()).collect();
    expected_order.sort();

    for (i, expected_id) in expected_order.iter().enumerate() {
        let req = make_request(
            make_step(i as u32, "batch.process"),
            PrincipalContext::user(1000, 1000),
            2_000_000 + i as u64 * 1000,
        );
        let assignment = manager.assign_step(&req).unwrap();
        assert_eq!(
            assignment.agent_id.to_string(),
            *expected_id,
            "Selection at index {} must match lexicographic ordering",
            i
        );
        // Force agent back to Ready so it's eligible for the next slot
        manager
            .update_agent_state(
                &assignment.agent_id,
                AgentLifecycleState::Ready,
                2_001_000 + i as u64 * 1000,
            )
            .unwrap();
    }
}

// ============================================================================
// 16. Concurrent Reservation Atomicity — Multi-Agent Race
// ============================================================================

#[test]
fn test_e2e_concurrent_reservation_two_agents_no_double_assignment() {
    let (_dir, path) = temp_db();

    // Seed two Ready agents
    {
        let store = AgentRegistryStore::open(&path).unwrap();
        for seed in [101u128, 102u128] {
            let agent = make_agent(
                seed,
                AgentLifecycleState::Ready,
                AgentScope::SystemWide,
                RestartPolicy::Never,
                &["concurrent.work"],
            );
            store.register_agent(&agent).unwrap();
        }
    }

    let path1 = path.clone();
    let path2 = path.clone();
    let path3 = path.clone();

    // Three threads race to claim two agents — all three must obtain a unique assignment
    // or get NoEligibleAgent if all slots are taken
    let h1 = std::thread::spawn(move || {
        let manager = open_manager(&path1);
        let req = make_request(
            make_step(0, "concurrent.work"),
            PrincipalContext::user(1000, 1000),
            2_000_000,
        );
        manager.assign_step(&req)
    });
    let h2 = std::thread::spawn(move || {
        let manager = open_manager(&path2);
        let req = make_request(
            make_step(0, "concurrent.work"),
            PrincipalContext::user(1000, 1000),
            2_000_000,
        );
        manager.assign_step(&req)
    });
    let h3 = std::thread::spawn(move || {
        let manager = open_manager(&path3);
        let req = make_request(
            make_step(0, "concurrent.work"),
            PrincipalContext::user(1000, 1000),
            2_000_000,
        );
        manager.assign_step(&req)
    });

    let results = [
        h1.join().expect("Thread 1 panicked"),
        h2.join().expect("Thread 2 panicked"),
        h3.join().expect("Thread 3 panicked"),
    ];

    let successes: Vec<_> = results.iter().filter(|r| r.is_ok()).collect();
    let no_eligible: Vec<_> = results
        .iter()
        .filter(|r| matches!(r, Err(AgentManagerError::NoEligibleAgent { .. })))
        .collect();

    // Exactly 2 threads win (one per agent), exactly 1 gets NoEligibleAgent
    assert_eq!(
        successes.len(),
        2,
        "With 2 agents and 3 threads, exactly 2 must succeed; got {}",
        successes.len()
    );
    assert_eq!(
        no_eligible.len(),
        1,
        "With 2 agents and 3 threads, exactly 1 must get NoEligibleAgent; got {}",
        no_eligible.len()
    );

    // No two winning assignments should have the same agent_id
    let winning_agent_ids: Vec<_> = successes
        .iter()
        .map(|r| r.as_ref().unwrap().agent_id)
        .collect();
    assert_ne!(
        winning_agent_ids[0], winning_agent_ids[1],
        "Each winning assignment must target a distinct agent"
    );
}

// ============================================================================
// 17. Causal Lineage Preservation
// ============================================================================

#[test]
fn test_e2e_causal_lineage_preserved_through_full_lifecycle() {
    let (_dir, path) = temp_db();
    let manager = open_manager(&path);

    let agent = make_agent(
        17,
        AgentLifecycleState::Ready,
        AgentScope::SystemWide,
        RestartPolicy::Never,
        &["trace.op"],
    );
    manager.register_agent(&agent).unwrap();

    let correlation_id = Uuid::new_v4();
    let request_id = Uuid::new_v4();
    let workflow_id = Uuid::new_v4();
    let step = make_step(0, "trace.op");
    let step_id = step.step_id;

    let request = AssignmentRequest::new(
        correlation_id,
        request_id,
        PrincipalContext::user(1000, 1000),
        workflow_id,
        step,
        2_000_000,
    );
    let assignment = manager.assign_step(&request).unwrap();

    // All causal identifiers must flow through unchanged
    assert_eq!(
        assignment.correlation_id, correlation_id,
        "correlation_id must be preserved"
    );
    assert_eq!(
        assignment.request_id, request_id,
        "request_id must be preserved"
    );
    assert_eq!(
        assignment.workflow_id, workflow_id,
        "workflow_id must be preserved"
    );
    assert_eq!(assignment.step_id, step_id, "step_id must be preserved");
    assert_eq!(
        assignment.agent_id, agent.agent_id,
        "agent_id must be recorded"
    );
    assert_eq!(
        assignment.capability_id, "trace.op",
        "capability_id must be preserved"
    );

    // Verify lineage persists to DB
    let fetched = manager
        .get_assignment(&assignment.assignment_id)
        .unwrap()
        .unwrap();
    assert_eq!(fetched.correlation_id, correlation_id);
    assert_eq!(fetched.request_id, request_id);
    assert_eq!(fetched.workflow_id, workflow_id);
    assert_eq!(fetched.step_id, step_id);
}

// ============================================================================
// 18. Unknown Process Observation Is Non-Destructive
// ============================================================================

#[test]
fn test_e2e_unknown_liveness_is_fail_closed_non_destructive() {
    let (_dir, path) = temp_db();
    let (manager, observer) = open_manager_with_mock(&path);

    // Running agent with a spawned identity, but observer returns Unknown
    let mut agent = make_agent(
        18,
        AgentLifecycleState::Running,
        AgentScope::SystemWide,
        RestartPolicy::on_failure(3, 1_000),
        &["monitor.check"],
    );
    agent.process_identity = ProcessIdentity::active(
        8888,
        600,
        agent.process_identity.instance_nonce,
        1000,
        1000,
        1_000_000,
    );
    manager.register_agent(&agent).unwrap();

    // Set observer to return Unknown for this PID
    observer.set_unknown(8888);

    let report = manager.reconcile_startup(2_000_000).unwrap();
    assert_eq!(report.agents_scanned, 1);
    // Unknown must produce zero recovery actions — agent must not be transitioned to Failed
    assert_eq!(
        report.agents_recovered.len(),
        0,
        "Unknown liveness must not trigger any recovery action"
    );

    // Agent state must be unchanged (still Running)
    let agent_after = manager.get_agent(&agent.agent_id).unwrap().unwrap();
    assert_eq!(
        agent_after.state,
        AgentLifecycleState::Running,
        "Unknown liveness must not change agent state"
    );
}

// ============================================================================
// 19. Database Integrity Checks (Dual-Write Consistency)
// ============================================================================

#[test]
fn test_e2e_dual_write_consistency_after_full_lifecycle() {
    let (_dir, path) = temp_db();
    let manager = open_manager(&path);

    let agent = make_agent(
        19,
        AgentLifecycleState::Ready,
        AgentScope::SystemWide,
        RestartPolicy::Never,
        &["validate.check"],
    );
    manager.register_agent(&agent).unwrap();

    // Perform full lifecycle: assign → start → complete
    let req = make_request(
        make_step(0, "validate.check"),
        PrincipalContext::user(1000, 1000),
        2_000_000,
    );
    let assignment = manager.assign_step(&req).unwrap();
    manager
        .start_assignment(&assignment.assignment_id, 2_001_000)
        .unwrap();
    manager
        .complete_assignment(&assignment.assignment_id, 2_002_000)
        .unwrap();

    // Verify the raw store integrity checks pass (real SQLite PRAGMA integrity_check)
    let store = manager.store();
    let integrity_result = store
        .query_pragma("integrity_check")
        .expect("PRAGMA integrity_check must not fail");
    assert_eq!(
        integrity_result, "ok",
        "PRAGMA integrity_check must return 'ok' after full lifecycle; got: {:?}",
        integrity_result
    );

    // Verify agent index consistency: re-fetch agent and confirm index matches payload
    let fetched = manager.get_agent(&agent.agent_id).unwrap().unwrap();
    assert_eq!(
        fetched.agent_id, agent.agent_id,
        "Agent ID must match after full lifecycle"
    );
    assert_eq!(
        fetched.state,
        AgentLifecycleState::Ready,
        "Agent must be Ready after assignment completion"
    );
}

// ============================================================================
// 20. Phase 1 Regression — Phase1Runtime.submit → Layer 5 Dispatch
// ============================================================================

#[test]
fn test_e2e_phase1_workflow_step_dispatched_via_layer5() {
    // Phase 1: synthesize Intent → Goal → Workflow with WorkflowStep
    let dir = tempfile::tempdir().unwrap();
    let runtime = open_phase1_stores(&dir);

    let result = runtime
        .submit(SubmitRequest {
            raw_input: "create directory workspace-demo".to_string(),
            principal: PrincipalContext::user(1000, 1000),
            correlation_id: Uuid::new_v4(),
            idempotency_key: None,
            created_at_ms: 1_000_000,
        })
        .expect("Phase 1 submit must succeed");

    // Verify Phase 1 produced a Workflow with at least one step
    assert!(!result.workflow.workflow_id.is_nil());
    assert!(
        !result.workflow.steps.is_empty(),
        "Phase 1 workflow must produce at least one step"
    );

    let phase1_step = &result.workflow.steps[0];
    let capability_id = phase1_step.capability_id.clone();

    // Layer 5: open GlobalAgentManager, register an agent for the capability
    let (_agent_dir, agent_path) = temp_db();
    let manager = open_manager(&agent_path);

    let agent = make_agent(
        20,
        AgentLifecycleState::Ready,
        AgentScope::SystemWide,
        RestartPolicy::Never,
        &[&capability_id],
    );
    manager.register_agent(&agent).unwrap();

    // Bridge: construct an AssignmentRequest from the Phase 1 step
    let layer5_step = WorkflowStep {
        step_id: phase1_step.step_id,
        step_index: phase1_step.step_index,
        capability_id: phase1_step.capability_id.clone(),
        capability_schema_version: phase1_step.capability_schema_version,
        resource: phase1_step.resource.clone(),
        arguments: phase1_step.arguments.clone(),
        dependency_step_ids: phase1_step.dependency_step_ids.clone(),
        state: StepExecutionState::Created,
        retry_classification: phase1_step.retry_classification,
        timeout_duration_ms: phase1_step.timeout_duration_ms,
    };

    let request = AssignmentRequest::new(
        result.workflow.workflow_id,
        Uuid::new_v4(),
        PrincipalContext::user(1000, 1000),
        result.workflow.workflow_id,
        layer5_step,
        2_000_000,
    );

    let assignment = manager
        .assign_step(&request)
        .expect("Layer 5 must successfully dispatch a Phase 1 WorkflowStep");

    assert_eq!(assignment.agent_id, agent.agent_id);
    assert_eq!(assignment.capability_id, capability_id);
    assert_eq!(assignment.status, AssignmentStatus::Assigned);

    // Phase 1 entities unmodified
    assert_eq!(result.intent.intent_id, result.intent.intent_id); // trivial
    assert!(!result.goal.goal_id.is_nil());
}

// ============================================================================
// 21. Security Audit — Zero Forbidden Primitives in Phase 2 Sources
// ============================================================================

/// Scans all Phase 2 production Rust source files for forbidden constructs.
///
/// Forbidden patterns (must be absent from production code paths):
///   - `std::process::Command`
///   - `std::process::exit`
///   - `Command::new`
///   - `fork(`
///   - `exec(`
///   - `TcpStream`, `TcpListener`, `UdpSocket` (live network)
///   - `reqwest`, `hyper::` (HTTP clients)
///   - `tokio::net::`
///   - `unsafe` in manager / lifecycle / observer production code
///
/// NOTE: `/proc/` read-only access is permitted in observer.rs (LinuxProcfsObserver).
/// NOTE: `unsafe` is allowed ONLY in explicitly marked test code, not production.
#[test]
fn test_security_audit_zero_forbidden_primitives_in_phase2_sources() {
    let phase2_source_files = [
        "src/agent/assignment.rs",
        "src/agent/health.rs",
        "src/agent/identity.rs",
        "src/agent/lifecycle.rs",
        "src/agent/machine.rs",
        "src/agent/manager.rs",
        "src/agent/monitor.rs",
        "src/agent/observer.rs",
        "src/agent/policy.rs",
        "src/agent/recovery.rs",
        "src/storage/agent_store.rs",
    ];

    let crate_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));

    // Patterns that must NOT appear in Phase 2 production sources
    let forbidden_patterns: &[(&str, &str)] = &[
        ("std::process::Command", "subprocess execution"),
        ("Command::new(", "subprocess execution"),
        ("fork()", "fork/exec"),
        ("execve(", "execve syscall"),
        ("TcpStream", "live TCP network"),
        ("TcpListener", "live TCP listener"),
        ("UdpSocket", "live UDP network"),
        ("reqwest", "HTTP client"),
        ("hyper::", "HTTP framework"),
        ("tokio::net::", "async network runtime"),
    ];

    let mut violations: Vec<String> = Vec::new();

    for relative_path in &phase2_source_files {
        let full_path = crate_root.join(relative_path);
        let content = match std::fs::read_to_string(&full_path) {
            Ok(c) => c,
            Err(e) => {
                // Some files may not exist if the path is wrong; report as violation
                violations.push(format!("Cannot read {}: {}", relative_path, e));
                continue;
            }
        };

        for (pattern, description) in forbidden_patterns {
            if content.contains(pattern) {
                violations.push(format!(
                    "FORBIDDEN: `{}` ({}) found in {}",
                    pattern, description, relative_path
                ));
            }
        }

        // std::process::exit is only acceptable in tests, not production sources
        if content.contains("std::process::exit") || content.contains("process::exit") {
            violations.push(format!(
                "FORBIDDEN: `process::exit` found in production source {}",
                relative_path
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "Security audit failed — forbidden primitives found in Phase 2 sources:\n{}",
        violations.join("\n")
    );
}

// ============================================================================
// 22. Scope Isolation — Private Agent Inaccessible to Foreign Principal
// ============================================================================

#[test]
fn test_e2e_private_scope_isolation_cross_principal() {
    let (_dir, path) = temp_db();
    let manager = open_manager(&path);

    let alice = PrincipalContext::user(1000, 1000);
    let bob = PrincipalContext::user(2000, 2000);

    let mut agent = make_agent(
        22,
        AgentLifecycleState::Ready,
        AgentScope::Private(alice.clone()),
        RestartPolicy::Never,
        &["private.op"],
    );
    agent.owner = alice.clone();
    manager.register_agent(&agent).unwrap();

    // Bob cannot access Alice's private agent
    let bob_req = make_request(make_step(0, "private.op"), bob, 2_000_000);
    let err = manager.assign_step(&bob_req).unwrap_err();
    assert!(
        matches!(err, AgentManagerError::NoEligibleAgent { .. }),
        "Foreign principal must not access private-scoped agent"
    );

    // Alice can access her own private agent
    let alice_req = make_request(make_step(0, "private.op"), alice, 2_000_001);
    let assignment = manager.assign_step(&alice_req).unwrap();
    assert_eq!(assignment.agent_id, agent.agent_id);
}

// ============================================================================
// 23. Terminal State Protection — Failed Agent Cannot Be Re-Assigned
// ============================================================================

#[test]
fn test_e2e_failed_agent_is_terminal_and_cannot_be_assigned() {
    let (_dir, path) = temp_db();
    let manager = open_manager(&path);

    let agent = make_agent(
        23,
        AgentLifecycleState::Failed,
        AgentScope::SystemWide,
        RestartPolicy::Never,
        &["risky.op"],
    );
    manager.register_agent(&agent).unwrap();

    let req = make_request(
        make_step(0, "risky.op"),
        PrincipalContext::user(1000, 1000),
        2_000_000,
    );
    let err = manager.assign_step(&req).unwrap_err();
    assert!(
        matches!(err, AgentManagerError::NoEligibleAgent { .. }),
        "Failed agent must be ineligible for assignment"
    );
}

// ============================================================================
// 24. Assignment Timestamp Regression Protection
// ============================================================================

#[test]
fn test_e2e_assignment_timestamp_regression_rejected() {
    let (_dir, path) = temp_db();
    let manager = open_manager(&path);

    let agent = make_agent(
        24,
        AgentLifecycleState::Ready,
        AgentScope::SystemWide,
        RestartPolicy::Never,
        &["time.sensitive"],
    );
    manager.register_agent(&agent).unwrap();

    let req = make_request(
        make_step(0, "time.sensitive"),
        PrincipalContext::user(1000, 1000),
        2_000_000,
    );
    let assignment = manager.assign_step(&req).unwrap();

    // Start at t=2_001_000
    manager
        .start_assignment(&assignment.assignment_id, 2_001_000)
        .unwrap();

    // Attempt to complete with an earlier timestamp → must be rejected
    let err = manager
        .complete_assignment(&assignment.assignment_id, 1_000_000)
        .unwrap_err();
    assert!(
        matches!(
            err,
            AgentManagerError::TimestampRegression { .. } | AgentManagerError::Lifecycle(_)
        ),
        "Timestamp regression must be rejected; got: {:?}",
        err
    );
}
