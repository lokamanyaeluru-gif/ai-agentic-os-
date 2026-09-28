//! Comprehensive test suite for Phase 2.5: Failure Recovery and Restart Handling.
//!
//! Verifies:
//! 1. Stale agent detection (PID recycling via `start_time_ticks` and process death).
//! 2. Startup recovery for in-flight agents (`Starting`, `Running`).
//! 3. Active assignment failure handling with strict causal lineage preservation.
//! 4. Declarative restart policy enforcement (`Never`, `OnFailure`, `Always`).
//! 5. Retry exhaustion and max_retries validation.
//! 6. Fresh `instance_nonce` minting and unspawned identity reset on restart.
//! 7. Atomic transaction commit and rollback on failure.
//! 8. Idempotent reconciliation (calling `reconcile_startup` twice).
//! 9. Timestamp regression protection.
//! 10. Terminal state protection.
//! 11. Multiple dead agents and multiple assignments in a single reconciliation.
//! 12. Explicit agent failure via `handle_agent_failure`.
//! 13. Targeted agent reconciliation via `reconcile_agent`.
//! 14. Heartbeat deadline timeout recovery via `check_heartbeat_timeouts` & `HeartbeatMonitor`.
//! 15. Persistence across database reopen.
//! 16. Selection rejection for dead or recycled processes.
//! 17. Zero forbidden primitives (source code audit).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::TempDir;
use uuid::Uuid;

use agenticos_contracts::{PrincipalContext, ProtocolVersion, ResourceRef};
use agenticos_core::agent::{
    AgentFailureReason, AgentId, AgentLifecycleError, AgentLifecycleState, AgentManagerError,
    AgentRecord, AgentResourceMetrics, AgentScope, AgentType, AgentVersion, AssignmentId,
    AssignmentRequest, AssignmentStatus, GlobalAgentManager, HeartbeatMonitor, HeartbeatRecord,
    MockProcessObserver, ProcessIdentity, ProcessLiveness, ProcessObserver, RestartPolicy,
    WorkAssignment,
};
use agenticos_core::storage::AgentRegistryStore;
use agenticos_core::workflow::WorkflowStep;

/// Helper: creates a temporary database and returns the directory and file path.
fn create_temp_db() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("Failed to create tempdir");
    let path = dir.path().join("agent_registry.db");
    (dir, path)
}

/// Helper: opens a `GlobalAgentManager` on the given database path with a `MockProcessObserver`.
fn create_manager_with_mock_observer(
    path: &Path,
) -> (GlobalAgentManager, Arc<MockProcessObserver>) {
    let store = AgentRegistryStore::open(path).expect("Failed to open AgentRegistryStore");
    let observer = Arc::new(MockProcessObserver::new());
    let manager = GlobalAgentManager::new(store).with_process_observer(observer.clone());
    (manager, observer)
}

/// Helper: constructs a test `AgentRecord`.
fn make_agent(
    id_seed: u128,
    state: AgentLifecycleState,
    policy: RestartPolicy,
    capabilities: &[&str],
) -> AgentRecord {
    let agent_id = AgentId::from_uuid(Uuid::from_u128(id_seed));
    let owner = PrincipalContext::user(1000, 1000);
    let mut declared_capabilities = BTreeSet::new();
    for cap in capabilities {
        declared_capabilities.insert(cap.to_string());
    }

    AgentRecord {
        agent_id,
        agent_type: AgentType::Builtin("WorkerAgent".to_string()),
        agent_version: AgentVersion::new(1, 0, 0),
        protocol_version: ProtocolVersion::V1_0,
        owner,
        scope: AgentScope::SystemWide,
        declared_capabilities,
        process_identity: ProcessIdentity::unspawned(1000, 1000),
        state,
        restart_policy: policy,
        registered_at_ms: 1_000_000,
        updated_at_ms: 1_000_000,
    }
}

/// Helper: spawns a process identity with active PID and ticks.
fn make_spawned_agent(
    id_seed: u128,
    state: AgentLifecycleState,
    policy: RestartPolicy,
    pid: u32,
    ticks: u64,
) -> AgentRecord {
    let mut agent = make_agent(id_seed, state, policy, &["compute.run"]);
    agent.process_identity = ProcessIdentity::active(
        pid,
        ticks,
        agent.process_identity.instance_nonce,
        1000,
        1000,
        1_000_000,
    );
    agent
}

/// Helper: creates a test `WorkAssignment`.
fn make_assignment(
    assignment_seed: u128,
    agent_id: AgentId,
    status: AssignmentStatus,
    timestamp_ms: u64,
) -> WorkAssignment {
    let mut assignment = WorkAssignment::new(
        Uuid::from_u128(100),
        Uuid::from_u128(200),
        PrincipalContext::user(1000, 1000),
        Uuid::from_u128(300),
        Uuid::from_u128(400),
        agent_id,
        "compute.run",
        serde_json::json!({"action": "execute"}),
        ResourceRef::path("/workspace/test"),
        timestamp_ms,
        30_000,
    )
    .expect("Failed to create WorkAssignment");

    assignment.assignment_id = AssignmentId::from_uuid(Uuid::from_u128(assignment_seed));
    assignment.status = status;
    assignment.updated_at_ms = timestamp_ms;
    assignment
}

// =======================================================================
// Test Cases
// =======================================================================

#[test]
fn test_stale_pid_recycled_detection() {
    let (_dir, path) = create_temp_db();
    let (manager, observer) = create_manager_with_mock_observer(&path);

    // Agent was registered with PID 1234, start_time_ticks 5000
    let agent = make_spawned_agent(
        1,
        AgentLifecycleState::Running,
        RestartPolicy::Never,
        1234,
        5000,
    );
    manager.register_agent(&agent).unwrap();

    // OS now has PID 1234, but its start_time_ticks is 9999 (PID recycled!)
    observer.register_process(1234, 9999);

    let report = manager.reconcile_startup(1_005_000).unwrap();
    assert_eq!(report.agents_scanned, 1);
    assert_eq!(report.agents_recovered.len(), 1);

    let outcome = &report.agents_recovered[0];
    assert_eq!(outcome.agent_id, agent.agent_id);
    assert_eq!(outcome.previous_state, AgentLifecycleState::Running);
    assert_eq!(outcome.new_state, AgentLifecycleState::Failed);
    assert!(!outcome.restarted);
    assert_eq!(
        outcome.failure_reason,
        AgentFailureReason::PidRecycled {
            pid: 1234,
            expected_ticks: 5000,
            observed_ticks: 9999,
        }
    );
}

#[test]
fn test_dead_process_termination_detection() {
    let (_dir, path) = create_temp_db();
    let (manager, observer) = create_manager_with_mock_observer(&path);

    // Agent with PID 4321, ticks 6000
    let agent = make_spawned_agent(
        2,
        AgentLifecycleState::Running,
        RestartPolicy::Never,
        4321,
        6000,
    );
    manager.register_agent(&agent).unwrap();

    // Observer has NO process 4321 (process terminated)
    observer.clear();

    let report = manager.reconcile_startup(1_005_000).unwrap();
    assert_eq!(report.agents_recovered.len(), 1);
    let outcome = &report.agents_recovered[0];
    assert_eq!(outcome.agent_id, agent.agent_id);
    assert_eq!(outcome.new_state, AgentLifecycleState::Failed);
    assert_eq!(
        outcome.failure_reason,
        AgentFailureReason::ProcessTerminated {
            pid: Some(4321),
            start_time_ticks: Some(6000),
        }
    );
}

#[test]
fn test_unspawned_starting_agent_untouched() {
    let (_dir, path) = create_temp_db();
    let (manager, _observer) = create_manager_with_mock_observer(&path);

    // Agent is in Starting state, but unspawned (pid: None, ticks: None)
    let agent = make_agent(
        3,
        AgentLifecycleState::Starting,
        RestartPolicy::on_failure(3, 1000),
        &["compute.run"],
    );
    manager.register_agent(&agent).unwrap();

    let report = manager.reconcile_startup(1_005_000).unwrap();
    assert_eq!(report.agents_scanned, 1);
    assert_eq!(report.agents_recovered.len(), 0);

    // Agent remains Starting, retries remain 0
    let reloaded = manager.get_agent(&agent.agent_id).unwrap().unwrap();
    assert_eq!(reloaded.state, AgentLifecycleState::Starting);
    assert_eq!(
        reloaded.restart_policy,
        RestartPolicy::OnFailure {
            max_retries: 3,
            current_retries: 0,
            backoff_ms: 1000,
        }
    );
}

#[test]
fn test_alive_running_agent_untouched() {
    let (_dir, path) = create_temp_db();
    let (manager, observer) = create_manager_with_mock_observer(&path);

    let agent = make_spawned_agent(
        4,
        AgentLifecycleState::Running,
        RestartPolicy::Never,
        5555,
        7777,
    );
    manager.register_agent(&agent).unwrap();

    // Observer confirms PID 5555 with exact ticks 7777 is Alive
    observer.register_process(5555, 7777);

    let report = manager.reconcile_startup(1_005_000).unwrap();
    assert_eq!(report.agents_scanned, 1);
    assert_eq!(report.agents_recovered.len(), 0);

    let reloaded = manager.get_agent(&agent.agent_id).unwrap().unwrap();
    assert_eq!(reloaded.state, AgentLifecycleState::Running);
}

#[test]
fn test_active_assignments_failed_with_lineage_preserved() {
    let (_dir, path) = create_temp_db();
    let (manager, _observer) = create_manager_with_mock_observer(&path);

    let agent = make_spawned_agent(
        5,
        AgentLifecycleState::Running,
        RestartPolicy::Never,
        1001,
        2001,
    );
    manager.register_agent(&agent).unwrap();

    // Create 2 active assignments (Assigned, InProgress) and 1 terminal (Completed)
    let a1 = make_assignment(11, agent.agent_id, AssignmentStatus::Assigned, 1_001_000);
    let a2 = make_assignment(12, agent.agent_id, AssignmentStatus::InProgress, 1_002_000);
    let a3 = make_assignment(13, agent.agent_id, AssignmentStatus::Completed, 1_003_000);

    manager.store().insert_assignment(&a1).unwrap();
    manager.store().insert_assignment(&a2).unwrap();
    manager.store().insert_assignment(&a3).unwrap();

    let report = manager.reconcile_startup(1_005_000).unwrap();
    assert_eq!(report.agents_recovered.len(), 1);
    assert_eq!(report.total_assignments_failed, 2);

    let outcome = &report.agents_recovered[0];
    assert_eq!(outcome.failed_assignments.len(), 2);
    assert!(outcome.failed_assignments.contains(&a1.assignment_id));
    assert!(outcome.failed_assignments.contains(&a2.assignment_id));

    // Verify active assignments transitioned to Failed
    let a1_reloaded = manager
        .store()
        .get_assignment(&a1.assignment_id)
        .unwrap()
        .unwrap();
    assert_eq!(a1_reloaded.status, AssignmentStatus::Failed);
    assert_eq!(a1_reloaded.correlation_id, a1.correlation_id);
    assert_eq!(a1_reloaded.request_id, a1.request_id);
    assert_eq!(a1_reloaded.workflow_id, a1.workflow_id);
    assert_eq!(a1_reloaded.step_id, a1.step_id);
    assert_eq!(a1_reloaded.originating_principal, a1.originating_principal);
    assert_eq!(a1_reloaded.updated_at_ms, 1_005_000);

    let a2_reloaded = manager
        .store()
        .get_assignment(&a2.assignment_id)
        .unwrap()
        .unwrap();
    assert_eq!(a2_reloaded.status, AssignmentStatus::Failed);
    assert_eq!(a2_reloaded.correlation_id, a2.correlation_id);

    // Completed assignment remains Completed!
    let a3_reloaded = manager
        .store()
        .get_assignment(&a3.assignment_id)
        .unwrap()
        .unwrap();
    assert_eq!(a3_reloaded.status, AssignmentStatus::Completed);
    assert_eq!(a3_reloaded.updated_at_ms, 1_003_000);
}

#[test]
fn test_restart_policy_never() {
    let (_dir, path) = create_temp_db();
    let (manager, _observer) = create_manager_with_mock_observer(&path);

    let agent = make_spawned_agent(
        6,
        AgentLifecycleState::Running,
        RestartPolicy::Never,
        1002,
        2002,
    );
    manager.register_agent(&agent).unwrap();

    let report = manager.reconcile_startup(1_005_000).unwrap();
    let outcome = &report.agents_recovered[0];
    assert_eq!(outcome.new_state, AgentLifecycleState::Failed);
    assert!(!outcome.restarted);
    assert_eq!(outcome.new_instance_nonce, None);
    assert_eq!(outcome.retries_attempted, 0);

    let reloaded = manager.get_agent(&agent.agent_id).unwrap().unwrap();
    assert_eq!(reloaded.state, AgentLifecycleState::Failed);
}

#[test]
fn test_restart_policy_on_failure_success() {
    let (_dir, path) = create_temp_db();
    let (manager, _observer) = create_manager_with_mock_observer(&path);

    let agent = make_spawned_agent(
        7,
        AgentLifecycleState::Running,
        RestartPolicy::on_failure(3, 1000),
        1003,
        2003,
    );
    let original_nonce = agent.process_identity.instance_nonce;
    manager.register_agent(&agent).unwrap();

    let report = manager.reconcile_startup(1_005_000).unwrap();
    let outcome = &report.agents_recovered[0];
    assert_eq!(outcome.new_state, AgentLifecycleState::Starting);
    assert!(outcome.restarted);
    assert_ne!(outcome.new_instance_nonce, Some(original_nonce));
    assert_eq!(outcome.retries_attempted, 1);

    let reloaded = manager.get_agent(&agent.agent_id).unwrap().unwrap();
    assert_eq!(reloaded.state, AgentLifecycleState::Starting);
    assert_eq!(
        reloaded.restart_policy,
        RestartPolicy::OnFailure {
            max_retries: 3,
            current_retries: 1,
            backoff_ms: 1000,
        }
    );
    // Identity must be reset to unspawned with the fresh nonce
    assert!(!reloaded.process_identity.is_spawned());
    assert_eq!(reloaded.process_identity.pid, None);
    assert_eq!(reloaded.process_identity.start_time_ticks, None);
    assert_eq!(
        reloaded.process_identity.instance_nonce,
        outcome.new_instance_nonce.unwrap()
    );
}

#[test]
fn test_restart_policy_on_failure_exhaustion() {
    let (_dir, path) = create_temp_db();
    let (manager, _observer) = create_manager_with_mock_observer(&path);

    // Agent already exhausted retries (2/2)
    let agent = make_spawned_agent(
        8,
        AgentLifecycleState::Running,
        RestartPolicy::OnFailure {
            max_retries: 2,
            current_retries: 2,
            backoff_ms: 1000,
        },
        1004,
        2004,
    );
    let nonce = agent.process_identity.instance_nonce;
    manager.register_agent(&agent).unwrap();

    let report = manager.reconcile_startup(1_005_000).unwrap();
    let outcome = &report.agents_recovered[0];
    assert_eq!(outcome.new_state, AgentLifecycleState::Failed);
    assert!(!outcome.restarted);
    assert_eq!(outcome.new_instance_nonce, None);
    assert_eq!(outcome.retries_attempted, 2);

    let reloaded = manager.get_agent(&agent.agent_id).unwrap().unwrap();
    assert_eq!(reloaded.state, AgentLifecycleState::Failed);
    assert_eq!(reloaded.process_identity.instance_nonce, nonce);
}

#[test]
fn test_restart_policy_always() {
    let (_dir, path) = create_temp_db();
    let (manager, _observer) = create_manager_with_mock_observer(&path);

    let agent = make_spawned_agent(
        9,
        AgentLifecycleState::Running,
        RestartPolicy::always(5, 500),
        1005,
        2005,
    );
    manager.register_agent(&agent).unwrap();

    let report = manager.reconcile_startup(1_005_000).unwrap();
    let outcome = &report.agents_recovered[0];
    assert_eq!(outcome.new_state, AgentLifecycleState::Starting);
    assert!(outcome.restarted);
    assert_eq!(outcome.retries_attempted, 1);

    let reloaded = manager.get_agent(&agent.agent_id).unwrap().unwrap();
    assert_eq!(reloaded.state, AgentLifecycleState::Starting);
    assert_eq!(
        reloaded.restart_policy,
        RestartPolicy::Always {
            max_retries: 5,
            current_retries: 1,
            backoff_ms: 500,
        }
    );
}

#[test]
fn test_idempotent_reconciliation() {
    let (_dir, path) = create_temp_db();
    let (manager, _observer) = create_manager_with_mock_observer(&path);

    let agent = make_spawned_agent(
        10,
        AgentLifecycleState::Running,
        RestartPolicy::on_failure(3, 1000),
        1006,
        2006,
    );
    manager.register_agent(&agent).unwrap();

    let a1 = make_assignment(21, agent.agent_id, AssignmentStatus::InProgress, 1_001_000);
    manager.store().insert_assignment(&a1).unwrap();

    // First recovery: agent restarts to Starting, assignment fails
    let report1 = manager.reconcile_startup(1_005_000).unwrap();
    assert_eq!(report1.agents_recovered.len(), 1);
    assert_eq!(report1.total_assignments_failed, 1);

    let reloaded1 = manager.get_agent(&agent.agent_id).unwrap().unwrap();
    assert_eq!(reloaded1.state, AgentLifecycleState::Starting);
    assert_eq!(
        reloaded1.restart_policy,
        RestartPolicy::OnFailure {
            max_retries: 3,
            current_retries: 1,
            backoff_ms: 1000,
        }
    );

    // Second recovery immediately after: strictly idempotent!
    let report2 = manager.reconcile_startup(1_006_000).unwrap();
    assert_eq!(report2.agents_scanned, 1); // scanned because in Starting
    assert_eq!(report2.agents_recovered.len(), 0); // 0 recovered because unspawned!
    assert_eq!(report2.total_assignments_failed, 0);

    // Verify retries did not double-increment
    let reloaded2 = manager.get_agent(&agent.agent_id).unwrap().unwrap();
    assert_eq!(reloaded2.state, AgentLifecycleState::Starting);
    assert_eq!(
        reloaded2.restart_policy,
        RestartPolicy::OnFailure {
            max_retries: 3,
            current_retries: 1,
            backoff_ms: 1000,
        }
    );
    assert_eq!(
        reloaded2.process_identity.instance_nonce,
        reloaded1.process_identity.instance_nonce
    );
}

#[test]
fn test_multiple_dead_agents_and_assignments() {
    let (_dir, path) = create_temp_db();
    let (manager, _observer) = create_manager_with_mock_observer(&path);

    let ag1 = make_spawned_agent(
        11,
        AgentLifecycleState::Running,
        RestartPolicy::on_failure(2, 500),
        2001,
        3001,
    );
    let ag2 = make_spawned_agent(
        12,
        AgentLifecycleState::Running,
        RestartPolicy::Never,
        2002,
        3002,
    );
    let ag3 = make_spawned_agent(
        13,
        AgentLifecycleState::Starting,
        RestartPolicy::always(3, 500),
        2003,
        3003,
    );

    manager.register_agent(&ag1).unwrap();
    manager.register_agent(&ag2).unwrap();
    manager.register_agent(&ag3).unwrap();

    let a1 = make_assignment(31, ag1.agent_id, AssignmentStatus::InProgress, 1_001_000);
    let a2 = make_assignment(32, ag1.agent_id, AssignmentStatus::Assigned, 1_002_000);
    let a3 = make_assignment(33, ag2.agent_id, AssignmentStatus::InProgress, 1_003_000);

    manager.store().insert_assignment(&a1).unwrap();
    manager.store().insert_assignment(&a2).unwrap();
    manager.store().insert_assignment(&a3).unwrap();

    let report = manager.reconcile_startup(1_005_000).unwrap();
    assert_eq!(report.agents_scanned, 3);
    assert_eq!(report.agents_recovered.len(), 3);
    assert_eq!(report.total_assignments_failed, 3);

    let r1 = manager.get_agent(&ag1.agent_id).unwrap().unwrap();
    assert_eq!(r1.state, AgentLifecycleState::Starting);
    let r2 = manager.get_agent(&ag2.agent_id).unwrap().unwrap();
    assert_eq!(r2.state, AgentLifecycleState::Failed);
    let r3 = manager.get_agent(&ag3.agent_id).unwrap().unwrap();
    assert_eq!(r3.state, AgentLifecycleState::Starting);
}

#[test]
fn test_handle_agent_failure_explicit() {
    let (_dir, path) = create_temp_db();
    let (manager, _observer) = create_manager_with_mock_observer(&path);

    let agent = make_spawned_agent(
        14,
        AgentLifecycleState::Running,
        RestartPolicy::on_failure(3, 1000),
        5001,
        6001,
    );
    manager.register_agent(&agent).unwrap();

    let a1 = make_assignment(41, agent.agent_id, AssignmentStatus::InProgress, 1_001_000);
    manager.store().insert_assignment(&a1).unwrap();

    let reason = AgentFailureReason::ExplicitFailure {
        reason: "OOM killer terminated agent process".into(),
    };
    let outcome = manager
        .handle_agent_failure(&agent.agent_id, reason.clone(), 1_005_000)
        .unwrap();

    assert_eq!(outcome.agent_id, agent.agent_id);
    assert_eq!(outcome.previous_state, AgentLifecycleState::Running);
    assert_eq!(outcome.new_state, AgentLifecycleState::Starting);
    assert!(outcome.restarted);
    assert_eq!(outcome.failed_assignments, vec![a1.assignment_id]);
    assert_eq!(outcome.failure_reason, reason);

    let a1_reloaded = manager
        .store()
        .get_assignment(&a1.assignment_id)
        .unwrap()
        .unwrap();
    assert_eq!(a1_reloaded.status, AssignmentStatus::Failed);
}

#[test]
fn test_reconcile_agent_targeted() {
    let (_dir, path) = create_temp_db();
    let (manager, observer) = create_manager_with_mock_observer(&path);

    let agent = make_spawned_agent(
        15,
        AgentLifecycleState::Running,
        RestartPolicy::on_failure(2, 500),
        6001,
        7001,
    );
    manager.register_agent(&agent).unwrap();

    // If observer sees process alive, reconcile_agent returns None
    observer.register_process(6001, 7001);
    let outcome1 = manager.reconcile_agent(&agent.agent_id, 1_005_000).unwrap();
    assert!(outcome1.is_none());

    // Once observer sees process terminated, reconcile_agent returns outcome
    observer.terminate_process(6001);
    let outcome2 = manager.reconcile_agent(&agent.agent_id, 1_006_000).unwrap();
    assert!(outcome2.is_some());
    let outcome = outcome2.unwrap();
    assert_eq!(outcome.new_state, AgentLifecycleState::Starting);
    assert!(outcome.restarted);
}

#[test]
fn test_heartbeat_timeout_recovery() {
    let (_dir, path) = create_temp_db();
    let (manager, _observer) = create_manager_with_mock_observer(&path);

    let agent = make_spawned_agent(
        16,
        AgentLifecycleState::Running,
        RestartPolicy::on_failure(2, 500),
        7001,
        8001,
    );
    manager.register_agent(&agent).unwrap();

    // Record a heartbeat at 1_000_000
    let hb = HeartbeatRecord {
        agent_id: agent.agent_id,
        instance_nonce: agent.process_identity.instance_nonce,
        sequence_number: 1,
        timestamp_ms: 1_000_000,
        metrics: AgentResourceMetrics {
            cpu_usage_permille: 100,
            memory_rss_bytes: 100_000_000,
            open_fds: 10,
        },
    };
    manager.record_heartbeat(&hb).unwrap();

    // At 1_006_000 (elapsed 6000ms > timeout 5000ms), heartbeat has expired!
    let monitor = HeartbeatMonitor::new(manager.clone());
    let outcomes = monitor.scan_and_reconcile_heartbeats(1_006_000).unwrap();

    assert_eq!(outcomes.len(), 1);
    let outcome = &outcomes[0];
    assert_eq!(outcome.agent_id, agent.agent_id);
    assert_eq!(outcome.new_state, AgentLifecycleState::Starting);
    assert!(outcome.restarted);
    assert!(matches!(
        outcome.failure_reason,
        AgentFailureReason::HeartbeatTimeout { .. }
    ));
}

#[test]
fn test_timestamp_regression_protection() {
    let (_dir, path) = create_temp_db();
    let (manager, _observer) = create_manager_with_mock_observer(&path);

    let mut agent = make_spawned_agent(
        17,
        AgentLifecycleState::Running,
        RestartPolicy::Never,
        8001,
        9001,
    );
    agent.updated_at_ms = 1_010_000;
    manager.register_agent(&agent).unwrap();

    // Attempting recovery at 1_005_000 (< 1_010_000) must fail closed with TimestampRegression
    let err = manager.reconcile_startup(1_005_000).unwrap_err();
    match err {
        AgentManagerError::Lifecycle(AgentLifecycleError::TimestampRegression {
            current_ms,
            proposed_ms,
            ..
        }) => {
            assert_eq!(current_ms, 1_010_000);
            assert_eq!(proposed_ms, 1_005_000);
        }
        other => panic!("Expected TimestampRegression, got: {:?}", other),
    }

    // Agent state must remain unmodified in DB
    let reloaded = manager.get_agent(&agent.agent_id).unwrap().unwrap();
    assert_eq!(reloaded.state, AgentLifecycleState::Running);
}

#[test]
fn test_terminal_state_protection() {
    let (_dir, path) = create_temp_db();
    let (manager, _observer) = create_manager_with_mock_observer(&path);

    let stopped_agent = make_agent(
        18,
        AgentLifecycleState::Stopped,
        RestartPolicy::Never,
        &["compute.run"],
    );
    let failed_agent = make_agent(
        19,
        AgentLifecycleState::Failed,
        RestartPolicy::Never,
        &["compute.run"],
    );

    manager.register_agent(&stopped_agent).unwrap();
    manager.register_agent(&failed_agent).unwrap();

    // Calling handle_agent_failure on stopped agent must fail
    let err1 = manager
        .handle_agent_failure(
            &stopped_agent.agent_id,
            AgentFailureReason::ExplicitFailure {
                reason: "fail".into(),
            },
            1_005_000,
        )
        .unwrap_err();
    assert!(matches!(
        err1,
        AgentManagerError::Lifecycle(AgentLifecycleError::TerminalState { .. })
    ));

    // Calling handle_agent_failure on failed agent must fail
    let err2 = manager
        .handle_agent_failure(
            &failed_agent.agent_id,
            AgentFailureReason::ExplicitFailure {
                reason: "fail".into(),
            },
            1_005_000,
        )
        .unwrap_err();
    assert!(matches!(
        err2,
        AgentManagerError::Lifecycle(AgentLifecycleError::TerminalState { .. })
    ));
}

#[test]
fn test_persistence_across_database_reopen() {
    let (_dir, path) = create_temp_db();
    let (manager, _observer) = create_manager_with_mock_observer(&path);

    let agent = make_spawned_agent(
        20,
        AgentLifecycleState::Running,
        RestartPolicy::on_failure(3, 1000),
        9991,
        8881,
    );
    manager.register_agent(&agent).unwrap();

    let a1 = make_assignment(51, agent.agent_id, AssignmentStatus::InProgress, 1_001_000);
    manager.store().insert_assignment(&a1).unwrap();

    let report = manager.reconcile_startup(1_005_000).unwrap();
    let new_nonce = report.agents_recovered[0].new_instance_nonce.unwrap();

    // Drop previous manager, reopen store from disk
    drop(manager);
    let reopened_store = AgentRegistryStore::open(&path).expect("Failed to reopen store");

    let agent_reloaded = reopened_store.get_agent(&agent.agent_id).unwrap().unwrap();
    assert_eq!(agent_reloaded.state, AgentLifecycleState::Starting);
    assert_eq!(
        agent_reloaded.restart_policy,
        RestartPolicy::OnFailure {
            max_retries: 3,
            current_retries: 1,
            backoff_ms: 1000,
        }
    );
    assert_eq!(agent_reloaded.process_identity.instance_nonce, new_nonce);
    assert!(!agent_reloaded.process_identity.is_spawned());

    let a1_reloaded = reopened_store
        .get_assignment(&a1.assignment_id)
        .unwrap()
        .unwrap();
    assert_eq!(a1_reloaded.status, AssignmentStatus::Failed);
}

#[test]
fn test_selection_rejection_for_dead_process() {
    let (_dir, path) = create_temp_db();
    let (manager, observer) = create_manager_with_mock_observer(&path);

    // Register a Ready agent with PID 7777, ticks 8888
    let agent = make_spawned_agent(
        21,
        AgentLifecycleState::Ready,
        RestartPolicy::Never,
        7777,
        8888,
    );
    manager.register_agent(&agent).unwrap();

    // Observer has NO process 7777 (dead!)
    observer.clear();
    let step = WorkflowStep {
        step_id: Uuid::new_v4(),
        step_index: 0,
        capability_id: "compute.run".to_string(),
        capability_schema_version: 1,
        resource: ResourceRef::path("/workspace/test"),
        arguments: serde_json::json!({"action": "run"}),
        dependency_step_ids: Vec::new(),
        state: agenticos_core::workflow::StepExecutionState::Created,
        retry_classification: agenticos_contracts::RetryClassification::Never,
        timeout_duration_ms: 30_000,
    };

    let request = AssignmentRequest::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        PrincipalContext::user(1000, 1000),
        Uuid::new_v4(),
        step,
        1_005_000,
    );

    // assign_step must reject dead process candidate with NoEligibleAgent
    let err = manager.assign_step(&request).unwrap_err();
    assert!(matches!(err, AgentManagerError::NoEligibleAgent { .. }));

    // Now register process as alive in observer
    observer.register_process(7777, 8888);

    // assign_step now succeeds!
    let assignment = manager.assign_step(&request).unwrap();
    assert_eq!(assignment.agent_id, agent.agent_id);
    assert_eq!(assignment.status, AssignmentStatus::Assigned);
}

#[test]
fn test_atomic_recovery_rollback_on_failure() {
    let (_dir, path) = create_temp_db();
    let (manager, _observer) = create_manager_with_mock_observer(&path);

    let agent = make_spawned_agent(
        22,
        AgentLifecycleState::Running,
        RestartPolicy::on_failure(3, 1000),
        4444,
        5555,
    );
    manager.register_agent(&agent).unwrap();

    // a1 has normal timestamp 1_001_000
    let a1 = make_assignment(61, agent.agent_id, AssignmentStatus::InProgress, 1_001_000);
    // a2 has future timestamp 1_010_000
    let a2 = make_assignment(62, agent.agent_id, AssignmentStatus::Assigned, 1_010_000);

    manager.store().insert_assignment(&a1).unwrap();
    manager.store().insert_assignment(&a2).unwrap();

    // Reconciling at 1_005_000 is valid for agent (1_000_000) and a1 (1_001_000),
    // but causes a timestamp regression on a2 (1_010_000 > 1_005_000)!
    let err = manager.reconcile_startup(1_005_000).unwrap_err();
    assert!(matches!(err, AgentManagerError::TimestampRegression { .. }));

    // Entire transaction must have rolled back:
    // 1. Agent must still be Running, retries still 0
    let reloaded_agent = manager.get_agent(&agent.agent_id).unwrap().unwrap();
    assert_eq!(reloaded_agent.state, AgentLifecycleState::Running);
    assert_eq!(
        reloaded_agent.restart_policy,
        RestartPolicy::OnFailure {
            max_retries: 3,
            current_retries: 0,
            backoff_ms: 1000,
        }
    );

    // 2. a1 must still be InProgress (NOT Failed!)
    let reloaded_a1 = manager
        .store()
        .get_assignment(&a1.assignment_id)
        .unwrap()
        .unwrap();
    assert_eq!(reloaded_a1.status, AssignmentStatus::InProgress);

    // 3. a2 must still be Assigned
    let reloaded_a2 = manager
        .store()
        .get_assignment(&a2.assignment_id)
        .unwrap()
        .unwrap();
    assert_eq!(reloaded_a2.status, AssignmentStatus::Assigned);
}

#[test]
fn test_fresh_instance_nonce_per_restart() {
    let (_dir, path) = create_temp_db();
    let (manager, observer) = create_manager_with_mock_observer(&path);

    let agent = make_spawned_agent(
        23,
        AgentLifecycleState::Running,
        RestartPolicy::on_failure(5, 500),
        1111,
        2222,
    );
    let nonce0 = agent.process_identity.instance_nonce;
    manager.register_agent(&agent).unwrap();

    // First crash & restart
    observer.terminate_process(1111);
    let r1 = manager.reconcile_startup(1_005_000).unwrap();
    let nonce1 = r1.agents_recovered[0].new_instance_nonce.unwrap();
    assert_ne!(nonce0, nonce1);

    // Simulate spawn and readiness into PID 3333 with nonce1
    let mut ag = manager.get_agent(&agent.agent_id).unwrap().unwrap();
    ag.state = AgentLifecycleState::Ready;
    ag.process_identity = ProcessIdentity::active(3333, 4444, nonce1, 1000, 1000, 1_006_000);
    ag.updated_at_ms = 1_006_000;
    manager.store().update_agent(&ag).unwrap();

    ag.state = AgentLifecycleState::Running;
    ag.updated_at_ms = 1_006_500;
    manager.store().update_agent(&ag).unwrap();

    // Second crash & restart
    observer.terminate_process(3333);
    let r2 = manager.reconcile_startup(1_007_000).unwrap();
    let nonce2 = r2.agents_recovered[0].new_instance_nonce.unwrap();
    assert_ne!(nonce1, nonce2);
    assert_ne!(nonce0, nonce2);
}

#[test]
fn test_cold_restart_unknown_does_not_fail_agent() {
    let (_dir, path) = create_temp_db();
    let store = AgentRegistryStore::open(&path).expect("Failed to open store");
    // Use UnknownProcessObserver
    let manager = GlobalAgentManager::new(store).with_process_observer(Arc::new(
        agenticos_core::agent::UnknownProcessObserver::new(),
    ));

    let agent = make_spawned_agent(
        24,
        AgentLifecycleState::Running,
        RestartPolicy::on_failure(3, 1000),
        7777,
        8888,
    );
    let original_nonce = agent.process_identity.instance_nonce;
    manager.register_agent(&agent).unwrap();

    // Reconcile startup: observer returns Unknown
    let report = manager.reconcile_startup(1_005_000).unwrap();
    assert_eq!(report.agents_scanned, 1);
    assert_eq!(report.agents_recovered.len(), 0);
    assert_eq!(report.total_assignments_failed, 0);

    // Agent must NOT transition to Failed, retries must NOT be incremented, nonce unchanged
    let reloaded = manager.get_agent(&agent.agent_id).unwrap().unwrap();
    assert_eq!(reloaded.state, AgentLifecycleState::Running);
    assert_eq!(
        reloaded.restart_policy,
        RestartPolicy::OnFailure {
            max_retries: 3,
            current_retries: 0,
            backoff_ms: 1000,
        }
    );
    assert_eq!(reloaded.process_identity.instance_nonce, original_nonce);
    assert_eq!(reloaded.updated_at_ms, 1_000_000);
}

#[test]
fn test_unknown_does_not_fail_active_assignments() {
    let (_dir, path) = create_temp_db();
    let store = AgentRegistryStore::open(&path).expect("Failed to open store");
    let manager = GlobalAgentManager::new(store).with_process_observer(Arc::new(
        agenticos_core::agent::UnknownProcessObserver::new(),
    ));

    let agent = make_spawned_agent(
        25,
        AgentLifecycleState::Running,
        RestartPolicy::on_failure(3, 1000),
        8888,
        9999,
    );
    manager.register_agent(&agent).unwrap();

    let a1 = make_assignment(71, agent.agent_id, AssignmentStatus::InProgress, 1_001_000);
    let a2 = make_assignment(72, agent.agent_id, AssignmentStatus::Assigned, 1_002_000);
    manager.store().insert_assignment(&a1).unwrap();
    manager.store().insert_assignment(&a2).unwrap();

    let report = manager.reconcile_startup(1_005_000).unwrap();
    assert_eq!(report.total_assignments_failed, 0);

    // Active assignments must remain intact and NOT failed
    let a1_reloaded = manager
        .store()
        .get_assignment(&a1.assignment_id)
        .unwrap()
        .unwrap();
    assert_eq!(a1_reloaded.status, AssignmentStatus::InProgress);
    assert_eq!(a1_reloaded.updated_at_ms, 1_001_000);

    let a2_reloaded = manager
        .store()
        .get_assignment(&a2.assignment_id)
        .unwrap()
        .unwrap();
    assert_eq!(a2_reloaded.status, AssignmentStatus::Assigned);
    assert_eq!(a2_reloaded.updated_at_ms, 1_002_000);
}

#[test]
fn test_unknown_does_not_consume_restart_retries() {
    let (_dir, path) = create_temp_db();
    let store = AgentRegistryStore::open(&path).expect("Failed to open store");
    let manager = GlobalAgentManager::new(store).with_process_observer(Arc::new(
        agenticos_core::agent::UnknownProcessObserver::new(),
    ));

    let agent = make_spawned_agent(
        26,
        AgentLifecycleState::Running,
        RestartPolicy::on_failure(1, 1000),
        9999,
        1111,
    );
    manager.register_agent(&agent).unwrap();

    // Call reconciliation multiple times
    for ts in [1_005_000, 1_006_000, 1_007_000] {
        let report = manager.reconcile_startup(ts).unwrap();
        assert_eq!(report.agents_recovered.len(), 0);
    }

    // Retries must still be 0 (never consumed), state still Running
    let reloaded = manager.get_agent(&agent.agent_id).unwrap().unwrap();
    assert_eq!(reloaded.state, AgentLifecycleState::Running);
    assert_eq!(
        reloaded.restart_policy,
        RestartPolicy::OnFailure {
            max_retries: 1,
            current_retries: 0,
            backoff_ms: 1000,
        }
    );
}

#[test]
fn test_linux_procfs_observer_mock_filesystem() {
    let temp = tempfile::tempdir().unwrap();
    let proc_root = temp.path().to_path_buf();
    let observer = agenticos_core::agent::LinuxProcfsObserver::with_proc_root(&proc_root);

    // 1. Non-existent PID directory -> Dead (actual host evidence of non-existence)
    let non_existent_identity =
        ProcessIdentity::active(12345, 5000, Uuid::new_v4(), 1000, 1000, 1_000_000);
    assert_eq!(
        observer.check_liveness(&non_existent_identity),
        ProcessLiveness::Dead
    );

    // 2. Existing PID directory with matching start_time_ticks -> Alive
    let pid_dir = proc_root.join("12345");
    std::fs::create_dir_all(&pid_dir).unwrap();
    let stat_content = "12345 (test_agent) S 1 1 1 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0 5000 1000 20 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0";
    std::fs::write(pid_dir.join("stat"), stat_content).unwrap();

    assert_eq!(
        observer.check_liveness(&non_existent_identity),
        ProcessLiveness::Alive
    );

    // 3. Existing PID with mismatched start_time_ticks -> Recycled
    let recycled_identity =
        ProcessIdentity::active(12345, 9999, Uuid::new_v4(), 1000, 1000, 1_000_000);
    assert_eq!(
        observer.check_liveness(&recycled_identity),
        ProcessLiveness::Recycled {
            observed_ticks: 5000
        }
    );

    // 4. Malformed stat content -> Unknown
    std::fs::write(pid_dir.join("stat"), "corrupt data").unwrap();
    assert_eq!(
        observer.check_liveness(&non_existent_identity),
        ProcessLiveness::Unknown
    );
}

#[test]
fn test_linux_procfs_observer_real_proc_self() {
    let observer = agenticos_core::agent::LinuxProcfsObserver::new();

    // Check against real /proc/self/stat
    let self_stat =
        std::fs::read_to_string("/proc/self/stat").expect("Failed to read /proc/self/stat");
    let self_ticks = agenticos_core::agent::LinuxProcfsObserver::parse_stat_starttime(&self_stat)
        .expect("Failed to parse starttime from /proc/self/stat");

    let my_pid = std::process::id();
    let my_identity =
        ProcessIdentity::active(my_pid, self_ticks, Uuid::new_v4(), 1000, 1000, 1_000_000);

    // Real PID with real starttime must report Alive!
    assert_eq!(
        observer.check_liveness(&my_identity),
        ProcessLiveness::Alive
    );

    // Real PID with wrong starttime must report Recycled!
    let recycled_identity = ProcessIdentity::active(
        my_pid,
        self_ticks.wrapping_add(10_000),
        Uuid::new_v4(),
        1000,
        1000,
        1_000_000,
    );
    assert_eq!(
        observer.check_liveness(&recycled_identity),
        ProcessLiveness::Recycled {
            observed_ticks: self_ticks
        }
    );

    // Unspawned identity must report Unspawned!
    let unspawned = ProcessIdentity::unspawned(1000, 1000);
    assert_eq!(
        observer.check_liveness(&unspawned),
        ProcessLiveness::Unspawned
    );
}

#[test]
fn test_source_code_audit_zero_forbidden_primitives() {
    let recovery_src = include_str!("../src/agent/recovery.rs");
    let observer_src = include_str!("../src/agent/observer.rs");
    let monitor_src = include_str!("../src/agent/monitor.rs");

    for src in &[recovery_src, observer_src, monitor_src] {
        assert!(
            !src.contains("Command::new"),
            "Forbidden Command::new found"
        );
        assert!(
            !src.contains("std::process::Command"),
            "Forbidden std::process::Command found"
        );
        assert!(!src.contains("fork("), "Forbidden fork found");
        assert!(!src.contains("exec("), "Forbidden exec found");
        assert!(!src.contains("std::net"), "Forbidden network module found");
        assert!(
            !src.contains("UnixListener"),
            "Forbidden live listener found"
        );
    }
}
