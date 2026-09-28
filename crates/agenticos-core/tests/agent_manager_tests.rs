//! Integration and unit test suite for Phase 2.4: Global Agent Manager Runtime.
//!
//! Aligned with Phase 2.0 specification, ADR-0002 through ADR-0007.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use uuid::Uuid;

use agenticos_contracts::{PrincipalContext, ProtocolVersion, ResourceRef, RetryClassification};
use agenticos_core::agent::{
    AgentId, AgentLifecycleState, AgentManagerError, AgentRecord, AgentResourceMetrics, AgentScope,
    AgentType, AgentVersion, AssignmentRequest, AssignmentStatus, DegradedEligibility,
    GlobalAgentManager, HeartbeatRecord, ProcessIdentity, RestartPolicy,
};
use agenticos_core::storage::AgentRegistryStore;
use agenticos_core::workflow::{StepExecutionState, WorkflowStep};

/// Helper: creates a temporary database and returns the directory and file path.
fn create_temp_db() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("Failed to create tempdir");
    let path = dir.path().join("agent_registry.db");
    (dir, path)
}

/// Helper: opens a `GlobalAgentManager` on the given database path.
fn create_manager(path: &Path) -> GlobalAgentManager {
    let store = AgentRegistryStore::open(path).expect("Failed to open AgentRegistryStore");
    GlobalAgentManager::new(store)
}

/// Helper: constructs a test `AgentRecord`.
fn make_agent(
    id_seed: u128,
    state: AgentLifecycleState,
    scope: AgentScope,
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
        agent_type: AgentType::Builtin("FileAgent".to_string()),
        agent_version: AgentVersion::new(1, 0, 0),
        protocol_version: ProtocolVersion::V1_0,
        owner,
        scope,
        declared_capabilities,
        process_identity: ProcessIdentity::unspawned(1000, 1000),
        state,
        restart_policy: RestartPolicy::Never,
        registered_at_ms: 1_000_000,
        updated_at_ms: 1_000_000,
    }
}

/// Helper: constructs a test `WorkflowStep`.
fn make_step(step_index: u32, capability_id: &str, timeout_duration_ms: u64) -> WorkflowStep {
    WorkflowStep {
        step_id: Uuid::new_v4(),
        step_index,
        capability_id: capability_id.to_string(),
        capability_schema_version: 1,
        resource: ResourceRef::path("/workspace/test"),
        arguments: serde_json::json!({ "flag": true }),
        dependency_step_ids: Vec::new(),
        state: StepExecutionState::Created,
        retry_classification: RetryClassification::Never,
        timeout_duration_ms,
    }
}

/// Helper: constructs a test `AssignmentRequest`.
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

// =======================================================================
// 1. Eligibility & Selection Tests
// =======================================================================

#[test]
fn test_no_eligible_agent_empty_registry() {
    let (_dir, db_path) = create_temp_db();
    let manager = create_manager(&db_path);

    let step = make_step(0, "fs.read_file", 5000);
    let request = make_request(step, PrincipalContext::user(1000, 1000), 1_001_000);

    let err = manager.assign_step(&request).unwrap_err();
    assert!(
        matches!(err, AgentManagerError::NoEligibleAgent { ref capability_id } if capability_id == "fs.read_file"),
        "Expected NoEligibleAgent, got: {:?}",
        err
    );
}

#[test]
fn test_one_eligible_agent_success() {
    let (_dir, db_path) = create_temp_db();
    let manager = create_manager(&db_path);

    let agent = make_agent(
        100,
        AgentLifecycleState::Ready,
        AgentScope::SharedSession,
        &["fs.read_file"],
    );
    manager.register_agent(&agent).unwrap();

    let step = make_step(0, "fs.read_file", 5000);
    let request = make_request(step, PrincipalContext::user(1000, 1000), 1_001_000);

    let assignment = manager.assign_step(&request).unwrap();
    assert_eq!(assignment.agent_id, agent.agent_id);
    assert_eq!(assignment.status, AssignmentStatus::Assigned);
    assert_eq!(assignment.capability_id, "fs.read_file");

    // Authoritative agent state must now be Running
    let updated_agent = manager.get_agent(&agent.agent_id).unwrap().unwrap();
    assert_eq!(updated_agent.state, AgentLifecycleState::Running);
}

#[test]
fn test_capability_filtering() {
    let (_dir, db_path) = create_temp_db();
    let manager = create_manager(&db_path);

    let agent = make_agent(
        100,
        AgentLifecycleState::Ready,
        AgentScope::SharedSession,
        &["fs.create_directory", "fs.read_file"],
    );
    manager.register_agent(&agent).unwrap();

    // Matching capability succeeds
    let step1 = make_step(0, "fs.create_directory", 5000);
    let req1 = make_request(step1, PrincipalContext::user(1000, 1000), 1_001_000);
    let assignment = manager.assign_step(&req1).unwrap();
    assert_eq!(assignment.capability_id, "fs.create_directory");

    // Non-matching capability fails with NoEligibleAgent
    let step2 = make_step(1, "net.http_request", 5000);
    let req2 = make_request(step2, PrincipalContext::user(1000, 1000), 1_002_000);
    let err = manager.assign_step(&req2).unwrap_err();
    assert!(
        matches!(err, AgentManagerError::NoEligibleAgent { ref capability_id } if capability_id == "net.http_request")
    );
}

#[test]
fn test_lifecycle_readiness_filtering() {
    let (_dir, db_path) = create_temp_db();
    let manager = create_manager(&db_path);

    // Register agents across all non-Ready states
    let non_ready_states = [
        AgentLifecycleState::Registered,
        AgentLifecycleState::Starting,
        AgentLifecycleState::Running,
        AgentLifecycleState::Stopping,
        AgentLifecycleState::Stopped,
        AgentLifecycleState::Failed,
    ];

    for (i, state) in non_ready_states.iter().enumerate() {
        let agent = make_agent(
            (i as u128) + 10,
            *state,
            AgentScope::SharedSession,
            &["fs.read_file"],
        );
        manager.register_agent(&agent).unwrap();
    }

    let step = make_step(0, "fs.read_file", 5000);
    let request = make_request(step, PrincipalContext::user(1000, 1000), 1_001_000);

    // None can be assigned
    let err = manager.assign_step(&request).unwrap_err();
    assert!(matches!(err, AgentManagerError::NoEligibleAgent { .. }));
}

// =======================================================================
// 2. Scope & Governance Filtering Tests
// =======================================================================

#[test]
fn test_scope_filtering_private() {
    let (_dir, db_path) = create_temp_db();
    let manager = create_manager(&db_path);

    let alice = PrincipalContext::user(1000, 1000);
    let bob = PrincipalContext::user(1001, 1001);

    let mut agent = make_agent(
        100,
        AgentLifecycleState::Ready,
        AgentScope::Private(alice.clone()),
        &["fs.read_file"],
    );
    agent.owner = alice.clone();
    manager.register_agent(&agent).unwrap();

    // Bob tries to reserve Alice's private agent -> rejected
    let step_bob = make_step(0, "fs.read_file", 5000);
    let req_bob = make_request(step_bob, bob, 1_001_000);
    let err = manager.assign_step(&req_bob).unwrap_err();
    assert!(matches!(err, AgentManagerError::NoEligibleAgent { .. }));

    // Alice reserves her private agent -> success
    let step_alice = make_step(0, "fs.read_file", 5000);
    let req_alice = make_request(step_alice, alice, 1_001_000);
    let assignment = manager.assign_step(&req_alice).unwrap();
    assert_eq!(assignment.agent_id, agent.agent_id);
}

#[test]
fn test_scope_filtering_shared_and_system_wide_allows_non_owner() {
    let (_dir, db_path) = create_temp_db();
    let manager = create_manager(&db_path);

    let alice = PrincipalContext::user(1000, 1000);
    let bob = PrincipalContext::user(1001, 1001);

    // Agent owned by Alice, but scope is SharedSession
    let mut agent = make_agent(
        100,
        AgentLifecycleState::Ready,
        AgentScope::SharedSession,
        &["fs.read_file"],
    );
    agent.owner = alice;
    manager.register_agent(&agent).unwrap();

    // Bob requests work -> permitted because scope is SharedSession (owner is provenance, not eligibility blocker)
    let step = make_step(0, "fs.read_file", 5000);
    let req = make_request(step, bob, 1_001_000);
    let assignment = manager.assign_step(&req).unwrap();
    assert_eq!(assignment.agent_id, agent.agent_id);
}

// =======================================================================
// 3. Deterministic Tie-Breaking Tests
// =======================================================================

#[test]
fn test_deterministic_tie_breaking_active_tasks() {
    let (_dir, db_path) = create_temp_db();
    let manager = create_manager(&db_path);

    // Agent A and Agent B
    let agent_a = make_agent(
        100,
        AgentLifecycleState::Ready,
        AgentScope::SharedSession,
        &["fs.read_file"],
    );
    let agent_b = make_agent(
        200,
        AgentLifecycleState::Ready,
        AgentScope::SharedSession,
        &["fs.read_file"],
    );
    manager.register_agent(&agent_a).unwrap();
    manager.register_agent(&agent_b).unwrap();

    // Assign a task to Agent A first
    let step1 = make_step(0, "fs.read_file", 5000);
    let req1 = make_request(step1, PrincipalContext::user(1000, 1000), 1_001_000);
    let assign1 = manager.assign_step(&req1).unwrap();
    assert_eq!(assign1.agent_id, agent_a.agent_id);

    // Re-mark Agent A as Ready (e.g. multi-task capable or simulating concurrency)
    manager
        .update_agent_state(&agent_a.agent_id, AgentLifecycleState::Ready, 1_002_000)
        .unwrap();

    // Now Agent A has 1 active task, Agent B has 0 active tasks
    // Next assignment MUST pick Agent B (fewest active tasks)
    let step2 = make_step(1, "fs.read_file", 5000);
    let req2 = make_request(step2, PrincipalContext::user(1000, 1000), 1_003_000);
    let assign2 = manager.assign_step(&req2).unwrap();
    assert_eq!(assign2.agent_id, agent_b.agent_id);
}

#[test]
fn test_deterministic_tie_breaking_historical_tasks() {
    let (_dir, db_path) = create_temp_db();
    let manager = create_manager(&db_path);

    let agent_a = make_agent(
        100,
        AgentLifecycleState::Ready,
        AgentScope::SharedSession,
        &["fs.read_file"],
    );
    let agent_b = make_agent(
        200,
        AgentLifecycleState::Ready,
        AgentScope::SharedSession,
        &["fs.read_file"],
    );
    manager.register_agent(&agent_a).unwrap();
    manager.register_agent(&agent_b).unwrap();

    // Assign to Agent A, start it, and complete it
    let step1 = make_step(0, "fs.read_file", 5000);
    let req1 = make_request(step1, PrincipalContext::user(1000, 1000), 1_001_000);
    let assign1 = manager.assign_step(&req1).unwrap();
    manager
        .start_assignment(&assign1.assignment_id, 1_001_500)
        .unwrap();
    manager
        .complete_assignment(&assign1.assignment_id, 1_002_000)
        .unwrap();

    // Now both Agent A and Agent B have 0 active tasks
    // But Agent A has 1 historical task, Agent B has 0 historical tasks
    // Manager MUST pick Agent B
    let step2 = make_step(1, "fs.read_file", 5000);
    let req2 = make_request(step2, PrincipalContext::user(1000, 1000), 1_003_000);
    let assign2 = manager.assign_step(&req2).unwrap();
    assert_eq!(assign2.agent_id, agent_b.agent_id);
}

#[test]
fn test_deterministic_tie_breaking_lexicographical_agent_id() {
    let (_dir, db_path) = create_temp_db();
    let manager = create_manager(&db_path);

    // Agent 1 with smaller UUID string vs Agent 2 with larger UUID string
    let agent_small = make_agent(
        1,
        AgentLifecycleState::Ready,
        AgentScope::SharedSession,
        &["fs.read_file"],
    );
    let agent_large = make_agent(
        2,
        AgentLifecycleState::Ready,
        AgentScope::SharedSession,
        &["fs.read_file"],
    );

    // Verify ordering
    assert!(agent_small.agent_id.to_string() < agent_large.agent_id.to_string());

    // Register large first, small second
    manager.register_agent(&agent_large).unwrap();
    manager.register_agent(&agent_small).unwrap();

    // Both have 0 active, 0 historical
    // Manager MUST pick agent_small
    let step = make_step(0, "fs.read_file", 5000);
    let req = make_request(step, PrincipalContext::user(1000, 1000), 1_001_000);
    let assignment = manager.assign_step(&req).unwrap();
    assert_eq!(assignment.agent_id, agent_small.agent_id);
}

// =======================================================================
// 4. Health State & Policy Tests
// =======================================================================

#[test]
fn test_unhealthy_agent_exclusion() {
    let (_dir, db_path) = create_temp_db();
    let manager = create_manager(&db_path);

    let agent = make_agent(
        100,
        AgentLifecycleState::Ready,
        AgentScope::SharedSession,
        &["fs.read_file"],
    );
    manager.register_agent(&agent).unwrap();

    // Record an expired heartbeat (e.g. 50,000ms ago, timeout is 5,000ms)
    let hb = HeartbeatRecord::new(
        agent.agent_id,
        agent.process_identity.instance_nonce,
        1_000_000,
        1,
        AgentResourceMetrics::new(100, 1024, 10),
    );
    manager.record_heartbeat(&hb).unwrap();

    // Request at 1_050_000ms (50s later) -> health evaluator evaluates Unhealthy
    let step = make_step(0, "fs.read_file", 5000);
    let req = make_request(step, PrincipalContext::user(1000, 1000), 1_050_000);

    let err = manager.assign_step(&req).unwrap_err();
    assert!(matches!(err, AgentManagerError::NoEligibleAgent { .. }));
}

#[test]
fn test_degraded_health_policy_behavior() {
    let (_dir, db_path) = create_temp_db();
    let store = AgentRegistryStore::open(&db_path).unwrap();

    let agent = make_agent(
        100,
        AgentLifecycleState::Ready,
        AgentScope::SharedSession,
        &["fs.read_file"],
    );
    store.register_agent(&agent).unwrap();

    // Heartbeat with high CPU (950 permille >= 900 threshold) -> Degraded
    let hb = HeartbeatRecord::new(
        agent.agent_id,
        agent.process_identity.instance_nonce,
        1_000_000,
        1,
        AgentResourceMetrics::new(950, 1024, 10),
    );
    store.append_heartbeat(&hb).unwrap();

    // 1. Manager with DegradedEligibility::Allow (default)
    let manager_allow = GlobalAgentManager::new(store.clone())
        .with_degraded_eligibility(DegradedEligibility::Allow);

    let step = make_step(0, "fs.read_file", 5000);
    let req = make_request(step.clone(), PrincipalContext::user(1000, 1000), 1_001_000);
    let assign = manager_allow.assign_step(&req).unwrap();
    assert_eq!(assign.agent_id, agent.agent_id);

    // Reset agent back to Ready for second test
    manager_allow
        .start_assignment(&assign.assignment_id, 1_001_500)
        .unwrap();
    manager_allow
        .complete_assignment(&assign.assignment_id, 1_002_000)
        .unwrap();

    // 2. Manager with DegradedEligibility::Deny
    let manager_deny =
        GlobalAgentManager::new(store).with_degraded_eligibility(DegradedEligibility::Deny);

    let req2 = make_request(step, PrincipalContext::user(1000, 1000), 1_003_000);
    let err = manager_deny.assign_step(&req2).unwrap_err();
    assert!(matches!(err, AgentManagerError::NoEligibleAgent { .. }));
}

// =======================================================================
// 5. Concurrency & Collision Fallback Tests
// =======================================================================

#[test]
fn test_concurrent_reservation_attempts_separate_connections() {
    let (_dir, db_path) = create_temp_db();

    // Set up database with exactly 1 Ready agent
    {
        let store = AgentRegistryStore::open(&db_path).unwrap();
        let agent = make_agent(
            100,
            AgentLifecycleState::Ready,
            AgentScope::SharedSession,
            &["fs.read_file"],
        );
        store.register_agent(&agent).unwrap();
    }

    // Two separate threads with separate SQLite connections/managers
    let path1 = db_path.clone();
    let path2 = db_path;

    let h1 = std::thread::spawn(move || {
        let store = AgentRegistryStore::open(&path1).unwrap();
        let manager = GlobalAgentManager::new(store);
        let step = make_step(0, "fs.read_file", 5000);
        let req = make_request(step, PrincipalContext::user(1000, 1000), 1_001_000);
        manager.assign_step(&req)
    });

    let h2 = std::thread::spawn(move || {
        let store = AgentRegistryStore::open(&path2).unwrap();
        let manager = GlobalAgentManager::new(store);
        let step = make_step(0, "fs.read_file", 5000);
        let req = make_request(step, PrincipalContext::user(1000, 1000), 1_001_000);
        manager.assign_step(&req)
    });

    let r1 = h1.join().unwrap();
    let r2 = h2.join().unwrap();

    // Exactly one must succeed, exactly one must receive NoEligibleAgent
    let results = [r1.is_ok(), r2.is_ok()];
    assert!(
        (results[0] && !results[1]) || (!results[0] && results[1]),
        "Exactly one reservation must succeed, got: r1: {:?}, r2: {:?}",
        r1,
        r2
    );

    // Verify exactly 1 assignment in database
    let store = AgentRegistryStore::open(_dir.path().join("agent_registry.db")).unwrap();
    let assignments = store
        .list_assignments_for_agent(&AgentId::from_uuid(Uuid::from_u128(100)))
        .unwrap();
    assert_eq!(assignments.len(), 1);

    // Verify agent is Running
    let agent = store
        .get_agent(&AgentId::from_uuid(Uuid::from_u128(100)))
        .unwrap()
        .unwrap();
    assert_eq!(agent.state, AgentLifecycleState::Running);
}

#[test]
fn test_reservation_collision_fallback() {
    let (_dir, db_path) = create_temp_db();
    let manager = create_manager(&db_path);

    // Agent 1 (UUID 10) and Agent 2 (UUID 20)
    let agent1 = make_agent(
        10,
        AgentLifecycleState::Ready,
        AgentScope::SharedSession,
        &["fs.read_file"],
    );
    let agent2 = make_agent(
        20,
        AgentLifecycleState::Ready,
        AgentScope::SharedSession,
        &["fs.read_file"],
    );
    manager.register_agent(&agent1).unwrap();
    manager.register_agent(&agent2).unwrap();

    // Transition Agent 1 to Running directly in storage right before reservation
    // simulating an external/concurrent reservation race
    manager
        .update_agent_state(&agent1.agent_id, AgentLifecycleState::Running, 1_001_000)
        .unwrap();

    // Now manager evaluates step: Agent 1 is no longer Ready, so Agent 2 is reserved!
    let step = make_step(0, "fs.read_file", 5000);
    let req = make_request(step, PrincipalContext::user(1000, 1000), 1_002_000);
    let assignment = manager.assign_step(&req).unwrap();

    assert_eq!(assignment.agent_id, agent2.agent_id);
    let updated2 = manager.get_agent(&agent2.agent_id).unwrap().unwrap();
    assert_eq!(updated2.state, AgentLifecycleState::Running);
}

// =======================================================================
// 6. Assignment Persistence & Lineage Preservation Tests
// =======================================================================

#[test]
fn test_assignment_persistence_and_query_apis() {
    let (_dir, db_path) = create_temp_db();
    let manager = create_manager(&db_path);

    let agent = make_agent(
        100,
        AgentLifecycleState::Ready,
        AgentScope::SharedSession,
        &["fs.read_file"],
    );
    manager.register_agent(&agent).unwrap();

    let step = make_step(0, "fs.read_file", 5000);
    let step_id = step.step_id;
    let request = make_request(step, PrincipalContext::user(1000, 1000), 1_001_000);
    let workflow_id = request.workflow_id;

    let assignment = manager.assign_step(&request).unwrap();

    // Query by ID
    let fetched = manager
        .get_assignment(&assignment.assignment_id)
        .unwrap()
        .unwrap();
    assert_eq!(fetched, assignment);

    // Query by agent
    let by_agent = manager.list_assignments_for_agent(&agent.agent_id).unwrap();
    assert_eq!(by_agent.len(), 1);
    assert_eq!(by_agent[0], assignment);

    // Query by workflow
    let by_workflow = manager.list_assignments_for_workflow(&workflow_id).unwrap();
    assert_eq!(by_workflow.len(), 1);
    assert_eq!(by_workflow[0], assignment);

    // Query by step
    let by_step = manager.list_assignments_for_step(&step_id).unwrap();
    assert_eq!(by_step.len(), 1);
    assert_eq!(by_step[0], assignment);
}

#[test]
fn test_assignment_lineage_preservation() {
    let (_dir, db_path) = create_temp_db();
    let manager = create_manager(&db_path);

    let agent = make_agent(
        100,
        AgentLifecycleState::Ready,
        AgentScope::SharedSession,
        &["fs.write_file"],
    );
    manager.register_agent(&agent).unwrap();

    let step = WorkflowStep {
        step_id: Uuid::new_v4(),
        step_index: 3,
        capability_id: "fs.write_file".to_string(),
        capability_schema_version: 2,
        resource: ResourceRef::path("/etc/config.json"),
        arguments: serde_json::json!({ "content": "hello world", "mode": 0o644 }),
        dependency_step_ids: vec![Uuid::new_v4()],
        state: StepExecutionState::Created,
        retry_classification: RetryClassification::Conditional,
        timeout_duration_ms: 10_000,
    };

    let principal = PrincipalContext::user(42, 42);
    let correlation_id = Uuid::new_v4();
    let request_id = Uuid::new_v4();
    let workflow_id = Uuid::new_v4();

    let request = AssignmentRequest {
        correlation_id,
        request_id,
        originating_principal: principal.clone(),
        workflow_id,
        step: step.clone(),
        timestamp_ms: 1_001_500,
    };

    let assignment = manager.assign_step(&request).unwrap();

    // Verify all lineage fields are strictly preserved
    assert_eq!(assignment.correlation_id, correlation_id);
    assert_eq!(assignment.request_id, request_id);
    assert_eq!(assignment.originating_principal, principal);
    assert_eq!(assignment.workflow_id, workflow_id);
    assert_eq!(assignment.step_id, step.step_id);
    assert_eq!(assignment.agent_id, agent.agent_id);
    assert_eq!(assignment.capability_id, "fs.write_file");
    assert_eq!(assignment.resource, ResourceRef::path("/etc/config.json"));
    assert_eq!(
        assignment.arguments,
        serde_json::json!({ "content": "hello world", "mode": 0o644 })
    );
    assert_eq!(assignment.timeout_duration_ms, 10_000);
    assert_eq!(assignment.assigned_at_ms, 1_001_500);
    assert_eq!(assignment.updated_at_ms, 1_001_500);
}

// =======================================================================
// 7. Assignment Lifecycle Coordination Tests
// =======================================================================

#[test]
fn test_assignment_full_lifecycle_success() {
    let (_dir, db_path) = create_temp_db();
    let manager = create_manager(&db_path);

    let agent = make_agent(
        100,
        AgentLifecycleState::Ready,
        AgentScope::SharedSession,
        &["fs.read_file"],
    );
    manager.register_agent(&agent).unwrap();

    let step = make_step(0, "fs.read_file", 5000);
    let request = make_request(step, PrincipalContext::user(1000, 1000), 1_001_000);

    // 1. Assign -> Assigned, agent Running
    let assignment = manager.assign_step(&request).unwrap();
    assert_eq!(assignment.status, AssignmentStatus::Assigned);
    assert_eq!(
        manager.get_agent(&agent.agent_id).unwrap().unwrap().state,
        AgentLifecycleState::Running
    );

    // 2. Start -> InProgress
    let in_progress = manager
        .start_assignment(&assignment.assignment_id, 1_002_000)
        .unwrap();
    assert_eq!(in_progress.status, AssignmentStatus::InProgress);

    // 3. Complete -> Completed, agent released back to Ready
    let (completed, updated_agent) = manager
        .complete_assignment(&assignment.assignment_id, 1_003_000)
        .unwrap();
    assert_eq!(completed.status, AssignmentStatus::Completed);
    assert_eq!(updated_agent.state, AgentLifecycleState::Ready);
    assert_eq!(
        manager.get_agent(&agent.agent_id).unwrap().unwrap().state,
        AgentLifecycleState::Ready
    );

    // 4. Terminal assignment cannot transition further
    let err = manager
        .complete_assignment(&assignment.assignment_id, 1_004_000)
        .unwrap_err();
    assert!(matches!(
        err,
        AgentManagerError::AssignmentTerminal { status, .. } if status == AssignmentStatus::Completed
    ));
}

#[test]
fn test_cancellation_releases_agent_to_ready() {
    let (_dir, db_path) = create_temp_db();
    let manager = create_manager(&db_path);

    let agent = make_agent(
        100,
        AgentLifecycleState::Ready,
        AgentScope::SharedSession,
        &["fs.read_file"],
    );
    manager.register_agent(&agent).unwrap();

    let step = make_step(0, "fs.read_file", 5000);
    let request = make_request(step, PrincipalContext::user(1000, 1000), 1_001_000);
    let assignment = manager.assign_step(&request).unwrap();

    // Cancel assignment
    let (cancelled, agent_record) = manager
        .cancel_assignment(&assignment.assignment_id, "User requested abort", 1_002_000)
        .unwrap();

    assert_eq!(cancelled.status, AssignmentStatus::Cancelled);
    assert_eq!(agent_record.state, AgentLifecycleState::Ready);

    let stored_agent = manager.get_agent(&agent.agent_id).unwrap().unwrap();
    assert_eq!(stored_agent.state, AgentLifecycleState::Ready);

    // Subsequent cancellation rejected as terminal
    let err = manager
        .cancel_assignment(&assignment.assignment_id, "redundant", 1_003_000)
        .unwrap_err();
    assert!(matches!(
        err,
        AgentManagerError::AssignmentTerminal { status, .. } if status == AssignmentStatus::Cancelled
    ));
}

#[test]
fn test_failure_propagation_releases_agent_to_ready() {
    let (_dir, db_path) = create_temp_db();
    let manager = create_manager(&db_path);

    let agent = make_agent(
        100,
        AgentLifecycleState::Ready,
        AgentScope::SharedSession,
        &["fs.read_file"],
    );
    manager.register_agent(&agent).unwrap();

    let step = make_step(0, "fs.read_file", 5000);
    let request = make_request(step, PrincipalContext::user(1000, 1000), 1_001_000);
    let assignment = manager.assign_step(&request).unwrap();

    // Fail assignment
    let (failed, agent_record) = manager
        .fail_assignment(
            &assignment.assignment_id,
            "File read permission denied",
            1_002_000,
        )
        .unwrap();

    assert_eq!(failed.status, AssignmentStatus::Failed);
    assert_eq!(agent_record.state, AgentLifecycleState::Ready);

    let stored_agent = manager.get_agent(&agent.agent_id).unwrap().unwrap();
    assert_eq!(stored_agent.state, AgentLifecycleState::Ready);

    // Subsequent failure rejected as terminal
    let err = manager
        .fail_assignment(&assignment.assignment_id, "redundant", 1_003_000)
        .unwrap_err();
    assert!(matches!(
        err,
        AgentManagerError::AssignmentTerminal { status, .. } if status == AssignmentStatus::Failed
    ));
}

// =======================================================================
// 8. Rollback & Fault Injection Tests
// =======================================================================

#[test]
fn test_rollback_on_zero_timeout_validation_failure() {
    let (_dir, db_path) = create_temp_db();
    let manager = create_manager(&db_path);

    let agent = make_agent(
        100,
        AgentLifecycleState::Ready,
        AgentScope::SharedSession,
        &["fs.read_file"],
    );
    manager.register_agent(&agent).unwrap();

    // Timeout duration 0 is illegal according to ADR-0007 / Domain invariants
    let step = make_step(0, "fs.read_file", 0);
    let request = make_request(step, PrincipalContext::user(1000, 1000), 1_001_000);

    let err = manager.assign_step(&request).unwrap_err();
    assert!(matches!(err, AgentManagerError::Domain(..)));

    // Full rollback: agent must still be in Ready state
    let agent_after = manager.get_agent(&agent.agent_id).unwrap().unwrap();
    assert_eq!(agent_after.state, AgentLifecycleState::Ready);

    // No assignments persisted
    let assignments = manager.list_assignments_for_agent(&agent.agent_id).unwrap();
    assert!(assignments.is_empty());
}

#[test]
fn test_timestamp_regression_rejections() {
    let (_dir, db_path) = create_temp_db();
    let manager = create_manager(&db_path);

    let agent = make_agent(
        100,
        AgentLifecycleState::Ready,
        AgentScope::SharedSession,
        &["fs.read_file"],
    );
    manager.register_agent(&agent).unwrap();

    let step = make_step(0, "fs.read_file", 5000);
    let request = make_request(step, PrincipalContext::user(1000, 1000), 1_010_000);
    let assignment = manager.assign_step(&request).unwrap();

    // Attempt start with timestamp older than assigned_at_ms (1_010_000)
    let err_start = manager
        .start_assignment(&assignment.assignment_id, 1_005_000)
        .unwrap_err();
    assert!(matches!(
        err_start,
        AgentManagerError::TimestampRegression { .. }
    ));

    // Attempt complete with timestamp older than assigned_at_ms
    let err_complete = manager
        .complete_assignment(&assignment.assignment_id, 1_005_000)
        .unwrap_err();
    assert!(matches!(
        err_complete,
        AgentManagerError::TimestampRegression { .. }
    ));

    // Attempt cancel with timestamp older than assigned_at_ms
    let err_cancel = manager
        .cancel_assignment(&assignment.assignment_id, "abort", 1_005_000)
        .unwrap_err();
    assert!(matches!(
        err_cancel,
        AgentManagerError::TimestampRegression { .. }
    ));
}

// =======================================================================
// 9. Reopen / Restart Persistence Tests
// =======================================================================

#[test]
fn test_restart_reopen_persistence() {
    let (_dir, db_path) = create_temp_db();

    let agent_id = AgentId::from_uuid(Uuid::from_u128(100));
    let assignment_id;

    // Session 1: Register and Assign
    {
        let store = AgentRegistryStore::open(&db_path).unwrap();
        let manager = GlobalAgentManager::new(store);

        let agent = make_agent(
            100,
            AgentLifecycleState::Ready,
            AgentScope::SharedSession,
            &["fs.read_file"],
        );
        manager.register_agent(&agent).unwrap();

        let step = make_step(0, "fs.read_file", 5000);
        let request = make_request(step, PrincipalContext::user(1000, 1000), 1_001_000);
        let assignment = manager.assign_step(&request).unwrap();
        assignment_id = assignment.assignment_id;
    }

    // Session 2: Reopen manager from SQLite file on disk
    {
        let store = AgentRegistryStore::open(&db_path).unwrap();
        let manager = GlobalAgentManager::new(store);

        // Verify persisted state intact
        let agent = manager.get_agent(&agent_id).unwrap().unwrap();
        assert_eq!(agent.state, AgentLifecycleState::Running);

        let assignment = manager.get_assignment(&assignment_id).unwrap().unwrap();
        assert_eq!(assignment.status, AssignmentStatus::Assigned);

        // Start and complete assignment in reopened session
        manager.start_assignment(&assignment_id, 1_001_500).unwrap();
        let (completed, updated_agent) = manager
            .complete_assignment(&assignment_id, 1_002_000)
            .unwrap();
        assert_eq!(completed.status, AssignmentStatus::Completed);
        assert_eq!(updated_agent.state, AgentLifecycleState::Ready);
    }

    // Session 3: Verify completed state persists across second reopen
    {
        let store = AgentRegistryStore::open(&db_path).unwrap();
        let manager = GlobalAgentManager::new(store);

        let agent = manager.get_agent(&agent_id).unwrap().unwrap();
        assert_eq!(agent.state, AgentLifecycleState::Ready);

        let assignment = manager.get_assignment(&assignment_id).unwrap().unwrap();
        assert_eq!(assignment.status, AssignmentStatus::Completed);
    }
}

// =======================================================================
// 10. Failure & Edge Case Handling Tests
// =======================================================================

#[test]
fn test_registry_failure_handling() {
    let (_dir, db_path) = create_temp_db();
    let manager = create_manager(&db_path);

    let agent = make_agent(
        100,
        AgentLifecycleState::Ready,
        AgentScope::SharedSession,
        &["fs.read_file"],
    );
    manager.register_agent(&agent).unwrap();

    // Duplicate registration must return typed storage error
    let dup_err = manager.register_agent(&agent).unwrap_err();
    assert!(
        matches!(
            dup_err,
            AgentManagerError::Storage(agenticos_core::storage::StorageError::DuplicateKey { .. })
        ),
        "Expected DuplicateKey error, got: {:?}",
        dup_err
    );

    // Non-existent assignment returns None
    let non_existent = manager
        .get_assignment(&agenticos_core::agent::AssignmentId::new())
        .unwrap();
    assert!(non_existent.is_none());

    // Transitioning non-existent assignment returns AssignmentNotFound
    let not_found_err = manager
        .start_assignment(&agenticos_core::agent::AssignmentId::new(), 1_002_000)
        .unwrap_err();
    assert!(matches!(
        not_found_err,
        AgentManagerError::AssignmentNotFound { .. }
    ));
}

#[test]
fn test_lifecycle_failure_handling() {
    let (_dir, db_path) = create_temp_db();
    let manager = create_manager(&db_path);

    let agent = make_agent(
        100,
        AgentLifecycleState::Registered,
        AgentScope::SharedSession,
        &["fs.read_file"],
    );
    manager.register_agent(&agent).unwrap();

    // Illegal transition Registered -> Running must fail
    let err = manager
        .update_agent_state(&agent.agent_id, AgentLifecycleState::Running, 1_001_000)
        .unwrap_err();
    assert!(
        matches!(
            err,
            AgentManagerError::Lifecycle(
                agenticos_core::agent::AgentLifecycleError::InvalidTransition { .. }
            )
        ),
        "Expected InvalidTransition error, got: {:?}",
        err
    );
}

// =======================================================================
// 11. Source Code Security Audit Test
// =======================================================================

#[test]
fn test_source_audit_no_forbidden_primitives() {
    let manager_source = include_str!("../src/agent/manager.rs");

    // Strictly forbidden process execution primitives
    assert!(!manager_source.contains("std::process"));
    assert!(!manager_source.contains("Command::new"));
    assert!(!manager_source.contains("process::Command"));
    assert!(!manager_source.contains("nix::unistd::fork"));
    assert!(!manager_source.contains("nix::unistd::exec"));

    // Strictly forbidden shell execution
    assert!(!manager_source.contains("/bin/sh"));
    assert!(!manager_source.contains("/bin/bash"));
    assert!(!manager_source.contains("bash -c"));
    assert!(!manager_source.contains("sh -c"));

    // Strictly forbidden networking primitives
    assert!(!manager_source.contains("std::net"));
    assert!(!manager_source.contains("TcpStream"));
    assert!(!manager_source.contains("UdpSocket"));
    assert!(!manager_source.contains("reqwest"));
    assert!(!manager_source.contains("hyper"));

    // Strictly forbidden live IPC listeners
    assert!(!manager_source.contains("UnixListener"));
    assert!(!manager_source.contains("zbus"));

    // Strictly forbidden sandbox/LLM primitives
    assert!(!manager_source.contains("bubblewrap"));
    assert!(!manager_source.contains("bwrap"));
    assert!(!manager_source.contains("openai"));
    assert!(!manager_source.contains("gemini"));
    assert!(!manager_source.contains("anthropic"));
}
