//! Integration and domain tests for Phase 2.1 — Agent Contracts & Domain Model.
//!
//! Validates:
//! - Serialization/Deserialization roundtrips
//! - `deny_unknown_fields` enforcement
//! - Valid and invalid agent lifecycle transitions
//! - Terminal state immutability and restart policy enforcement
//! - Valid and invalid work assignment status transitions
//! - `AgentScope` authorization rules
//! - `ProcessIdentity` instance disambiguation semantics
//! - `WorkAssignment` causal lineage and contract preservation
//! - Rejection of invalid/empty domain values (null bytes, empty strings, zero timeouts)

use std::collections::BTreeSet;
use uuid::Uuid;

use agenticos_contracts::{PrincipalContext, ProtocolVersion, ResourceRef};
use agenticos_core::agent::{
    AgentHealthState, AgentId, AgentLifecycleState, AgentRecord, AgentResourceMetrics, AgentScope,
    AgentType, AgentVersion, AssignmentStatus, HeartbeatRecord, ProcessIdentity, RestartPolicy,
    WorkAssignment,
};
use agenticos_core::error::DomainError;

// ---------------------------------------------------------------------------
// Test Helpers
// ---------------------------------------------------------------------------

fn make_principal(uid: u32) -> PrincipalContext {
    PrincipalContext::user(uid, uid)
}

fn make_valid_capabilities() -> BTreeSet<String> {
    let mut caps = BTreeSet::new();
    caps.insert("fs.create_directory".to_string());
    caps.insert("fs.read_file".to_string());
    caps
}

fn make_valid_agent() -> AgentRecord {
    AgentRecord::new(
        AgentType::Builtin("FileAgent".to_string()),
        AgentVersion::new(1, 0, 0),
        ProtocolVersion::V1_0,
        make_principal(1000),
        AgentScope::SharedSession,
        make_valid_capabilities(),
        RestartPolicy::on_failure(3, 500),
        1_000_000,
    )
    .expect("valid agent record creation should succeed")
}

fn make_valid_assignment(agent_id: AgentId) -> WorkAssignment {
    WorkAssignment::new(
        Uuid::new_v4(), // correlation_id
        Uuid::new_v4(), // request_id
        make_principal(1000),
        Uuid::new_v4(), // workflow_id
        Uuid::new_v4(), // step_id
        agent_id,
        "fs.create_directory",
        serde_json::json!({ "path": "/tmp/test" }),
        ResourceRef::path("/tmp/test"),
        1_000_000,
        10_000,
    )
    .expect("valid work assignment creation should succeed")
}

// ===========================================================================
// 1. Serialization / Deserialization Roundtrip Tests
// ===========================================================================

#[test]
fn test_agent_record_serde_roundtrip() {
    let agent = make_valid_agent();
    let json = serde_json::to_string_pretty(&agent).expect("serialization should succeed");
    let recovered: AgentRecord =
        serde_json::from_str(&json).expect("deserialization should succeed");
    assert_eq!(agent, recovered);
}

#[test]
fn test_work_assignment_serde_roundtrip() {
    let agent = make_valid_agent();
    let assignment = make_valid_assignment(agent.agent_id);
    let json = serde_json::to_string_pretty(&assignment).expect("serialization should succeed");
    let recovered: WorkAssignment =
        serde_json::from_str(&json).expect("deserialization should succeed");
    assert_eq!(assignment, recovered);
}

#[test]
fn test_heartbeat_record_serde_roundtrip() {
    let heartbeat = HeartbeatRecord::new(
        AgentId::new(),
        Uuid::new_v4(),
        1_500_000,
        42,
        AgentResourceMetrics::new(150, 1024 * 1024 * 64, 18),
    );
    let json = serde_json::to_string(&heartbeat).expect("serialization should succeed");
    let recovered: HeartbeatRecord =
        serde_json::from_str(&json).expect("deserialization should succeed");
    assert_eq!(heartbeat, recovered);
}

#[test]
fn test_restart_policy_variants_serde_roundtrip() {
    let policies = vec![
        RestartPolicy::Never,
        RestartPolicy::on_failure(5, 1000),
        RestartPolicy::always(10, 2000),
    ];

    for policy in policies {
        let json = serde_json::to_string(&policy).expect("serialization should succeed");
        let recovered: RestartPolicy =
            serde_json::from_str(&json).expect("deserialization should succeed");
        assert_eq!(policy, recovered);
    }
}

#[test]
fn test_agent_health_state_variants_serde_roundtrip() {
    let states = vec![
        AgentHealthState::Healthy,
        AgentHealthState::Degraded {
            reason: "High memory utilization".to_string(),
        },
        AgentHealthState::Unhealthy {
            reason: "Heartbeat missed deadline".to_string(),
        },
        AgentHealthState::Unknown,
    ];

    for state in states {
        let json = serde_json::to_string(&state).expect("serialization should succeed");
        let recovered: AgentHealthState =
            serde_json::from_str(&json).expect("deserialization should succeed");
        assert_eq!(state, recovered);
    }
}

// ===========================================================================
// 2. Deny Unknown Fields Tests (ADR-0007 / Contract Strictness)
// ===========================================================================

#[test]
fn test_agent_record_rejects_unknown_fields() {
    let agent = make_valid_agent();
    let mut val = serde_json::to_value(&agent).unwrap();
    val.as_object_mut()
        .unwrap()
        .insert("unrecognized_field".to_string(), serde_json::json!(123));

    let err = serde_json::from_value::<AgentRecord>(val);
    assert!(err.is_err(), "AgentRecord must reject unknown fields");
}

#[test]
fn test_work_assignment_rejects_unknown_fields() {
    let assignment = make_valid_assignment(AgentId::new());
    let mut val = serde_json::to_value(&assignment).unwrap();
    val.as_object_mut().unwrap().insert(
        "rogue_capability_grant".to_string(),
        serde_json::json!("sudo"),
    );

    let err = serde_json::from_value::<WorkAssignment>(val);
    assert!(err.is_err(), "WorkAssignment must reject unknown fields");
}

#[test]
fn test_process_identity_rejects_unknown_fields() {
    let identity = ProcessIdentity::unspawned(1000, 1000);
    let mut val = serde_json::to_value(&identity).unwrap();
    val.as_object_mut()
        .unwrap()
        .insert("kernel_privilege".to_string(), serde_json::json!("root"));

    let err = serde_json::from_value::<ProcessIdentity>(val);
    assert!(err.is_err(), "ProcessIdentity must reject unknown fields");
}

#[test]
fn test_restart_policy_rejects_unknown_fields() {
    let json =
        r#"{"OnFailure":{"max_retries":3,"current_retries":0,"backoff_ms":500,"extra":true}}"#;
    let err = serde_json::from_str::<RestartPolicy>(json);
    assert!(err.is_err(), "RestartPolicy must reject unknown fields");
}

// ===========================================================================
// 3. Agent Lifecycle State Machine Tests
// ===========================================================================

#[test]
fn test_agent_lifecycle_valid_transitions() {
    // Registered -> Starting -> Ready -> Running -> Ready -> Stopping -> Stopped
    let mut state = AgentLifecycleState::Registered;
    assert!(state.can_transition_to(AgentLifecycleState::Starting));
    state.transition_to(AgentLifecycleState::Starting).unwrap();

    assert!(state.can_transition_to(AgentLifecycleState::Ready));
    state.transition_to(AgentLifecycleState::Ready).unwrap();

    assert!(state.can_transition_to(AgentLifecycleState::Running));
    state.transition_to(AgentLifecycleState::Running).unwrap();

    assert!(state.can_transition_to(AgentLifecycleState::Ready));
    state.transition_to(AgentLifecycleState::Ready).unwrap();

    assert!(state.can_transition_to(AgentLifecycleState::Stopping));
    state.transition_to(AgentLifecycleState::Stopping).unwrap();

    assert!(state.can_transition_to(AgentLifecycleState::Stopped));
    state.transition_to(AgentLifecycleState::Stopped).unwrap();

    assert!(state.is_terminal());
}

#[test]
fn test_agent_lifecycle_direct_failure_paths() {
    // Starting -> Failed
    let mut s1 = AgentLifecycleState::Starting;
    s1.transition_to(AgentLifecycleState::Failed).unwrap();
    assert!(s1.is_terminal());

    // Ready -> Failed
    let mut s2 = AgentLifecycleState::Ready;
    s2.transition_to(AgentLifecycleState::Failed).unwrap();
    assert!(s2.is_terminal());

    // Running -> Failed
    let mut s3 = AgentLifecycleState::Running;
    s3.transition_to(AgentLifecycleState::Failed).unwrap();
    assert!(s3.is_terminal());

    // Stopping -> Failed
    let mut s4 = AgentLifecycleState::Stopping;
    s4.transition_to(AgentLifecycleState::Failed).unwrap();
    assert!(s4.is_terminal());
}

#[test]
fn test_agent_lifecycle_invalid_transitions_rejected() {
    // Registered cannot skip to Ready or Running
    let mut s = AgentLifecycleState::Registered;
    assert!(!s.can_transition_to(AgentLifecycleState::Ready));
    assert!(!s.can_transition_to(AgentLifecycleState::Running));
    assert!(matches!(
        s.transition_to(AgentLifecycleState::Ready),
        Err(DomainError::InvalidStateTransition { .. })
    ));

    // Starting cannot skip to Running (must become Ready first)
    let mut s2 = AgentLifecycleState::Starting;
    assert!(!s2.can_transition_to(AgentLifecycleState::Running));
    assert!(matches!(
        s2.transition_to(AgentLifecycleState::Running),
        Err(DomainError::InvalidStateTransition { .. })
    ));

    // Ready cannot jump backwards to Starting or Registered
    let mut s3 = AgentLifecycleState::Ready;
    assert!(!s3.can_transition_to(AgentLifecycleState::Starting));
    assert!(!s3.can_transition_to(AgentLifecycleState::Registered));
    assert!(matches!(
        s3.transition_to(AgentLifecycleState::Starting),
        Err(DomainError::InvalidStateTransition { .. })
    ));
}

#[test]
fn test_agent_terminal_state_immutability() {
    let mut stopped = AgentLifecycleState::Stopped;
    assert!(stopped.is_terminal());
    assert!(!stopped.can_transition_to(AgentLifecycleState::Starting));
    assert!(!stopped.can_transition_to(AgentLifecycleState::Ready));
    assert!(matches!(
        stopped.transition_to(AgentLifecycleState::Starting),
        Err(DomainError::TerminalState { .. })
    ));

    let mut failed = AgentLifecycleState::Failed;
    assert!(failed.is_terminal());
    assert!(!failed.can_transition_to(AgentLifecycleState::Starting));
    assert!(matches!(
        failed.transition_to(AgentLifecycleState::Ready),
        Err(DomainError::TerminalState { .. })
    ));
}

#[test]
fn test_agent_restart_rearms_terminal_agent() {
    let mut agent = make_valid_agent();

    // Advance to terminal Stopped
    agent
        .transition(AgentLifecycleState::Starting, 1_001_000)
        .unwrap();
    agent
        .transition(AgentLifecycleState::Stopping, 1_002_000)
        .unwrap();
    agent
        .transition(AgentLifecycleState::Stopped, 1_003_000)
        .unwrap();
    assert!(agent.state.is_terminal());

    // Restart re-arms to Starting with fresh nonce and increments retry counter
    let new_nonce = Uuid::new_v4();
    agent.restart(new_nonce, 1_004_000).unwrap();

    assert_eq!(agent.state, AgentLifecycleState::Starting);
    assert_eq!(agent.process_identity.instance_nonce, new_nonce);
    assert_eq!(agent.updated_at_ms, 1_004_000);
    assert_eq!(agent.process_identity.pid, None);
    assert!(!agent.process_identity.is_spawned());

    // Verify retry counter incremented
    match agent.restart_policy {
        RestartPolicy::OnFailure {
            current_retries, ..
        } => {
            assert_eq!(current_retries, 1);
        }
        _ => panic!("Expected OnFailure policy"),
    }
}

#[test]
fn test_agent_restart_rejected_on_non_terminal() {
    let mut agent = make_valid_agent();
    assert_eq!(agent.state, AgentLifecycleState::Registered);

    let err = agent.restart(Uuid::new_v4(), 2_000_000);
    assert!(matches!(err, Err(DomainError::InvalidAgentRecord { .. })));
}

#[test]
fn test_agent_restart_rejected_when_policy_exhausted() {
    let mut agent = AgentRecord::new(
        AgentType::Builtin("WorkerAgent".to_string()),
        AgentVersion::new(1, 0, 0),
        ProtocolVersion::V1_0,
        make_principal(1000),
        AgentScope::SharedSession,
        make_valid_capabilities(),
        RestartPolicy::on_failure(1, 100), // only 1 retry allowed
        1_000_000,
    )
    .unwrap();

    agent
        .transition(AgentLifecycleState::Starting, 1_001_000)
        .unwrap();
    agent
        .transition(AgentLifecycleState::Failed, 1_002_000)
        .unwrap();

    // First restart succeeds (current_retries becomes 1)
    agent.restart(Uuid::new_v4(), 1_003_000).unwrap();

    // Drive back to Failed
    agent
        .transition(AgentLifecycleState::Failed, 1_004_000)
        .unwrap();

    // Second restart must fail due to exhausted policy
    let err = agent.restart(Uuid::new_v4(), 1_005_000);
    assert!(matches!(err, Err(DomainError::RestartExhausted { .. })));
}

// ===========================================================================
// 4. Work Assignment Lifecycle Tests
// ===========================================================================

#[test]
fn test_work_assignment_valid_lifecycle() {
    let agent_id = AgentId::new();
    let mut assignment = make_valid_assignment(agent_id);

    assert_eq!(assignment.status, AssignmentStatus::Assigned);
    assert!(!assignment.status.is_terminal());

    // Assigned -> InProgress
    assignment
        .transition(AssignmentStatus::InProgress, 1_001_000)
        .unwrap();
    assert_eq!(assignment.status, AssignmentStatus::InProgress);
    assert_eq!(assignment.updated_at_ms, 1_001_000);

    // InProgress -> Completed
    assignment
        .transition(AssignmentStatus::Completed, 1_002_000)
        .unwrap();
    assert_eq!(assignment.status, AssignmentStatus::Completed);
    assert!(assignment.status.is_terminal());
}

#[test]
fn test_work_assignment_cancellation_and_failure() {
    // Assigned -> Cancelled
    let mut a1 = make_valid_assignment(AgentId::new());
    a1.transition(AssignmentStatus::Cancelled, 1_001_000)
        .unwrap();
    assert!(a1.status.is_terminal());

    // Assigned -> Failed
    let mut a2 = make_valid_assignment(AgentId::new());
    a2.transition(AssignmentStatus::Failed, 1_001_000).unwrap();
    assert!(a2.status.is_terminal());

    // InProgress -> Failed
    let mut a3 = make_valid_assignment(AgentId::new());
    a3.transition(AssignmentStatus::InProgress, 1_001_000)
        .unwrap();
    a3.transition(AssignmentStatus::Failed, 1_002_000).unwrap();
    assert!(a3.status.is_terminal());

    // InProgress -> Cancelled
    let mut a4 = make_valid_assignment(AgentId::new());
    a4.transition(AssignmentStatus::InProgress, 1_001_000)
        .unwrap();
    a4.transition(AssignmentStatus::Cancelled, 1_002_000)
        .unwrap();
    assert!(a4.status.is_terminal());
}

#[test]
fn test_work_assignment_invalid_transitions_rejected() {
    let mut assignment = make_valid_assignment(AgentId::new());

    // Cannot skip directly from Assigned to Completed
    assert!(!assignment
        .status
        .can_transition_to(AssignmentStatus::Completed));
    assert!(matches!(
        assignment.transition(AssignmentStatus::Completed, 1_001_000),
        Err(DomainError::InvalidStateTransition { .. })
    ));

    // Transition to terminal Completed
    assignment
        .transition(AssignmentStatus::InProgress, 1_001_000)
        .unwrap();
    assignment
        .transition(AssignmentStatus::Completed, 1_002_000)
        .unwrap();

    // Terminal states cannot be mutated
    assert!(matches!(
        assignment.transition(AssignmentStatus::InProgress, 1_003_000),
        Err(DomainError::TerminalState { .. })
    ));
}

// ===========================================================================
// 5. AgentScope Semantics Tests
// ===========================================================================

#[test]
fn test_agent_scope_private_authorization() {
    let owner = make_principal(1000);
    let scope = AgentScope::Private(owner.clone());

    let same_user = make_principal(1000);
    let other_user = make_principal(2000);

    assert!(
        scope.authorizes(&same_user),
        "Private scope must authorize exact owner match"
    );
    assert!(
        !scope.authorizes(&other_user),
        "Private scope must reject different principal"
    );
}

#[test]
fn test_agent_scope_shared_session_authorization() {
    let scope = AgentScope::SharedSession;
    let user_a = make_principal(1000);
    let user_b = make_principal(1001);

    assert!(scope.authorizes(&user_a));
    assert!(scope.authorizes(&user_b));
}

#[test]
fn test_agent_scope_system_wide_authorization() {
    let scope = AgentScope::SystemWide;
    let any_principal = make_principal(5000);

    assert!(scope.authorizes(&any_principal));
}

// ===========================================================================
// 6. ProcessIdentity Semantics Tests
// ===========================================================================

#[test]
fn test_process_identity_unspawned_vs_active() {
    let unspawned = ProcessIdentity::unspawned(1000, 1000);
    assert!(!unspawned.is_spawned());
    assert_eq!(unspawned.pid, None);
    assert_eq!(unspawned.start_time_ticks, None);

    let active = ProcessIdentity::active(
        12345,
        987654321,
        unspawned.instance_nonce,
        1000,
        1000,
        1_000_500,
    );
    assert!(active.is_spawned());
    assert_eq!(active.pid, Some(12345));
    assert_eq!(active.start_time_ticks, Some(987654321));
    assert_eq!(active.instance_nonce, unspawned.instance_nonce);
}

#[test]
fn test_process_identity_nonce_uniqueness() {
    let id1 = ProcessIdentity::unspawned(1000, 1000);
    let id2 = ProcessIdentity::unspawned(1000, 1000);

    assert_ne!(
        id1.instance_nonce, id2.instance_nonce,
        "Each ProcessIdentity instance must have a unique instance_nonce"
    );
}

// ===========================================================================
// 7. WorkAssignment Lineage & Immutability Tests
// ===========================================================================

#[test]
fn test_work_assignment_preserves_causal_lineage() {
    let correlation_id = Uuid::new_v4();
    let request_id = Uuid::new_v4();
    let principal = make_principal(1000);
    let workflow_id = Uuid::new_v4();
    let step_id = Uuid::new_v4();
    let agent_id = AgentId::new();

    let assignment = WorkAssignment::new(
        correlation_id,
        request_id,
        principal.clone(),
        workflow_id,
        step_id,
        agent_id,
        "fs.create_directory",
        serde_json::json!({ "path": "/home/user/project" }),
        ResourceRef::path("/home/user/project"),
        1_234_567,
        30_000,
    )
    .unwrap();

    assert_eq!(assignment.correlation_id, correlation_id);
    assert_eq!(assignment.request_id, request_id);
    assert_eq!(assignment.originating_principal, principal);
    assert_eq!(assignment.workflow_id, workflow_id);
    assert_eq!(assignment.step_id, step_id);
    assert_eq!(assignment.agent_id, agent_id);
    assert_eq!(assignment.capability_id, "fs.create_directory");
    assert_eq!(assignment.timeout_duration_ms, 30_000);
}

// ===========================================================================
// 8. Rejection of Invalid / Malformed Domain Values
// ===========================================================================

#[test]
fn test_agent_record_rejects_empty_capabilities() {
    let empty_caps = BTreeSet::new();
    let err = AgentRecord::new(
        AgentType::Builtin("FileAgent".to_string()),
        AgentVersion::new(1, 0, 0),
        ProtocolVersion::V1_0,
        make_principal(1000),
        AgentScope::SharedSession,
        empty_caps,
        RestartPolicy::Never,
        1_000_000,
    );

    assert!(matches!(err, Err(DomainError::InvalidAgentRecord { .. })));
}

#[test]
fn test_agent_record_rejects_empty_capability_name() {
    let mut caps = BTreeSet::new();
    caps.insert("   ".to_string()); // empty/whitespace
    let err = AgentRecord::new(
        AgentType::Builtin("FileAgent".to_string()),
        AgentVersion::new(1, 0, 0),
        ProtocolVersion::V1_0,
        make_principal(1000),
        AgentScope::SharedSession,
        caps,
        RestartPolicy::Never,
        1_000_000,
    );

    assert!(matches!(err, Err(DomainError::InvalidAgentRecord { .. })));
}

#[test]
fn test_agent_record_rejects_null_bytes_in_capability_name() {
    let mut caps = BTreeSet::new();
    caps.insert("fs.create\0directory".to_string());
    let err = AgentRecord::new(
        AgentType::Builtin("FileAgent".to_string()),
        AgentVersion::new(1, 0, 0),
        ProtocolVersion::V1_0,
        make_principal(1000),
        AgentScope::SharedSession,
        caps,
        RestartPolicy::Never,
        1_000_000,
    );

    assert!(matches!(err, Err(DomainError::InvalidAgentRecord { .. })));
}

#[test]
fn test_agent_type_rejects_invalid_values() {
    assert!(matches!(
        AgentType::Builtin("".to_string()).validate(),
        Err(DomainError::InvalidAgentRecord { .. })
    ));

    assert!(matches!(
        AgentType::Custom("invalid\0name".to_string()).validate(),
        Err(DomainError::InvalidAgentRecord { .. })
    ));

    let oversized = "a".repeat(300);
    assert!(matches!(
        AgentType::Builtin(oversized).validate(),
        Err(DomainError::InvalidAgentRecord { .. })
    ));
}

#[test]
fn test_work_assignment_rejects_invalid_capability_or_timeout() {
    // Empty capability
    let err1 = WorkAssignment::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        make_principal(1000),
        Uuid::new_v4(),
        Uuid::new_v4(),
        AgentId::new(),
        "",
        serde_json::json!({}),
        ResourceRef::path("/path"),
        1_000_000,
        10_000,
    );
    assert!(matches!(
        err1,
        Err(DomainError::InvalidWorkAssignment { .. })
    ));

    // Null byte in capability
    let err2 = WorkAssignment::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        make_principal(1000),
        Uuid::new_v4(),
        Uuid::new_v4(),
        AgentId::new(),
        "fs.create\0dir",
        serde_json::json!({}),
        ResourceRef::path("/path"),
        1_000_000,
        10_000,
    );
    assert!(matches!(
        err2,
        Err(DomainError::InvalidWorkAssignment { .. })
    ));

    // Zero timeout duration
    let err3 = WorkAssignment::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        make_principal(1000),
        Uuid::new_v4(),
        Uuid::new_v4(),
        AgentId::new(),
        "fs.create_directory",
        serde_json::json!({}),
        ResourceRef::path("/path"),
        1_000_000,
        0, // invalid zero timeout
    );
    assert!(matches!(
        err3,
        Err(DomainError::InvalidWorkAssignment { .. })
    ));
}
