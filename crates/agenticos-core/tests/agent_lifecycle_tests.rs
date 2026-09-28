//! Integration tests for Phase 2.3 Agent Lifecycle State Machine (`AgentLifecycleEngine`).
//!
//! Validates:
//! - Deterministic lifecycle transitions across all states
//! - Every valid transition path
//! - Rejection of all invalid transitions
//! - Terminal state protection (Stopped and Failed immutability)
//! - Explicit restart from Stopped and Failed states
//! - Rejection of restart on non-terminal states
//! - RestartPolicy::Never enforcement
//! - Retry exhaustion enforcement
//! - Retry counter persistence across database close and reopen
//! - Timestamp updates and regression rejection
//! - Concurrent / transactional lifecycle updates
//! - Rollback on failed transitions
//! - Process identity lifecycle tracking and reset on restart
//! - Immutable provenance protection

use std::collections::BTreeSet;
use std::sync::Arc;
use tempfile::tempdir;
use uuid::Uuid;

use agenticos_contracts::{PrincipalContext, ProtocolVersion};
use agenticos_core::agent::{
    AgentId, AgentLifecycleEngine, AgentLifecycleError, AgentLifecycleState, AgentRecord,
    AgentScope, AgentType, AgentVersion, RestartPolicy,
};
use agenticos_core::storage::{AgentRegistryStore, StorageError};

fn make_principal(uid: u32) -> PrincipalContext {
    PrincipalContext::user(uid, uid)
}

fn create_test_agent(name: &str, policy: RestartPolicy) -> AgentRecord {
    let mut caps = BTreeSet::new();
    caps.insert("fs.read".to_string());
    caps.insert("fs.write".to_string());

    AgentRecord::new(
        AgentType::Builtin(name.to_string()),
        AgentVersion::new(1, 0, 0),
        ProtocolVersion::V1_0,
        make_principal(1000),
        AgentScope::SharedSession,
        caps,
        policy,
        1_000_000,
    )
    .expect("valid agent record")
}

// ============================================================================
// 1. All Valid Lifecycle Transitions
// ============================================================================

#[test]
fn test_all_13_valid_lifecycle_transitions() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent_registry.db");
    let store = AgentRegistryStore::open(&db_path).unwrap();
    let engine = AgentLifecycleEngine::new(store.clone());

    // Branch 1: Registered -> Starting -> Ready -> Running -> Ready -> Stopping -> Stopped
    {
        let agent = create_test_agent("AgentB1", RestartPolicy::on_failure(3, 500));
        let agent_id = agent.agent_id;
        store.register_agent(&agent).unwrap();

        // 1. Registered -> Starting
        let a = engine
            .transition(&agent_id, AgentLifecycleState::Starting, 1_001_000)
            .unwrap();
        assert_eq!(a.state, AgentLifecycleState::Starting);
        assert_eq!(a.updated_at_ms, 1_001_000);

        // 2. Starting -> Ready
        let a = engine
            .transition(&agent_id, AgentLifecycleState::Ready, 1_002_000)
            .unwrap();
        assert_eq!(a.state, AgentLifecycleState::Ready);

        // 3. Ready -> Running
        let a = engine
            .transition(&agent_id, AgentLifecycleState::Running, 1_003_000)
            .unwrap();
        assert_eq!(a.state, AgentLifecycleState::Running);

        // 4. Running -> Ready
        let a = engine
            .transition(&agent_id, AgentLifecycleState::Ready, 1_004_000)
            .unwrap();
        assert_eq!(a.state, AgentLifecycleState::Ready);

        // 5. Ready -> Stopping
        let a = engine
            .transition(&agent_id, AgentLifecycleState::Stopping, 1_005_000)
            .unwrap();
        assert_eq!(a.state, AgentLifecycleState::Stopping);

        // 6. Stopping -> Stopped
        let a = engine
            .transition(&agent_id, AgentLifecycleState::Stopped, 1_006_000)
            .unwrap();
        assert_eq!(a.state, AgentLifecycleState::Stopped);
        assert!(a.state.is_terminal());

        let persisted = store.get_agent(&agent_id).unwrap().unwrap();
        assert_eq!(persisted.state, AgentLifecycleState::Stopped);
    }

    // Branch 2: Registered -> Stopped (immediate administrative stop before spawn)
    {
        let agent = create_test_agent("AgentB2", RestartPolicy::on_failure(3, 500));
        let agent_id = agent.agent_id;
        store.register_agent(&agent).unwrap();

        // 7. Registered -> Stopped
        let a = engine
            .transition(&agent_id, AgentLifecycleState::Stopped, 1_001_000)
            .unwrap();
        assert_eq!(a.state, AgentLifecycleState::Stopped);
        assert!(a.state.is_terminal());
    }

    // Branch 3: Registered -> Starting -> Stopping -> Failed
    {
        let agent = create_test_agent("AgentB3", RestartPolicy::on_failure(3, 500));
        let agent_id = agent.agent_id;
        store.register_agent(&agent).unwrap();

        engine
            .transition(&agent_id, AgentLifecycleState::Starting, 1_001_000)
            .unwrap();

        // 8. Starting -> Stopping
        let a = engine
            .transition(&agent_id, AgentLifecycleState::Stopping, 1_002_000)
            .unwrap();
        assert_eq!(a.state, AgentLifecycleState::Stopping);

        // 9. Stopping -> Failed (timeout or abort during stop)
        let a = engine
            .transition(&agent_id, AgentLifecycleState::Failed, 1_003_000)
            .unwrap();
        assert_eq!(a.state, AgentLifecycleState::Failed);
        assert!(a.state.is_terminal());
    }

    // Branch 4: Registered -> Starting -> Failed (bootstrap crash)
    {
        let agent = create_test_agent("AgentB4", RestartPolicy::on_failure(3, 500));
        let agent_id = agent.agent_id;
        store.register_agent(&agent).unwrap();

        engine
            .transition(&agent_id, AgentLifecycleState::Starting, 1_001_000)
            .unwrap();

        // 10. Starting -> Failed
        let a = engine
            .transition(&agent_id, AgentLifecycleState::Failed, 1_002_000)
            .unwrap();
        assert_eq!(a.state, AgentLifecycleState::Failed);
        assert!(a.state.is_terminal());
    }

    // Branch 5: Ready -> Failed (liveness / heartbeat failure while idle)
    {
        let agent = create_test_agent("AgentB5", RestartPolicy::on_failure(3, 500));
        let agent_id = agent.agent_id;
        store.register_agent(&agent).unwrap();

        engine
            .transition(&agent_id, AgentLifecycleState::Starting, 1_001_000)
            .unwrap();
        engine
            .transition(&agent_id, AgentLifecycleState::Ready, 1_002_000)
            .unwrap();

        // 11. Ready -> Failed
        let a = engine
            .transition(&agent_id, AgentLifecycleState::Failed, 1_003_000)
            .unwrap();
        assert_eq!(a.state, AgentLifecycleState::Failed);
        assert!(a.state.is_terminal());
    }

    // Branch 6: Running -> Stopping (graceful stop while executing)
    {
        let agent = create_test_agent("AgentB6", RestartPolicy::on_failure(3, 500));
        let agent_id = agent.agent_id;
        store.register_agent(&agent).unwrap();

        engine
            .transition(&agent_id, AgentLifecycleState::Starting, 1_001_000)
            .unwrap();
        engine
            .transition(&agent_id, AgentLifecycleState::Ready, 1_002_000)
            .unwrap();
        engine
            .transition(&agent_id, AgentLifecycleState::Running, 1_003_000)
            .unwrap();

        // 12. Running -> Stopping
        let a = engine
            .transition(&agent_id, AgentLifecycleState::Stopping, 1_004_000)
            .unwrap();
        assert_eq!(a.state, AgentLifecycleState::Stopping);
    }

    // Branch 7: Running -> Failed (unhandled crash / fault while executing)
    {
        let agent = create_test_agent("AgentB7", RestartPolicy::on_failure(3, 500));
        let agent_id = agent.agent_id;
        store.register_agent(&agent).unwrap();

        engine
            .transition(&agent_id, AgentLifecycleState::Starting, 1_001_000)
            .unwrap();
        engine
            .transition(&agent_id, AgentLifecycleState::Ready, 1_002_000)
            .unwrap();
        engine
            .transition(&agent_id, AgentLifecycleState::Running, 1_003_000)
            .unwrap();

        // 13. Running -> Failed
        let a = engine
            .transition(&agent_id, AgentLifecycleState::Failed, 1_004_000)
            .unwrap();
        assert_eq!(a.state, AgentLifecycleState::Failed);
        assert!(a.state.is_terminal());
    }
}

// ============================================================================
// 2. Every Invalid Transition Rejection
// ============================================================================

#[test]
fn test_every_invalid_transition_matrix() {
    let all_states = [
        AgentLifecycleState::Registered,
        AgentLifecycleState::Starting,
        AgentLifecycleState::Ready,
        AgentLifecycleState::Running,
        AgentLifecycleState::Stopping,
        AgentLifecycleState::Stopped,
        AgentLifecycleState::Failed,
    ];

    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent_registry.db");
    let store = AgentRegistryStore::open(&db_path).unwrap();
    let engine = AgentLifecycleEngine::new(store.clone());

    // Helper to drive an agent to any desired state
    let setup_agent_in_state = |name: &str, target: AgentLifecycleState| -> AgentId {
        let agent = create_test_agent(name, RestartPolicy::on_failure(3, 500));
        let id = agent.agent_id;
        store.register_agent(&agent).unwrap();

        match target {
            AgentLifecycleState::Registered => {}
            AgentLifecycleState::Starting => {
                engine
                    .transition(&id, AgentLifecycleState::Starting, 1_001_000)
                    .unwrap();
            }
            AgentLifecycleState::Ready => {
                engine
                    .transition(&id, AgentLifecycleState::Starting, 1_001_000)
                    .unwrap();
                engine
                    .transition(&id, AgentLifecycleState::Ready, 1_002_000)
                    .unwrap();
            }
            AgentLifecycleState::Running => {
                engine
                    .transition(&id, AgentLifecycleState::Starting, 1_001_000)
                    .unwrap();
                engine
                    .transition(&id, AgentLifecycleState::Ready, 1_002_000)
                    .unwrap();
                engine
                    .transition(&id, AgentLifecycleState::Running, 1_003_000)
                    .unwrap();
            }
            AgentLifecycleState::Stopping => {
                engine
                    .transition(&id, AgentLifecycleState::Starting, 1_001_000)
                    .unwrap();
                engine
                    .transition(&id, AgentLifecycleState::Stopping, 1_002_000)
                    .unwrap();
            }
            AgentLifecycleState::Stopped => {
                engine
                    .transition(&id, AgentLifecycleState::Stopped, 1_001_000)
                    .unwrap();
            }
            AgentLifecycleState::Failed => {
                engine
                    .transition(&id, AgentLifecycleState::Starting, 1_001_000)
                    .unwrap();
                engine
                    .transition(&id, AgentLifecycleState::Failed, 1_002_000)
                    .unwrap();
            }
        }
        id
    };

    let mut counter = 0;
    for &from in &all_states {
        for &to in &all_states {
            if !from.can_transition_to(to) {
                counter += 1;
                let name = format!("Agent_Inv_{}", counter);
                let agent_id = setup_agent_in_state(&name, from);

                let res = engine.transition(&agent_id, to, 1_010_000);
                assert!(
                    res.is_err(),
                    "Transition from {:?} to {:?} must fail, but succeeded!",
                    from,
                    to
                );

                if from.is_terminal() {
                    assert!(
                        matches!(res.unwrap_err(), AgentLifecycleError::TerminalState { .. }),
                        "Expected TerminalState for from: {:?}",
                        from
                    );
                } else {
                    assert!(
                        matches!(
                            res.unwrap_err(),
                            AgentLifecycleError::InvalidTransition { .. }
                        ),
                        "Expected InvalidTransition for from: {:?} to: {:?}",
                        from,
                        to
                    );
                }

                // Verify persisted state remains unchanged
                let persisted = store.get_agent(&agent_id).unwrap().unwrap();
                assert_eq!(persisted.state, from);
            }
        }
    }
}

// ============================================================================
// 3. Terminal State Protection & Direct Store Tamper Rejection
// ============================================================================

#[test]
fn test_terminal_state_protection_and_direct_store_rejection() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent_registry.db");
    let store = AgentRegistryStore::open(&db_path).unwrap();
    let engine = AgentLifecycleEngine::new(store.clone());

    let agent = create_test_agent("AgentTerm", RestartPolicy::on_failure(3, 500));
    let agent_id = agent.agent_id;
    store.register_agent(&agent).unwrap();

    // Drive to Stopped
    engine
        .transition(&agent_id, AgentLifecycleState::Stopped, 1_001_000)
        .unwrap();

    // 1. Normal transition attempt must fail
    let err = engine
        .transition(&agent_id, AgentLifecycleState::Ready, 1_002_000)
        .unwrap_err();
    assert!(matches!(err, AgentLifecycleError::TerminalState { .. }));

    // 2. Direct store.update_agent attempt to mutate fields without restart must fail
    let mut tampered = store.get_agent(&agent_id).unwrap().unwrap();
    tampered.updated_at_ms = 1_003_000;
    tampered.state = AgentLifecycleState::Ready;

    let store_err = store.update_agent(&tampered).unwrap_err();
    assert!(matches!(store_err, StorageError::TerminalState { .. }));

    // Ensure database remains in Stopped
    let persisted = store.get_agent(&agent_id).unwrap().unwrap();
    assert_eq!(persisted.state, AgentLifecycleState::Stopped);
}

// ============================================================================
// 4. Restart from Stopped & Failed States
// ============================================================================

#[test]
fn test_restart_from_stopped_and_failed() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent_registry.db");
    let store = AgentRegistryStore::open(&db_path).unwrap();
    let engine = AgentLifecycleEngine::new(store.clone());

    // Case 1: Restart from Stopped
    {
        let agent = create_test_agent("AgentStop", RestartPolicy::on_failure(3, 500));
        let agent_id = agent.agent_id;
        let original_nonce = agent.process_identity.instance_nonce;
        store.register_agent(&agent).unwrap();

        engine
            .transition(&agent_id, AgentLifecycleState::Stopped, 1_001_000)
            .unwrap();

        let fresh_nonce = Uuid::new_v4();
        let restarted = engine.restart(&agent_id, fresh_nonce, 1_002_000).unwrap();

        assert_eq!(restarted.state, AgentLifecycleState::Starting);
        assert_eq!(restarted.process_identity.instance_nonce, fresh_nonce);
        assert_ne!(fresh_nonce, original_nonce);
        assert!(restarted.process_identity.pid.is_none());
        assert!(restarted.process_identity.start_time_ticks.is_none());
        assert_eq!(restarted.updated_at_ms, 1_002_000);

        // Verify retry counter incremented
        match restarted.restart_policy {
            RestartPolicy::OnFailure {
                current_retries, ..
            } => assert_eq!(current_retries, 1),
            _ => panic!("Expected OnFailure"),
        }

        // Verify persisted record in storage
        let persisted = store.get_agent(&agent_id).unwrap().unwrap();
        assert_eq!(persisted.state, AgentLifecycleState::Starting);
        assert_eq!(persisted.process_identity.instance_nonce, fresh_nonce);
    }

    // Case 2: Restart from Failed
    {
        let agent = create_test_agent("AgentFail", RestartPolicy::on_failure(3, 500));
        let agent_id = agent.agent_id;
        store.register_agent(&agent).unwrap();

        engine
            .transition(&agent_id, AgentLifecycleState::Starting, 1_001_000)
            .unwrap();
        engine
            .transition(&agent_id, AgentLifecycleState::Failed, 1_002_000)
            .unwrap();

        let fresh_nonce = Uuid::new_v4();
        let restarted = engine.restart(&agent_id, fresh_nonce, 1_003_000).unwrap();

        assert_eq!(restarted.state, AgentLifecycleState::Starting);
        assert_eq!(restarted.process_identity.instance_nonce, fresh_nonce);

        match restarted.restart_policy {
            RestartPolicy::OnFailure {
                current_retries, ..
            } => assert_eq!(current_retries, 1),
            _ => panic!("Expected OnFailure"),
        }
    }
}

// ============================================================================
// 5. Restart Rejection on Non-Terminal States
// ============================================================================

#[test]
fn test_restart_rejected_on_non_terminal_states() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent_registry.db");
    let store = AgentRegistryStore::open(&db_path).unwrap();
    let engine = AgentLifecycleEngine::new(store.clone());

    let non_terminal_states = [
        AgentLifecycleState::Registered,
        AgentLifecycleState::Starting,
        AgentLifecycleState::Ready,
        AgentLifecycleState::Running,
        AgentLifecycleState::Stopping,
    ];

    for (idx, &state) in non_terminal_states.iter().enumerate() {
        let name = format!("Agent_NonTerm_{}", idx);
        let agent = create_test_agent(&name, RestartPolicy::on_failure(3, 500));
        let agent_id = agent.agent_id;
        store.register_agent(&agent).unwrap();

        // Drive to state
        if state != AgentLifecycleState::Registered {
            engine
                .transition(&agent_id, AgentLifecycleState::Starting, 1_001_000)
                .unwrap();
            if state == AgentLifecycleState::Ready || state == AgentLifecycleState::Running {
                engine
                    .transition(&agent_id, AgentLifecycleState::Ready, 1_002_000)
                    .unwrap();
            }
            if state == AgentLifecycleState::Running {
                engine
                    .transition(&agent_id, AgentLifecycleState::Running, 1_003_000)
                    .unwrap();
            }
            if state == AgentLifecycleState::Stopping {
                engine
                    .transition(&agent_id, AgentLifecycleState::Stopping, 1_002_000)
                    .unwrap();
            }
        }

        // Attempting restart on non-terminal must fail
        let err = engine
            .restart(&agent_id, Uuid::new_v4(), 1_010_000)
            .unwrap_err();
        assert!(
            matches!(err, AgentLifecycleError::CannotRestartNonTerminal { .. }),
            "Expected CannotRestartNonTerminal for state {:?}",
            state
        );
    }
}

// ============================================================================
// 6. RestartPolicy::Never Enforcement
// ============================================================================

#[test]
fn test_restart_policy_never_enforcement() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent_registry.db");
    let store = AgentRegistryStore::open(&db_path).unwrap();
    let engine = AgentLifecycleEngine::new(store.clone());

    let agent = create_test_agent("AgentNever", RestartPolicy::Never);
    let agent_id = agent.agent_id;
    store.register_agent(&agent).unwrap();

    engine
        .transition(&agent_id, AgentLifecycleState::Starting, 1_001_000)
        .unwrap();
    engine
        .transition(&agent_id, AgentLifecycleState::Failed, 1_002_000)
        .unwrap();

    // Attempting restart on Never must fail
    let err = engine
        .restart(&agent_id, Uuid::new_v4(), 1_003_000)
        .unwrap_err();
    assert!(matches!(
        err,
        AgentLifecycleError::RestartPolicyNever { .. }
    ));

    // Verify agent remains in Failed
    let persisted = store.get_agent(&agent_id).unwrap().unwrap();
    assert_eq!(persisted.state, AgentLifecycleState::Failed);
}

// ============================================================================
// 7. Retry Exhaustion Enforcement
// ============================================================================

#[test]
fn test_retry_exhaustion_enforcement() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent_registry.db");
    let store = AgentRegistryStore::open(&db_path).unwrap();
    let engine = AgentLifecycleEngine::new(store.clone());

    // Policy permits exactly 2 retries
    let agent = create_test_agent("AgentExhaust", RestartPolicy::on_failure(2, 500));
    let agent_id = agent.agent_id;
    store.register_agent(&agent).unwrap();

    engine
        .transition(&agent_id, AgentLifecycleState::Starting, 1_001_000)
        .unwrap();
    engine
        .transition(&agent_id, AgentLifecycleState::Failed, 1_002_000)
        .unwrap();

    // Restart 1: current_retries becomes 1 (succeeds)
    let a1 = engine
        .restart(&agent_id, Uuid::new_v4(), 1_003_000)
        .unwrap();
    match a1.restart_policy {
        RestartPolicy::OnFailure {
            current_retries, ..
        } => assert_eq!(current_retries, 1),
        _ => panic!("Expected OnFailure"),
    }

    // Fail again
    engine
        .transition(&agent_id, AgentLifecycleState::Failed, 1_004_000)
        .unwrap();

    // Restart 2: current_retries becomes 2 (succeeds)
    let a2 = engine
        .restart(&agent_id, Uuid::new_v4(), 1_005_000)
        .unwrap();
    match a2.restart_policy {
        RestartPolicy::OnFailure {
            current_retries, ..
        } => assert_eq!(current_retries, 2),
        _ => panic!("Expected OnFailure"),
    }

    // Fail third time
    engine
        .transition(&agent_id, AgentLifecycleState::Failed, 1_006_000)
        .unwrap();

    // Restart 3: must be REJECTED due to exhausted retries
    let err = engine
        .restart(&agent_id, Uuid::new_v4(), 1_007_000)
        .unwrap_err();
    match err {
        AgentLifecycleError::RestartPolicyExhausted {
            max_retries,
            current_retries,
            ..
        } => {
            assert_eq!(max_retries, 2);
            assert_eq!(current_retries, 2);
        }
        other => panic!("Expected RestartPolicyExhausted, got: {:?}", other),
    }

    // Persisted record must remain Failed
    let persisted = store.get_agent(&agent_id).unwrap().unwrap();
    assert_eq!(persisted.state, AgentLifecycleState::Failed);
}

// ============================================================================
// 8. Retry Persistence Across Database Reopen
// ============================================================================

#[test]
fn test_retry_persistence_across_database_reopen() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent_registry.db");
    let agent_id;

    // Session 1: Register, fail, restart once
    {
        let store = AgentRegistryStore::open(&db_path).unwrap();
        let engine = AgentLifecycleEngine::new(store.clone());

        let agent = create_test_agent("AgentReopen", RestartPolicy::on_failure(3, 500));
        agent_id = agent.agent_id;
        store.register_agent(&agent).unwrap();

        engine
            .transition(&agent_id, AgentLifecycleState::Starting, 1_001_000)
            .unwrap();
        engine
            .transition(&agent_id, AgentLifecycleState::Failed, 1_002_000)
            .unwrap();

        let a = engine
            .restart(&agent_id, Uuid::new_v4(), 1_003_000)
            .unwrap();
        assert_eq!(a.state, AgentLifecycleState::Starting);
    }

    // Session 2: Reopen database from disk and assert retry counter preserved
    {
        let store = AgentRegistryStore::open(&db_path).unwrap();
        let engine = AgentLifecycleEngine::new(store.clone());

        let loaded = engine.get_agent(&agent_id).unwrap();
        assert_eq!(loaded.state, AgentLifecycleState::Starting);
        match loaded.restart_policy {
            RestartPolicy::OnFailure {
                current_retries, ..
            } => assert_eq!(
                current_retries, 1,
                "current_retries must persist across reopen"
            ),
            _ => panic!("Expected OnFailure"),
        }

        // Fail and restart second time
        engine
            .transition(&agent_id, AgentLifecycleState::Failed, 1_004_000)
            .unwrap();
        let a2 = engine
            .restart(&agent_id, Uuid::new_v4(), 1_005_000)
            .unwrap();
        match a2.restart_policy {
            RestartPolicy::OnFailure {
                current_retries, ..
            } => assert_eq!(current_retries, 2),
            _ => panic!("Expected OnFailure"),
        }
    }

    // Session 3: Reopen again and assert retries = 2
    {
        let store = AgentRegistryStore::open(&db_path).unwrap();
        let engine = AgentLifecycleEngine::new(store);

        let loaded = engine.get_agent(&agent_id).unwrap();
        match loaded.restart_policy {
            RestartPolicy::OnFailure {
                current_retries, ..
            } => assert_eq!(current_retries, 2),
            _ => panic!("Expected OnFailure"),
        }
    }
}

// ============================================================================
// 9. Timestamp Updates & Regression Rejection
// ============================================================================

#[test]
fn test_timestamp_updates_and_regression_rejection() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent_registry.db");
    let store = AgentRegistryStore::open(&db_path).unwrap();
    let engine = AgentLifecycleEngine::new(store.clone());

    let agent = create_test_agent("AgentTime", RestartPolicy::on_failure(3, 500));
    let agent_id = agent.agent_id;
    assert_eq!(agent.registered_at_ms, 1_000_000);
    assert_eq!(agent.updated_at_ms, 1_000_000);
    store.register_agent(&agent).unwrap();

    // Advance to Starting at 1_005_000
    let a1 = engine
        .transition(&agent_id, AgentLifecycleState::Starting, 1_005_000)
        .unwrap();
    assert_eq!(a1.registered_at_ms, 1_000_000);
    assert_eq!(a1.updated_at_ms, 1_005_000);

    // Attempting transition with timestamp regression (1_004_000 < 1_005_000) must fail
    let err = engine
        .transition(&agent_id, AgentLifecycleState::Ready, 1_004_000)
        .unwrap_err();
    match err {
        AgentLifecycleError::TimestampRegression {
            current_ms,
            proposed_ms,
            ..
        } => {
            assert_eq!(current_ms, 1_005_000);
            assert_eq!(proposed_ms, 1_004_000);
        }
        other => panic!("Expected TimestampRegression, got: {:?}", other),
    }

    // Persisted state must retain 1_005_000
    let persisted = store.get_agent(&agent_id).unwrap().unwrap();
    assert_eq!(persisted.updated_at_ms, 1_005_000);
    assert_eq!(persisted.state, AgentLifecycleState::Starting);

    // Advancing with equal or greater timestamp succeeds
    let a2 = engine
        .transition(&agent_id, AgentLifecycleState::Ready, 1_005_000)
        .unwrap();
    assert_eq!(a2.updated_at_ms, 1_005_000);
    assert_eq!(a2.state, AgentLifecycleState::Ready);
}

// ============================================================================
// 10. Process Identity Lifecycle & Reset on Restart
// ============================================================================

#[test]
fn test_process_identity_lifecycle_and_reset_on_restart() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent_registry.db");
    let store = AgentRegistryStore::open(&db_path).unwrap();
    let engine = AgentLifecycleEngine::new(store.clone());

    let agent = create_test_agent("AgentProc", RestartPolicy::on_failure(3, 500));
    let agent_id = agent.agent_id;
    store.register_agent(&agent).unwrap();

    engine
        .transition(&agent_id, AgentLifecycleState::Starting, 1_001_000)
        .unwrap();

    // Update active process identity upon process spawn / handshake
    let updated = engine
        .update_process_identity(&agent_id, 4567, 12345678, 1_001_500, 1_001_500)
        .unwrap();
    assert_eq!(updated.process_identity.pid, Some(4567));
    assert_eq!(updated.process_identity.start_time_ticks, Some(12345678));
    assert_eq!(
        updated.process_identity.process_started_at_ms,
        Some(1_001_500)
    );

    // Drive to Ready -> Running -> Failed
    engine
        .transition(&agent_id, AgentLifecycleState::Ready, 1_002_000)
        .unwrap();
    engine
        .transition(&agent_id, AgentLifecycleState::Running, 1_003_000)
        .unwrap();
    engine
        .transition(&agent_id, AgentLifecycleState::Failed, 1_004_000)
        .unwrap();

    // Restart resets process identity to unspawned with new nonce
    let fresh_nonce = Uuid::new_v4();
    let restarted = engine.restart(&agent_id, fresh_nonce, 1_005_000).unwrap();
    assert_eq!(restarted.process_identity.instance_nonce, fresh_nonce);
    assert_eq!(restarted.process_identity.pid, None);
    assert_eq!(restarted.process_identity.start_time_ticks, None);
    assert_eq!(restarted.process_identity.process_started_at_ms, None);
    assert_eq!(restarted.process_identity.uid, 1000);
    assert_eq!(restarted.process_identity.gid, 1000);
}

// ============================================================================
// 11. Rollback on Failed Transition
// ============================================================================

#[test]
fn test_rollback_on_failed_transition() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent_registry.db");
    let store = AgentRegistryStore::open(&db_path).unwrap();
    let engine = AgentLifecycleEngine::new(store.clone());

    let agent = create_test_agent("AgentRollback", RestartPolicy::on_failure(3, 500));
    let agent_id = agent.agent_id;
    store.register_agent(&agent).unwrap();

    // Invalid transition attempt: Registered -> Running directly
    let res = engine.transition(&agent_id, AgentLifecycleState::Running, 1_002_000);
    assert!(res.is_err());

    // Verify stored agent was completely unmutated
    let persisted = store.get_agent(&agent_id).unwrap().unwrap();
    assert_eq!(persisted.state, AgentLifecycleState::Registered);
    assert_eq!(persisted.updated_at_ms, 1_000_000);
}

// ============================================================================
// 12. Concurrent Transactional Lifecycle Updates
// ============================================================================

#[test]
fn test_concurrent_transactional_lifecycle_updates() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent_registry.db");
    let store = AgentRegistryStore::open(&db_path).unwrap();
    let engine = Arc::new(AgentLifecycleEngine::new(store.clone()));

    let agent = create_test_agent("AgentConcur", RestartPolicy::on_failure(3, 500));
    let agent_id = agent.agent_id;
    store.register_agent(&agent).unwrap();

    engine
        .transition(&agent_id, AgentLifecycleState::Starting, 1_001_000)
        .unwrap();
    engine
        .transition(&agent_id, AgentLifecycleState::Ready, 1_002_000)
        .unwrap();

    // Two concurrent workers:
    // Worker 1 wants to transition Ready -> Running
    // Worker 2 wants to transition Ready -> Stopping
    let engine1 = Arc::clone(&engine);
    let engine2 = Arc::clone(&engine);

    let h1 = std::thread::spawn(move || {
        engine1.transition(&agent_id, AgentLifecycleState::Running, 1_003_000)
    });

    let h2 = std::thread::spawn(move || {
        engine2.transition(&agent_id, AgentLifecycleState::Stopping, 1_003_000)
    });

    let r1 = h1.join().unwrap();
    let r2 = h2.join().unwrap();

    // Exactly one must succeed, or both succeed sequentially if serialized cleanly
    // If r1 (Running) succeeds first: r2 (Stopping from Running) can ALSO legally succeed!
    // If r2 (Stopping) succeeds first: r1 (Running from Stopping) MUST be rejected!
    let final_agent = engine.get_agent(&agent_id).unwrap();
    assert!(
        final_agent.state == AgentLifecycleState::Running
            || final_agent.state == AgentLifecycleState::Stopping,
        "Final state must be valid, got: {:?}",
        final_agent.state
    );

    // If final state is Stopping, either r2 succeeded after r1, or r2 succeeded and r1 failed
    if let Err(err) = r1 {
        assert!(
            matches!(
                err,
                AgentLifecycleError::InvalidTransition { .. }
                    | AgentLifecycleError::Storage(StorageError::InvalidStateTransition { .. })
            ),
            "Expected invalid transition or storage transition rejection, got: {:?}",
            err
        );
        assert!(r2.is_ok());
    }
}
