//! Integration and unit tests for Phase 2.2 Persistent Agent Registry (`agent_registry.db`).

use std::collections::BTreeSet;
use uuid::Uuid;

use agenticos_contracts::{PrincipalContext, ProtocolVersion, ResourceRef};
use agenticos_core::agent::{
    AgentId, AgentLifecycleState, AgentRecord, AgentResourceMetrics, AgentScope, AgentType,
    AgentVersion, AssignmentStatus, HeartbeatRecord, RestartPolicy, WorkAssignment,
};
use agenticos_core::storage::{AgentRegistryStore, StorageError};
use rusqlite::Connection;
use tempfile::tempdir;

fn make_principal(uid: u32) -> PrincipalContext {
    PrincipalContext::user(uid, uid)
}

fn make_agent(name: &str, capabilities: Vec<&str>) -> AgentRecord {
    let mut caps = BTreeSet::new();
    for c in capabilities {
        caps.insert(c.to_string());
    }

    AgentRecord::new(
        AgentType::Builtin(name.to_string()),
        AgentVersion::new(1, 0, 0),
        ProtocolVersion::V1_0,
        make_principal(1000),
        AgentScope::SharedSession,
        caps,
        RestartPolicy::on_failure(3, 500),
        1_000_000,
    )
    .expect("agent creation should succeed")
}

fn make_assignment(agent_id: AgentId, cap: &str) -> WorkAssignment {
    WorkAssignment::new(
        Uuid::new_v4(), // correlation_id
        Uuid::new_v4(), // request_id
        make_principal(1000),
        Uuid::new_v4(), // workflow_id
        Uuid::new_v4(), // step_id
        agent_id,
        cap,
        serde_json::json!({"path": "/tmp/test.txt"}),
        ResourceRef::new("file", "/tmp/test.txt"),
        1_000_000,
        30_000,
    )
    .expect("assignment creation should succeed")
}

#[test]
fn test_open_and_migrations_idempotence() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent_registry.db");

    // Open first time - creates schema
    {
        let _store = AgentRegistryStore::open(&db_path).expect("open failed");

        let conn = Connection::open(&db_path).unwrap();
        let user_version: u32 = conn
            .query_row("PRAGMA user_version;", [], |row| row.get(0))
            .unwrap();
        assert_eq!(user_version, 1);

        let migration_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version = 1;",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(migration_count, 1);
    }

    // Open second time - idempotent migrations
    {
        let _store = AgentRegistryStore::open(&db_path).expect("reopen failed");

        let conn = Connection::open(&db_path).unwrap();
        let user_version: u32 = conn
            .query_row("PRAGMA user_version;", [], |row| row.get(0))
            .unwrap();
        assert_eq!(user_version, 1);

        let migration_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version = 1;",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(migration_count, 1);
    }
}

#[test]
fn test_agent_registration_crud_and_reopen_persistence() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent_registry.db");

    let agent = make_agent("FileAgent", vec!["fs.read", "fs.write"]);
    let agent_id = agent.agent_id;

    // Register agent
    {
        let store = AgentRegistryStore::open(&db_path).unwrap();
        store.register_agent(&agent).expect("register failed");

        // Verify retrieval
        let loaded = store
            .get_agent(&agent_id)
            .unwrap()
            .expect("agent not found");
        assert_eq!(loaded.agent_id, agent_id);
        assert_eq!(loaded.agent_type.as_str(), "FileAgent");
        assert_eq!(loaded.declared_capabilities, agent.declared_capabilities);
        assert_eq!(loaded.state, AgentLifecycleState::Registered);

        // Verify capabilities list
        let caps = store.list_capabilities_for_agent(&agent_id).unwrap();
        assert_eq!(caps.len(), 2);
        assert!(caps.contains("fs.read"));
        assert!(caps.contains("fs.write"));
    }

    // Reopen database and verify persistence
    {
        let store = AgentRegistryStore::open(&db_path).unwrap();
        let loaded = store
            .get_agent(&agent_id)
            .unwrap()
            .expect("agent not found");
        assert_eq!(loaded.agent_id, agent_id);
        assert_eq!(loaded.declared_capabilities, agent.declared_capabilities);

        let list = store.list_agents().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].agent_id, agent_id);
    }
}

#[test]
fn test_duplicate_agent_id_rejected() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent_registry.db");
    let store = AgentRegistryStore::open(&db_path).unwrap();

    let agent1 = make_agent("Agent1", vec!["cap1"]);
    store.register_agent(&agent1).unwrap();

    // Create another agent with same AgentId but different nonce
    let mut agent2 = make_agent("Agent2", vec!["cap2"]);
    agent2.agent_id = agent1.agent_id;

    let result = store.register_agent(&agent2);
    assert!(result.is_err());
    match result.unwrap_err() {
        StorageError::DuplicateKey { entity, key } => {
            assert_eq!(entity, "Agent");
            assert_eq!(key, agent1.agent_id.to_string());
        }
        err => panic!("Unexpected error: {:?}", err),
    }
}

#[test]
fn test_duplicate_active_instance_nonce_rejected() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent_registry.db");
    let store = AgentRegistryStore::open(&db_path).unwrap();

    let agent1 = make_agent("Agent1", vec!["cap1"]);
    store.register_agent(&agent1).unwrap();

    // Create agent 2 with distinct agent_id, but same instance_nonce
    let mut agent2 = make_agent("Agent2", vec!["cap2"]);
    agent2.process_identity = agent1.process_identity.clone();

    let result = store.register_agent(&agent2);
    assert!(result.is_err());
    match result.unwrap_err() {
        StorageError::DuplicateKey { entity, key } => {
            assert_eq!(entity, "AgentInstanceNonce");
            assert_eq!(key, agent1.process_identity.instance_nonce.to_string());
        }
        err => panic!("Unexpected error: {:?}", err),
    }
}

#[test]
fn test_agent_update_lifecycle_and_terminal_protection() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent_registry.db");
    let store = AgentRegistryStore::open(&db_path).unwrap();

    let mut agent = make_agent("Worker", vec!["exec"]);
    store.register_agent(&agent).unwrap();

    // Transition Registered -> Starting -> Ready
    agent
        .transition(AgentLifecycleState::Starting, 1_001_000)
        .unwrap();
    store.update_agent(&agent).expect("update Starting failed");

    agent
        .transition(AgentLifecycleState::Ready, 1_002_000)
        .unwrap();
    store.update_agent(&agent).expect("update Ready failed");

    // Transition Ready -> Running
    agent
        .transition(AgentLifecycleState::Running, 1_003_000)
        .unwrap();
    store.update_agent(&agent).expect("update Running failed");

    // Transition Running -> Stopping -> Stopped (terminal)
    agent
        .transition(AgentLifecycleState::Stopping, 1_004_000)
        .unwrap();
    store.update_agent(&agent).expect("update Stopping failed");

    agent
        .transition(AgentLifecycleState::Stopped, 1_005_000)
        .unwrap();
    store.update_agent(&agent).expect("update Stopped failed");

    // Attempting to update a terminal agent without restarting to Starting fails
    let err = store.update_agent(&agent).unwrap_err();
    match err {
        StorageError::TerminalState {
            entity,
            id,
            state: current_state,
        } => {
            assert_eq!(entity, "Agent");
            assert_eq!(id, agent.agent_id.to_string());
            assert_eq!(current_state, "Stopped");
        }
        other => panic!("Unexpected error: {:?}", other),
    }

    // Valid restart: transition from Stopped -> Starting with fresh instance_nonce via restart()
    let fresh_nonce = Uuid::new_v4();
    agent.restart(fresh_nonce, 1_006_000).unwrap();
    store
        .update_agent(&agent)
        .expect("restart transition to Starting should succeed");

    let loaded = store.get_agent(&agent.agent_id).unwrap().unwrap();
    assert_eq!(loaded.state, AgentLifecycleState::Starting);
    assert_eq!(loaded.process_identity.instance_nonce, fresh_nonce);
}

#[test]
fn test_find_by_capability_and_principal() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent_registry.db");
    let store = AgentRegistryStore::open(&db_path).unwrap();

    let agent1 = make_agent("FileAgent", vec!["fs.read", "fs.write"]);
    let agent2 = make_agent("MonitorAgent", vec!["system.metrics", "fs.read"]);

    store.register_agent(&agent1).unwrap();
    store.register_agent(&agent2).unwrap();

    // Query fs.read -> both
    let fs_readers = store.find_by_capability("fs.read").unwrap();
    assert_eq!(fs_readers.len(), 2);

    // Query fs.write -> agent1 only
    let fs_writers = store.find_by_capability("fs.write").unwrap();
    assert_eq!(fs_writers.len(), 1);
    assert_eq!(fs_writers[0].agent_id, agent1.agent_id);

    // Query system.metrics -> agent2 only
    let metric_collectors = store.find_by_capability("system.metrics").unwrap();
    assert_eq!(metric_collectors.len(), 1);
    assert_eq!(metric_collectors[0].agent_id, agent2.agent_id);

    // Query by principal
    let principal_agents = store.find_by_principal(&agent1.owner.actor_id).unwrap();
    assert_eq!(principal_agents.len(), 2);
}

#[test]
fn test_agent_delete_restricted_by_assignment_history() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent_registry.db");
    let store = AgentRegistryStore::open(&db_path).unwrap();

    let agent = make_agent("Worker", vec!["compute"]);
    let agent_id = agent.agent_id;
    store.register_agent(&agent).unwrap();

    let assignment = make_assignment(agent_id, "compute");
    let assignment_id = assignment.assignment_id;
    store.insert_assignment(&assignment).unwrap();

    let heartbeat = HeartbeatRecord::new(
        agent_id,
        agent.process_identity.instance_nonce,
        1_000_100,
        1,
        AgentResourceMetrics::new(100, 50_000_000, 15),
    );
    store.append_heartbeat(&heartbeat).unwrap();

    // 1. Attempting to delete an agent with historical assignments fails with a foreign key violation
    let del_err = store.delete_agent(&agent_id).unwrap_err();
    match del_err {
        StorageError::ForeignKeyViolation { .. } | StorageError::Sqlite(_) => {}
        other => panic!("Expected foreign key violation, got: {:?}", other),
    }

    // Agent and assignment still intact
    assert!(store.get_agent(&agent_id).unwrap().is_some());
    assert!(store.get_assignment(&assignment_id).unwrap().is_some());

    // 2. An unassigned agent can be deleted and cleanly cascades its capabilities and heartbeats
    let unassigned_agent = make_agent("UnassignedWorker", vec!["noop"]);
    let unassigned_id = unassigned_agent.agent_id;
    store.register_agent(&unassigned_agent).unwrap();

    let hb = HeartbeatRecord::new(
        unassigned_id,
        unassigned_agent.process_identity.instance_nonce,
        1_000_100,
        1,
        AgentResourceMetrics::new(10, 10_000_000, 2),
    );
    store.append_heartbeat(&hb).unwrap();

    store
        .delete_agent(&unassigned_id)
        .expect("unassigned agent deletion should succeed");

    assert!(store.get_agent(&unassigned_id).unwrap().is_none());
    assert!(store
        .list_capabilities_for_agent(&unassigned_id)
        .unwrap()
        .is_empty());
    assert!(store
        .list_recent_heartbeats(&unassigned_id, 10)
        .unwrap()
        .is_empty());
}

#[test]
fn test_work_assignment_crud_and_terminal_protection() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent_registry.db");
    let store = AgentRegistryStore::open(&db_path).unwrap();

    let agent = make_agent("Worker", vec!["fs.read"]);
    store.register_agent(&agent).unwrap();

    let mut assignment = make_assignment(agent.agent_id, "fs.read");
    let assignment_id = assignment.assignment_id;

    // Insert
    store.insert_assignment(&assignment).unwrap();

    // Duplicate insert rejected
    let dup_err = store.insert_assignment(&assignment).unwrap_err();
    match dup_err {
        StorageError::DuplicateKey { entity, key } => {
            assert_eq!(entity, "WorkAssignment");
            assert_eq!(key, assignment_id.to_string());
        }
        other => panic!("Unexpected error: {:?}", other),
    }

    // Read back
    let loaded = store
        .get_assignment(&assignment_id)
        .unwrap()
        .expect("assignment missing");
    assert_eq!(loaded.status, AssignmentStatus::Assigned);
    assert_eq!(loaded.capability_id, "fs.read");

    // List queries
    let agent_assigns = store.list_assignments_for_agent(&agent.agent_id).unwrap();
    assert_eq!(agent_assigns.len(), 1);

    let wf_assigns = store
        .list_assignments_for_workflow(&assignment.workflow_id)
        .unwrap();
    assert_eq!(wf_assigns.len(), 1);

    let step_assigns = store
        .list_assignments_for_step(&assignment.step_id)
        .unwrap();
    assert_eq!(step_assigns.len(), 1);

    // Update Assigned -> InProgress
    assignment
        .transition(AssignmentStatus::InProgress, 1_001_000)
        .unwrap();
    store.update_assignment(&assignment).unwrap();

    // Update InProgress -> Completed (terminal)
    assignment
        .transition(AssignmentStatus::Completed, 1_002_000)
        .unwrap();
    store.update_assignment(&assignment).unwrap();

    // Further mutation of terminal assignment is rejected in storage
    let mut illegal_mutation = assignment.clone();
    illegal_mutation.status = AssignmentStatus::Failed;
    let term_err = store.update_assignment(&illegal_mutation).unwrap_err();
    match term_err {
        StorageError::TerminalState { entity, id, state } => {
            assert_eq!(entity, "WorkAssignment");
            assert_eq!(id, assignment_id.to_string());
            assert_eq!(state, "Completed");
        }
        other => panic!("Unexpected error: {:?}", other),
    }
}

#[test]
fn test_foreign_key_enforcement() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent_registry.db");
    let store = AgentRegistryStore::open(&db_path).unwrap();

    let non_existent_agent_id = AgentId::new();

    // Attempting to assign work to a non-existent agent should fail with FK constraint error
    let assignment = make_assignment(non_existent_agent_id, "fs.read");
    let result = store.insert_assignment(&assignment);
    assert!(result.is_err());
    match result.unwrap_err() {
        StorageError::ForeignKeyViolation { reason } => {
            assert!(reason.contains("does not exist in registry"));
        }
        StorageError::Sqlite(err) => {
            assert!(err.to_string().to_lowercase().contains("foreign key"));
        }
        other => panic!("Unexpected error: {:?}", other),
    }

    // Attempting to append heartbeat for non-existent agent should fail with ForeignKeyViolation
    let heartbeat = HeartbeatRecord::new(
        non_existent_agent_id,
        Uuid::new_v4(),
        1_000_100,
        1,
        AgentResourceMetrics::new(10, 20_000_000, 5),
    );
    let hb_result = store.append_heartbeat(&heartbeat);
    assert!(hb_result.is_err());
    match hb_result.unwrap_err() {
        StorageError::ForeignKeyViolation { reason } => {
            assert!(reason.contains("does not exist in registry"));
        }
        other => panic!("Unexpected error: {:?}", other),
    }
}

#[test]
fn test_heartbeat_stale_instance_nonce_rejected() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent_registry.db");
    let store = AgentRegistryStore::open(&db_path).unwrap();

    let agent = make_agent("Worker", vec!["test"]);
    store.register_agent(&agent).unwrap();

    // Valid heartbeat matching active instance_nonce
    let valid_hb = HeartbeatRecord::new(
        agent.agent_id,
        agent.process_identity.instance_nonce,
        1_000_100,
        1,
        AgentResourceMetrics::new(10, 20_000_000, 5),
    );
    store
        .append_heartbeat(&valid_hb)
        .expect("valid heartbeat should succeed");

    // Stale heartbeat from old/reused process with stale nonce
    let stale_nonce = Uuid::new_v4();
    let stale_hb = HeartbeatRecord::new(
        agent.agent_id,
        stale_nonce,
        1_000_200,
        2,
        AgentResourceMetrics::new(10, 20_000_000, 5),
    );
    let stale_err = store.append_heartbeat(&stale_hb).unwrap_err();
    match stale_err {
        StorageError::CorruptRecord { entity, id, reason } => {
            assert_eq!(entity, "HeartbeatRecord");
            assert_eq!(id, agent.agent_id.to_string());
            assert!(reason.contains("Heartbeat instance_nonce"));
            assert!(reason.contains(&stale_nonce.to_string()));
        }
        other => panic!("Unexpected error: {:?}", other),
    }

    // Verify recent heartbeats
    let hbs = store.list_recent_heartbeats(&agent.agent_id, 10).unwrap();
    assert_eq!(hbs.len(), 1);
    assert_eq!(hbs[0].instance_nonce, agent.process_identity.instance_nonce);
}

#[test]
fn test_authoritative_state_separated_from_heartbeat_observation() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent_registry.db");
    let store = AgentRegistryStore::open(&db_path).unwrap();

    let agent = make_agent("Worker", vec!["test"]);
    store.register_agent(&agent).unwrap();

    // Agent state in authoritative table is Registered
    let authoritative = store.get_agent(&agent.agent_id).unwrap().unwrap();
    assert_eq!(authoritative.state, AgentLifecycleState::Registered);

    // An observational heartbeat is appended
    let hb = HeartbeatRecord::new(
        agent.agent_id,
        agent.process_identity.instance_nonce,
        1_000_100,
        1,
        AgentResourceMetrics::new(50, 30_000_000, 10),
    );
    store.append_heartbeat(&hb).unwrap();

    // Verify authoritative agent record state was NOT changed by observational heartbeat
    let authoritative_after = store.get_agent(&agent.agent_id).unwrap().unwrap();
    assert_eq!(authoritative_after.state, AgentLifecycleState::Registered);
}

#[test]
fn test_dual_write_corruption_detection() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent_registry.db");

    let agent = make_agent("Worker", vec!["test"]);
    let agent_id = agent.agent_id;

    {
        let store = AgentRegistryStore::open(&db_path).unwrap();
        store.register_agent(&agent).unwrap();
    }

    // Tamper directly with the indexed `state` column in SQLite without modifying payload
    {
        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            "UPDATE agents SET state = 'Failed' WHERE agent_id = ?1",
            rusqlite::params![agent_id.to_string()],
        )
        .unwrap();
    }

    // Reading through AgentRegistryStore should catch the mismatch and return StorageError::CorruptRecord
    {
        let store = AgentRegistryStore::open(&db_path).unwrap();
        let result = store.get_agent(&agent_id);
        assert!(result.is_err());
        match result.unwrap_err() {
            StorageError::CorruptRecord { entity, id, reason } => {
                assert_eq!(entity, "Agent");
                assert_eq!(id, agent_id.to_string());
                assert!(
                    reason.contains("Indexed database columns contradict serialized JSON payload")
                );
            }
            other => panic!("Unexpected error: {:?}", other),
        }
    }
}

#[test]
fn test_all_pragmas_runtime_values_verified() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent_registry.db");
    let store = AgentRegistryStore::open(&db_path).unwrap();

    let journal_mode = store.query_pragma("journal_mode").unwrap();
    assert_eq!(journal_mode.to_lowercase(), "wal");

    let synchronous = store.query_pragma("synchronous").unwrap();
    assert_eq!(synchronous, "1"); // 1 = NORMAL

    let foreign_keys = store.query_pragma("foreign_keys").unwrap();
    assert_eq!(foreign_keys, "1"); // 1 = ON

    let busy_timeout = store.query_pragma("busy_timeout").unwrap();
    assert_eq!(busy_timeout, "5000"); // 5000ms

    let temp_store = store.query_pragma("temp_store").unwrap();
    assert_eq!(temp_store, "2"); // 2 = MEMORY

    let auto_vacuum = store.query_pragma("auto_vacuum").unwrap();
    assert_eq!(auto_vacuum, "2"); // 2 = INCREMENTAL
}

#[test]
fn test_capability_dual_write_corruption_scenarios() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent_registry.db");

    // Case 1: Extra capability in relational mapping (payload has A, relational has A, EXTRA)
    {
        let store = AgentRegistryStore::open(&db_path).unwrap();
        let agent = make_agent("AgentA", vec!["cap.A"]);
        store.register_agent(&agent).unwrap();

        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            "INSERT INTO agent_capabilities (agent_id, capability_id) VALUES (?1, 'cap.EXTRA');",
            rusqlite::params![agent.agent_id.to_string()],
        )
        .unwrap();

        let err = store.get_agent(&agent.agent_id).unwrap_err();
        match err {
            StorageError::CorruptRecord { entity, id, reason } => {
                assert_eq!(entity, "Agent");
                assert_eq!(id, agent.agent_id.to_string());
                assert!(reason.contains("Relational agent_capabilities"));
            }
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    // Case 2: Missing capability in relational mapping (payload has A, B, relational has A only)
    {
        let store = AgentRegistryStore::open(&db_path).unwrap();
        let agent = make_agent("AgentB", vec!["cap.A", "cap.B"]);
        store.register_agent(&agent).unwrap();

        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            "DELETE FROM agent_capabilities WHERE agent_id = ?1 AND capability_id = 'cap.B';",
            rusqlite::params![agent.agent_id.to_string()],
        )
        .unwrap();

        let err = store.get_agent(&agent.agent_id).unwrap_err();
        match err {
            StorageError::CorruptRecord { entity, id, reason } => {
                assert_eq!(entity, "Agent");
                assert_eq!(id, agent.agent_id.to_string());
                assert!(reason.contains("Relational agent_capabilities"));
            }
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    // Case 3: Altered capability (payload has A, B; relational has A, C)
    {
        let store = AgentRegistryStore::open(&db_path).unwrap();
        let agent = make_agent("AgentC", vec!["cap.A", "cap.B"]);
        store.register_agent(&agent).unwrap();

        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            "UPDATE agent_capabilities SET capability_id = 'cap.C' WHERE agent_id = ?1 AND capability_id = 'cap.B';",
            rusqlite::params![agent.agent_id.to_string()],
        )
        .unwrap();

        let err = store.get_agent(&agent.agent_id).unwrap_err();
        match err {
            StorageError::CorruptRecord { entity, id, reason } => {
                assert_eq!(entity, "Agent");
                assert_eq!(id, agent.agent_id.to_string());
                assert!(reason.contains("Relational agent_capabilities"));
            }
            other => panic!("Unexpected error: {:?}", other),
        }
    }
}

#[test]
fn test_unsupported_newer_schema_rejected() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent_registry.db");

    // Initialize first
    {
        let _store = AgentRegistryStore::open(&db_path).unwrap();
    }

    // Manually tamper user_version to future schema version 999
    {
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch("PRAGMA user_version = 999;").unwrap();
    }

    let result = AgentRegistryStore::open(&db_path);
    assert!(result.is_err());
    match result.unwrap_err() {
        StorageError::IncompatibleSchemaVersion { found, supported } => {
            assert_eq!(found, 999);
            assert_eq!(supported, 1);
        }
        other => panic!("Unexpected error: {:?}", other),
    }
}

#[test]
fn test_transaction_rollback_on_failed_registration() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent_registry.db");
    let store = AgentRegistryStore::open(&db_path).unwrap();

    let agent1 = make_agent("Agent1", vec!["cap1"]);
    store.register_agent(&agent1).unwrap();

    // Attempt to register agent 2 with the same instance_nonce (duplicate nonce)
    let mut agent2 = make_agent("Agent2", vec!["cap2"]);
    agent2.process_identity = agent1.process_identity.clone();

    let result = store.register_agent(&agent2);
    assert!(result.is_err());

    // Verify agent2 was completely rolled back: neither in agents nor agent_capabilities
    assert!(store.get_agent(&agent2.agent_id).unwrap().is_none());
    assert!(store
        .list_capabilities_for_agent(&agent2.agent_id)
        .unwrap()
        .is_empty());
}

#[test]
fn test_startup_integrity_validation_explicit_checks() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent_registry.db");
    let store = AgentRegistryStore::open(&db_path).expect("open must succeed");

    // 1. Explicitly verify PRAGMA integrity_check returns "ok"
    let integrity = store.query_pragma("integrity_check").unwrap();
    assert_eq!(integrity.to_lowercase(), "ok");

    // 2. Explicitly verify PRAGMA foreign_key_check returns no violations
    let conn = Connection::open(&db_path).unwrap();
    let mut stmt = conn.prepare("PRAGMA foreign_key_check;").unwrap();
    let mut rows = stmt.query([]).unwrap();
    assert!(
        rows.next().unwrap().is_none(),
        "Startup foreign key check must have zero violations"
    );
}

#[test]
fn test_startup_foreign_key_failure_rejects_database() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent_registry.db");

    // Initialize valid database
    {
        let _store = AgentRegistryStore::open(&db_path).unwrap();
    }

    // Insert an orphan foreign key reference with foreign_keys turned off
    {
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            r#"
            PRAGMA foreign_keys = OFF;
            INSERT INTO agent_capabilities (agent_id, capability_id) VALUES ('non-existent-agent', 'fs.read');
            "#,
        )
        .unwrap();
    }

    // Opening with AgentRegistryStore must fail during startup foreign_key_check
    let result = AgentRegistryStore::open(&db_path);
    assert!(result.is_err());
    match result.unwrap_err() {
        StorageError::ForeignKeyViolation { reason } => {
            assert!(reason.contains("Foreign key check failed"));
            assert!(reason.contains("agent_capabilities"));
        }
        other => panic!("Expected ForeignKeyViolation error, got: {:?}", other),
    }
}

#[test]
fn test_startup_integrity_failure_rejects_corrupted_database() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent_registry.db");

    // Initialize database with an agent
    {
        let store = AgentRegistryStore::open(&db_path).unwrap();
        let agent = make_agent("Worker", vec!["test.cap"]);
        store.register_agent(&agent).unwrap();
    }

    // Corrupt database file bytes on disk (overwrite page bytes after header)
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&db_path)
            .unwrap();
        // Seek past SQLite 100-byte header to offset 512 and write corrupt garbage
        file.seek(SeekFrom::Start(512)).unwrap();
        file.write_all(&[0xFF; 256]).unwrap();
        file.flush().unwrap();
    }

    // Opening corrupted database must fail with a typed error (DatabaseCorrupted or Sqlite)
    let result = AgentRegistryStore::open(&db_path);
    assert!(
        result.is_err(),
        "Opening corrupted database must not succeed"
    );
    match result.unwrap_err() {
        StorageError::DatabaseCorrupted { details } => {
            assert!(!details.is_empty());
        }
        StorageError::Sqlite(_) => {}
        other => panic!("Expected typed corruption error, got: {:?}", other),
    }
}

#[test]
fn test_auto_vacuum_verification_lifecycle() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent_registry.db");

    // Case 1: Newly created DB -> auto_vacuum = 2 (INCREMENTAL)
    {
        let store = AgentRegistryStore::open(&db_path).unwrap();
        let auto_vacuum = store.query_pragma("auto_vacuum").unwrap();
        assert_eq!(
            auto_vacuum, "2",
            "Newly created database must have auto_vacuum = INCREMENTAL (2)"
        );

        // Populate with an agent so tables have real data
        let agent = make_agent("Worker", vec!["cap.work"]);
        store.register_agent(&agent).unwrap();
    }

    // Case 2: Reopen correct DB -> auto_vacuum = 2 (INCREMENTAL)
    {
        let store = AgentRegistryStore::open(&db_path).unwrap();
        let auto_vacuum = store.query_pragma("auto_vacuum").unwrap();
        assert_eq!(
            auto_vacuum, "2",
            "Reopened valid database must maintain auto_vacuum = INCREMENTAL (2)"
        );
        let list = store.list_agents().unwrap();
        assert_eq!(list.len(), 1);
    }

    // Case 3: Existing incompatible DB (created with auto_vacuum = 0) -> startup rejected
    {
        let bad_db_path = dir.path().join("incompatible.db");
        // Create an incompatible SQLite database with tables and default auto_vacuum = 0 (NONE)
        {
            let conn = Connection::open(&bad_db_path).unwrap();
            conn.execute("CREATE TABLE dummy (id INTEGER PRIMARY KEY);", [])
                .unwrap();
            let raw_auto_vac: i64 = conn
                .query_row("PRAGMA auto_vacuum;", [], |row| row.get(0))
                .unwrap();
            assert_eq!(
                raw_auto_vac, 0,
                "Incompatible database must have auto_vacuum = 0"
            );
        }

        // Attempting to open as AgentRegistryStore must fail closed with StorageError::ConfigurationFailed
        let res = AgentRegistryStore::open(&bad_db_path);
        assert!(res.is_err(), "Opening incompatible database must fail");
        match res.unwrap_err() {
            StorageError::ConfigurationFailed { reason } => {
                assert!(
                    reason.contains("auto_vacuum mode is 0, but INCREMENTAL (2) is required"),
                    "Expected auto_vacuum configuration error, got: {}",
                    reason
                );
            }
            other => panic!(
                "Expected StorageError::ConfigurationFailed, got: {:?}",
                other
            ),
        }

        // Verify database was NOT automatically rewritten or VACUUMed
        {
            let conn = Connection::open(&bad_db_path).unwrap();
            let raw_auto_vac: i64 = conn
                .query_row("PRAGMA auto_vacuum;", [], |row| row.get(0))
                .unwrap();
            assert_eq!(
                raw_auto_vac, 0,
                "Database must not be rewritten by failed open"
            );
        }
    }
}

#[test]
fn test_heartbeat_duplicate_timestamp_rejected_by_timing_invariant() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("agent_registry.db");
    let store = AgentRegistryStore::open(&db_path).unwrap();

    let agent = make_agent("Worker", vec!["test.cap"]);
    store.register_agent(&agent).unwrap();

    let hb1 = HeartbeatRecord::new(
        agent.agent_id,
        agent.process_identity.instance_nonce,
        1_000_100,
        1,
        AgentResourceMetrics::new(50, 30_000_000, 10),
    );
    store.append_heartbeat(&hb1).unwrap();

    // A second heartbeat sharing the identical timestamp_ms for the same agent
    // must be rejected under the Heartbeat Timing Invariant via PRIMARY KEY (agent_id, timestamp_ms)
    let hb2 = HeartbeatRecord::new(
        agent.agent_id,
        agent.process_identity.instance_nonce,
        1_000_100, // same timestamp
        2,         // different sequence number
        AgentResourceMetrics::new(55, 31_000_000, 10),
    );
    let err = store.append_heartbeat(&hb2).unwrap_err();
    assert!(
        matches!(err, StorageError::DuplicateKey { .. }),
        "Expected DuplicateKey error on duplicate heartbeat timestamp, got: {:?}",
        err
    );

    // Verify only the first heartbeat is in storage
    let recent = store.list_recent_heartbeats(&agent.agent_id, 10).unwrap();
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].sequence_number, 1);
}
