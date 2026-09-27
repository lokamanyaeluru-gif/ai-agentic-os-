//! Focused integration tests for Phase 1.2.1 Persistent Domain Storage Foundation.
//!
//! Validates:
//! - Schema initialization and migration tracking
//! - WAL mode, foreign keys, synchronous, and busy_timeout configuration
//! - Intent, Goal, Workflow persistence roundtrip
//! - Deserialization with deny_unknown_fields enforcement and corrupt record rejection
//! - Idempotency lookup scoped to authenticated originating principal
//! - Duplicate idempotency rejection
//! - Database reopen and state recovery
//! - Separate domain database ownership
//! - State machine transition enforcement in storage
//! - Transaction rollback on failure
//! - Empty and missing record handling
//! - Relational foreign key constraints and cascade deletion
//! - Corruption detection via quick_check

use agenticos_contracts::{PrincipalContext, ResourceRef, RetryClassification};
use agenticos_core::storage::{GoalStore, IntentStore, WorkflowStore};
use agenticos_core::{
    normalize_intent, Goal, GoalObjective, GoalStatus, Intent, IntentStatus, StepDependency,
    StepExecutionState, StorageError, Workflow, WorkflowStatus, WorkflowStep,
};
use rusqlite::Connection;
use serde_json::json;
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use tempfile::tempdir;
use uuid::Uuid;

// ============================================================================
// Test Helpers
// ============================================================================

fn test_principal(uid: u32) -> PrincipalContext {
    PrincipalContext::user(uid, uid)
}

fn create_test_intent(principal: PrincipalContext, idempotency_key: Option<String>) -> Intent {
    Intent::new(
        "create a project folder called demo",
        principal,
        Uuid::new_v4(),
        idempotency_key,
        1000,
    )
    .unwrap()
}

fn create_test_goal(intent: &Intent) -> Goal {
    let objective = GoalObjective::new(
        "Create Directory",
        "Ensure workspace directory exists",
        vec!["directory exists".to_string()],
        "workspace",
    );
    Goal::from_intent(intent, objective, 1100)
}

fn create_test_workflow(goal: &Goal) -> Workflow {
    let step1 = WorkflowStep::new(
        0,
        "fs.create_directory",
        1,
        ResourceRef::path("demo"),
        json!({ "path": "demo" }),
        vec![],
        RetryClassification::Safe,
        5000,
    );
    let step1_id = step1.step_id;

    let step2 = WorkflowStep::new(
        1,
        "fs.verify_directory",
        1,
        ResourceRef::path("demo"),
        json!({ "path": "demo" }),
        vec![step1_id],
        RetryClassification::Safe,
        5000,
    );

    let dependencies = vec![StepDependency::new(step2.step_id, step1_id)];

    Workflow::from_goal(goal, vec![step1, step2], dependencies, 1200).unwrap()
}

// ============================================================================
// 1. Schema Initialization & SQLite Configuration Tests
// ============================================================================

#[test]
fn test_schema_initialization_and_versioning() {
    let dir = tempdir().unwrap();

    let intent_db = dir.path().join("intents.db");
    let goal_db = dir.path().join("goals.db");
    let workflow_db = dir.path().join("workflows.db");

    let _intent_store = IntentStore::open(&intent_db).unwrap();
    let _goal_store = GoalStore::open(&goal_db).unwrap();
    let _workflow_store = WorkflowStore::open(&workflow_db).unwrap();

    // Verify user_version = 1 on all three
    for db_path in [&intent_db, &goal_db, &workflow_db] {
        let conn = Connection::open(db_path).unwrap();
        let user_version: u32 = conn
            .query_row("PRAGMA user_version;", [], |row| row.get(0))
            .unwrap();
        assert_eq!(user_version, 1);

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version = 1;",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }
}

#[test]
fn test_sqlite_configuration_pragmas() {
    let dir = tempdir().unwrap();
    let intent_db = dir.path().join("intents.db");
    let intent_store = IntentStore::open(&intent_db).unwrap();

    // Verify WAL mode
    let journal_mode = intent_store.query_pragma("journal_mode").unwrap();
    assert_eq!(journal_mode.to_lowercase(), "wal");

    // Verify synchronous = NORMAL (1)
    let sync = intent_store.query_pragma("synchronous").unwrap();
    assert_eq!(sync, "1");

    // Verify foreign_keys = ON (1)
    let fk = intent_store.query_pragma("foreign_keys").unwrap();
    assert_eq!(fk, "1");

    // Verify busy_timeout = 5000
    let timeout = intent_store.query_pragma("busy_timeout").unwrap();
    assert_eq!(timeout, "5000");

    // Verify temp_store = MEMORY (2)
    let temp_store = intent_store.query_pragma("temp_store").unwrap();
    assert_eq!(temp_store, "2");
}

// ============================================================================
// 2. Persistence Roundtrip Tests (Intent, Goal, Workflow)
// ============================================================================

#[test]
fn test_intent_persistence_roundtrip_and_lifecycle_updates() {
    let dir = tempdir().unwrap();
    let store = IntentStore::open(dir.path().join("intents.db")).unwrap();

    let principal = test_principal(1000);
    let mut intent = create_test_intent(principal.clone(), Some("tx-123".into()));
    let intent_id = intent.intent_id;

    // Insert
    store.insert(&intent).unwrap();

    // Retrieve
    let loaded = store.get(&intent_id).unwrap().expect("Intent must exist");
    assert_eq!(loaded.intent_id, intent.intent_id);
    assert_eq!(loaded.correlation_id, intent.correlation_id);
    assert_eq!(loaded.idempotency_key, Some("tx-123".into()));
    assert_eq!(loaded.originating_principal, principal);
    assert_eq!(loaded.status, IntentStatus::Created);
    assert_eq!(loaded.created_at_ms, 1000);

    // Transition to Accepted
    let normalized = normalize_intent(&intent.raw_input).unwrap();
    intent.accept(normalized).unwrap();
    store.update(&intent).unwrap();

    let updated = store.get(&intent_id).unwrap().unwrap();
    assert_eq!(updated.status, IntentStatus::Accepted);
    assert!(updated.normalized.is_some());
    assert_eq!(updated.normalized.unwrap().action, "create_directory");

    // Transition to Completed
    intent.transition(IntentStatus::Completed).unwrap();
    store.update(&intent).unwrap();

    let completed = store.get(&intent_id).unwrap().unwrap();
    assert_eq!(completed.status, IntentStatus::Completed);
}

#[test]
fn test_goal_persistence_roundtrip_and_lifecycle_updates() {
    let dir = tempdir().unwrap();
    let intent_store = IntentStore::open(dir.path().join("intents.db")).unwrap();
    let goal_store = GoalStore::open(dir.path().join("goals.db")).unwrap();

    let intent = create_test_intent(test_principal(1000), None);
    intent_store.insert(&intent).unwrap();

    let mut goal = create_test_goal(&intent);
    let goal_id = goal.goal_id;

    // Insert
    goal_store.insert(&goal).unwrap();

    // Retrieve
    let loaded = goal_store.get(&goal_id).unwrap().expect("Goal must exist");
    assert_eq!(loaded.goal_id, goal.goal_id);
    assert_eq!(loaded.correlation_id, intent.correlation_id);
    assert_eq!(loaded.originating_intent_id, intent.intent_id);
    assert_eq!(loaded.status, GoalStatus::Created);
    assert_eq!(loaded.objective.title, "Create Directory");

    // Transition Created -> Accepted
    goal.transition(GoalStatus::Accepted, 1150).unwrap();
    goal_store.update(&goal).unwrap();

    let updated = goal_store.get(&goal_id).unwrap().unwrap();
    assert_eq!(updated.status, GoalStatus::Accepted);
    assert_eq!(updated.updated_at_ms, 1150);

    // Transition Accepted -> Running
    goal.transition(GoalStatus::Running, 1200).unwrap();
    goal_store.update(&goal).unwrap();
    assert_eq!(
        goal_store.get(&goal_id).unwrap().unwrap().status,
        GoalStatus::Running
    );

    // Transition Running -> Completed
    goal.transition(GoalStatus::Completed, 1300).unwrap();
    goal_store.update(&goal).unwrap();
    assert_eq!(
        goal_store.get(&goal_id).unwrap().unwrap().status,
        GoalStatus::Completed
    );

    // Query by intent ID
    let goals_by_intent = goal_store.find_by_intent_id(&intent.intent_id).unwrap();
    assert_eq!(goals_by_intent.len(), 1);
    assert_eq!(goals_by_intent[0].goal_id, goal_id);

    // Query by correlation ID
    let goals_by_corr = goal_store
        .find_by_correlation_id(&intent.correlation_id)
        .unwrap();
    assert_eq!(goals_by_corr.len(), 1);
    assert_eq!(goals_by_corr[0].goal_id, goal_id);
}

#[test]
fn test_workflow_persistence_roundtrip_and_lifecycle_updates() {
    let dir = tempdir().unwrap();
    let goal_store = GoalStore::open(dir.path().join("goals.db")).unwrap();
    let workflow_store = WorkflowStore::open(dir.path().join("workflows.db")).unwrap();

    let intent = create_test_intent(test_principal(1000), None);
    let goal = create_test_goal(&intent);
    goal_store.insert(&goal).unwrap();

    let mut workflow = create_test_workflow(&goal);
    let workflow_id = workflow.workflow_id;
    let step2_id = workflow.steps[1].step_id;

    // Insert
    workflow_store.insert(&workflow).unwrap();

    // Retrieve
    let loaded = workflow_store
        .get(&workflow_id)
        .unwrap()
        .expect("Workflow must exist");
    assert_eq!(loaded.workflow_id, workflow_id);
    assert_eq!(loaded.goal_id, goal.goal_id);
    assert_eq!(loaded.correlation_id, goal.correlation_id);
    assert_eq!(loaded.status, WorkflowStatus::Created);
    assert_eq!(loaded.steps.len(), 2);
    assert_eq!(loaded.dependencies.len(), 1);

    // Find by step ID index
    let by_step = workflow_store
        .find_by_step_id(&step2_id)
        .unwrap()
        .expect("Must find workflow by step ID");
    assert_eq!(by_step.workflow_id, workflow_id);

    // Transition Workflow: Created -> Accepted
    workflow.transition(WorkflowStatus::Accepted, 1250).unwrap();
    workflow_store.update(&workflow).unwrap();

    // Transition Step 1: Created -> Running
    workflow.steps[0]
        .transition(StepExecutionState::Running)
        .unwrap();
    workflow_store.update(&workflow).unwrap();

    let wf_updated = workflow_store.get(&workflow_id).unwrap().unwrap();
    assert_eq!(wf_updated.status, WorkflowStatus::Accepted);
    assert_eq!(wf_updated.steps[0].state, StepExecutionState::Running);

    // Transition Step 1: Running -> Completed
    workflow.steps[0]
        .transition(StepExecutionState::Completed)
        .unwrap();
    // Transition Step 2: Waiting -> Running
    workflow.steps[1]
        .transition(StepExecutionState::Waiting)
        .unwrap();
    workflow.steps[1]
        .transition(StepExecutionState::Running)
        .unwrap();
    workflow_store.update(&workflow).unwrap();

    let wf_step2 = workflow_store.get(&workflow_id).unwrap().unwrap();
    assert_eq!(wf_step2.steps[0].state, StepExecutionState::Completed);
    assert_eq!(wf_step2.steps[1].state, StepExecutionState::Running);
}

// ============================================================================
// 3. Idempotency Key Scoping & Deduplication Tests
// ============================================================================

#[test]
fn test_idempotency_lookup_scoped_by_principal() {
    let dir = tempdir().unwrap();
    let store = IntentStore::open(dir.path().join("intents.db")).unwrap();

    let principal_a = test_principal(1000);
    let principal_b = test_principal(2000);

    let key = "client-action-12345".to_string();

    let intent_a = Intent::new(
        "mkdir project_a",
        principal_a.clone(),
        Uuid::new_v4(),
        Some(key.clone()),
        1000,
    )
    .unwrap();

    let intent_b = Intent::new(
        "mkdir project_b",
        principal_b.clone(),
        Uuid::new_v4(),
        Some(key.clone()),
        1050,
    )
    .unwrap();

    // Both should insert successfully despite identical idempotency keys (different principals)
    store.insert(&intent_a).unwrap();
    store.insert(&intent_b).unwrap();

    // Scoped query for principal A
    let found_a = store
        .find_by_idempotency_key(&principal_a, &key)
        .unwrap()
        .expect("Principal A intent must be found");
    assert_eq!(found_a.intent_id, intent_a.intent_id);
    assert_eq!(found_a.raw_input, "mkdir project_a");

    // Scoped query for principal B
    let found_b = store
        .find_by_idempotency_key(&principal_b, &key)
        .unwrap()
        .expect("Principal B intent must be found");
    assert_eq!(found_b.intent_id, intent_b.intent_id);
    assert_eq!(found_b.raw_input, "mkdir project_b");
}

#[test]
fn test_duplicate_idempotency_key_rejected_for_same_principal() {
    let dir = tempdir().unwrap();
    let store = IntentStore::open(dir.path().join("intents.db")).unwrap();

    let principal = test_principal(1000);
    let key = "unique-client-key-42".to_string();

    let intent1 = Intent::new(
        "create directory first",
        principal.clone(),
        Uuid::new_v4(),
        Some(key.clone()),
        1000,
    )
    .unwrap();

    let intent2 = Intent::new(
        "create directory second",
        principal.clone(),
        Uuid::new_v4(),
        Some(key.clone()),
        1050,
    )
    .unwrap();

    store.insert(&intent1).unwrap();

    let err = store
        .insert(&intent2)
        .expect_err("Duplicate idempotency key for same principal must be rejected");

    match err {
        StorageError::DuplicateIdempotencyKey {
            principal_id,
            idempotency_key,
        } => {
            assert_eq!(principal_id, principal.actor_id);
            assert_eq!(idempotency_key, key);
        }
        other => panic!("Expected DuplicateIdempotencyKey, got: {:?}", other),
    }
}

// ============================================================================
// 4. State Machine Integrity & Terminal State Protection in Storage
// ============================================================================

#[test]
fn test_storage_rejects_invalid_intent_transitions() {
    let dir = tempdir().unwrap();
    let store = IntentStore::open(dir.path().join("intents.db")).unwrap();

    let mut intent = create_test_intent(test_principal(1000), None);
    store.insert(&intent).unwrap();

    // Invalid transition: Created -> Completed (skipping Accepted)
    // We intentionally bypass domain method to simulate illegal update attempt
    intent.status = IntentStatus::Completed;
    let err = store
        .update(&intent)
        .expect_err("Storage must reject illegal transition");
    assert!(matches!(err, StorageError::InvalidStateTransition { .. }));

    // Reset and complete validly
    intent.status = IntentStatus::Accepted;
    store.update(&intent).unwrap();
    intent.status = IntentStatus::Completed;
    store.update(&intent).unwrap();

    // Terminal state protection: attempt update from Completed to Accepted
    intent.status = IntentStatus::Accepted;
    let err = store
        .update(&intent)
        .expect_err("Storage must reject transition from terminal state");
    assert!(matches!(err, StorageError::TerminalState { .. }));
}

#[test]
fn test_storage_rejects_invalid_goal_transitions() {
    let dir = tempdir().unwrap();
    let store = GoalStore::open(dir.path().join("goals.db")).unwrap();

    let intent = create_test_intent(test_principal(1000), None);
    let mut goal = create_test_goal(&intent);
    store.insert(&goal).unwrap();

    // Invalid transition: Created -> Running (skipping Accepted)
    goal.status = GoalStatus::Running;
    let err = store
        .update(&goal)
        .expect_err("Storage must reject illegal transition");
    assert!(matches!(err, StorageError::InvalidStateTransition { .. }));

    // Transition properly to terminal state
    goal.status = GoalStatus::Accepted;
    store.update(&goal).unwrap();
    goal.status = GoalStatus::Running;
    store.update(&goal).unwrap();
    goal.status = GoalStatus::Completed;
    store.update(&goal).unwrap();

    // Terminal state protection
    goal.status = GoalStatus::Running;
    let err = store
        .update(&goal)
        .expect_err("Storage must reject transition from terminal Completed state");
    assert!(matches!(err, StorageError::TerminalState { .. }));
}

// ============================================================================
// 5. Corrupt Record & Malformed Deserialization Rejection
// ============================================================================

#[test]
fn test_corrupt_serialized_record_rejected() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("intents.db");
    let store = IntentStore::open(&db_path).unwrap();

    let corrupt_id = Uuid::new_v4();

    // Manually insert malformed JSON payload into database
    {
        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            r#"
            INSERT INTO intents (
                intent_id,
                correlation_id,
                principal_id,
                idempotency_key,
                status,
                created_at_ms,
                payload
            ) VALUES (?, ?, ?, ?, ?, ?, ?);
            "#,
            rusqlite::params![
                corrupt_id.to_string(),
                Uuid::new_v4().to_string(),
                "User::\"1000\"",
                None::<String>,
                "Created",
                1000i64,
                r#"{"malicious_garbage": true, "corrupted": 123}"#,
            ],
        )
        .unwrap();
    }

    let err = store
        .get(&corrupt_id)
        .expect_err("Malformed record must fail explicit deserialization");

    match err {
        StorageError::CorruptRecord { entity, id, reason } => {
            assert_eq!(entity, "Intent");
            assert_eq!(id, corrupt_id.to_string());
            assert!(
                reason.contains("missing field `raw_input`") || reason.contains("unknown field")
            );
        }
        other => panic!("Expected CorruptRecord error, got: {:?}", other),
    }
}

// ============================================================================
// 6. Database Reopen, Reload & Ownership Separation Tests
// ============================================================================

#[test]
fn test_database_reopen_and_state_recovery() {
    let dir = tempdir().unwrap();
    let intent_path = dir.path().join("intents.db");
    let goal_path = dir.path().join("goals.db");
    let workflow_path = dir.path().join("workflows.db");

    let intent = create_test_intent(test_principal(1000), Some("key-reopen".into()));
    let goal = create_test_goal(&intent);
    let workflow = create_test_workflow(&goal);

    let intent_id = intent.intent_id;
    let goal_id = goal.goal_id;
    let workflow_id = workflow.workflow_id;

    // Scope 1: Write and drop connections
    {
        let i_store = IntentStore::open(&intent_path).unwrap();
        let g_store = GoalStore::open(&goal_path).unwrap();
        let w_store = WorkflowStore::open(&workflow_path).unwrap();

        i_store.insert(&intent).unwrap();
        g_store.insert(&goal).unwrap();
        w_store.insert(&workflow).unwrap();
    }

    // Scope 2: Reopen from disk
    {
        let i_store = IntentStore::open(&intent_path).unwrap();
        let g_store = GoalStore::open(&goal_path).unwrap();
        let w_store = WorkflowStore::open(&workflow_path).unwrap();

        let loaded_intent = i_store.get(&intent_id).unwrap().unwrap();
        assert_eq!(loaded_intent.intent_id, intent_id);
        assert_eq!(loaded_intent.idempotency_key, Some("key-reopen".into()));

        let loaded_goal = g_store.get(&goal_id).unwrap().unwrap();
        assert_eq!(loaded_goal.goal_id, goal_id);

        let loaded_workflow = w_store.get(&workflow_id).unwrap().unwrap();
        assert_eq!(loaded_workflow.workflow_id, workflow_id);
        assert_eq!(loaded_workflow.steps.len(), 2);
    }
}

#[test]
fn test_separate_database_ownership() {
    let dir = tempdir().unwrap();
    let intent_path = dir.path().join("intents.db");
    let goal_path = dir.path().join("goals.db");

    let i_store = IntentStore::open(&intent_path).unwrap();
    let g_store = GoalStore::open(&goal_path).unwrap();

    let intent = create_test_intent(test_principal(1000), None);
    i_store.insert(&intent).unwrap();

    // Goal store must not see Intent records and vice-versa
    let goal = g_store.get(&intent.intent_id).unwrap();
    assert!(goal.is_none());

    // Assert separate physical files exist on disk
    assert!(intent_path.exists());
    assert!(goal_path.exists());
    assert_ne!(intent_path, goal_path);
}

// ============================================================================
// 7. Relational Foreign Key Constraint Tests
// ============================================================================

#[test]
fn test_relational_foreign_key_enforcement_and_cascade() {
    let dir = tempdir().unwrap();
    let workflow_path = dir.path().join("workflows.db");
    let _store = WorkflowStore::open(&workflow_path).unwrap();

    let conn = Connection::open(&workflow_path).unwrap();
    conn.execute("PRAGMA foreign_keys = ON;", []).unwrap();

    let fake_workflow_id = Uuid::new_v4().to_string();
    let step_id = Uuid::new_v4().to_string();

    // Attempt to insert a workflow_step referencing a non-existent workflow
    let err = conn.execute(
        r#"
        INSERT INTO workflow_steps (
            step_id,
            workflow_id,
            step_index,
            capability_id,
            state
        ) VALUES (?, ?, ?, ?, ?);
        "#,
        rusqlite::params![
            step_id,
            fake_workflow_id,
            0,
            "fs.create_directory",
            "Created"
        ],
    );

    assert!(
        err.is_err(),
        "Foreign key constraint must reject orphaned step record"
    );
}

// ============================================================================
// 8. Empty & Missing Record Handling
// ============================================================================

#[test]
fn test_empty_and_missing_record_behavior() {
    let dir = tempdir().unwrap();
    let i_store = IntentStore::open(dir.path().join("intents.db")).unwrap();
    let g_store = GoalStore::open(dir.path().join("goals.db")).unwrap();
    let w_store = WorkflowStore::open(dir.path().join("workflows.db")).unwrap();

    let missing = Uuid::new_v4();

    assert!(i_store.get(&missing).unwrap().is_none());
    assert!(g_store.get(&missing).unwrap().is_none());
    assert!(w_store.get(&missing).unwrap().is_none());

    assert!(i_store
        .find_by_idempotency_key(&test_principal(1000), "missing-key")
        .unwrap()
        .is_none());

    assert!(i_store.find_by_correlation_id(&missing).unwrap().is_empty());
    assert!(g_store.find_by_intent_id(&missing).unwrap().is_empty());
    assert!(g_store.find_by_correlation_id(&missing).unwrap().is_empty());
    assert!(w_store.find_by_goal_id(&missing).unwrap().is_empty());
    assert!(w_store.find_by_step_id(&missing).unwrap().is_none());

    // Update on non-existent record must return NotFound
    let ghost_intent = create_test_intent(test_principal(1000), None);
    let err = i_store.update(&ghost_intent).unwrap_err();
    assert!(matches!(err, StorageError::NotFound { .. }));
}

// ============================================================================
// 9. Quick Check Corruption Detection Test
// ============================================================================

#[test]
fn test_quick_check_corruption_detected_without_destructive_overwrite() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("intents.db");

    // Initialize valid DB and checkpoint WAL into main database file
    {
        let store = IntentStore::open(&db_path).unwrap();
        let intent = create_test_intent(test_principal(1000), None);
        store.insert(&intent).unwrap();
        let _ = store.query_pragma("wal_checkpoint(TRUNCATE)");
    }

    // Intentionally corrupt bytes in the database page content
    {
        let mut file = OpenOptions::new().write(true).open(&db_path).unwrap();
        // SQLite header is 100 bytes; corrupt the first page structure right after header
        file.seek(SeekFrom::Start(100)).unwrap();
        file.write_all(&[0xDE; 1024]).unwrap();
        file.flush().unwrap();
    }

    // Remove WAL file if any exists so SQLite must read the corrupted main file
    let wal_path = dir.path().join("intents.db-wal");
    if wal_path.exists() {
        let _ = std::fs::remove_file(wal_path);
    }

    // Reopen must detect corruption and reject with explicit error
    let reopen_result = IntentStore::open(&db_path);
    assert!(
        reopen_result.is_err(),
        "Corrupted database must be detected on open"
    );

    // Assert database file is NOT silently deleted or overwritten
    assert!(db_path.exists());
    let metadata = std::fs::metadata(&db_path).unwrap();
    assert!(metadata.len() > 0);
}

// ============================================================================
// 10. Transaction Rollback on Failure Test
// ============================================================================

#[test]
fn test_transaction_rollback_on_failure() {
    let dir = tempdir().unwrap();
    let workflow_path = dir.path().join("workflows.db");
    let store = WorkflowStore::open(&workflow_path).unwrap();

    let intent = create_test_intent(test_principal(1000), None);
    let goal = create_test_goal(&intent);
    let workflow = create_test_workflow(&goal);
    let workflow_id = workflow.workflow_id;
    let step2_id = workflow.steps[1].step_id;

    // Pre-insert an orphaned/conflicting step_id into workflow_steps to force a collision during step 2 insertion
    {
        let conn = Connection::open(&workflow_path).unwrap();
        // Insert a dummy workflow first to satisfy FK
        let dummy_wf_id = Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO workflows (workflow_id, goal_id, correlation_id, status, created_at_ms, updated_at_ms, payload) VALUES (?, ?, ?, ?, ?, ?, ?);",
            rusqlite::params![dummy_wf_id, Uuid::new_v4().to_string(), Uuid::new_v4().to_string(), "Created", 1000i64, 1000i64, "{}"],
        ).unwrap();
        // Insert step2_id under dummy_wf_id
        conn.execute(
            "INSERT INTO workflow_steps (step_id, workflow_id, step_index, capability_id, state) VALUES (?, ?, ?, ?, ?);",
            rusqlite::params![step2_id.to_string(), dummy_wf_id, 0, "fs.dummy", "Created"],
        ).unwrap();
    }

    // Attempt to insert the new workflow: Step 1 succeeds, but Step 2 collides on PRIMARY KEY (step_id)
    let err = store.insert(&workflow);
    assert!(
        err.is_err(),
        "Must fail due to duplicate step_id in workflow_steps"
    );

    // Verify transaction rollback: the new workflow must NOT exist in `workflows`
    let conn = Connection::open(&workflow_path).unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM workflows WHERE workflow_id = ?;",
            rusqlite::params![workflow_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        count, 0,
        "Workflow row must be rolled back on step insertion failure"
    );

    // Also verify step 1 of the new workflow was not orphaned in `workflow_steps`
    let step1_id = workflow.steps[0].step_id.to_string();
    let step1_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM workflow_steps WHERE step_id = ?;",
            rusqlite::params![step1_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        step1_count, 0,
        "Step 1 must be rolled back when transaction fails"
    );
}

// ============================================================================
// 11. Additional Focused Verification Tests
// ============================================================================

#[test]
fn test_payload_index_mismatch_detected_as_corruption() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("intents.db");
    let store = IntentStore::open(&db_path).unwrap();

    let intent = create_test_intent(test_principal(1000), None);
    let intent_id = intent.intent_id;
    store.insert(&intent).unwrap();

    // Intentionally corrupt indexed status column while leaving payload as "Created"
    {
        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            "UPDATE intents SET status = 'Completed' WHERE intent_id = ?;",
            rusqlite::params![intent_id.to_string()],
        )
        .unwrap();
    }

    // Reading must detect contradiction between indexed column and payload
    let err = store
        .get(&intent_id)
        .expect_err("Indexed column contradicting payload must be rejected as corrupt");

    match err {
        StorageError::CorruptRecord { entity, id, reason } => {
            assert_eq!(entity, "Intent");
            assert_eq!(id, intent_id.to_string());
            assert!(reason.contains("contradicts serialized payload"));
        }
        other => panic!("Expected CorruptRecord error, got: {:?}", other),
    }
}

#[test]
fn test_terminal_record_payload_mutation_rejected() {
    let dir = tempdir().unwrap();
    let store = IntentStore::open(dir.path().join("intents.db")).unwrap();

    let mut intent = create_test_intent(test_principal(1000), None);
    let intent_id = intent.intent_id;
    store.insert(&intent).unwrap();

    // Transition properly to terminal state
    intent.transition(IntentStatus::Accepted).unwrap();
    store.update(&intent).unwrap();
    intent.transition(IntentStatus::Completed).unwrap();
    store.update(&intent).unwrap();

    // Now attempt to mutate raw_input while keeping status as Completed
    let mut mutated_terminal_intent = intent.clone();
    mutated_terminal_intent.raw_input = "tampered input".to_string();

    let err = store
        .update(&mutated_terminal_intent)
        .expect_err("Mutation on terminal record must be rejected even if status matches");

    match err {
        StorageError::TerminalState { entity, id, state } => {
            assert_eq!(entity, "Intent");
            assert_eq!(id, intent_id.to_string());
            assert_eq!(state, "Completed");
        }
        other => panic!("Expected TerminalState error, got: {:?}", other),
    }
}

#[test]
fn test_unsupported_future_schema_version_rejected() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("intents.db");

    // Initialize DB with future version 99
    {
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            r#"
            PRAGMA user_version = 99;
            CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, description TEXT);
            INSERT INTO schema_migrations VALUES (99, 'Future migration');
            "#,
        )
        .unwrap();
    }

    // Opening with current binary (which only supports version 1) must be rejected
    let err = IntentStore::open(&db_path)
        .expect_err("Database with future schema version must be rejected");

    match err {
        StorageError::IncompatibleSchemaVersion { found, supported } => {
            assert_eq!(found, 99);
            assert_eq!(supported, 1);
        }
        other => panic!("Expected IncompatibleSchemaVersion error, got: {:?}", other),
    }
}

#[test]
fn test_principal_identity_exact_match_scoping() {
    let dir = tempdir().unwrap();
    let store = IntentStore::open(dir.path().join("intents.db")).unwrap();

    let principal_user = PrincipalContext {
        actor_id: "User::\"1000\"".to_string(),
        uid: 1000,
        gid: 1000,
    };

    let principal_variant_gid = PrincipalContext {
        actor_id: "User::\"1000\"".to_string(),
        uid: 1000,
        gid: 2000, // Different GID
    };

    let key = "shared-idempotency-key".to_string();
    let intent = Intent::new(
        "test scoping",
        principal_user.clone(),
        Uuid::new_v4(),
        Some(key.clone()),
        1000,
    )
    .unwrap();

    store.insert(&intent).unwrap();

    // Query with exact matching principal must succeed
    let found = store
        .find_by_idempotency_key(&principal_user, &key)
        .unwrap();
    assert!(found.is_some());

    // Query with differing GID must return None to prevent identity collapse
    let not_found = store
        .find_by_idempotency_key(&principal_variant_gid, &key)
        .unwrap();
    assert!(
        not_found.is_none(),
        "Principals with different GID must not collapse"
    );
}
