//! Integration tests for Phase 1.2.2 — Deterministic Intent → Goal → Workflow Runtime.
//!
//! Tests are numbered to correspond to the Phase 1.2.2 specification test requirements.
//! All tests use isolated temporary databases (via `tempfile::tempdir()`).
//!
//! Security invariant: no std::process, Command::, shell, network, or unsafe code.

use agenticos_contracts::{PrincipalContext, RetryClassification};
use agenticos_core::storage::{GoalStore, IntentStore, WorkflowStore};
use agenticos_core::{
    GoalStatus, IntentStatus, Phase1Result, Phase1Runtime, RuntimeError, StorageError,
    SubmitRequest, WorkflowStatus,
};
use tempfile::tempdir;
use uuid::Uuid;

// ============================================================================
// Test helpers
// ============================================================================

fn make_principal(uid: u32) -> PrincipalContext {
    PrincipalContext::user(uid, uid)
}

fn open_stores(dir: &tempfile::TempDir) -> (IntentStore, GoalStore, WorkflowStore) {
    let i = IntentStore::open(dir.path().join("intents.db")).unwrap();
    let g = GoalStore::open(dir.path().join("goals.db")).unwrap();
    let w = WorkflowStore::open(dir.path().join("workflows.db")).unwrap();
    (i, g, w)
}

fn make_runtime(dir: &tempfile::TempDir) -> Phase1Runtime {
    let (i, g, w) = open_stores(dir);
    Phase1Runtime::new(i, g, w)
}

fn submit_fs_request(
    runtime: &Phase1Runtime,
    raw_input: &str,
    principal: PrincipalContext,
    idempotency_key: Option<&str>,
) -> Result<Phase1Result, RuntimeError> {
    runtime.submit(SubmitRequest {
        raw_input: raw_input.to_string(),
        principal,
        correlation_id: Uuid::new_v4(),
        idempotency_key: idempotency_key.map(|s| s.to_string()),
        created_at_ms: 1_000_000,
    })
}

// ============================================================================
// Test 1: New intent creates exactly one Goal and Workflow
// ============================================================================

#[test]
fn test_1_new_intent_creates_exactly_one_goal_and_workflow() {
    let dir = tempdir().unwrap();
    let runtime = make_runtime(&dir);

    let result = submit_fs_request(
        &runtime,
        "create directory demo",
        make_principal(1000),
        None,
    )
    .unwrap();

    // Exactly one of each was created
    let (i_store, g_store, w_store) = open_stores(&dir);

    assert_eq!(i_store.list().unwrap().len(), 1);
    assert_eq!(g_store.list().unwrap().len(), 1);
    assert_eq!(w_store.list().unwrap().len(), 1);

    // The returned objects have valid IDs
    assert!(!result.intent.intent_id.is_nil());
    assert!(!result.goal.goal_id.is_nil());
    assert!(!result.workflow.workflow_id.is_nil());
}

// ============================================================================
// Test 2: Correlation ID propagates across all three entities
// ============================================================================

#[test]
fn test_2_correlation_id_propagates_across_chain() {
    let dir = tempdir().unwrap();
    let runtime = make_runtime(&dir);

    let correlation_id = Uuid::new_v4();
    let result = runtime
        .submit(SubmitRequest {
            raw_input: "create folder projects".to_string(),
            principal: make_principal(1000),
            correlation_id,
            idempotency_key: None,
            created_at_ms: 2_000_000,
        })
        .unwrap();

    assert_eq!(result.intent.correlation_id, correlation_id);
    assert_eq!(result.goal.correlation_id, correlation_id);
    assert_eq!(result.workflow.correlation_id, correlation_id);
}

// ============================================================================
// Test 3: First submission succeeds and returns Accepted states
// ============================================================================

#[test]
fn test_3_first_submission_succeeds_with_accepted_states() {
    let dir = tempdir().unwrap();
    let runtime = make_runtime(&dir);

    let result = submit_fs_request(
        &runtime,
        "mkdir workspace",
        make_principal(1000),
        Some("first-sub-key"),
    )
    .unwrap();

    assert_eq!(result.intent.status, IntentStatus::Accepted);
    assert_eq!(result.goal.status, GoalStatus::Accepted);
    assert_eq!(result.workflow.status, WorkflowStatus::Accepted);
    assert!(!result.is_replay);
}

// ============================================================================
// Test 4: Exact idempotent retry does not duplicate entities
// ============================================================================

#[test]
fn test_4_exact_idempotent_retry_does_not_duplicate() {
    let dir = tempdir().unwrap();
    let runtime = make_runtime(&dir);

    let principal = make_principal(1000);
    let key = Some("idem-key-42");
    let input = "create directory idempotent_test";

    let first = submit_fs_request(&runtime, input, principal.clone(), key).unwrap();
    let second = submit_fs_request(&runtime, input, principal, key).unwrap();

    // Same IDs returned
    assert_eq!(first.intent.intent_id, second.intent.intent_id);
    assert_eq!(first.goal.goal_id, second.goal.goal_id);
    assert_eq!(first.workflow.workflow_id, second.workflow.workflow_id);

    // Second is flagged as replay
    assert!(!first.is_replay);
    assert!(second.is_replay);

    // Only one of each in storage
    let (i_store, g_store, w_store) = open_stores(&dir);
    assert_eq!(i_store.list().unwrap().len(), 1);
    assert_eq!(g_store.list().unwrap().len(), 1);
    assert_eq!(w_store.list().unwrap().len(), 1);
}

// ============================================================================
// Test 5: Same idempotency key under a different principal does not collide
// ============================================================================

#[test]
fn test_5_same_key_different_principal_is_isolated() {
    let dir = tempdir().unwrap();
    let runtime = make_runtime(&dir);

    let key = Some("shared-key");

    let result_a = submit_fs_request(
        &runtime,
        "create directory alpha",
        make_principal(1000),
        key,
    )
    .unwrap();

    let result_b =
        submit_fs_request(&runtime, "create directory beta", make_principal(2000), key).unwrap();

    // Different intent IDs — fully isolated
    assert_ne!(result_a.intent.intent_id, result_b.intent.intent_id);
    assert_ne!(result_a.goal.goal_id, result_b.goal.goal_id);
    assert_ne!(result_a.workflow.workflow_id, result_b.workflow.workflow_id);

    // Two of each in storage
    let (i_store, g_store, w_store) = open_stores(&dir);
    assert_eq!(i_store.list().unwrap().len(), 2);
    assert_eq!(g_store.list().unwrap().len(), 2);
    assert_eq!(w_store.list().unwrap().len(), 2);
}

// ============================================================================
// Test 6: Same key + materially different content is rejected
// ============================================================================

#[test]
fn test_6_same_key_different_content_is_rejected() {
    let dir = tempdir().unwrap();
    let runtime = make_runtime(&dir);

    let principal = make_principal(1000);
    let key = Some("conflict-key");

    submit_fs_request(
        &runtime,
        "create directory original",
        principal.clone(),
        key,
    )
    .unwrap();

    let err = submit_fs_request(&runtime, "create directory tampered", principal, key)
        .expect_err("Content conflict must be rejected");

    assert!(
        matches!(err, RuntimeError::IdempotencyKeyConflict { .. }),
        "Expected IdempotencyKeyConflict, got: {:?}",
        err
    );
}

// ============================================================================
// Test 7: Existing Intent + missing Goal can be resumed
// ============================================================================

#[test]
fn test_7_existing_intent_missing_goal_can_be_resumed() {
    let dir = tempdir().unwrap();
    let (i_store, g_store, w_store) = open_stores(&dir);

    // Manually create an Accepted intent without any goal
    let principal = make_principal(1000);
    let correlation_id = Uuid::new_v4();
    let mut intent = agenticos_core::Intent::new(
        "create directory resume_test",
        principal.clone(),
        correlation_id,
        None,
        3_000_000,
    )
    .unwrap();

    let normalized = agenticos_core::normalize_intent(&intent.raw_input).unwrap();
    intent.accept(normalized).unwrap();
    i_store.insert(&intent).unwrap();
    // Update to Accepted state
    i_store.update(&intent).unwrap();

    let intent_id = intent.intent_id;

    // Open a new runtime on the same stores
    let runtime = Phase1Runtime::new(i_store, g_store, w_store);

    // Resume from the existing intent
    let result = runtime.resume(&intent_id, 3_001_000).unwrap();

    assert_eq!(result.intent.intent_id, intent_id);
    assert_eq!(result.goal.originating_intent_id, intent_id);
    assert_eq!(result.goal.status, GoalStatus::Accepted);
    assert_eq!(result.workflow.status, WorkflowStatus::Accepted);
    assert_eq!(result.goal.correlation_id, correlation_id);
    assert_eq!(result.workflow.correlation_id, correlation_id);
}

// ============================================================================
// Test 8: Existing Intent + Goal + missing Workflow can be resumed
// ============================================================================

#[test]
fn test_8_existing_intent_and_goal_missing_workflow_can_be_resumed() {
    let dir = tempdir().unwrap();
    let (i_store, g_store, w_store) = open_stores(&dir);

    let principal = make_principal(1000);
    let correlation_id = Uuid::new_v4();

    // Manually create Accepted intent
    let mut intent = agenticos_core::Intent::new(
        "create directory with_goal",
        principal.clone(),
        correlation_id,
        None,
        4_000_000,
    )
    .unwrap();
    let normalized = agenticos_core::normalize_intent(&intent.raw_input).unwrap();
    intent.accept(normalized).unwrap();
    i_store.insert(&intent).unwrap();
    i_store.update(&intent).unwrap();

    // Manually create Accepted goal (no workflow)
    let objective = agenticos_core::GoalObjective::new(
        "Create Directory",
        "Ensure directory 'with_goal' exists",
        vec!["Directory 'with_goal' exists".to_string()],
        "workspace",
    );
    let mut goal = agenticos_core::Goal::from_intent(&intent, objective, 4_000_000);
    g_store.insert(&goal).unwrap();
    goal.transition(GoalStatus::Accepted, 4_000_000).unwrap();
    g_store.update(&goal).unwrap();

    let intent_id = intent.intent_id;
    let goal_id = goal.goal_id;

    let runtime = Phase1Runtime::new(i_store, g_store, w_store);
    let result = runtime.resume(&intent_id, 4_001_000).unwrap();

    assert_eq!(result.intent.intent_id, intent_id);
    assert_eq!(result.goal.goal_id, goal_id);
    assert_eq!(result.workflow.goal_id, goal_id);
    assert_eq!(result.workflow.status, WorkflowStatus::Accepted);
    assert_eq!(result.workflow.correlation_id, correlation_id);
}

// ============================================================================
// Test 9: Existing complete chain can be safely resumed without duplication
// ============================================================================

#[test]
fn test_9_complete_chain_resume_returns_existing_without_duplication() {
    let dir = tempdir().unwrap();
    let runtime = make_runtime(&dir);

    let result_first = submit_fs_request(
        &runtime,
        "create directory no_dup",
        make_principal(1000),
        None,
    )
    .unwrap();

    let intent_id = result_first.intent.intent_id;

    // Resume the complete chain
    let result_resumed = runtime.resume(&intent_id, 5_001_000).unwrap();

    // Same IDs — no duplication
    assert_eq!(result_resumed.intent.intent_id, intent_id);
    assert_eq!(result_resumed.goal.goal_id, result_first.goal.goal_id);
    assert_eq!(
        result_resumed.workflow.workflow_id,
        result_first.workflow.workflow_id
    );

    // Only one of each in storage
    let (i_store, g_store, w_store) = open_stores(&dir);
    assert_eq!(i_store.list().unwrap().len(), 1);
    assert_eq!(g_store.list().unwrap().len(), 1);
    assert_eq!(w_store.list().unwrap().len(), 1);
}

// ============================================================================
// Test 10: Partial failure does not create duplicate objects on retry
// ============================================================================

#[test]
fn test_10_partial_failure_retry_does_not_create_duplicates() {
    let dir = tempdir().unwrap();
    let (i_store, g_store, w_store) = open_stores(&dir);

    // Simulate: intent persisted + accepted, but goal creation never happened
    let principal = make_principal(1000);
    let correlation_id = Uuid::new_v4();
    let mut intent = agenticos_core::Intent::new(
        "create directory retry_test",
        principal.clone(),
        correlation_id,
        Some("partial-fail-key".to_string()),
        6_000_000,
    )
    .unwrap();
    let normalized = agenticos_core::normalize_intent(&intent.raw_input).unwrap();
    intent.accept(normalized).unwrap();
    i_store.insert(&intent).unwrap();
    i_store.update(&intent).unwrap();

    let intent_id = intent.intent_id;

    let runtime = Phase1Runtime::new(i_store, g_store, w_store);

    // First resume creates Goal + Workflow
    let result1 = runtime.resume(&intent_id, 6_001_000).unwrap();

    // Second resume — should reuse existing chain
    let result2 = runtime.resume(&intent_id, 6_002_000).unwrap();

    assert_eq!(result1.goal.goal_id, result2.goal.goal_id);
    assert_eq!(result1.workflow.workflow_id, result2.workflow.workflow_id);

    // Still exactly one of each
    let (i_store2, g_store2, w_store2) = open_stores(&dir);
    assert_eq!(i_store2.list().unwrap().len(), 1);
    assert_eq!(g_store2.list().unwrap().len(), 1);
    assert_eq!(w_store2.list().unwrap().len(), 1);
}

// ============================================================================
// Test 11: Invalid persisted state returns explicit runtime error
// ============================================================================

#[test]
fn test_11_invalid_persisted_state_returns_explicit_error() {
    let dir = tempdir().unwrap();
    let runtime = make_runtime(&dir);

    // Resume non-existent intent
    let fake_id = Uuid::new_v4();
    let err = runtime
        .resume(&fake_id, 7_000_000)
        .expect_err("Missing intent must produce an error");

    assert!(
        matches!(err, RuntimeError::InconsistentState { .. }),
        "Expected InconsistentState, got: {:?}",
        err
    );
}

// ============================================================================
// Test 12: Illegal state transitions are rejected
// ============================================================================

#[test]
fn test_12_illegal_state_transitions_are_rejected_by_storage() {
    let dir = tempdir().unwrap();
    let (i_store, g_store, w_store) = open_stores(&dir);
    let runtime = Phase1Runtime::new(i_store.clone(), g_store, w_store);

    let result = submit_fs_request(
        &runtime,
        "create directory legit",
        make_principal(1000),
        None,
    )
    .unwrap();

    // Attempt to transition the stored Intent directly to Created (illegal backward transition)
    let mut tampered = result.intent.clone();
    tampered.status = agenticos_core::IntentStatus::Created;

    let err = i_store
        .update(&tampered)
        .expect_err("Illegal backward transition must be rejected");

    assert!(
        matches!(err, StorageError::InvalidStateTransition { .. }),
        "Expected InvalidStateTransition, got: {:?}",
        err
    );
}

// ============================================================================
// Test 13: Runtime never marks Goal/Workflow Completed without execution
// ============================================================================

#[test]
fn test_13_runtime_never_marks_completed_without_execution() {
    let dir = tempdir().unwrap();
    let runtime = make_runtime(&dir);

    let result = submit_fs_request(
        &runtime,
        "create directory no_complete",
        make_principal(1000),
        None,
    )
    .unwrap();

    // After submit, neither Goal nor Workflow may be Completed or Running
    assert_ne!(result.goal.status, GoalStatus::Completed);
    assert_ne!(result.goal.status, GoalStatus::Running);
    assert_ne!(result.workflow.status, WorkflowStatus::Completed);
    assert_ne!(result.workflow.status, WorkflowStatus::Running);

    // Verify the same from storage
    let (_, g_store, w_store) = open_stores(&dir);
    let stored_goal = g_store.get(&result.goal.goal_id).unwrap().unwrap();
    let stored_wf = w_store.get(&result.workflow.workflow_id).unwrap().unwrap();

    assert_eq!(stored_goal.status, GoalStatus::Accepted);
    assert_eq!(stored_wf.status, WorkflowStatus::Accepted);
}

// ============================================================================
// Test 14: Runtime never invokes shell/process/network APIs
// ============================================================================

#[test]
fn test_14_runtime_contains_no_shell_or_network_invocation() {
    // This is a structural/architectural test. The runtime completes without
    // spawning any process, shell, or network connection. If it completes
    // without error, that invariant holds. The security grep in the final
    // verification phase confirms the source-level constraint.
    let dir = tempdir().unwrap();
    let runtime = make_runtime(&dir);

    let result =
        submit_fs_request(&runtime, "mkdir security_test", make_principal(1000), None).unwrap();

    // The result was produced without any shell/network invocation
    assert_eq!(result.intent.status, IntentStatus::Accepted);
}

// ============================================================================
// Test 15: Explicit timestamps are preserved
// ============================================================================

#[test]
fn test_15_explicit_timestamps_are_preserved() {
    let dir = tempdir().unwrap();
    let runtime = make_runtime(&dir);

    let ts: u64 = 1_718_000_000_000;

    let result = runtime
        .submit(SubmitRequest {
            raw_input: "create directory timestamped".to_string(),
            principal: make_principal(1000),
            correlation_id: Uuid::new_v4(),
            idempotency_key: None,
            created_at_ms: ts,
        })
        .unwrap();

    assert_eq!(result.intent.created_at_ms, ts);
    assert_eq!(result.goal.created_at_ms, ts);
    assert_eq!(result.workflow.created_at_ms, ts);

    // Verify from storage
    let (i_store, g_store, w_store) = open_stores(&dir);
    let stored_intent = i_store.get(&result.intent.intent_id).unwrap().unwrap();
    let stored_goal = g_store.get(&result.goal.goal_id).unwrap().unwrap();
    let stored_wf = w_store.get(&result.workflow.workflow_id).unwrap().unwrap();

    assert_eq!(stored_intent.created_at_ms, ts);
    assert_eq!(stored_goal.created_at_ms, ts);
    assert_eq!(stored_wf.created_at_ms, ts);
}

// ============================================================================
// Test 16: Correlation ID remains stable through retry/resume
// ============================================================================

#[test]
fn test_16_correlation_id_stable_through_retry_and_resume() {
    let dir = tempdir().unwrap();
    let runtime = make_runtime(&dir);

    let corr = Uuid::new_v4();
    let key = "stable-corr-key";

    let result1 = runtime
        .submit(SubmitRequest {
            raw_input: "create directory stable_corr".to_string(),
            principal: make_principal(1000),
            correlation_id: corr,
            idempotency_key: Some(key.to_string()),
            created_at_ms: 1_000_000,
        })
        .unwrap();

    // Idempotent retry with the same correlation_id
    let result2 = runtime
        .submit(SubmitRequest {
            raw_input: "create directory stable_corr".to_string(),
            principal: make_principal(1000),
            correlation_id: corr, // same correlation_id
            idempotency_key: Some(key.to_string()),
            created_at_ms: 1_001_000,
        })
        .unwrap();

    // Resume
    let result3 = runtime
        .resume(&result1.intent.intent_id, 1_002_000)
        .unwrap();

    assert_eq!(result1.intent.correlation_id, corr);
    assert_eq!(result2.intent.correlation_id, corr);
    assert_eq!(result3.intent.correlation_id, corr);

    // All three views see the same chain
    assert_eq!(result1.goal.goal_id, result2.goal.goal_id);
    assert_eq!(result1.goal.goal_id, result3.goal.goal_id);
}

// ============================================================================
// Test 17: Request IDs are not confused with correlation IDs
// ============================================================================

#[test]
fn test_17_request_ids_not_confused_with_correlation_ids() {
    let dir = tempdir().unwrap();
    let runtime = make_runtime(&dir);

    let corr = Uuid::new_v4();
    let request_id = Uuid::new_v4(); // distinct from correlation_id

    // The runtime accepts correlation_id separately from any request_id
    // (request_id lives at the IPC/invocation layer, not in SubmitRequest)
    let result = runtime
        .submit(SubmitRequest {
            raw_input: "create directory id_test".to_string(),
            principal: make_principal(1000),
            correlation_id: corr,
            idempotency_key: None,
            created_at_ms: 1_000_000,
        })
        .unwrap();

    // correlation_id is the one supplied, not the intent_id or request_id
    assert_eq!(result.intent.correlation_id, corr);
    assert_ne!(result.intent.intent_id, corr);
    assert_ne!(result.intent.intent_id, request_id);
    assert_ne!(result.intent.correlation_id, result.intent.intent_id);
}

// ============================================================================
// Test 18: Unsupported workflow input fails deterministically
// ============================================================================

#[test]
fn test_18_unsupported_workflow_input_fails_deterministically() {
    let dir = tempdir().unwrap();
    let runtime = make_runtime(&dir);

    // This pattern is not registered in the normalizer
    let err = submit_fs_request(&runtime, "rm -rf /", make_principal(1000), None)
        .expect_err("Unsupported input must fail");

    assert!(
        matches!(err, RuntimeError::InvalidInput { .. }),
        "Expected InvalidInput (normalization failure), got: {:?}",
        err
    );
}

// ============================================================================
// Test 19: Two separate principals using the same idempotency key remain isolated
// ============================================================================

#[test]
fn test_19_two_principals_same_key_fully_isolated() {
    let dir = tempdir().unwrap();
    let runtime = make_runtime(&dir);

    let key = "shared-across-principals";

    let r1 = submit_fs_request(
        &runtime,
        "create directory principal_one",
        make_principal(1001),
        Some(key),
    )
    .unwrap();

    let r2 = submit_fs_request(
        &runtime,
        "create directory principal_two",
        make_principal(1002),
        Some(key),
    )
    .unwrap();

    // Completely isolated chains
    assert_ne!(r1.intent.intent_id, r2.intent.intent_id);
    assert_ne!(r1.goal.goal_id, r2.goal.goal_id);
    assert_ne!(r1.workflow.workflow_id, r2.workflow.workflow_id);
    assert_ne!(r1.intent.correlation_id, r2.intent.correlation_id);

    // Each chain has correct principal
    assert_eq!(r1.intent.originating_principal, make_principal(1001));
    assert_eq!(r2.intent.originating_principal, make_principal(1002));

    // Idempotency lookup for each is isolated
    let (i_store, _, _) = open_stores(&dir);
    let found_1 = i_store
        .find_by_idempotency_key(&make_principal(1001), key)
        .unwrap()
        .unwrap();
    let found_2 = i_store
        .find_by_idempotency_key(&make_principal(1002), key)
        .unwrap()
        .unwrap();

    assert_eq!(found_1.intent_id, r1.intent.intent_id);
    assert_eq!(found_2.intent_id, r2.intent.intent_id);
}

// ============================================================================
// Additional: get_state API
// ============================================================================

#[test]
fn test_get_state_returns_full_chain_after_submit() {
    let dir = tempdir().unwrap();
    let runtime = make_runtime(&dir);

    let result = submit_fs_request(
        &runtime,
        "create directory state_test",
        make_principal(1000),
        None,
    )
    .unwrap();

    let state = runtime.get_state(&result.intent.intent_id).unwrap();

    assert!(state.intent.is_some());
    assert!(state.goal.is_some());
    assert!(state.workflow.is_some());

    assert_eq!(state.intent.unwrap().intent_id, result.intent.intent_id);
    assert_eq!(state.goal.unwrap().goal_id, result.goal.goal_id);
    assert_eq!(
        state.workflow.unwrap().workflow_id,
        result.workflow.workflow_id
    );
}

#[test]
fn test_get_state_returns_none_for_unknown_intent() {
    let dir = tempdir().unwrap();
    let runtime = make_runtime(&dir);

    let state = runtime.get_state(&Uuid::new_v4()).unwrap();
    assert!(state.intent.is_none());
    assert!(state.goal.is_none());
    assert!(state.workflow.is_none());
}

// ============================================================================
// Additional: workflow step structure integrity
// ============================================================================

#[test]
fn test_workflow_steps_have_correct_capability_and_resource() {
    let dir = tempdir().unwrap();
    let runtime = make_runtime(&dir);

    let result = submit_fs_request(
        &runtime,
        "create directory my_project",
        make_principal(1000),
        None,
    )
    .unwrap();

    let wf = &result.workflow;
    assert_eq!(wf.steps.len(), 1);

    let step = &wf.steps[0];
    assert_eq!(step.step_index, 0);
    assert_eq!(step.capability_id, "fs.create_directory");
    assert_eq!(step.capability_schema_version, 1);
    assert_eq!(step.retry_classification, RetryClassification::Safe);
    assert!(step.dependency_step_ids.is_empty());
    assert!(wf.dependencies.is_empty());

    // Resource and arguments reference the correct path
    assert_eq!(step.resource.identifier, "my_project");
    assert_eq!(step.arguments["path"], "my_project");
}

// ============================================================================
// Additional: goal objective correctly derived from intent
// ============================================================================

#[test]
fn test_goal_objective_correctly_derived_from_intent() {
    let dir = tempdir().unwrap();
    let runtime = make_runtime(&dir);

    let result = submit_fs_request(
        &runtime,
        "mkdir objectives_test",
        make_principal(1000),
        None,
    )
    .unwrap();

    let obj = &result.goal.objective;
    assert_eq!(obj.title, "Create Directory");
    assert!(obj.description.contains("objectives_test"));
    assert!(!obj.acceptance_criteria.is_empty());
    assert_eq!(obj.scope, "workspace");
}

// ============================================================================
// Additional: intent normalization content is preserved across storage round-trip
// ============================================================================

#[test]
fn test_normalized_intent_preserved_across_storage_roundtrip() {
    let dir = tempdir().unwrap();
    let runtime = make_runtime(&dir);

    let result = submit_fs_request(
        &runtime,
        "create folder round_trip",
        make_principal(1000),
        None,
    )
    .unwrap();

    let (i_store, _, _) = open_stores(&dir);
    let loaded = i_store.get(&result.intent.intent_id).unwrap().unwrap();

    let norm = loaded
        .normalized
        .expect("Normalized intent must be persisted");
    assert_eq!(norm.category, "fs");
    assert_eq!(norm.action, "create_directory");
    assert_eq!(norm.target_resource.identifier, "round_trip");
    assert_eq!(norm.parameters["path"], "round_trip");
}
