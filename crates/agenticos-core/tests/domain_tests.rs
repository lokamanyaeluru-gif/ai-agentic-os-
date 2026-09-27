use agenticos_contracts::{
    ErrorCode, ErrorPayload, PrincipalContext, ResourceRef, RetryClassification,
};
use agenticos_core::{
    normalize_intent, DomainError, ExecutionOutcomeStatus, ExecutionResult, Goal, GoalObjective,
    GoalStatus, Intent, IntentStatus, NormalizedIntent, StepDependency, StepExecutionState,
    Workflow, WorkflowStatus, WorkflowStep, MAX_RAW_INPUT_LEN,
};
use serde_json::json;
use uuid::Uuid;

// ============================================================================
// 1. OBJECT CREATION & INPUT VALIDATION TESTS
// ============================================================================

#[test]
fn test_valid_intent_creation() {
    let principal = PrincipalContext::user(1000, 1000);
    let correlation_id = Uuid::new_v4();
    let idempotency_key = Some("idemp-key-001".to_string());
    let created_at_ms = 1_700_000_000_000;

    let intent = Intent::new(
        "Create a project folder called demo",
        principal.clone(),
        correlation_id,
        idempotency_key.clone(),
        created_at_ms,
    )
    .expect("Valid intent should be created successfully");

    assert_eq!(intent.raw_input, "Create a project folder called demo");
    assert_eq!(intent.originating_principal, principal);
    assert_eq!(intent.correlation_id, correlation_id);
    assert_eq!(intent.idempotency_key, idempotency_key);
    assert_eq!(intent.created_at_ms, created_at_ms);
    assert_eq!(intent.status, IntentStatus::Created);
    assert!(intent.normalized.is_none());
}

#[test]
fn test_invalid_intent_rejection_empty_input() {
    let principal = PrincipalContext::user(1000, 1000);
    let correlation_id = Uuid::new_v4();

    let err = Intent::new("", principal, correlation_id, None, 1000)
        .expect_err("Empty raw input must be rejected");

    assert_eq!(
        err,
        DomainError::InvalidRawInput {
            reason: "raw_input cannot be empty"
        }
    );
}

#[test]
fn test_invalid_intent_rejection_excessive_length() {
    let principal = PrincipalContext::user(1000, 1000);
    let correlation_id = Uuid::new_v4();
    let oversized = "a".repeat(MAX_RAW_INPUT_LEN + 1);

    let err = Intent::new(oversized, principal, correlation_id, None, 1000)
        .expect_err("Input exceeding 64 KiB ceiling must be rejected");

    assert_eq!(
        err,
        DomainError::InvalidRawInput {
            reason: "raw_input exceeds maximum length ceiling (64 KiB)"
        }
    );
}

#[test]
fn test_invalid_intent_rejection_null_bytes() {
    let principal = PrincipalContext::user(1000, 1000);
    let correlation_id = Uuid::new_v4();

    let err = Intent::new("invalid\0input", principal, correlation_id, None, 1000)
        .expect_err("Input containing null bytes must be rejected");

    assert_eq!(
        err,
        DomainError::InvalidRawInput {
            reason: "raw_input contains prohibited null bytes"
        }
    );
}

#[test]
fn test_goal_creation_from_intent() {
    let principal = PrincipalContext::user(1000, 1000);
    let correlation_id = Uuid::new_v4();
    let intent = Intent::new(
        "create directory demo",
        principal,
        correlation_id,
        None,
        1000,
    )
    .unwrap();

    let objective = GoalObjective::new(
        "Create Directory",
        "Ensure directory 'demo' exists",
        vec!["Directory exists and is readable".to_string()],
        "workspace",
    );

    let goal = Goal::from_intent(&intent, objective.clone(), 1050);

    assert_eq!(goal.correlation_id, intent.correlation_id);
    assert_eq!(goal.originating_intent_id, intent.intent_id);
    assert_eq!(goal.status, GoalStatus::Created);
    assert_eq!(goal.created_at_ms, 1050);
    assert_eq!(goal.updated_at_ms, 1050);
    assert_eq!(goal.objective, objective);
}

#[test]
fn test_execution_result_constructors() {
    let request_id = Uuid::new_v4();
    let correlation_id = Uuid::new_v4();
    let step_id = Uuid::new_v4();

    // Success outcome
    let success_res = ExecutionResult::success(
        request_id,
        correlation_id,
        step_id,
        json!({ "created": true, "path": "demo" }),
        2000,
        15,
    );
    assert_eq!(success_res.status, ExecutionOutcomeStatus::Success);
    assert!(success_res.output.is_some());
    assert!(success_res.error.is_none());
    assert_eq!(success_res.execution_duration_ms, 15);

    // Failure outcome
    let error_payload = ErrorPayload::new(
        ErrorCode::CapabilityExecutionFailed,
        "Failed to create directory",
        "fs-worker",
        RetryClassification::Safe,
    );
    let failure_res = ExecutionResult::failure(
        request_id,
        correlation_id,
        step_id,
        error_payload.clone(),
        2000,
        20,
    );
    assert_eq!(failure_res.status, ExecutionOutcomeStatus::Failure);
    assert!(failure_res.output.is_none());
    assert_eq!(failure_res.error, Some(error_payload));

    // Cancelled outcome
    let cancelled_res =
        ExecutionResult::cancelled(request_id, correlation_id, step_id, None, 2000, 5);
    assert_eq!(cancelled_res.status, ExecutionOutcomeStatus::Cancelled);
    assert!(cancelled_res.output.is_none());
    assert!(cancelled_res.error.is_none());
}

// ============================================================================
// 2. STATE MACHINE & TRANSITION INVARIANT TESTS
// ============================================================================

#[test]
fn test_intent_valid_lifecycle_transitions() {
    let principal = PrincipalContext::user(1000, 1000);
    let mut intent = Intent::new(
        "create directory demo",
        principal,
        Uuid::new_v4(),
        None,
        1000,
    )
    .unwrap();
    assert_eq!(intent.status, IntentStatus::Created);

    // Created -> Accepted
    let normalized = NormalizedIntent::new(
        "fs",
        "create_directory",
        ResourceRef::path("demo"),
        json!({ "path": "demo" }),
    );
    intent
        .accept(normalized.clone())
        .expect("Intent acceptance must succeed");
    assert_eq!(intent.status, IntentStatus::Accepted);
    assert_eq!(intent.normalized, Some(normalized));

    // Accepted -> Completed
    intent
        .transition(IntentStatus::Completed)
        .expect("Transition to Completed must succeed");
    assert_eq!(intent.status, IntentStatus::Completed);
}

#[test]
fn test_intent_cancellation_and_failure_transitions() {
    let principal = PrincipalContext::user(1000, 1000);

    // Created -> Failed
    let mut intent1 = Intent::new(
        "create directory demo",
        principal.clone(),
        Uuid::new_v4(),
        None,
        1000,
    )
    .unwrap();
    intent1
        .transition(IntentStatus::Failed)
        .expect("Created -> Failed must succeed");
    assert_eq!(intent1.status, IntentStatus::Failed);

    // Accepted -> Cancelled
    let mut intent2 = Intent::new(
        "create directory demo",
        principal,
        Uuid::new_v4(),
        None,
        1000,
    )
    .unwrap();
    intent2.transition(IntentStatus::Accepted).unwrap();
    intent2
        .transition(IntentStatus::Cancelled)
        .expect("Accepted -> Cancelled must succeed");
    assert_eq!(intent2.status, IntentStatus::Cancelled);
}

#[test]
fn test_intent_invalid_transitions_rejected() {
    let principal = PrincipalContext::user(1000, 1000);
    let mut intent = Intent::new(
        "create directory demo",
        principal,
        Uuid::new_v4(),
        None,
        1000,
    )
    .unwrap();

    // Created -> Completed (illegal: must be Accepted first)
    let err = intent
        .transition(IntentStatus::Completed)
        .expect_err("Created -> Completed must fail");
    assert_eq!(
        err,
        DomainError::InvalidStateTransition {
            entity: "Intent",
            from: "Created".to_string(),
            to: "Completed".to_string(),
        }
    );

    // Created -> Cancelled (illegal: can only cancel Accepted)
    let err = intent
        .transition(IntentStatus::Cancelled)
        .expect_err("Created -> Cancelled must fail");
    assert_eq!(
        err,
        DomainError::InvalidStateTransition {
            entity: "Intent",
            from: "Created".to_string(),
            to: "Cancelled".to_string(),
        }
    );
}

#[test]
fn test_intent_terminal_state_protection() {
    let principal = PrincipalContext::user(1000, 1000);

    // Completed is terminal
    let mut intent = Intent::new(
        "create directory demo",
        principal,
        Uuid::new_v4(),
        None,
        1000,
    )
    .unwrap();
    intent.transition(IntentStatus::Accepted).unwrap();
    intent.transition(IntentStatus::Completed).unwrap();

    let err = intent
        .transition(IntentStatus::Accepted)
        .expect_err("Transition out of Completed must be rejected");
    assert_eq!(
        err,
        DomainError::TerminalState {
            entity: "Intent",
            state: "Completed".to_string(),
        }
    );

    let err = intent
        .transition(IntentStatus::Failed)
        .expect_err("Transition out of Completed must be rejected");
    assert_eq!(
        err,
        DomainError::TerminalState {
            entity: "Intent",
            state: "Completed".to_string(),
        }
    );
}

#[test]
fn test_goal_valid_lifecycle_transitions() {
    let principal = PrincipalContext::user(1000, 1000);
    let intent = Intent::new(
        "create directory demo",
        principal,
        Uuid::new_v4(),
        None,
        1000,
    )
    .unwrap();
    let objective = GoalObjective::new(
        "Title",
        "Description",
        vec!["Crit".to_string()],
        "workspace",
    );
    let mut goal = Goal::from_intent(&intent, objective, 1000);

    // Created -> Accepted
    goal.transition(GoalStatus::Accepted, 1100).unwrap();
    assert_eq!(goal.status, GoalStatus::Accepted);
    assert_eq!(goal.updated_at_ms, 1100);

    // Accepted -> Running
    goal.transition(GoalStatus::Running, 1200).unwrap();
    assert_eq!(goal.status, GoalStatus::Running);
    assert_eq!(goal.updated_at_ms, 1200);

    // Running -> Completed
    goal.transition(GoalStatus::Completed, 1300).unwrap();
    assert_eq!(goal.status, GoalStatus::Completed);
    assert_eq!(goal.updated_at_ms, 1300);

    // Terminal check
    let err = goal
        .transition(GoalStatus::Running, 1400)
        .expect_err("Transition out of Completed must fail");
    assert_eq!(
        err,
        DomainError::TerminalState {
            entity: "Goal",
            state: "Completed".to_string(),
        }
    );
}

#[test]
fn test_goal_invalid_transitions() {
    let principal = PrincipalContext::user(1000, 1000);
    let intent = Intent::new(
        "create directory demo",
        principal,
        Uuid::new_v4(),
        None,
        1000,
    )
    .unwrap();
    let objective = GoalObjective::new(
        "Title",
        "Description",
        vec!["Crit".to_string()],
        "workspace",
    );
    let mut goal = Goal::from_intent(&intent, objective, 1000);

    // Created -> Running (illegal: must go through Accepted)
    let err = goal
        .transition(GoalStatus::Running, 1100)
        .expect_err("Created -> Running must fail");
    assert_eq!(
        err,
        DomainError::InvalidStateTransition {
            entity: "Goal",
            from: "Created".to_string(),
            to: "Running".to_string(),
        }
    );

    // Created -> Completed (illegal)
    let err = goal
        .transition(GoalStatus::Completed, 1100)
        .expect_err("Created -> Completed must fail");
    assert_eq!(
        err,
        DomainError::InvalidStateTransition {
            entity: "Goal",
            from: "Created".to_string(),
            to: "Completed".to_string(),
        }
    );
}

#[test]
fn test_workflow_step_state_machine() {
    let mut step = WorkflowStep::new(
        0,
        "fs.create_directory",
        1,
        ResourceRef::path("demo"),
        json!({ "path": "demo" }),
        vec![],
        RetryClassification::Safe,
        10000,
    );
    assert_eq!(step.state, StepExecutionState::Created);

    // Created -> Waiting
    step.transition(StepExecutionState::Waiting).unwrap();
    assert_eq!(step.state, StepExecutionState::Waiting);

    // Waiting -> Running
    step.transition(StepExecutionState::Running).unwrap();
    assert_eq!(step.state, StepExecutionState::Running);

    // Running -> Completed
    step.transition(StepExecutionState::Completed).unwrap();
    assert_eq!(step.state, StepExecutionState::Completed);

    // Terminal protection
    let err = step
        .transition(StepExecutionState::Running)
        .expect_err("Transition out of Completed must fail");
    assert_eq!(
        err,
        DomainError::TerminalState {
            entity: "WorkflowStep",
            state: "Completed".to_string(),
        }
    );
}

// ============================================================================
// 3. WORKFLOW DAG & DEPENDENCY INVARIANT TESTS
// ============================================================================

fn create_test_goal() -> Goal {
    let principal = PrincipalContext::user(1000, 1000);
    let intent = Intent::new(
        "create directory demo",
        principal,
        Uuid::new_v4(),
        None,
        1000,
    )
    .unwrap();
    let objective = GoalObjective::new(
        "Title",
        "Description",
        vec!["Crit".to_string()],
        "workspace",
    );
    Goal::from_intent(&intent, objective, 1000)
}

#[test]
fn test_workflow_linear_dag_success() {
    let goal = create_test_goal();

    let step1 = WorkflowStep::new(
        0,
        "fs.create_directory",
        1,
        ResourceRef::path("demo"),
        json!({ "path": "demo" }),
        vec![],
        RetryClassification::Safe,
        10000,
    );
    let step1_id = step1.step_id;

    let step2 = WorkflowStep::new(
        1,
        "fs.create_file",
        1,
        ResourceRef::path("demo/init.txt"),
        json!({ "path": "demo/init.txt" }),
        vec![step1_id],
        RetryClassification::Safe,
        10000,
    );
    let step2_id = step2.step_id;

    let dependencies = vec![StepDependency::new(step2_id, step1_id)];

    let mut workflow = Workflow::from_goal(&goal, vec![step1, step2], dependencies, 1000)
        .expect("Valid linear DAG must be accepted");

    assert_eq!(workflow.correlation_id, goal.correlation_id);
    assert_eq!(workflow.goal_id, goal.goal_id);
    assert_eq!(workflow.status, WorkflowStatus::Created);

    workflow.transition(WorkflowStatus::Accepted, 1100).unwrap();
    workflow.transition(WorkflowStatus::Running, 1200).unwrap();
    workflow
        .transition(WorkflowStatus::Completed, 1300)
        .unwrap();
}

#[test]
fn test_workflow_branching_diamond_dag_success() {
    let goal = create_test_goal();

    // A -> B, A -> C, B -> D, C -> D
    let step_a = WorkflowStep::new(
        0,
        "cap.a",
        1,
        ResourceRef::path("a"),
        json!({}),
        vec![],
        RetryClassification::Safe,
        1000,
    );
    let step_a_id = step_a.step_id;

    let step_b = WorkflowStep::new(
        1,
        "cap.b",
        1,
        ResourceRef::path("b"),
        json!({}),
        vec![step_a_id],
        RetryClassification::Safe,
        1000,
    );
    let step_b_id = step_b.step_id;

    let step_c = WorkflowStep::new(
        2,
        "cap.c",
        1,
        ResourceRef::path("c"),
        json!({}),
        vec![step_a_id],
        RetryClassification::Safe,
        1000,
    );
    let step_c_id = step_c.step_id;

    let mut step_d_deps = vec![step_b_id, step_c_id];
    step_d_deps.sort();

    let step_d = WorkflowStep::new(
        3,
        "cap.d",
        1,
        ResourceRef::path("d"),
        json!({}),
        step_d_deps,
        RetryClassification::Safe,
        1000,
    );
    let step_d_id = step_d.step_id;

    let dependencies = vec![
        StepDependency::new(step_b_id, step_a_id),
        StepDependency::new(step_c_id, step_a_id),
        StepDependency::new(step_d_id, step_b_id),
        StepDependency::new(step_d_id, step_c_id),
    ];

    let workflow = Workflow::from_goal(
        &goal,
        vec![step_a, step_b, step_c, step_d],
        dependencies,
        1000,
    );
    assert!(workflow.is_ok(), "Diamond DAG must be valid");
}

#[test]
fn test_workflow_rejection_direct_cycle() {
    let goal = create_test_goal();

    let step1_id = Uuid::new_v4();
    let step2_id = Uuid::new_v4();

    let mut step1 = WorkflowStep::new(
        0,
        "cap.a",
        1,
        ResourceRef::path("a"),
        json!({}),
        vec![step2_id],
        RetryClassification::Safe,
        1000,
    );
    step1.step_id = step1_id;

    let mut step2 = WorkflowStep::new(
        1,
        "cap.b",
        1,
        ResourceRef::path("b"),
        json!({}),
        vec![step1_id],
        RetryClassification::Safe,
        1000,
    );
    step2.step_id = step2_id;

    // Cycle: 1 depends on 2, 2 depends on 1
    let dependencies = vec![
        StepDependency::new(step1_id, step2_id),
        StepDependency::new(step2_id, step1_id),
    ];

    let err = Workflow::from_goal(&goal, vec![step1, step2], dependencies, 1000)
        .expect_err("Direct cycle must be rejected");

    match err {
        DomainError::DependencyCycle { step_id } => {
            assert!(step_id == step1_id || step_id == step2_id);
        }
        other => panic!("Expected DependencyCycle, got: {:?}", other),
    }
}

#[test]
fn test_workflow_rejection_3_step_cycle() {
    let goal = create_test_goal();

    let s1 = Uuid::new_v4();
    let s2 = Uuid::new_v4();
    let s3 = Uuid::new_v4();

    let mut step1 = WorkflowStep::new(
        0,
        "c1",
        1,
        ResourceRef::path("1"),
        json!({}),
        vec![s3],
        RetryClassification::Safe,
        1000,
    );
    step1.step_id = s1;

    let mut step2 = WorkflowStep::new(
        1,
        "c2",
        1,
        ResourceRef::path("2"),
        json!({}),
        vec![s1],
        RetryClassification::Safe,
        1000,
    );
    step2.step_id = s2;

    let mut step3 = WorkflowStep::new(
        2,
        "c3",
        1,
        ResourceRef::path("3"),
        json!({}),
        vec![s2],
        RetryClassification::Safe,
        1000,
    );
    step3.step_id = s3;

    // 1 -> 2 -> 3 -> 1
    let dependencies = vec![
        StepDependency::new(s2, s1),
        StepDependency::new(s3, s2),
        StepDependency::new(s1, s3),
    ];

    let err = Workflow::from_goal(&goal, vec![step1, step2, step3], dependencies, 1000)
        .expect_err("3-step cycle must be rejected");

    assert!(matches!(err, DomainError::DependencyCycle { .. }));
}

#[test]
fn test_workflow_rejection_self_dependency() {
    let goal = create_test_goal();

    let step = WorkflowStep::new(
        0,
        "c1",
        1,
        ResourceRef::path("1"),
        json!({}),
        vec![],
        RetryClassification::Safe,
        1000,
    );
    let step_id = step.step_id;

    let dependencies = vec![StepDependency::new(step_id, step_id)];

    let err = Workflow::from_goal(&goal, vec![step], dependencies, 1000)
        .expect_err("Self-dependency must be rejected");

    assert_eq!(err, DomainError::SelfDependency { step_id });
}

#[test]
fn test_workflow_rejection_duplicate_dependency_edge() {
    let goal = create_test_goal();

    let step1 = WorkflowStep::new(
        0,
        "c1",
        1,
        ResourceRef::path("1"),
        json!({}),
        vec![],
        RetryClassification::Safe,
        1000,
    );
    let step1_id = step1.step_id;

    let step2 = WorkflowStep::new(
        1,
        "c2",
        1,
        ResourceRef::path("2"),
        json!({}),
        vec![step1_id],
        RetryClassification::Safe,
        1000,
    );
    let step2_id = step2.step_id;

    let dependencies = vec![
        StepDependency::new(step2_id, step1_id),
        StepDependency::new(step2_id, step1_id),
    ];

    let err = Workflow::from_goal(&goal, vec![step1, step2], dependencies, 1000)
        .expect_err("Duplicate dependency edge must be rejected");

    assert_eq!(
        err,
        DomainError::DuplicateDependency {
            step_id: step2_id,
            depends_on_step_id: step1_id
        }
    );
}

#[test]
fn test_workflow_rejection_missing_step_reference() {
    let goal = create_test_goal();

    let step1 = WorkflowStep::new(
        0,
        "c1",
        1,
        ResourceRef::path("1"),
        json!({}),
        vec![],
        RetryClassification::Safe,
        1000,
    );
    let step1_id = step1.step_id;
    let non_existent_step = Uuid::new_v4();

    let dependencies = vec![StepDependency::new(step1_id, non_existent_step)];

    let err = Workflow::from_goal(&goal, vec![step1], dependencies, 1000)
        .expect_err("Reference to non-existent step must be rejected");

    assert_eq!(
        err,
        DomainError::StepNotFound {
            step_id: non_existent_step
        }
    );
}

#[test]
fn test_workflow_rejection_dependency_cache_inconsistency() {
    let goal = create_test_goal();

    let step1 = WorkflowStep::new(
        0,
        "c1",
        1,
        ResourceRef::path("1"),
        json!({}),
        vec![],
        RetryClassification::Safe,
        1000,
    );
    let step1_id = step1.step_id;

    // Notice: step2 cache declares vec![], but authoritative dependencies declares step2 depends on step1
    let step2 = WorkflowStep::new(
        1,
        "c2",
        1,
        ResourceRef::path("2"),
        json!({}),
        vec![],
        RetryClassification::Safe,
        1000,
    );
    let step2_id = step2.step_id;

    let dependencies = vec![StepDependency::new(step2_id, step1_id)];

    let err = Workflow::from_goal(&goal, vec![step1, step2], dependencies, 1000)
        .expect_err("Inconsistency between step cache and workflow dependencies must be rejected");

    assert_eq!(
        err,
        DomainError::DependencyInconsistency { step_id: step2_id }
    );
}

// ============================================================================
// 4. IDEMPOTENCY KEY & CORRELATION ID HANDLING
// ============================================================================

#[test]
fn test_idempotency_key_preservation_and_scoping() {
    let principal = PrincipalContext::user(1000, 1000);
    let correlation_id = Uuid::new_v4();
    let key = "client-dedup-987".to_string();

    let intent = Intent::new(
        "mkdir demo",
        principal.clone(),
        correlation_id,
        Some(key.clone()),
        1000,
    )
    .unwrap();

    assert_eq!(intent.idempotency_key, Some(key.clone()));
    assert_eq!(intent.originating_principal, principal);
    assert_eq!(intent.correlation_id, correlation_id);

    // Intent without idempotency key
    let intent_no_key = Intent::new("mkdir demo2", principal, correlation_id, None, 1000).unwrap();
    assert_eq!(intent_no_key.idempotency_key, None);
    // Correlation ID can be shared for causal trees without conflating idempotency keys
    assert_eq!(intent_no_key.correlation_id, correlation_id);
}

#[test]
fn test_correlation_id_propagation_across_subsystems() {
    let principal = PrincipalContext::user(1000, 1000);
    let root_correlation_id = Uuid::new_v4();

    let intent = Intent::new(
        "create directory demo",
        principal,
        root_correlation_id,
        Some("idem-1".to_string()),
        1000,
    )
    .unwrap();
    assert_eq!(intent.correlation_id, root_correlation_id);

    let objective = GoalObjective::new(
        "Create Directory",
        "demo",
        vec!["exists".to_string()],
        "workspace",
    );
    let goal = Goal::from_intent(&intent, objective, 1100);
    assert_eq!(goal.correlation_id, root_correlation_id);
    assert_eq!(goal.originating_intent_id, intent.intent_id);

    let step = WorkflowStep::new(
        0,
        "fs.create_directory",
        1,
        ResourceRef::path("demo"),
        json!({}),
        vec![],
        RetryClassification::Safe,
        1000,
    );
    let step_id = step.step_id;
    let workflow = Workflow::from_goal(&goal, vec![step], vec![], 1200).unwrap();
    assert_eq!(workflow.correlation_id, root_correlation_id);
    assert_eq!(workflow.goal_id, goal.goal_id);

    let result = ExecutionResult::success(
        Uuid::new_v4(),
        workflow.correlation_id,
        step_id,
        json!({ "created": true }),
        1300,
        12,
    );
    assert_eq!(result.correlation_id, root_correlation_id);
}

// ============================================================================
// 5. SERIALIZATION & DENY_UNKNOWN_FIELDS TESTS
// ============================================================================

#[test]
fn test_serde_roundtrip_intent() {
    let principal = PrincipalContext::user(1000, 1000);
    let mut intent = Intent::new(
        "create a project folder called demo",
        principal,
        Uuid::new_v4(),
        Some("key-123".to_string()),
        1000,
    )
    .unwrap();

    let normalized = normalize_intent(&intent.raw_input).unwrap();
    intent.accept(normalized).unwrap();

    let json_str = serde_json::to_string(&intent).expect("Serialization must succeed");
    let deserialized: Intent =
        serde_json::from_str(&json_str).expect("Deserialization must succeed");

    assert_eq!(intent, deserialized);
}

#[test]
fn test_serde_deny_unknown_fields_intent() {
    let mut valid_intent_json = serde_json::to_value(
        Intent::new(
            "create directory demo",
            PrincipalContext::user(1000, 1000),
            Uuid::new_v4(),
            None,
            1000,
        )
        .unwrap(),
    )
    .unwrap();

    // Inject unknown field
    valid_intent_json
        .as_object_mut()
        .unwrap()
        .insert("unrecognized_field".to_string(), json!("unexpected"));

    let err = serde_json::from_value::<Intent>(valid_intent_json)
        .expect_err("Deserialization with unknown fields must be rejected");

    assert!(err
        .to_string()
        .contains("unknown field `unrecognized_field`"));
}

#[test]
fn test_serde_deny_unknown_fields_goal() {
    let goal = create_test_goal();
    let mut goal_json = serde_json::to_value(&goal).unwrap();

    goal_json
        .as_object_mut()
        .unwrap()
        .insert("malicious_extra".to_string(), json!(true));

    let err = serde_json::from_value::<Goal>(goal_json)
        .expect_err("Deserialization with unknown fields must fail");

    assert!(err.to_string().contains("unknown field `malicious_extra`"));
}

#[test]
fn test_serde_deny_unknown_fields_workflow() {
    let goal = create_test_goal();
    let step = WorkflowStep::new(
        0,
        "cap",
        1,
        ResourceRef::path("p"),
        json!({}),
        vec![],
        RetryClassification::Safe,
        1000,
    );
    let workflow = Workflow::from_goal(&goal, vec![step], vec![], 1000).unwrap();

    let mut wf_json = serde_json::to_value(&workflow).unwrap();
    wf_json
        .as_object_mut()
        .unwrap()
        .insert("extra_prop".to_string(), json!(123));

    let err = serde_json::from_value::<Workflow>(wf_json)
        .expect_err("Deserialization with unknown fields must fail");

    assert!(err.to_string().contains("unknown field `extra_prop`"));
}

// ============================================================================
// 6. DETERMINISTIC NORMALIZATION TESTS
// ============================================================================

#[test]
fn test_deterministic_normalization() {
    let input = "Create a project folder called demo";

    let n1 = normalize_intent(input).expect("Normalization must succeed");
    let n2 = normalize_intent(input).expect("Normalization must succeed");

    assert_eq!(n1, n2);
    assert_eq!(n1.category, "fs");
    assert_eq!(n1.action, "create_directory");
    assert_eq!(n1.target_resource, ResourceRef::path("demo"));
    assert_eq!(n1.parameters, json!({ "path": "demo" }));

    // Verify bit-for-bit serialized deterministic identity
    let j1 = serde_json::to_string(&n1).unwrap();
    let j2 = serde_json::to_string(&n2).unwrap();
    assert_eq!(j1, j2);
}

#[test]
fn test_normalization_alternative_directory_patterns() {
    let patterns = [
        "create directory my_project",
        "create folder my_project",
        "mkdir my_project",
        "create a directory my_project",
        "Create a folder called 'my_project'",
    ];

    for pat in patterns {
        let normalized =
            normalize_intent(pat).unwrap_or_else(|e| panic!("Pattern '{}' failed: {:?}", pat, e));
        assert_eq!(normalized.category, "fs");
        assert_eq!(normalized.action, "create_directory");
        assert_eq!(normalized.target_resource, ResourceRef::path("my_project"));
        assert_eq!(normalized.parameters, json!({ "path": "my_project" }));
    }
}

#[test]
fn test_normalization_unrecognized_pattern_fails() {
    let err = normalize_intent("delete system root").expect_err("Unregistered pattern must fail");
    assert!(matches!(err, DomainError::NormalizationFailed { .. }));
}
