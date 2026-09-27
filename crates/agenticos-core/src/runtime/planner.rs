//! Deterministic workflow planner for Phase 1.
//!
//! Synthesizes a `Workflow` from a `NormalizedIntent` using only registered,
//! deterministic patterns. No shell execution, no LLM calls, no network access.
//!
//! The planner is the single place where `NormalizedIntent` action/category
//! is translated into a concrete `WorkflowStep` plan. Any unrecognised pattern
//! produces `RuntimeError::UnsupportedWorkflow` — never silently falls through.

use agenticos_contracts::{ResourceRef, RetryClassification};
use serde_json::json;
use uuid::Uuid;

use crate::goal::Goal;
use crate::intent::NormalizedIntent;
use crate::runtime::error::RuntimeError;
use crate::workflow::{StepDependency, Workflow, WorkflowStep};

/// Synthesizes a deterministic `Workflow` from a `NormalizedIntent` and its parent `Goal`.
///
/// # Determinism
/// For identical `NormalizedIntent` inputs the resulting `Workflow` structure
/// (capability IDs, arguments, dependency graph shape) is always identical.
/// Only `Uuid` values differ across invocations.
///
/// # Supported Patterns
/// - `fs::create_directory` → single-step workflow: `fs.create_directory`
///
/// # Errors
/// Returns `RuntimeError::UnsupportedWorkflow` for any unrecognised pattern.
pub fn synthesize_workflow(
    goal: &Goal,
    normalized: &NormalizedIntent,
    created_at_ms: u64,
) -> Result<Workflow, RuntimeError> {
    match (normalized.category.as_str(), normalized.action.as_str()) {
        ("fs", "create_directory") => {
            synthesize_fs_create_directory(goal, normalized, created_at_ms)
        }
        (category, action) => Err(RuntimeError::UnsupportedWorkflow {
            reason: format!(
                "No registered workflow plan for category '{}' action '{}'",
                category, action
            ),
        }),
    }
}

// ---------------------------------------------------------------------------
// Pattern implementations
// ---------------------------------------------------------------------------

/// Synthesizes a single-step `fs.create_directory` workflow.
///
/// Step layout:
/// ```text
/// Step 0: fs.create_directory   (no dependencies)
/// ```
fn synthesize_fs_create_directory(
    goal: &Goal,
    normalized: &NormalizedIntent,
    created_at_ms: u64,
) -> Result<Workflow, RuntimeError> {
    // Extract the path parameter from the normalized intent
    let path = normalized
        .parameters
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RuntimeError::UnsupportedWorkflow {
            reason: "fs.create_directory normalized intent is missing required 'path' parameter"
                .to_string(),
        })?;

    let resource = ResourceRef::path(path);

    let step = WorkflowStep::new(
        0,
        "fs.create_directory",
        1,
        resource,
        json!({ "path": path }),
        Vec::<Uuid>::new(), // no dependencies
        RetryClassification::Safe,
        10_000,
    );

    // No dependency edges for a single-step workflow
    let dependencies: Vec<StepDependency> = Vec::new();

    let workflow = Workflow::from_goal(goal, vec![step], dependencies, created_at_ms)
        .map_err(RuntimeError::DomainViolation)?;

    Ok(workflow)
}
