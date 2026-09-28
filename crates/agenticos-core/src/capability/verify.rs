//! Verification contracts and fixture evaluation (Phase 3.2 §22).
//!
//! Condition expressions (`CheckExpr`) are evaluated only over an injected
//! [`FilesystemView`]. Production `stat(2)`-backed views are deferred: no
//! host filesystem reads occur anywhere in Phase 3.2. Fixtures use the
//! in-memory [`MemView`].
//!
//! `{arg:NAME}` substitution in `path` fields is a fixture-scoped
//! convention (NON-NORMATIVE): `NAME` must be alphanumeric/underscore and
//! present in the request arguments object; strings substitute raw, other
//! values as compact JSON. The general precondition-expression grammar
//! remains TBD.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// One declared check expression (pre- or postcondition).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckExpr {
    /// Check name (fixtures: `path_exists`, `is_directory`, `absent`).
    pub check: String,
    /// Target path, optionally containing `{arg:NAME}` references.
    pub path: String,
    /// Expected outcome value.
    pub expected: serde_json::Value,
}

/// Observed file metadata behind a view lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileMeta {
    pub exists: bool,
    pub is_directory: bool,
}

/// Filesystem view: production `stat(2)` binding deferred to a future phase.
pub trait FilesystemView {
    fn lookup(&self, path: &str) -> Option<FileMeta>;
}

/// In-memory fixture view: exact-path map lookup only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemView {
    entries: HashMap<String, FileMeta>,
}

impl MemView {
    pub fn new(entries: HashMap<String, FileMeta>) -> Self {
        Self { entries }
    }

    pub fn file(path: &str) -> Self {
        let mut entries = HashMap::new();
        entries.insert(
            path.to_string(),
            FileMeta {
                exists: true,
                is_directory: false,
            },
        );
        Self { entries }
    }

    pub fn directory(path: &str) -> Self {
        let mut entries = HashMap::new();
        entries.insert(
            path.to_string(),
            FileMeta {
                exists: true,
                is_directory: true,
            },
        );
        Self { entries }
    }
}

impl FilesystemView for MemView {
    fn lookup(&self, path: &str) -> Option<FileMeta> {
        self.entries.get(path).copied()
    }
}

/// One evaluated condition result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConditionResult {
    pub check: String,
    pub path: String,
    pub expected: serde_json::Value,
    pub actual: serde_json::Value,
    pub status: ConditionStatus,
}

/// Pass/fail status of a single condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConditionStatus {
    Pass,
    Fail,
}

/// Verification result shape (`architecture.md` §4.9, shape only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationResult {
    pub verification_id: Uuid,
    pub goal_id: Uuid,
    pub is_satisfied: bool,
    pub condition_results: Vec<ConditionResult>,
    pub verification_duration_ms: u64,
}

/// Substitute `{arg:NAME}` references using the arguments object.
///
/// Unknown reference shapes fail the substitution (fail-closed at the
/// condition level, never silent).
fn substitute(path: &str, args: &serde_json::Value) -> Result<String, String> {
    let object = args
        .as_object()
        .ok_or_else(|| "arguments must be an object for substitution".to_string())?;
    let mut out = String::with_capacity(path.len());
    let mut rest = path;
    while let Some(start) = rest.find("{arg:") {
        out.push_str(&rest[..start]);
        let tail = &rest[start + 5..];
        let end = tail
            .find('}')
            .ok_or_else(|| format!("unclosed arg reference in '{path}'"))?;
        let name = &tail[..end];
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(format!("invalid arg reference '{{arg:{name}}}'"));
        }
        let value = object
            .get(name)
            .ok_or_else(|| format!("unknown arg reference '{{arg:{name}}}'"))?;
        match value {
            serde_json::Value::String(s) => out.push_str(s),
            other => out.push_str(
                &serde_json::to_string(other)
                    .map_err(|_| "arg serialization failed".to_string())?,
            ),
        }
        rest = &tail[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Evaluate one check expression against a view.
fn evaluate_check(
    expr: &CheckExpr,
    args: &serde_json::Value,
    view: &dyn FilesystemView,
) -> Result<ConditionResult, String> {
    let path = substitute(&expr.path, args)?;
    let meta = view.lookup(&path);
    let actual = match expr.check.as_str() {
        "path_exists" => serde_json::json!(meta.map(|m| m.exists).unwrap_or(false)),
        "is_directory" => {
            serde_json::json!(meta.map(|m| m.exists && m.is_directory).unwrap_or(false))
        }
        "absent" => serde_json::json!(meta.map(|m| !m.exists).unwrap_or(true)),
        other => return Err(format!("unknown check '{other}'")),
    };
    let status = if actual == expr.expected {
        ConditionStatus::Pass
    } else {
        ConditionStatus::Fail
    };
    Ok(ConditionResult {
        check: expr.check.clone(),
        path,
        expected: expr.expected.clone(),
        actual,
        status,
    })
}

/// Evaluate a condition list over a view.
///
/// Unknown checks or bad substitutions fail the *condition* (status
/// `Fail` with an error payload as `actual`), never the evaluation itself.
/// `is_satisfied` is true only when every condition passes; worker
/// self-reports play no role.
pub fn evaluate_conditions(
    exprs: &[CheckExpr],
    args: &serde_json::Value,
    view: &dyn FilesystemView,
) -> (Vec<ConditionResult>, bool) {
    let mut results = Vec::with_capacity(exprs.len());
    let mut satisfied = true;
    for expr in exprs {
        match evaluate_check(expr, args, view) {
            Ok(result) => {
                satisfied &= result.status == ConditionStatus::Pass;
                results.push(result);
            }
            Err(reason) => {
                satisfied = false;
                results.push(ConditionResult {
                    check: expr.check.clone(),
                    path: expr.path.clone(),
                    expected: expr.expected.clone(),
                    actual: serde_json::json!({"evaluation_error": reason}),
                    status: ConditionStatus::Fail,
                });
            }
        }
    }
    (results, satisfied)
}
