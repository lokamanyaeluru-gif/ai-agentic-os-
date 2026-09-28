//! Capability manifests, fixture manifests, and manifest validation.
//!
//! A manifest *describes* a capability for selection and planning. It never
//! implements host behavior. The three fixture manifests (`fs.read_file`,
//! `fs.create_directory`, `fs.delete_tree`) are test data only: they define
//! no binaries, no filesystem effects, and no deletion semantics.
//!
//! Load-time hygiene bounds below are NON-NORMATIVE implementation safety
//! defaults (same discipline as Phase 3.1), not architectural limits.

use super::error::CapabilityError;
use super::verify::CheckExpr;
use serde::{Deserialize, Serialize};

/// Maximum accepted label lengths (NON-NORMATIVE safety bounds).
pub const MAX_MANIFEST_ID_LEN: usize = 256;
pub const MAX_SCOPE_LABEL_LEN: usize = 256;
pub const MAX_MANIFEST_VERSION_LEN: usize = 64;

/// Capability risk tier per `security.md` §4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RiskTier {
    Tier0,
    Tier1,
    Tier2,
    Tier3,
    Tier4,
}

/// Sandbox construction profile per ADR-0003.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SandboxProfile {
    /// Dedicated worker + Landlock + seccomp data (low-risk).
    Profile1,
    /// Bubblewrap container + in-container Landlock/seccomp data (high-risk).
    Profile2,
}

/// Mutating-capability atomicity declaration (ADR-0007 cancellation §).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Atomicity {
    Atomic,
    NonAtomic,
}

/// Capability manifest: selection-time description only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityManifest {
    pub capability_id: String,
    pub manifest_version: String,
    pub capability_schema_version: u32,
    pub risk_tier: RiskTier,
    pub input_schema: serde_json::Value,
    pub output_schema: serde_json::Value,
    pub sandbox_profile: SandboxProfile,
    /// Purpose-bound binary name (symbolic in fixtures). Required Tier 2+.
    pub purpose_binary: Option<String>,
    /// Opaque scope labels matched by exact equality only (Decision 4).
    pub declared_read_scopes: Vec<String>,
    /// Opaque scope labels matched by exact equality only (Decision 4).
    pub declared_write_scopes: Vec<String>,
    /// Named local endpoint or None. Tier 0/1 must be None.
    pub network_need: Option<String>,
    pub atomicity: Atomicity,
    /// Opaque compensating-action reference or None (DSL TBD).
    pub compensation: Option<String>,
    pub retry_class: agenticos_contracts::RetryClassification,
    pub preconditions: Vec<CheckExpr>,
    pub postconditions: Vec<CheckExpr>,
}

/// Tier 4 identifiers are never registrable (deny-by-default, `security.md`).
const TIER4_DENY_IDS: &[&str] = &["sys.modify_config", "network.bind_socket", "sys.reboot"];

/// Full path segments that mark a generic/shell capability (load-time ban).
/// `run` is deliberately absent: ADR-0003's own purpose-specific examples
/// (`python.run`, `compiler.run`, `test.run`) use it legitimately.
const GENERIC_SEGMENTS: &[&str] = &[
    "shell",
    "sh",
    "bash",
    "zsh",
    "dash",
    "fish",
    "powershell",
    "cmd",
    "exec",
    "eval",
    "script",
    "command",
];

/// Shell binary stems banned from `purpose_binary` (exact stem match).
const SHELL_STEMS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "fish",
    "powershell",
    "cmd",
    "cmd.exe",
];

/// Shell metacharacters banned from `purpose_binary` hygiene.
const BINARY_METACHARS: &[char] = &['|', ';', '&', '$', '`', '(', ')', '<', '>', '\\', '/', ' '];

/// Validate a manifest for registry admission (fail-closed).
pub fn validate_manifest(manifest: &CapabilityManifest) -> Result<(), CapabilityError> {
    let invalid = |reason: &str| CapabilityError::InvalidManifest {
        reason: reason.to_string(),
    };
    if manifest.capability_id.is_empty() || manifest.capability_id.len() > MAX_MANIFEST_ID_LEN {
        return Err(invalid("capability_id must be 1..=256 chars"));
    }
    if manifest.capability_id.contains('\0') {
        return Err(invalid("capability_id contains NUL byte"));
    }
    let segments: Vec<&str> = manifest.capability_id.split('.').collect();
    if segments.len() < 2 || segments.iter().any(|segment| segment.is_empty()) {
        return Err(invalid(
            "capability_id must be dotted with non-empty segments",
        ));
    }
    for segment in &segments {
        if GENERIC_SEGMENTS.contains(segment) {
            return Err(invalid("capability_id declares generic execution"));
        }
    }
    if TIER4_DENY_IDS.contains(&manifest.capability_id.as_str()) {
        return Err(invalid("Tier 4 capability is never registrable"));
    }
    if manifest.risk_tier == RiskTier::Tier4 {
        return Err(invalid("Tier 4 capability is never registrable"));
    }
    if manifest.manifest_version.is_empty()
        || manifest.manifest_version.len() > MAX_MANIFEST_VERSION_LEN
    {
        return Err(invalid("manifest_version must be 1..=64 chars"));
    }
    validate_profile_consistency(manifest)?;
    validate_binary_binding(manifest)?;
    validate_network_declaration(manifest)?;
    validate_scopes(manifest)?;
    validate_schema_supported(&manifest.input_schema, "input_schema")?;
    validate_schema_supported(&manifest.output_schema, "output_schema")?;
    Ok(())
}

/// Tier/profile agreement: Tier 0/1 → Profile 1, Tier 2/3 → Profile 2.
fn validate_profile_consistency(manifest: &CapabilityManifest) -> Result<(), CapabilityError> {
    let expected = match manifest.risk_tier {
        RiskTier::Tier0 | RiskTier::Tier1 => SandboxProfile::Profile1,
        RiskTier::Tier2 | RiskTier::Tier3 => SandboxProfile::Profile2,
        RiskTier::Tier4 => {
            return Err(CapabilityError::InvalidManifest {
                reason: "Tier 4 capability is never registrable".to_string(),
            });
        }
    };
    if manifest.sandbox_profile != expected {
        return Err(CapabilityError::InvalidManifest {
            reason: "sandbox profile disagrees with risk tier".to_string(),
        });
    }
    Ok(())
}

/// Purpose-binary hygiene: required Tier 2+, never a shell, no metachars.
fn validate_binary_binding(manifest: &CapabilityManifest) -> Result<(), CapabilityError> {
    match (&manifest.risk_tier, &manifest.purpose_binary) {
        (RiskTier::Tier2 | RiskTier::Tier3, None) => Err(CapabilityError::InvalidManifest {
            reason: "Tier 2+ capabilities require a purpose_binary".to_string(),
        }),
        (_, None) => Ok(()),
        (_, Some(binary)) => {
            if binary.is_empty() || binary.len() > MAX_MANIFEST_ID_LEN {
                return Err(CapabilityError::InvalidManifest {
                    reason: "purpose_binary must be 1..=256 chars".to_string(),
                });
            }
            if binary.contains('\0') {
                return Err(CapabilityError::InvalidManifest {
                    reason: "purpose_binary contains NUL byte".to_string(),
                });
            }
            let stem = binary.rsplit('/').next().unwrap_or(binary);
            let stem = stem.strip_suffix(".exe").unwrap_or(stem);
            if SHELL_STEMS.contains(&stem) {
                return Err(CapabilityError::InvalidManifest {
                    reason: "purpose_binary names a shell interpreter".to_string(),
                });
            }
            if binary.chars().any(|c| BINARY_METACHARS.contains(&c)) {
                return Err(CapabilityError::InvalidManifest {
                    reason: "purpose_binary contains shell metacharacters".to_string(),
                });
            }
            Ok(())
        }
    }
}

/// Network declarations: Tier 0/1 must be None; others need a named endpoint.
fn validate_network_declaration(manifest: &CapabilityManifest) -> Result<(), CapabilityError> {
    match (&manifest.risk_tier, &manifest.network_need) {
        (RiskTier::Tier0 | RiskTier::Tier1, Some(_)) => Err(CapabilityError::InvalidManifest {
            reason: "Tier 0/1 capabilities must not declare network need".to_string(),
        }),
        (_, Some(endpoint)) if endpoint.is_empty() || endpoint.len() > MAX_SCOPE_LABEL_LEN => {
            Err(CapabilityError::InvalidManifest {
                reason: "network_need must be a non-empty named endpoint".to_string(),
            })
        }
        (_, Some(endpoint)) if endpoint.contains('\0') => Err(CapabilityError::InvalidManifest {
            reason: "network_need contains NUL byte".to_string(),
        }),
        _ => Ok(()),
    }
}

/// Scope labels: opaque symbolic strings, exact-match only (Decision 4).
/// Absolute paths and `..` segments are rejected: labels are NOT paths.
fn validate_scopes(manifest: &CapabilityManifest) -> Result<(), CapabilityError> {
    for scope in manifest
        .declared_read_scopes
        .iter()
        .chain(manifest.declared_write_scopes.iter())
    {
        if scope.is_empty() || scope.len() > MAX_SCOPE_LABEL_LEN {
            return Err(CapabilityError::InvalidManifest {
                reason: "scope label must be 1..=256 chars".to_string(),
            });
        }
        if scope.contains('\0') {
            return Err(CapabilityError::InvalidManifest {
                reason: "scope label contains NUL byte".to_string(),
            });
        }
        if scope.starts_with('/') || scope.contains("..") || scope.contains('\\') {
            return Err(CapabilityError::InvalidManifest {
                reason: "scope labels are symbolic; paths are not permitted".to_string(),
            });
        }
    }
    Ok(())
}

/// JSON-Schema subset supported by the binding-time checker: `type`,
/// `required`, `properties` (recursive), `minLength`, `maxLength`,
/// `minimum`, `maximum`. Any other keyword rejects the manifest
/// (fail-closed; schema expressiveness beyond this is deferred).
pub fn validate_schema_supported(
    schema: &serde_json::Value,
    name: &str,
) -> Result<(), CapabilityError> {
    fn walk(value: &serde_json::Value, path: &str) -> Result<(), String> {
        let object = value
            .as_object()
            .ok_or_else(|| format!("{path}: schema node must be an object"))?;
        for key in object.keys() {
            match key.as_str() {
                "type" | "required" | "properties" | "minLength" | "maxLength" | "minimum"
                | "maximum" => {}
                other => return Err(format!("{path}: unsupported keyword '{other}'")),
            }
        }
        if let Some(properties) = object.get("properties") {
            let map = properties
                .as_object()
                .ok_or_else(|| format!("{path}: properties must be an object"))?;
            for (name, subschema) in map {
                walk(subschema, &format!("{path}.properties.{name}"))?;
            }
        }
        Ok(())
    }
    walk(schema, name).map_err(|reason| CapabilityError::InvalidManifest { reason })
}

/// Check request arguments against a manifest input schema (supported subset).
pub fn check_arguments(
    schema: &serde_json::Value,
    args: &serde_json::Value,
) -> Result<(), CapabilityError> {
    check_node(schema, args, "arguments")
        .map_err(|reason| CapabilityError::SchemaViolation { reason })
}

fn check_node(
    schema: &serde_json::Value,
    value: &serde_json::Value,
    path: &str,
) -> Result<(), String> {
    if let Some(expected) = schema.get("type").and_then(|t| t.as_str()) {
        check_type(expected, value, path)?;
    }
    if let (Some(required), Some(object)) = (
        schema.get("required").and_then(|r| r.as_array()),
        value.as_object(),
    ) {
        for key in required {
            let key = key
                .as_str()
                .ok_or_else(|| format!("{path}: required key must be a string"))?;
            if !object.contains_key(key) {
                return Err(format!("{path}: missing required key '{key}'"));
            }
        }
    }
    if let (Some(properties), Some(object)) = (
        schema.get("properties").and_then(|p| p.as_object()),
        value.as_object(),
    ) {
        for (key, subschema) in properties {
            if let Some(field) = object.get(key) {
                check_node(subschema, field, &format!("{path}.{key}"))?;
            }
        }
    }
    if let (Some(min), Some(s)) = (
        schema.get("minLength").and_then(|n| n.as_u64()),
        value.as_str(),
    ) {
        if s.chars().count() < min as usize {
            return Err(format!("{path}: shorter than minLength"));
        }
    }
    if let (Some(max), Some(s)) = (
        schema.get("maxLength").and_then(|n| n.as_u64()),
        value.as_str(),
    ) {
        if s.chars().count() > max as usize {
            return Err(format!("{path}: longer than maxLength"));
        }
    }
    if let Some(minimum) = schema.get("minimum").and_then(|n| n.as_f64()) {
        let actual = value
            .as_f64()
            .ok_or_else(|| format!("{path}: minimum requires a number"))?;
        if actual < minimum {
            return Err(format!("{path}: below minimum"));
        }
    }
    if let Some(maximum) = schema.get("maximum").and_then(|n| n.as_f64()) {
        let actual = value
            .as_f64()
            .ok_or_else(|| format!("{path}: maximum requires a number"))?;
        if actual > maximum {
            return Err(format!("{path}: above maximum"));
        }
    }
    Ok(())
}

fn check_type(expected: &str, value: &serde_json::Value, path: &str) -> Result<(), String> {
    let matches = match expected {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        "integer" => value.as_u64().is_some() || value.as_i64().is_some(),
        "number" => value.as_f64().map(|f| f.is_finite()).unwrap_or(false),
        other => return Err(format!("{path}: unsupported type '{other}'")),
    };
    if matches {
        Ok(())
    } else {
        Err(format!("{path}: expected {expected}"))
    }
}

fn path_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "required": ["path"],
        "properties": {
            "path": {"type": "string", "minLength": 1, "maxLength": 1024}
        }
    })
}

/// Fixture manifest: `fs.read_file` (Tier 0, Profile 1). Test data only.
pub fn fixture_read_file() -> CapabilityManifest {
    CapabilityManifest {
        capability_id: "fs.read_file".to_string(),
        manifest_version: "v1".to_string(),
        capability_schema_version: 1,
        risk_tier: RiskTier::Tier0,
        input_schema: path_schema(),
        output_schema: serde_json::json!({"type": "object"}),
        sandbox_profile: SandboxProfile::Profile1,
        purpose_binary: None,
        declared_read_scopes: vec!["workspace".to_string()],
        declared_write_scopes: vec![],
        network_need: None,
        atomicity: Atomicity::Atomic,
        compensation: None,
        retry_class: agenticos_contracts::RetryClassification::Safe,
        preconditions: vec![super::verify::CheckExpr {
            check: "path_exists".to_string(),
            path: "{arg:path}".to_string(),
            expected: serde_json::json!(true),
        }],
        postconditions: vec![super::verify::CheckExpr {
            check: "path_exists".to_string(),
            path: "{arg:path}".to_string(),
            expected: serde_json::json!(true),
        }],
    }
}

/// Fixture manifest: `fs.create_directory` (Tier 1, Profile 1). Test data only.
pub fn fixture_create_directory() -> CapabilityManifest {
    CapabilityManifest {
        capability_id: "fs.create_directory".to_string(),
        manifest_version: "v1".to_string(),
        capability_schema_version: 1,
        risk_tier: RiskTier::Tier1,
        input_schema: path_schema(),
        output_schema: serde_json::json!({"type": "object"}),
        sandbox_profile: SandboxProfile::Profile1,
        purpose_binary: None,
        declared_read_scopes: vec!["workspace".to_string()],
        declared_write_scopes: vec!["workspace".to_string()],
        network_need: None,
        atomicity: Atomicity::Atomic,
        compensation: None,
        retry_class: agenticos_contracts::RetryClassification::Safe,
        preconditions: vec![],
        postconditions: vec![super::verify::CheckExpr {
            check: "is_directory".to_string(),
            path: "{arg:path}".to_string(),
            expected: serde_json::json!(true),
        }],
    }
}

/// Fixture manifest: `fs.delete_tree` (Tier 2, Profile 2, CONFIRM-gated).
/// Test data only: no deletion semantics, traversal rules, or recovery
/// behavior are defined anywhere in this codebase.
pub fn fixture_delete_tree() -> CapabilityManifest {
    CapabilityManifest {
        capability_id: "fs.delete_tree".to_string(),
        manifest_version: "v1".to_string(),
        capability_schema_version: 1,
        risk_tier: RiskTier::Tier2,
        input_schema: path_schema(),
        output_schema: serde_json::json!({"type": "object"}),
        sandbox_profile: SandboxProfile::Profile2,
        purpose_binary: Some("agenticos-fs-rmtree".to_string()),
        declared_read_scopes: vec!["workspace".to_string()],
        declared_write_scopes: vec!["workspace".to_string()],
        network_need: None,
        atomicity: Atomicity::NonAtomic,
        compensation: Some("agenticos-fs-restore".to_string()),
        retry_class: agenticos_contracts::RetryClassification::Never,
        preconditions: vec![super::verify::CheckExpr {
            check: "path_exists".to_string(),
            path: "{arg:path}".to_string(),
            expected: serde_json::json!(true),
        }],
        postconditions: vec![super::verify::CheckExpr {
            check: "absent".to_string(),
            path: "{arg:path}".to_string(),
            expected: serde_json::json!(true),
        }],
    }
}

/// All fixture manifests in deterministic order.
pub fn fixture_bundle_manifests() -> Vec<CapabilityManifest> {
    vec![
        fixture_read_file(),
        fixture_create_directory(),
        fixture_delete_tree(),
    ]
}
