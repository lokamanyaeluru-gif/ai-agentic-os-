//! Deterministic intent normalization for Phase 1.
//!
//! Aligned with Phase 1.0 specification and ADR-0001 (Deterministic Operation).

use agenticos_contracts::ResourceRef;

use crate::error::DomainError;
use crate::intent::NormalizedIntent;

/// Deterministically parses and normalizes human/caller input into typed `NormalizedIntent`.
///
/// Phase 1 supports deterministic filesystem directory creation patterns.
/// The normalizer is strictly deterministic: running identical input strings
/// produces bit-for-bit identical `NormalizedIntent` instances without variance.
pub fn normalize_intent(raw_input: &str) -> Result<NormalizedIntent, DomainError> {
    let trimmed = raw_input.trim();

    // Check lowercase representation for matching patterns
    let lower = trimmed.to_lowercase();

    // Pattern 1: "create a project folder called <name>" / "create project folder called <name>"
    if let Some(rest) = lower
        .strip_prefix("create a project folder called ")
        .or_else(|| lower.strip_prefix("create project folder called "))
        .or_else(|| lower.strip_prefix("create folder called "))
        .or_else(|| lower.strip_prefix("create a folder called "))
    {
        let folder_name = rest.trim().trim_matches('\'').trim_matches('"').trim();
        if folder_name.is_empty() {
            return Err(DomainError::NormalizationFailed {
                reason: "Empty folder name in create folder command".to_string(),
            });
        }
        return Ok(NormalizedIntent::new(
            "fs",
            "create_directory",
            ResourceRef::path(folder_name),
            serde_json::json!({ "path": folder_name }),
        ));
    }

    // Pattern 2: "create directory <name>" / "create a directory <name>"
    if let Some(rest) = lower
        .strip_prefix("create a directory ")
        .or_else(|| lower.strip_prefix("create directory "))
        .or_else(|| lower.strip_prefix("create folder "))
        .or_else(|| lower.strip_prefix("create a folder "))
        .or_else(|| lower.strip_prefix("mkdir "))
    {
        let folder_name = rest.trim().trim_matches('\'').trim_matches('"').trim();
        if folder_name.is_empty() {
            return Err(DomainError::NormalizationFailed {
                reason: "Empty directory name in command".to_string(),
            });
        }
        return Ok(NormalizedIntent::new(
            "fs",
            "create_directory",
            ResourceRef::path(folder_name),
            serde_json::json!({ "path": folder_name }),
        ));
    }

    Err(DomainError::NormalizationFailed {
        reason: format!("Unrecognized command pattern: '{}'", trimmed),
    })
}
