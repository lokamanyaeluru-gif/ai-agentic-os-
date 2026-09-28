//! In-memory capability registry over declarative bundle data.
//!
//! No SQLite database is created (Decision 4 / ADR-0006 ownership
//! discipline). The registry indexes validated manifests with deterministic
//! insertion-order iteration; lookup is exact-match on
//! `(capability_id, capability_schema_version)` with no fallback.

use super::error::CapabilityError;
use super::manifest::{validate_manifest, CapabilityManifest};
use std::collections::HashMap;

/// Declarative registry bundle: one manifest document per capability version.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ManifestBundle {
    pub manifests: Vec<CapabilityManifest>,
}

impl ManifestBundle {
    pub fn new(manifests: Vec<CapabilityManifest>) -> Self {
        Self { manifests }
    }

    /// Fixture bundle: the three approved fixture manifests, in order.
    pub fn fixtures() -> Self {
        Self::new(super::manifest::fixture_bundle_manifests())
    }
}

/// In-memory capability registry (selection plane only, never authorizing).
#[derive(Debug, Clone, Default)]
pub struct CapabilityRegistry {
    entries: Vec<CapabilityManifest>,
    index: HashMap<(String, u32), usize>,
}

impl CapabilityRegistry {
    /// Load and validate a bundle. Any invalid entry — or any duplicate
    /// `(capability_id, schema_version)` pair — rejects the whole bundle.
    pub fn load(bundle: ManifestBundle) -> Result<Self, CapabilityError> {
        let mut registry = Self::default();
        for manifest in bundle.manifests {
            validate_manifest(&manifest)?;
            let key = (
                manifest.capability_id.clone(),
                manifest.capability_schema_version,
            );
            if registry.index.contains_key(&key) {
                return Err(CapabilityError::InvalidManifest {
                    reason: format!("duplicate manifest for {} v{}", key.0, key.1),
                });
            }
            registry.index.insert(key, registry.entries.len());
            registry.entries.push(manifest);
        }
        Ok(registry)
    }

    /// Empty registry (no capabilities known).
    pub fn empty() -> Self {
        Self::default()
    }

    /// Fixture registry: the three approved fixture manifests.
    pub fn fixtures() -> Result<Self, CapabilityError> {
        Self::load(ManifestBundle::fixtures())
    }

    /// Exact-match lookup. Unknown ID or unknown version yields
    /// [`CapabilityError::UnknownCapability`] — never a silent fallback.
    pub fn get(
        &self,
        capability_id: &str,
        capability_schema_version: u32,
    ) -> Result<&CapabilityManifest, CapabilityError> {
        self.index
            .get(&(capability_id.to_string(), capability_schema_version))
            .and_then(|position| self.entries.get(*position))
            .ok_or_else(|| CapabilityError::UnknownCapability {
                capability_id: capability_id.to_string(),
                capability_schema_version,
            })
    }

    /// Number of registered manifests.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Manifests in deterministic insertion order.
    pub fn manifests(&self) -> impl Iterator<Item = &CapabilityManifest> {
        self.entries.iter()
    }
}
