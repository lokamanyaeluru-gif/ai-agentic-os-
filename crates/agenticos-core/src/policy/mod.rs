//! Layer 8 Policy Engine / Security Governance evaluation plane.
//!
//! Phase 3.1 implementation strictly from
//! `docs/phases/phase-3-capability-layer.md` (v3.0.1).
//!
//! Evaluation-only: produces `ALLOW` / `DENY` / `CONFIRM` decisions and
//! sandbox-handoff constraint *data*. No capability execution, no sandbox
//! launch, no agent runtime, no UI, no LLM, no networking.
//!
//! Unresolved TBDs from the specification (§25) are preserved as TBD:
//! the `ResourceRef` → Cedar entity mapping stays an opaque passthrough
//! (context-attribute matching on exact strings only; no path hierarchy,
//! no prefix containment), and approval-token cryptography (algorithm,
//! keys, signing, verification, replay durability) is NOT implemented —
//! only structural binding shapes are checked against test fixtures.

pub mod audit;
pub mod bundle;
pub mod canonical;
pub mod error;
pub mod evaluate;
pub mod request;
pub mod snapshot;

pub use audit::PolicyAuditRecord;
pub use bundle::{PolicyBundleSource, PolicyTier, POLICY_SCHEMA_SRC};
pub use canonical::sha256_hex;
pub use error::PolicyError;
pub use evaluate::{
    PolicyDecision, SandboxConstraints, ENGINE_MAX_TIMEOUT_MS, MAX_CONFIRMATION_TOKEN_TTL_MS,
};
pub use request::{
    compute_request_hash, ApprovalSubject, ApprovalToken, ApprovalTokenSignedPayload,
    CapabilityInvocationRequest,
};
pub use snapshot::{PolicyEngine, PolicySnapshot};
