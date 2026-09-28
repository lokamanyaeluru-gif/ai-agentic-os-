//! Layer 9 boundary: capability selection, handoff binding, sandbox
//! construction contracts, and verification shapes.
//!
//! Phase 3.2 implementation strictly from
//! `docs/phases/phase-3.2-capability-execution-boundary.md`.
//!
//! DATA ONLY: produces validated `InvocationBinding` and
//! `SandboxConstructionPlan` records. No worker is spawned, no filter is
//! installed, no namespace is created, no socket is opened. An `ALLOW` from
//! Layer 8 is permission to PLAN, never permission to execute.
//!
//! All Phase 3.0 §25 / Phase 3.2 §30 TBDs are preserved: Bubblewrap pins,
//! Landlock ABI, seccomp allowlists, openat2 rules, numeric ceilings, token
//! crypto, path mapping, confirmation transport, audit signing, vault,
//! plan-cache bounds, supervision timings, verification grammar, and the
//! compensation DSL remain unresolved.

pub mod binding;
pub mod error;
pub mod manifest;
pub mod plan;
pub mod registry;
pub mod report;
pub mod verify;
pub mod worker;

pub use binding::{bind, DecisionRef, InvocationBinding, ResolvedConstraints};
pub use error::CapabilityError;
pub use manifest::{
    check_arguments, fixture_bundle_manifests, fixture_create_directory, fixture_delete_tree,
    fixture_read_file, validate_manifest, Atomicity, CapabilityManifest, RiskTier, SandboxProfile,
};
pub use plan::{
    build_plan, validate, BwrapArgv, Ceilings, ExecArg, ExecPlan, FdPlan, LandlockRights,
    LandlockRule, MountEntry, MountMode, MountSource, SandboxConstructionPlan, SeccompData,
    UnshareSet,
};
pub use registry::{CapabilityRegistry, ManifestBundle};
pub use report::{
    CancelSignal, CrashShape, ExecutionReport, ExecutionStatus, RestartShape, TimeoutSpec,
    VerificationRef,
};
pub use verify::{
    evaluate_conditions, CheckExpr, ConditionResult, ConditionStatus, FileMeta, FilesystemView,
    MemView, VerificationResult,
};
pub use worker::{EscalationPolicy, StdioPlan, SupervisionShape, WorkerBoundary};
