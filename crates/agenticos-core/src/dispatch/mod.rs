//! Layer 6 dispatch consumer: claim → synthesize → submit → settle.
//!
//! Phase 3.3 implementation strictly from
//! `docs/phases/phase-3.3-dispatch-consumer.md`.
//!
//! The dispatcher *proposes and conveys*; Layer 8 (Phase 3.1) *disposes*.
//! An `ALLOW` is permission to PLAN, never permission to execute. Nothing
//! is spawned, installed, dialed, read, or written here: terminal records
//! stop at validated plan data. Cancellation is cooperative and in-process
//! only (caller-provided flag); live signal handling is deferred.

#[allow(clippy::module_inception)]
pub mod dispatch;
pub mod error;
pub mod record;
pub mod synthesize;

pub use dispatch::{never_cancel, CancelFlag, Dispatcher};
pub use error::DispatchError;
pub use record::{ConfirmationChallenge, DispatchOutcome, DispatchRecord};
