//! Runtime coordinator module for AI Agentic OS Phase 1.
//!
//! Provides the deterministic `Phase1Runtime` that orchestrates the
//! Intent → Goal → Workflow lifecycle across three domain-owned SQLite stores.

pub mod error;
pub mod phase1;
pub mod planner;

pub use error::RuntimeError;
pub use phase1::{ChainState, Phase1Result, Phase1Runtime, SubmitRequest};
