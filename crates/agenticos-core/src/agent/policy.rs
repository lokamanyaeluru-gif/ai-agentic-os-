//! Declarative restart and recovery policies for agents.

use serde::{Deserialize, Serialize};

use crate::error::DomainError;

/// Declarative policy governing recovery when an agent reaches `Failed` or terminates unexpectedly.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum RestartPolicy {
    /// Never restart automatically on failure. Remains in terminal `Failed`.
    Never,

    /// Restart on non-zero exit or failure up to `max_retries`.
    OnFailure {
        max_retries: u32,
        current_retries: u32,
        backoff_ms: u64,
    },

    /// Always restart when agent exits or fails, up to `max_retries`.
    Always {
        max_retries: u32,
        current_retries: u32,
        backoff_ms: u64,
    },
}

impl RestartPolicy {
    /// Constructs an `OnFailure` policy with zero current retries.
    pub const fn on_failure(max_retries: u32, backoff_ms: u64) -> Self {
        Self::OnFailure {
            max_retries,
            current_retries: 0,
            backoff_ms,
        }
    }

    /// Constructs an `Always` policy with zero current retries.
    pub const fn always(max_retries: u32, backoff_ms: u64) -> Self {
        Self::Always {
            max_retries,
            current_retries: 0,
            backoff_ms,
        }
    }

    /// Determines whether another restart attempt is permitted under the policy.
    pub fn can_restart(&self) -> bool {
        match self {
            Self::Never => false,
            Self::OnFailure {
                max_retries,
                current_retries,
                ..
            }
            | Self::Always {
                max_retries,
                current_retries,
                ..
            } => current_retries < max_retries,
        }
    }

    /// Records a restart attempt by incrementing the retry counter.
    ///
    /// Returns the new `current_retries` count, or an error if retries are exhausted.
    pub fn record_restart(&mut self) -> Result<u32, DomainError> {
        match self {
            Self::Never => Err(DomainError::RestartExhausted {
                max_retries: 0,
                current_retries: 0,
            }),
            Self::OnFailure {
                max_retries,
                current_retries,
                ..
            }
            | Self::Always {
                max_retries,
                current_retries,
                ..
            } => {
                if *current_retries >= *max_retries {
                    return Err(DomainError::RestartExhausted {
                        max_retries: *max_retries,
                        current_retries: *current_retries,
                    });
                }
                *current_retries += 1;
                Ok(*current_retries)
            }
        }
    }

    /// Resets the current retry counter to zero (e.g. after a prolonged period of healthy operation).
    pub fn reset_retries(&mut self) {
        match self {
            Self::Never => {}
            Self::OnFailure {
                current_retries, ..
            }
            | Self::Always {
                current_retries, ..
            } => {
                *current_retries = 0;
            }
        }
    }

    /// Returns the backoff delay in milliseconds associated with the policy, if applicable.
    pub fn backoff_ms(&self) -> Option<u64> {
        match self {
            Self::Never => None,
            Self::OnFailure { backoff_ms, .. } | Self::Always { backoff_ms, .. } => {
                Some(*backoff_ms)
            }
        }
    }
}
