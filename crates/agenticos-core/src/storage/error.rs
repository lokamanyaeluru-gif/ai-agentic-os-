use agenticos_contracts::ErrorPayload;
use thiserror::Error;

/// Storage-specific errors for AI Agentic OS domain repositories.
#[derive(Debug, Error)]
pub enum StorageError {
    /// Underlying SQLite driver error.
    #[error("SQLite database error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// SQLite pragma or runtime configuration failure.
    #[error("Database configuration error: {reason}")]
    ConfigurationFailed { reason: String },

    /// Database corruption detected during startup integrity check.
    #[error("Database corruption detected during quick_check: {details}")]
    DatabaseCorrupted { details: String },

    /// Schema version in database exceeds what current binary supports.
    #[error("Incompatible schema version: found {found}, maximum supported is {supported}")]
    IncompatibleSchemaVersion { found: u32, supported: u32 },

    /// Schema migration failed.
    #[error("Schema migration failed for version {version}: {reason}")]
    MigrationFailed { version: u32, reason: String },

    /// Serde JSON serialization or deserialization error.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Persisted record payload is corrupt or invalid.
    #[error("Corrupt record in storage for entity '{entity}' with ID '{id}': {reason}")]
    CorruptRecord {
        entity: &'static str,
        id: String,
        reason: String,
    },

    /// Duplicate idempotency key detected for the authenticated originating principal.
    #[error("Duplicate idempotency key '{idempotency_key}' for principal '{principal_id}'")]
    DuplicateIdempotencyKey {
        principal_id: String,
        idempotency_key: String,
    },

    /// Duplicate primary key or unique constraint violation.
    #[error("Duplicate key for entity '{entity}': {key}")]
    DuplicateKey { entity: &'static str, key: String },

    /// Storage engine busy or locked (SQLITE_BUSY).
    #[error("Database busy or locked: {reason}")]
    Busy { reason: String },

    /// Transition violates domain state-machine rules.
    #[error("Invalid state transition in storage for entity '{entity}' with ID '{id}': cannot transition from '{from}' to '{to}'")]
    InvalidStateTransition {
        entity: &'static str,
        id: String,
        from: String,
        to: String,
    },

    /// Attempted state mutation on an entity already in a terminal state.
    #[error("Attempted transition from terminal state in storage for entity '{entity}' with ID '{id}': current state is '{state}'")]
    TerminalState {
        entity: &'static str,
        id: String,
        state: String,
    },

    /// Requested entity not found in storage.
    #[error("Entity '{entity}' with ID '{id}' not found in storage")]
    NotFound { entity: &'static str, id: String },

    /// Relational foreign key constraint violation.
    #[error("Foreign key constraint violation: {reason}")]
    ForeignKeyViolation { reason: String },

    /// Underlying filesystem I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Internal mutex lock was poisoned.
    #[error("Storage lock error: mutex poisoned")]
    LockPoisoned,
}

impl From<StorageError> for ErrorPayload {
    fn from(err: StorageError) -> Self {
        let (code, retry) = match &err {
            StorageError::DuplicateIdempotencyKey { .. }
            | StorageError::DuplicateKey { .. }
            | StorageError::InvalidStateTransition { .. }
            | StorageError::TerminalState { .. }
            | StorageError::ForeignKeyViolation { .. } => (
                agenticos_contracts::ErrorCode::InvalidRequest,
                agenticos_contracts::RetryClassification::Never,
            ),
            StorageError::NotFound { .. } => (
                agenticos_contracts::ErrorCode::StorageFailure,
                agenticos_contracts::RetryClassification::Never,
            ),
            StorageError::Busy { .. } => (
                agenticos_contracts::ErrorCode::StorageFailure,
                agenticos_contracts::RetryClassification::Safe,
            ),
            StorageError::DatabaseCorrupted { .. }
            | StorageError::IncompatibleSchemaVersion { .. }
            | StorageError::CorruptRecord { .. }
            | StorageError::ConfigurationFailed { .. }
            | StorageError::MigrationFailed { .. } => (
                agenticos_contracts::ErrorCode::StorageFailure,
                agenticos_contracts::RetryClassification::Safe,
            ),
            _ => (
                agenticos_contracts::ErrorCode::StorageFailure,
                agenticos_contracts::RetryClassification::Safe,
            ),
        };

        ErrorPayload::new(code, err.to_string(), "storage", retry)
    }
}
