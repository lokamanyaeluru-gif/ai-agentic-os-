use super::config::{apply_migrations, configure_connection, verify_integrity, Migration};
use super::error::StorageError;
use crate::intent::Intent;
use agenticos_contracts::PrincipalContext;
use rusqlite::Connection;
use std::path::Path;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

const INTENT_MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    description: "Initialize intents table and principal idempotency index",
    sql: r#"
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY NOT NULL,
            description TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS intents (
            intent_id TEXT PRIMARY KEY NOT NULL,
            correlation_id TEXT NOT NULL,
            principal_id TEXT NOT NULL,
            idempotency_key TEXT,
            status TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL,
            payload TEXT NOT NULL
        );

        CREATE UNIQUE INDEX IF NOT EXISTS idx_intents_principal_idempotency
        ON intents(principal_id, idempotency_key)
        WHERE idempotency_key IS NOT NULL;

        CREATE INDEX IF NOT EXISTS idx_intents_correlation_id ON intents(correlation_id);
        CREATE INDEX IF NOT EXISTS idx_intents_principal_id ON intents(principal_id);
        CREATE INDEX IF NOT EXISTS idx_intents_status ON intents(status);
    "#,
}];

/// Authoritative repository for Intent domain entities (`intents.db`), owned by Layer 2 Intent Intelligence.
#[derive(Debug, Clone)]
pub struct IntentStore {
    conn: Arc<Mutex<Connection>>,
}

impl IntentStore {
    /// Opens and configures the Intent database with WAL mode, foreign keys, and migration execution.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let mut conn = Connection::open(path)?;
        configure_connection(&conn)?;
        verify_integrity(&conn)?;
        apply_migrations(&mut conn, INTENT_MIGRATIONS)?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Persists a new `Intent` to storage.
    ///
    /// Validates idempotency key uniqueness scoped to `intent.originating_principal`.
    pub fn insert(&self, intent: &Intent) -> Result<(), StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;

        let principal_id = &intent.originating_principal.actor_id;

        // Pre-check for duplicate idempotency key scoped to principal
        if let Some(ref key) = intent.idempotency_key {
            let exists: bool = conn
                .query_row(
                    "SELECT 1 FROM intents WHERE principal_id = ? AND idempotency_key = ? LIMIT 1;",
                    rusqlite::params![principal_id, key],
                    |_| Ok(true),
                )
                .unwrap_or(false);

            if exists {
                return Err(StorageError::DuplicateIdempotencyKey {
                    principal_id: principal_id.clone(),
                    idempotency_key: key.clone(),
                });
            }
        }

        let payload = serde_json::to_string(intent)?;
        let status_str = format!("{:?}", intent.status);

        let res = conn.execute(
            r#"
            INSERT INTO intents (
                intent_id,
                correlation_id,
                principal_id,
                idempotency_key,
                status,
                created_at_ms,
                payload
            ) VALUES (?, ?, ?, ?, ?, ?, ?);
            "#,
            rusqlite::params![
                intent.intent_id.to_string(),
                intent.correlation_id.to_string(),
                principal_id,
                intent.idempotency_key,
                status_str,
                intent.created_at_ms as i64,
                payload,
            ],
        );

        match res {
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ffi::ErrorCode::ConstraintViolation =>
            {
                if let Some(ref key) = intent.idempotency_key {
                    Err(StorageError::DuplicateIdempotencyKey {
                        principal_id: principal_id.clone(),
                        idempotency_key: key.clone(),
                    })
                } else {
                    Err(StorageError::Sqlite(rusqlite::Error::SqliteFailure(
                        err, None,
                    )))
                }
            }
            Err(e) => Err(StorageError::Sqlite(e)),
        }
    }

    /// Updates an existing `Intent` in storage, strictly validating domain state-machine rules.
    pub fn update(&self, intent: &Intent) -> Result<(), StorageError> {
        let mut conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let tx = conn.transaction()?;

        let intent_id_str = intent.intent_id.to_string();

        let existing_payload: Option<String> = tx
            .query_row(
                "SELECT payload FROM intents WHERE intent_id = ?;",
                rusqlite::params![intent_id_str],
                |row| row.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })?;

        let existing_payload = match existing_payload {
            Some(p) => p,
            None => {
                return Err(StorageError::NotFound {
                    entity: "Intent",
                    id: intent_id_str,
                });
            }
        };

        let old_intent: Intent =
            serde_json::from_str(&existing_payload).map_err(|e| StorageError::CorruptRecord {
                entity: "Intent",
                id: intent_id_str.clone(),
                reason: e.to_string(),
            })?;

        // State machine integrity check: terminal records are strictly immutable
        if old_intent.status.is_terminal() {
            return Err(StorageError::TerminalState {
                entity: "Intent",
                id: intent_id_str,
                state: format!("{:?}", old_intent.status),
            });
        }

        if old_intent.status != intent.status && !old_intent.status.can_transition_to(intent.status)
        {
            return Err(StorageError::InvalidStateTransition {
                entity: "Intent",
                id: intent_id_str,
                from: format!("{:?}", old_intent.status),
                to: format!("{:?}", intent.status),
            });
        }

        let new_payload = serde_json::to_string(intent)?;
        let status_str = format!("{:?}", intent.status);

        tx.execute(
            "UPDATE intents SET status = ?, payload = ? WHERE intent_id = ?;",
            rusqlite::params![status_str, new_payload, intent_id_str],
        )?;

        tx.commit()?;
        Ok(())
    }

    /// Retrieves an `Intent` by its unique `intent_id`.
    ///
    /// Asserts that indexed columns do not contradict the deserialized payload.
    pub fn get(&self, intent_id: &Uuid) -> Result<Option<Intent>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let id_str = intent_id.to_string();

        let row_data: Option<(String, String, String, String, i64, String)> = conn
            .query_row(
                "SELECT intent_id, correlation_id, principal_id, status, created_at_ms, payload FROM intents WHERE intent_id = ?;",
                rusqlite::params![id_str],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })?;

        match row_data {
            Some((row_id, row_corr, row_princ, row_status, row_created, p)) => {
                let intent: Intent =
                    serde_json::from_str(&p).map_err(|e| StorageError::CorruptRecord {
                        entity: "Intent",
                        id: id_str.clone(),
                        reason: e.to_string(),
                    })?;

                // Invariant: Indexed columns must not contradict the authoritative serialized domain object
                if intent.intent_id.to_string() != row_id
                    || intent.correlation_id.to_string() != row_corr
                    || intent.originating_principal.actor_id != row_princ
                    || format!("{:?}", intent.status) != row_status
                    || intent.created_at_ms as i64 != row_created
                {
                    return Err(StorageError::CorruptRecord {
                        entity: "Intent",
                        id: id_str,
                        reason: "Indexed metadata contradicts serialized payload".into(),
                    });
                }

                Ok(Some(intent))
            }
            None => Ok(None),
        }
    }

    /// Looks up an existing `Intent` by authenticated principal and idempotency key.
    ///
    /// Scoped strictly to the authenticated principal to prevent cross-principal deduplication leaks.
    pub fn find_by_idempotency_key(
        &self,
        principal: &PrincipalContext,
        idempotency_key: &str,
    ) -> Result<Option<Intent>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;

        let payload: Option<String> = conn
            .query_row(
                "SELECT payload FROM intents WHERE principal_id = ? AND idempotency_key = ?;",
                rusqlite::params![principal.actor_id, idempotency_key],
                |row| row.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })?;

        match payload {
            Some(p) => {
                let intent: Intent =
                    serde_json::from_str(&p).map_err(|e| StorageError::CorruptRecord {
                        entity: "Intent",
                        id: format!("{}:{}", principal.actor_id, idempotency_key),
                        reason: e.to_string(),
                    })?;

                // Guard against principal identity collapse: full equality check on PrincipalContext
                if intent.originating_principal != *principal {
                    return Ok(None);
                }

                Ok(Some(intent))
            }
            None => Ok(None),
        }
    }

    /// Retrieves all intents sharing a causal root `correlation_id`.
    pub fn find_by_correlation_id(
        &self,
        correlation_id: &Uuid,
    ) -> Result<Vec<Intent>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let id_str = correlation_id.to_string();

        let mut stmt = conn.prepare(
            "SELECT payload FROM intents WHERE correlation_id = ? ORDER BY created_at_ms ASC;",
        )?;

        let rows = stmt.query_map(rusqlite::params![id_str], |row| row.get::<_, String>(0))?;

        let mut result = Vec::new();
        for row in rows {
            let payload = row?;
            let intent: Intent =
                serde_json::from_str(&payload).map_err(|e| StorageError::CorruptRecord {
                    entity: "Intent",
                    id: id_str.clone(),
                    reason: e.to_string(),
                })?;
            result.push(intent);
        }

        Ok(result)
    }

    /// Lists all persisted intents ordered chronologically by `created_at_ms`.
    pub fn list(&self) -> Result<Vec<Intent>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;

        let mut stmt = conn.prepare("SELECT payload FROM intents ORDER BY created_at_ms ASC;")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;

        let mut result = Vec::new();
        for row in rows {
            let payload = row?;
            let intent: Intent =
                serde_json::from_str(&payload).map_err(|e| StorageError::CorruptRecord {
                    entity: "Intent",
                    id: "unknown".into(),
                    reason: e.to_string(),
                })?;
            result.push(intent);
        }

        Ok(result)
    }

    /// Queries a pragma value on the active connection (for inspection and tests).
    pub fn query_pragma(&self, pragma: &str) -> Result<String, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let sql = format!("PRAGMA {};", pragma);
        let val: rusqlite::types::Value = conn.query_row(&sql, [], |row| row.get(0))?;
        let s = match val {
            rusqlite::types::Value::Null => "null".to_string(),
            rusqlite::types::Value::Integer(i) => i.to_string(),
            rusqlite::types::Value::Real(r) => r.to_string(),
            rusqlite::types::Value::Text(t) => t,
            rusqlite::types::Value::Blob(_) => "<blob>".to_string(),
        };
        Ok(s)
    }
}
