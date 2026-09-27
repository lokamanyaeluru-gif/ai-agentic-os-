use super::config::{apply_migrations, configure_connection, verify_integrity, Migration};
use super::error::StorageError;
use crate::goal::Goal;
use rusqlite::Connection;
use std::path::Path;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

const GOAL_MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    description: "Initialize goals table and foreign indexes",
    sql: r#"
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY NOT NULL,
            description TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS goals (
            goal_id TEXT PRIMARY KEY NOT NULL,
            correlation_id TEXT NOT NULL,
            originating_intent_id TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL,
            payload TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_goals_originating_intent_id ON goals(originating_intent_id);
        CREATE INDEX IF NOT EXISTS idx_goals_correlation_id ON goals(correlation_id);
        CREATE INDEX IF NOT EXISTS idx_goals_status ON goals(status);
    "#,
}];

/// Authoritative repository for Goal domain entities (`goals.db`), owned by Layer 3 Goal Runtime.
#[derive(Debug, Clone)]
pub struct GoalStore {
    conn: Arc<Mutex<Connection>>,
}

impl GoalStore {
    /// Opens and configures the Goal database with WAL mode, foreign keys, and migration execution.
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
        apply_migrations(&mut conn, GOAL_MIGRATIONS)?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Persists a new `Goal` to storage.
    pub fn insert(&self, goal: &Goal) -> Result<(), StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;

        let payload = serde_json::to_string(goal)?;
        let status_str = format!("{:?}", goal.status);

        conn.execute(
            r#"
            INSERT INTO goals (
                goal_id,
                correlation_id,
                originating_intent_id,
                status,
                created_at_ms,
                updated_at_ms,
                payload
            ) VALUES (?, ?, ?, ?, ?, ?, ?);
            "#,
            rusqlite::params![
                goal.goal_id.to_string(),
                goal.correlation_id.to_string(),
                goal.originating_intent_id.to_string(),
                status_str,
                goal.created_at_ms as i64,
                goal.updated_at_ms as i64,
                payload,
            ],
        )?;

        Ok(())
    }

    /// Updates an existing `Goal` in storage, validating state-machine transition rules.
    pub fn update(&self, goal: &Goal) -> Result<(), StorageError> {
        let mut conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let tx = conn.transaction()?;

        let goal_id_str = goal.goal_id.to_string();

        let existing_payload: Option<String> = tx
            .query_row(
                "SELECT payload FROM goals WHERE goal_id = ?;",
                rusqlite::params![goal_id_str],
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
                    entity: "Goal",
                    id: goal_id_str,
                });
            }
        };

        let old_goal: Goal =
            serde_json::from_str(&existing_payload).map_err(|e| StorageError::CorruptRecord {
                entity: "Goal",
                id: goal_id_str.clone(),
                reason: e.to_string(),
            })?;

        // State machine integrity check: terminal records are strictly immutable
        if old_goal.status.is_terminal() {
            return Err(StorageError::TerminalState {
                entity: "Goal",
                id: goal_id_str,
                state: format!("{:?}", old_goal.status),
            });
        }

        if old_goal.status != goal.status && !old_goal.status.can_transition_to(goal.status) {
            return Err(StorageError::InvalidStateTransition {
                entity: "Goal",
                id: goal_id_str,
                from: format!("{:?}", old_goal.status),
                to: format!("{:?}", goal.status),
            });
        }

        let new_payload = serde_json::to_string(goal)?;
        let status_str = format!("{:?}", goal.status);

        tx.execute(
            "UPDATE goals SET status = ?, updated_at_ms = ?, payload = ? WHERE goal_id = ?;",
            rusqlite::params![
                status_str,
                goal.updated_at_ms as i64,
                new_payload,
                goal_id_str
            ],
        )?;

        tx.commit()?;
        Ok(())
    }

    /// Retrieves a `Goal` by its unique `goal_id`.
    ///
    /// Asserts that indexed columns do not contradict the deserialized payload.
    pub fn get(&self, goal_id: &Uuid) -> Result<Option<Goal>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let id_str = goal_id.to_string();

        let row_data: Option<(String, String, String, String, i64, i64, String)> = conn
            .query_row(
                "SELECT goal_id, correlation_id, originating_intent_id, status, created_at_ms, updated_at_ms, payload FROM goals WHERE goal_id = ?;",
                rusqlite::params![id_str],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })?;

        match row_data {
            Some((row_id, row_corr, row_intent, row_status, row_created, row_updated, p)) => {
                let goal: Goal =
                    serde_json::from_str(&p).map_err(|e| StorageError::CorruptRecord {
                        entity: "Goal",
                        id: id_str.clone(),
                        reason: e.to_string(),
                    })?;

                // Invariant: Indexed columns must not contradict deserialized payload
                if goal.goal_id.to_string() != row_id
                    || goal.correlation_id.to_string() != row_corr
                    || goal.originating_intent_id.to_string() != row_intent
                    || format!("{:?}", goal.status) != row_status
                    || goal.created_at_ms as i64 != row_created
                    || goal.updated_at_ms as i64 != row_updated
                {
                    return Err(StorageError::CorruptRecord {
                        entity: "Goal",
                        id: id_str,
                        reason: "Indexed metadata contradicts serialized payload".into(),
                    });
                }

                Ok(Some(goal))
            }
            None => Ok(None),
        }
    }

    /// Retrieves all goals derived from an originating `intent_id`.
    pub fn find_by_intent_id(&self, intent_id: &Uuid) -> Result<Vec<Goal>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let id_str = intent_id.to_string();

        let mut stmt = conn.prepare(
            "SELECT payload FROM goals WHERE originating_intent_id = ? ORDER BY created_at_ms ASC;",
        )?;

        let rows = stmt.query_map(rusqlite::params![id_str], |row| row.get::<_, String>(0))?;

        let mut result = Vec::new();
        for row in rows {
            let payload = row?;
            let goal: Goal =
                serde_json::from_str(&payload).map_err(|e| StorageError::CorruptRecord {
                    entity: "Goal",
                    id: id_str.clone(),
                    reason: e.to_string(),
                })?;
            result.push(goal);
        }

        Ok(result)
    }

    /// Retrieves all goals sharing a root `correlation_id`.
    pub fn find_by_correlation_id(&self, correlation_id: &Uuid) -> Result<Vec<Goal>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let id_str = correlation_id.to_string();

        let mut stmt = conn.prepare(
            "SELECT payload FROM goals WHERE correlation_id = ? ORDER BY created_at_ms ASC;",
        )?;

        let rows = stmt.query_map(rusqlite::params![id_str], |row| row.get::<_, String>(0))?;

        let mut result = Vec::new();
        for row in rows {
            let payload = row?;
            let goal: Goal =
                serde_json::from_str(&payload).map_err(|e| StorageError::CorruptRecord {
                    entity: "Goal",
                    id: id_str.clone(),
                    reason: e.to_string(),
                })?;
            result.push(goal);
        }

        Ok(result)
    }

    /// Lists all persisted goals ordered chronologically.
    pub fn list(&self) -> Result<Vec<Goal>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;

        let mut stmt = conn.prepare("SELECT payload FROM goals ORDER BY created_at_ms ASC;")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;

        let mut result = Vec::new();
        for row in rows {
            let payload = row?;
            let goal: Goal =
                serde_json::from_str(&payload).map_err(|e| StorageError::CorruptRecord {
                    entity: "Goal",
                    id: "unknown".into(),
                    reason: e.to_string(),
                })?;
            result.push(goal);
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
