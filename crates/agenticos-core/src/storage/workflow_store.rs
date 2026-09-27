use super::config::{apply_migrations, configure_connection, verify_integrity, Migration};
use super::error::StorageError;
use crate::workflow::Workflow;
use rusqlite::Connection;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

const WORKFLOW_MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    description: "Initialize workflows and workflow_steps tables with foreign keys and indexes",
    sql: r#"
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY NOT NULL,
            description TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS workflows (
            workflow_id TEXT PRIMARY KEY NOT NULL,
            goal_id TEXT NOT NULL,
            correlation_id TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL,
            payload TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS workflow_steps (
            step_id TEXT PRIMARY KEY NOT NULL,
            workflow_id TEXT NOT NULL,
            step_index INTEGER NOT NULL,
            capability_id TEXT NOT NULL,
            state TEXT NOT NULL,
            FOREIGN KEY (workflow_id) REFERENCES workflows(workflow_id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_workflows_goal_id ON workflows(goal_id);
        CREATE INDEX IF NOT EXISTS idx_workflows_correlation_id ON workflows(correlation_id);
        CREATE INDEX IF NOT EXISTS idx_workflows_status ON workflows(status);
        CREATE INDEX IF NOT EXISTS idx_workflow_steps_workflow_id ON workflow_steps(workflow_id);
        CREATE INDEX IF NOT EXISTS idx_workflow_steps_state ON workflow_steps(state);
    "#,
}];

/// Authoritative repository for Workflow domain entities (`workflows.db`), owned by Layer 4 Workflow Runtime.
#[derive(Debug, Clone)]
pub struct WorkflowStore {
    conn: Arc<Mutex<Connection>>,
}

impl WorkflowStore {
    /// Opens and configures the Workflow database with WAL mode, foreign keys, and migration execution.
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
        apply_migrations(&mut conn, WORKFLOW_MIGRATIONS)?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Persists a new `Workflow` and its child steps within an atomic transaction.
    pub fn insert(&self, workflow: &Workflow) -> Result<(), StorageError> {
        let mut conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let tx = conn.transaction()?;

        let payload = serde_json::to_string(workflow)?;
        let status_str = format!("{:?}", workflow.status);
        let workflow_id_str = workflow.workflow_id.to_string();

        tx.execute(
            r#"
            INSERT INTO workflows (
                workflow_id,
                goal_id,
                correlation_id,
                status,
                created_at_ms,
                updated_at_ms,
                payload
            ) VALUES (?, ?, ?, ?, ?, ?, ?);
            "#,
            rusqlite::params![
                workflow_id_str,
                workflow.goal_id.to_string(),
                workflow.correlation_id.to_string(),
                status_str,
                workflow.created_at_ms as i64,
                workflow.updated_at_ms as i64,
                payload,
            ],
        )?;

        // Insert indexed step records
        for step in &workflow.steps {
            let state_str = format!("{:?}", step.state);
            tx.execute(
                r#"
                INSERT INTO workflow_steps (
                    step_id,
                    workflow_id,
                    step_index,
                    capability_id,
                    state
                ) VALUES (?, ?, ?, ?, ?);
                "#,
                rusqlite::params![
                    step.step_id.to_string(),
                    workflow_id_str,
                    step.step_index,
                    step.capability_id,
                    state_str,
                ],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    /// Updates an existing `Workflow` in storage, validating workflow and step state-machine integrity.
    pub fn update(&self, workflow: &Workflow) -> Result<(), StorageError> {
        let mut conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let tx = conn.transaction()?;

        let workflow_id_str = workflow.workflow_id.to_string();

        let existing_payload: Option<String> = tx
            .query_row(
                "SELECT payload FROM workflows WHERE workflow_id = ?;",
                rusqlite::params![workflow_id_str],
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
                    entity: "Workflow",
                    id: workflow_id_str,
                });
            }
        };

        let old_wf: Workflow =
            serde_json::from_str(&existing_payload).map_err(|e| StorageError::CorruptRecord {
                entity: "Workflow",
                id: workflow_id_str.clone(),
                reason: e.to_string(),
            })?;

        // 1. Workflow-level state machine validation: terminal records are strictly immutable
        if old_wf.status.is_terminal() {
            return Err(StorageError::TerminalState {
                entity: "Workflow",
                id: workflow_id_str,
                state: format!("{:?}", old_wf.status),
            });
        }

        if old_wf.status != workflow.status && !old_wf.status.can_transition_to(workflow.status) {
            return Err(StorageError::InvalidStateTransition {
                entity: "Workflow",
                id: workflow_id_str,
                from: format!("{:?}", old_wf.status),
                to: format!("{:?}", workflow.status),
            });
        }

        // 2. Step-level state machine validation
        let old_step_map: HashMap<Uuid, &crate::workflow::WorkflowStep> =
            old_wf.steps.iter().map(|s| (s.step_id, s)).collect();

        for new_step in &workflow.steps {
            if let Some(old_step) = old_step_map.get(&new_step.step_id) {
                if old_step.state != new_step.state {
                    if old_step.state.is_terminal() {
                        return Err(StorageError::TerminalState {
                            entity: "WorkflowStep",
                            id: new_step.step_id.to_string(),
                            state: format!("{:?}", old_step.state),
                        });
                    }
                    if !old_step.state.can_transition_to(new_step.state) {
                        return Err(StorageError::InvalidStateTransition {
                            entity: "WorkflowStep",
                            id: new_step.step_id.to_string(),
                            from: format!("{:?}", old_step.state),
                            to: format!("{:?}", new_step.state),
                        });
                    }
                }
            }
        }

        let new_payload = serde_json::to_string(workflow)?;
        let status_str = format!("{:?}", workflow.status);

        tx.execute(
            "UPDATE workflows SET status = ?, updated_at_ms = ?, payload = ? WHERE workflow_id = ?;",
            rusqlite::params![status_str, workflow.updated_at_ms as i64, new_payload, workflow_id_str],
        )?;

        // Re-sync workflow steps
        tx.execute(
            "DELETE FROM workflow_steps WHERE workflow_id = ?;",
            rusqlite::params![workflow_id_str],
        )?;

        for step in &workflow.steps {
            let state_str = format!("{:?}", step.state);
            tx.execute(
                r#"
                INSERT INTO workflow_steps (
                    step_id,
                    workflow_id,
                    step_index,
                    capability_id,
                    state
                ) VALUES (?, ?, ?, ?, ?);
                "#,
                rusqlite::params![
                    step.step_id.to_string(),
                    workflow_id_str,
                    step.step_index,
                    step.capability_id,
                    state_str,
                ],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    /// Retrieves a `Workflow` by its unique `workflow_id`.
    ///
    /// Asserts that indexed columns do not contradict the deserialized payload.
    pub fn get(&self, workflow_id: &Uuid) -> Result<Option<Workflow>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let id_str = workflow_id.to_string();

        let row_data: Option<(String, String, String, String, i64, i64, String)> = conn
            .query_row(
                "SELECT workflow_id, goal_id, correlation_id, status, created_at_ms, updated_at_ms, payload FROM workflows WHERE workflow_id = ?;",
                rusqlite::params![id_str],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })?;

        match row_data {
            Some((row_id, row_goal, row_corr, row_status, row_created, row_updated, p)) => {
                let workflow: Workflow =
                    serde_json::from_str(&p).map_err(|e| StorageError::CorruptRecord {
                        entity: "Workflow",
                        id: id_str.clone(),
                        reason: e.to_string(),
                    })?;

                // Invariant: Indexed columns must not contradict deserialized payload
                if workflow.workflow_id.to_string() != row_id
                    || workflow.goal_id.to_string() != row_goal
                    || workflow.correlation_id.to_string() != row_corr
                    || format!("{:?}", workflow.status) != row_status
                    || workflow.created_at_ms as i64 != row_created
                    || workflow.updated_at_ms as i64 != row_updated
                {
                    return Err(StorageError::CorruptRecord {
                        entity: "Workflow",
                        id: id_str,
                        reason: "Indexed metadata contradicts serialized payload".into(),
                    });
                }

                Ok(Some(workflow))
            }
            None => Ok(None),
        }
    }

    /// Retrieves all workflows linked to a `goal_id`.
    pub fn find_by_goal_id(&self, goal_id: &Uuid) -> Result<Vec<Workflow>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let id_str = goal_id.to_string();

        let mut stmt = conn.prepare(
            "SELECT payload FROM workflows WHERE goal_id = ? ORDER BY created_at_ms ASC;",
        )?;

        let rows = stmt.query_map(rusqlite::params![id_str], |row| row.get::<_, String>(0))?;

        let mut result = Vec::new();
        for row in rows {
            let payload = row?;
            let workflow: Workflow =
                serde_json::from_str(&payload).map_err(|e| StorageError::CorruptRecord {
                    entity: "Workflow",
                    id: id_str.clone(),
                    reason: e.to_string(),
                })?;
            result.push(workflow);
        }

        Ok(result)
    }

    /// Retrieves all workflows sharing a root `correlation_id`.
    pub fn find_by_correlation_id(
        &self,
        correlation_id: &Uuid,
    ) -> Result<Vec<Workflow>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let id_str = correlation_id.to_string();

        let mut stmt = conn.prepare(
            "SELECT payload FROM workflows WHERE correlation_id = ? ORDER BY created_at_ms ASC;",
        )?;

        let rows = stmt.query_map(rusqlite::params![id_str], |row| row.get::<_, String>(0))?;

        let mut result = Vec::new();
        for row in rows {
            let payload = row?;
            let workflow: Workflow =
                serde_json::from_str(&payload).map_err(|e| StorageError::CorruptRecord {
                    entity: "Workflow",
                    id: id_str.clone(),
                    reason: e.to_string(),
                })?;
            result.push(workflow);
        }

        Ok(result)
    }

    /// Finds the containing `Workflow` for a specific `step_id` using the child step index.
    pub fn find_by_step_id(&self, step_id: &Uuid) -> Result<Option<Workflow>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let id_str = step_id.to_string();

        let payload: Option<String> = conn
            .query_row(
                r#"
                SELECT w.payload FROM workflows w
                INNER JOIN workflow_steps s ON w.workflow_id = s.workflow_id
                WHERE s.step_id = ?;
                "#,
                rusqlite::params![id_str],
                |row| row.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })?;

        match payload {
            Some(p) => {
                let workflow: Workflow =
                    serde_json::from_str(&p).map_err(|e| StorageError::CorruptRecord {
                        entity: "Workflow",
                        id: format!("by_step_{}", id_str),
                        reason: e.to_string(),
                    })?;
                Ok(Some(workflow))
            }
            None => Ok(None),
        }
    }

    /// Lists all persisted workflows ordered chronologically.
    pub fn list(&self) -> Result<Vec<Workflow>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;

        let mut stmt = conn.prepare("SELECT payload FROM workflows ORDER BY created_at_ms ASC;")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;

        let mut result = Vec::new();
        for row in rows {
            let payload = row?;
            let workflow: Workflow =
                serde_json::from_str(&payload).map_err(|e| StorageError::CorruptRecord {
                    entity: "Workflow",
                    id: "unknown".into(),
                    reason: e.to_string(),
                })?;
            result.push(workflow);
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
