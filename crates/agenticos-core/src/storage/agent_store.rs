//! Authoritative persistent storage for Layer 5 (Global Agent Manager) in `agent_registry.db`.
//!
//! Aligned with ADR-0006 (Storage Architecture), ADR-0007, and Phase 2.0 specification.
//!
//! # Storage Ownership Matrix
//! - **Authoritative Owner**: Layer 5 Global Agent Manager.
//! - Neither Layer 4 (Workflow Runtime) nor Layer 6 (Agent Runtime) may directly access this database.
//!
//! # Data Classification
//! - **Authoritative**: `agents`, `agent_capabilities`, `assignments`.
//! - **Observational Telemetry**: `agent_heartbeats`.

use rusqlite::Connection;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use super::config::{
    apply_migrations, configure_agent_registry_connection, default_data_dir, verify_foreign_keys,
    verify_full_integrity, Migration,
};
use super::error::StorageError;
use crate::agent::{AgentId, AgentRecord, AssignmentId, HeartbeatRecord, WorkAssignment};

/// Schema migrations for `agent_registry.db`.
const AGENT_REGISTRY_MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    description: "Initialize authoritative agents, capabilities, assignments, and observational heartbeats tables",
    sql: r#"
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY NOT NULL,
            description TEXT NOT NULL
        );

        -- Authoritative agents table
        CREATE TABLE IF NOT EXISTS agents (
            agent_id TEXT PRIMARY KEY NOT NULL,
            agent_type TEXT NOT NULL,
            principal_id TEXT NOT NULL,
            scope TEXT NOT NULL,
            instance_nonce TEXT NOT NULL UNIQUE,
            pid INTEGER,
            start_time_ticks INTEGER,
            state TEXT NOT NULL,
            registered_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL,
            payload TEXT NOT NULL
        );

        -- Authoritative relational mapping for capability queries
        CREATE TABLE IF NOT EXISTS agent_capabilities (
            agent_id TEXT NOT NULL,
            capability_id TEXT NOT NULL,
            PRIMARY KEY (agent_id, capability_id),
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
        );

        -- Authoritative work assignments table
        CREATE TABLE IF NOT EXISTS assignments (
            assignment_id TEXT PRIMARY KEY NOT NULL,
            correlation_id TEXT NOT NULL,
            request_id TEXT NOT NULL,
            workflow_id TEXT NOT NULL,
            step_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            capability_id TEXT NOT NULL,
            status TEXT NOT NULL,
            assigned_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL,
            payload TEXT NOT NULL,
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
        );

        -- Observational heartbeat telemetry table (derived health; not authoritative lifecycle state)
        CREATE TABLE IF NOT EXISTS agent_heartbeats (
            agent_id TEXT NOT NULL,
            timestamp_ms INTEGER NOT NULL,
            sequence_number INTEGER NOT NULL,
            cpu_usage_permille INTEGER NOT NULL,
            memory_rss_bytes INTEGER NOT NULL,
            open_fds INTEGER NOT NULL,
            payload TEXT NOT NULL,
            PRIMARY KEY (agent_id, timestamp_ms),
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
        );

        -- Indexes for performance and isolation
        CREATE INDEX IF NOT EXISTS idx_agents_principal_id ON agents(principal_id);
        CREATE INDEX IF NOT EXISTS idx_agents_state ON agents(state);
        CREATE INDEX IF NOT EXISTS idx_agents_type ON agents(agent_type);
        CREATE INDEX IF NOT EXISTS idx_agents_instance_nonce ON agents(instance_nonce);
        CREATE INDEX IF NOT EXISTS idx_agent_capabilities_cap ON agent_capabilities(capability_id);
        CREATE INDEX IF NOT EXISTS idx_assignments_correlation ON assignments(correlation_id);
        CREATE INDEX IF NOT EXISTS idx_assignments_request ON assignments(request_id);
        CREATE INDEX IF NOT EXISTS idx_assignments_agent ON assignments(agent_id);
        CREATE INDEX IF NOT EXISTS idx_assignments_status ON assignments(status);
        CREATE INDEX IF NOT EXISTS idx_heartbeats_agent ON agent_heartbeats(agent_id);
    "#,
}];

/// Maps low-level SQLite errors into typed `StorageError` instances.
fn map_sqlite_err(e: rusqlite::Error) -> StorageError {
    match &e {
        rusqlite::Error::SqliteFailure(err, msg) => {
            if err.code == rusqlite::ErrorCode::DatabaseBusy {
                StorageError::Busy {
                    reason: msg
                        .clone()
                        .unwrap_or_else(|| "Database busy (SQLITE_BUSY)".into()),
                }
            } else if err.code == rusqlite::ErrorCode::ConstraintViolation {
                let msg_str = msg.as_deref().unwrap_or("");
                if msg_str.contains("FOREIGN KEY") {
                    StorageError::ForeignKeyViolation {
                        reason: msg_str.to_string(),
                    }
                } else if msg_str.contains("UNIQUE") {
                    StorageError::DuplicateKey {
                        entity: "ConstraintViolation",
                        key: msg_str.to_string(),
                    }
                } else {
                    StorageError::Sqlite(e)
                }
            } else {
                StorageError::Sqlite(e)
            }
        }
        _ => StorageError::Sqlite(e),
    }
}

/// Asserts that relational `agent_capabilities` rows strictly match `agent.declared_capabilities`.
fn verify_agent_capabilities(conn: &Connection, agent: &AgentRecord) -> Result<(), StorageError> {
    let agent_id_str = agent.agent_id.to_string();
    let mut stmt = conn
        .prepare(
            "SELECT capability_id FROM agent_capabilities WHERE agent_id = ? ORDER BY capability_id ASC;",
        )
        .map_err(map_sqlite_err)?;

    let rows = stmt
        .query_map(rusqlite::params![agent_id_str], |row| {
            row.get::<_, String>(0)
        })
        .map_err(map_sqlite_err)?;

    let mut db_caps = std::collections::BTreeSet::new();
    for cap in rows {
        db_caps.insert(cap.map_err(map_sqlite_err)?);
    }

    if db_caps != agent.declared_capabilities {
        return Err(StorageError::CorruptRecord {
            entity: "Agent",
            id: agent_id_str,
            reason: format!(
                "Relational agent_capabilities ({:?}) contradict payload declared_capabilities ({:?})",
                db_caps, agent.declared_capabilities
            ),
        });
    }

    Ok(())
}

/// Authoritative repository for Layer 5 (`agent_registry.db`).
#[derive(Debug, Clone)]
pub struct AgentRegistryStore {
    conn: Arc<Mutex<Connection>>,
}

impl AgentRegistryStore {
    /// Opens and configures the Agent Registry database with WAL mode, foreign keys, and migrations.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let mut conn = Connection::open(path)?;
        configure_agent_registry_connection(&conn)?;
        verify_full_integrity(&conn)?;
        verify_foreign_keys(&conn)?;
        apply_migrations(&mut conn, AGENT_REGISTRY_MIGRATIONS)?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Opens the default Agent Registry database at `$XDG_DATA_HOME/agenticos/data/agent_registry.db`.
    pub fn open_default() -> Result<Self, StorageError> {
        let db_path = default_data_dir().join("agent_registry.db");
        Self::open(db_path)
    }

    // =======================================================================
    // Agent Operations (Authoritative)
    // =======================================================================

    /// Registers a new agent record and indexes its declared capabilities atomically.
    pub fn register_agent(&self, agent: &AgentRecord) -> Result<(), StorageError> {
        let mut conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let tx = conn.transaction().map_err(map_sqlite_err)?;

        let agent_id_str = agent.agent_id.to_string();
        let nonce_str = agent.process_identity.instance_nonce.to_string();

        // 1. Explicit pre-check for duplicate agent_id
        let exists_id: bool = tx
            .query_row(
                "SELECT 1 FROM agents WHERE agent_id = ? LIMIT 1;",
                rusqlite::params![agent_id_str],
                |_| Ok(true),
            )
            .unwrap_or(false);

        if exists_id {
            return Err(StorageError::DuplicateKey {
                entity: "Agent",
                key: agent_id_str,
            });
        }

        // 2. Explicit pre-check for duplicate instance_nonce
        let exists_nonce: bool = tx
            .query_row(
                "SELECT 1 FROM agents WHERE instance_nonce = ? LIMIT 1;",
                rusqlite::params![nonce_str],
                |_| Ok(true),
            )
            .unwrap_or(false);

        if exists_nonce {
            return Err(StorageError::DuplicateKey {
                entity: "AgentInstanceNonce",
                key: nonce_str,
            });
        }

        let payload = serde_json::to_string(agent)?;
        let state_str = format!("{:?}", agent.state);
        let scope_str = format!("{:?}", agent.scope);

        tx.execute(
            r#"
            INSERT INTO agents (
                agent_id,
                agent_type,
                principal_id,
                scope,
                instance_nonce,
                pid,
                start_time_ticks,
                state,
                registered_at_ms,
                updated_at_ms,
                payload
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            "#,
            rusqlite::params![
                agent_id_str,
                agent.agent_type.as_str(),
                agent.owner.actor_id,
                scope_str,
                nonce_str,
                agent.process_identity.pid,
                agent.process_identity.start_time_ticks,
                state_str,
                agent.registered_at_ms,
                agent.updated_at_ms,
                payload,
            ],
        )
        .map_err(map_sqlite_err)?;

        // Insert declared capability indexes
        for cap in &agent.declared_capabilities {
            tx.execute(
                "INSERT INTO agent_capabilities (agent_id, capability_id) VALUES (?, ?);",
                rusqlite::params![agent_id_str, cap],
            )
            .map_err(map_sqlite_err)?;
        }

        tx.commit().map_err(map_sqlite_err)?;
        Ok(())
    }

    /// Retrieves an agent record by `AgentId`, verifying dual-write index/payload consistency.
    pub fn get_agent(&self, agent_id: &AgentId) -> Result<Option<AgentRecord>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let agent_id_str = agent_id.to_string();

        let mut stmt = conn
            .prepare(
                r#"
                SELECT agent_id, state, principal_id, instance_nonce, payload
                FROM agents
                WHERE agent_id = ?;
                "#,
            )
            .map_err(map_sqlite_err)?;

        let mut rows = stmt
            .query(rusqlite::params![agent_id_str])
            .map_err(map_sqlite_err)?;

        let row = match rows.next().map_err(map_sqlite_err)? {
            Some(row) => row,
            None => return Ok(None),
        };

        let col_agent_id: String = row.get(0).map_err(map_sqlite_err)?;
        let col_state: String = row.get(1).map_err(map_sqlite_err)?;
        let col_principal: String = row.get(2).map_err(map_sqlite_err)?;
        let col_nonce: String = row.get(3).map_err(map_sqlite_err)?;
        let payload: String = row.get(4).map_err(map_sqlite_err)?;

        let agent: AgentRecord = serde_json::from_str(&payload)?;

        // Dual-write integrity check
        if agent.agent_id.to_string() != col_agent_id
            || format!("{:?}", agent.state) != col_state
            || agent.owner.actor_id != col_principal
            || agent.process_identity.instance_nonce.to_string() != col_nonce
        {
            return Err(StorageError::CorruptRecord {
                entity: "Agent",
                id: agent_id_str,
                reason: "Indexed database columns contradict serialized JSON payload".into(),
            });
        }

        verify_agent_capabilities(&conn, &agent)?;

        Ok(Some(agent))
    }

    /// Lists all registered agents in storage with dual-write integrity verification.
    pub fn list_agents(&self) -> Result<Vec<AgentRecord>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;

        let mut stmt = conn
            .prepare(
                r#"
                SELECT agent_id, state, principal_id, instance_nonce, payload
                FROM agents
                ORDER BY registered_at_ms ASC, agent_id ASC;
                "#,
            )
            .map_err(map_sqlite_err)?;

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(map_sqlite_err)?;

        let mut agents = Vec::new();
        for item in rows {
            let (col_agent_id, col_state, col_principal, col_nonce, payload) =
                item.map_err(map_sqlite_err)?;

            let agent: AgentRecord = serde_json::from_str(&payload)?;

            if agent.agent_id.to_string() != col_agent_id
                || format!("{:?}", agent.state) != col_state
                || agent.owner.actor_id != col_principal
                || agent.process_identity.instance_nonce.to_string() != col_nonce
            {
                return Err(StorageError::CorruptRecord {
                    entity: "Agent",
                    id: col_agent_id,
                    reason: "Indexed database columns contradict serialized JSON payload".into(),
                });
            }

            verify_agent_capabilities(&conn, &agent)?;

            agents.push(agent);
        }

        Ok(agents)
    }

    /// Updates an agent record, enforcing terminal state immutability.
    pub fn update_agent(&self, agent: &AgentRecord) -> Result<(), StorageError> {
        let mut conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let tx = conn.transaction().map_err(map_sqlite_err)?;

        let agent_id_str = agent.agent_id.to_string();

        // 1. Fetch current persisted state to enforce terminal state rules
        let existing: Result<(String, String), rusqlite::Error> = tx.query_row(
            "SELECT state, payload FROM agents WHERE agent_id = ?;",
            rusqlite::params![agent_id_str],
            |row| Ok((row.get(0)?, row.get(1)?)),
        );

        let (current_state, current_payload) = match existing {
            Ok(pair) => pair,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                return Err(StorageError::NotFound {
                    entity: "Agent",
                    id: agent_id_str,
                })
            }
            Err(e) => return Err(map_sqlite_err(e)),
        };

        let existing_agent: AgentRecord = serde_json::from_str(&current_payload)?;

        // If currently in a terminal state (Stopped or Failed), update is allowed only
        // if this is a validated restart transition to Starting with incremented retries.
        if existing_agent.state.is_terminal() {
            let is_valid_restart = agent.state == crate::agent::AgentLifecycleState::Starting
                && agent.process_identity.instance_nonce
                    != existing_agent.process_identity.instance_nonce;

            if !is_valid_restart {
                return Err(StorageError::TerminalState {
                    entity: "Agent",
                    id: agent_id_str,
                    state: current_state,
                });
            }
        }

        let payload = serde_json::to_string(agent)?;
        let state_str = format!("{:?}", agent.state);
        let scope_str = format!("{:?}", agent.scope);
        let nonce_str = agent.process_identity.instance_nonce.to_string();

        let rows_affected = tx
            .execute(
                r#"
                UPDATE agents
                SET agent_type = ?,
                    principal_id = ?,
                    scope = ?,
                    instance_nonce = ?,
                    pid = ?,
                    start_time_ticks = ?,
                    state = ?,
                    updated_at_ms = ?,
                    payload = ?
                WHERE agent_id = ?;
                "#,
                rusqlite::params![
                    agent.agent_type.as_str(),
                    agent.owner.actor_id,
                    scope_str,
                    nonce_str,
                    agent.process_identity.pid,
                    agent.process_identity.start_time_ticks,
                    state_str,
                    agent.updated_at_ms,
                    payload,
                    agent_id_str,
                ],
            )
            .map_err(map_sqlite_err)?;

        if rows_affected == 0 {
            return Err(StorageError::NotFound {
                entity: "Agent",
                id: agent_id_str,
            });
        }

        // Resync capability indexes
        tx.execute(
            "DELETE FROM agent_capabilities WHERE agent_id = ?;",
            rusqlite::params![agent_id_str],
        )
        .map_err(map_sqlite_err)?;

        for cap in &agent.declared_capabilities {
            tx.execute(
                "INSERT INTO agent_capabilities (agent_id, capability_id) VALUES (?, ?);",
                rusqlite::params![agent_id_str, cap],
            )
            .map_err(map_sqlite_err)?;
        }

        tx.commit().map_err(map_sqlite_err)?;
        Ok(())
    }

    /// Deletes an agent record, cascading to capabilities and heartbeats via foreign keys.
    pub fn delete_agent(&self, agent_id: &AgentId) -> Result<(), StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let agent_id_str = agent_id.to_string();

        let affected = conn
            .execute(
                "DELETE FROM agents WHERE agent_id = ?;",
                rusqlite::params![agent_id_str],
            )
            .map_err(map_sqlite_err)?;

        if affected == 0 {
            return Err(StorageError::NotFound {
                entity: "Agent",
                id: agent_id_str,
            });
        }

        Ok(())
    }

    /// Queries all agents declaring support for a given capability identifier.
    pub fn find_by_capability(
        &self,
        capability_id: &str,
    ) -> Result<Vec<AgentRecord>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;

        let mut stmt = conn
            .prepare(
                r#"
                SELECT a.agent_id, a.state, a.principal_id, a.instance_nonce, a.payload
                FROM agents a
                INNER JOIN agent_capabilities c ON a.agent_id = c.agent_id
                WHERE c.capability_id = ?
                ORDER BY a.agent_id ASC;
                "#,
            )
            .map_err(map_sqlite_err)?;

        let rows = stmt
            .query_map(rusqlite::params![capability_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(map_sqlite_err)?;

        let mut agents = Vec::new();
        for item in rows {
            let (col_agent_id, col_state, col_principal, col_nonce, payload) =
                item.map_err(map_sqlite_err)?;

            let agent: AgentRecord = serde_json::from_str(&payload)?;

            if agent.agent_id.to_string() != col_agent_id
                || format!("{:?}", agent.state) != col_state
                || agent.owner.actor_id != col_principal
                || agent.process_identity.instance_nonce.to_string() != col_nonce
            {
                return Err(StorageError::CorruptRecord {
                    entity: "Agent",
                    id: col_agent_id,
                    reason: "Indexed database columns contradict serialized JSON payload".into(),
                });
            }

            if !agent.declared_capabilities.contains(capability_id) {
                return Err(StorageError::CorruptRecord {
                    entity: "Agent",
                    id: col_agent_id,
                    reason: format!(
                        "Relational capability '{}' missing from payload declared_capabilities",
                        capability_id
                    ),
                });
            }

            verify_agent_capabilities(&conn, &agent)?;

            agents.push(agent);
        }

        Ok(agents)
    }

    /// Queries all agents owned by a specific principal identifier.
    pub fn find_by_principal(&self, principal_id: &str) -> Result<Vec<AgentRecord>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;

        let mut stmt = conn
            .prepare(
                r#"
                SELECT agent_id, state, principal_id, instance_nonce, payload
                FROM agents
                WHERE principal_id = ?
                ORDER BY agent_id ASC;
                "#,
            )
            .map_err(map_sqlite_err)?;

        let rows = stmt
            .query_map(rusqlite::params![principal_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(map_sqlite_err)?;

        let mut agents = Vec::new();
        for item in rows {
            let (col_agent_id, col_state, col_principal, col_nonce, payload) =
                item.map_err(map_sqlite_err)?;

            let agent: AgentRecord = serde_json::from_str(&payload)?;

            if agent.agent_id.to_string() != col_agent_id
                || format!("{:?}", agent.state) != col_state
                || agent.owner.actor_id != col_principal
                || agent.process_identity.instance_nonce.to_string() != col_nonce
            {
                return Err(StorageError::CorruptRecord {
                    entity: "Agent",
                    id: col_agent_id,
                    reason: "Indexed database columns contradict serialized JSON payload".into(),
                });
            }

            verify_agent_capabilities(&conn, &agent)?;

            agents.push(agent);
        }

        Ok(agents)
    }

    /// Lists all capabilities registered for an agent from the `agent_capabilities` index table.
    pub fn list_capabilities_for_agent(
        &self,
        agent_id: &AgentId,
    ) -> Result<BTreeSet<String>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let agent_id_str = agent_id.to_string();

        let mut stmt = conn
            .prepare("SELECT capability_id FROM agent_capabilities WHERE agent_id = ? ORDER BY capability_id ASC;")
            .map_err(map_sqlite_err)?;

        let rows = stmt
            .query_map(rusqlite::params![agent_id_str], |row| {
                row.get::<_, String>(0)
            })
            .map_err(map_sqlite_err)?;

        let mut caps = BTreeSet::new();
        for cap in rows {
            caps.insert(cap.map_err(map_sqlite_err)?);
        }

        Ok(caps)
    }

    // =======================================================================
    // WorkAssignment Operations (Authoritative)
    // =======================================================================

    /// Persists a new `WorkAssignment` record.
    pub fn insert_assignment(&self, assignment: &WorkAssignment) -> Result<(), StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;

        let assignment_id_str = assignment.assignment_id.to_string();
        let agent_id_str = assignment.agent_id.to_string();

        // Foreign key check: verify agent exists
        let agent_exists: bool = conn
            .query_row(
                "SELECT 1 FROM agents WHERE agent_id = ? LIMIT 1;",
                rusqlite::params![agent_id_str],
                |_| Ok(true),
            )
            .unwrap_or(false);

        if !agent_exists {
            return Err(StorageError::ForeignKeyViolation {
                reason: format!("Agent '{}' does not exist in registry", agent_id_str),
            });
        }

        // Duplicate check
        let exists: bool = conn
            .query_row(
                "SELECT 1 FROM assignments WHERE assignment_id = ? LIMIT 1;",
                rusqlite::params![assignment_id_str],
                |_| Ok(true),
            )
            .unwrap_or(false);

        if exists {
            return Err(StorageError::DuplicateKey {
                entity: "WorkAssignment",
                key: assignment_id_str,
            });
        }

        let payload = serde_json::to_string(assignment)?;
        let status_str = format!("{:?}", assignment.status);

        conn.execute(
            r#"
            INSERT INTO assignments (
                assignment_id,
                correlation_id,
                request_id,
                workflow_id,
                step_id,
                agent_id,
                capability_id,
                status,
                assigned_at_ms,
                updated_at_ms,
                payload
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            "#,
            rusqlite::params![
                assignment_id_str,
                assignment.correlation_id.to_string(),
                assignment.request_id.to_string(),
                assignment.workflow_id.to_string(),
                assignment.step_id.to_string(),
                agent_id_str,
                assignment.capability_id,
                status_str,
                assignment.assigned_at_ms,
                assignment.updated_at_ms,
                payload,
            ],
        )
        .map_err(map_sqlite_err)?;

        Ok(())
    }

    /// Retrieves a work assignment by `AssignmentId`, validating dual-write consistency.
    pub fn get_assignment(
        &self,
        assignment_id: &AssignmentId,
    ) -> Result<Option<WorkAssignment>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let assignment_id_str = assignment_id.to_string();

        let mut stmt = conn
            .prepare(
                r#"
                SELECT assignment_id, correlation_id, request_id, agent_id, status, payload
                FROM assignments
                WHERE assignment_id = ?;
                "#,
            )
            .map_err(map_sqlite_err)?;

        let mut rows = stmt
            .query(rusqlite::params![assignment_id_str])
            .map_err(map_sqlite_err)?;

        let row = match rows.next().map_err(map_sqlite_err)? {
            Some(row) => row,
            None => return Ok(None),
        };

        let col_assignment_id: String = row.get(0).map_err(map_sqlite_err)?;
        let col_correlation_id: String = row.get(1).map_err(map_sqlite_err)?;
        let col_request_id: String = row.get(2).map_err(map_sqlite_err)?;
        let col_agent_id: String = row.get(3).map_err(map_sqlite_err)?;
        let col_status: String = row.get(4).map_err(map_sqlite_err)?;
        let payload: String = row.get(5).map_err(map_sqlite_err)?;

        let assignment: WorkAssignment = serde_json::from_str(&payload)?;

        // Dual-write integrity validation
        if assignment.assignment_id.to_string() != col_assignment_id
            || assignment.correlation_id.to_string() != col_correlation_id
            || assignment.request_id.to_string() != col_request_id
            || assignment.agent_id.to_string() != col_agent_id
            || format!("{:?}", assignment.status) != col_status
        {
            return Err(StorageError::CorruptRecord {
                entity: "WorkAssignment",
                id: assignment_id_str,
                reason: "Indexed database columns contradict serialized JSON payload".into(),
            });
        }

        Ok(Some(assignment))
    }

    /// Updates an existing work assignment, enforcing terminal state immutability.
    pub fn update_assignment(&self, assignment: &WorkAssignment) -> Result<(), StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let assignment_id_str = assignment.assignment_id.to_string();

        // 1. Fetch current status to enforce terminal state rules
        let current_status: Result<String, rusqlite::Error> = conn.query_row(
            "SELECT status FROM assignments WHERE assignment_id = ?;",
            rusqlite::params![assignment_id_str],
            |row| row.get(0),
        );

        let current_status_str = match current_status {
            Ok(status) => status,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                return Err(StorageError::NotFound {
                    entity: "WorkAssignment",
                    id: assignment_id_str,
                })
            }
            Err(e) => return Err(map_sqlite_err(e)),
        };

        if current_status_str == "Completed"
            || current_status_str == "Failed"
            || current_status_str == "Cancelled"
        {
            return Err(StorageError::TerminalState {
                entity: "WorkAssignment",
                id: assignment_id_str,
                state: current_status_str,
            });
        }

        let payload = serde_json::to_string(assignment)?;
        let status_str = format!("{:?}", assignment.status);

        let affected = conn
            .execute(
                r#"
                UPDATE assignments
                SET status = ?,
                    updated_at_ms = ?,
                    payload = ?
                WHERE assignment_id = ?;
                "#,
                rusqlite::params![
                    status_str,
                    assignment.updated_at_ms,
                    payload,
                    assignment_id_str
                ],
            )
            .map_err(map_sqlite_err)?;

        if affected == 0 {
            return Err(StorageError::NotFound {
                entity: "WorkAssignment",
                id: assignment_id_str,
            });
        }

        Ok(())
    }

    /// Lists all assignments bound to a given agent.
    pub fn list_assignments_for_agent(
        &self,
        agent_id: &AgentId,
    ) -> Result<Vec<WorkAssignment>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;

        let mut stmt = conn
            .prepare(
                r#"
                SELECT assignment_id, correlation_id, request_id, agent_id, status, payload
                FROM assignments
                WHERE agent_id = ?
                ORDER BY assigned_at_ms ASC;
                "#,
            )
            .map_err(map_sqlite_err)?;

        let rows = stmt
            .query_map(rusqlite::params![agent_id.to_string()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .map_err(map_sqlite_err)?;

        let mut assignments = Vec::new();
        for item in rows {
            let (id, corr, req, ag, stat, payload) = item.map_err(map_sqlite_err)?;
            let a: WorkAssignment = serde_json::from_str(&payload)?;
            if a.assignment_id.to_string() != id
                || a.correlation_id.to_string() != corr
                || a.request_id.to_string() != req
                || a.agent_id.to_string() != ag
                || format!("{:?}", a.status) != stat
            {
                return Err(StorageError::CorruptRecord {
                    entity: "WorkAssignment",
                    id,
                    reason: "Indexed database columns contradict serialized JSON payload".into(),
                });
            }
            assignments.push(a);
        }

        Ok(assignments)
    }

    /// Lists all assignments associated with a parent workflow ID.
    pub fn list_assignments_for_workflow(
        &self,
        workflow_id: &Uuid,
    ) -> Result<Vec<WorkAssignment>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;

        let mut stmt = conn
            .prepare(
                r#"
                SELECT assignment_id, correlation_id, request_id, agent_id, status, payload
                FROM assignments
                WHERE workflow_id = ?
                ORDER BY assigned_at_ms ASC;
                "#,
            )
            .map_err(map_sqlite_err)?;

        let rows = stmt
            .query_map(rusqlite::params![workflow_id.to_string()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .map_err(map_sqlite_err)?;

        let mut assignments = Vec::new();
        for item in rows {
            let (id, corr, req, ag, stat, payload) = item.map_err(map_sqlite_err)?;
            let a: WorkAssignment = serde_json::from_str(&payload)?;
            if a.assignment_id.to_string() != id
                || a.correlation_id.to_string() != corr
                || a.request_id.to_string() != req
                || a.agent_id.to_string() != ag
                || format!("{:?}", a.status) != stat
            {
                return Err(StorageError::CorruptRecord {
                    entity: "WorkAssignment",
                    id,
                    reason: "Indexed database columns contradict serialized JSON payload".into(),
                });
            }
            assignments.push(a);
        }

        Ok(assignments)
    }

    /// Lists all assignments associated with a specific workflow step ID.
    pub fn list_assignments_for_step(
        &self,
        step_id: &Uuid,
    ) -> Result<Vec<WorkAssignment>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;

        let mut stmt = conn
            .prepare(
                r#"
                SELECT assignment_id, correlation_id, request_id, agent_id, status, payload
                FROM assignments
                WHERE step_id = ?
                ORDER BY assigned_at_ms ASC;
                "#,
            )
            .map_err(map_sqlite_err)?;

        let rows = stmt
            .query_map(rusqlite::params![step_id.to_string()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .map_err(map_sqlite_err)?;

        let mut assignments = Vec::new();
        for item in rows {
            let (id, corr, req, ag, stat, payload) = item.map_err(map_sqlite_err)?;
            let a: WorkAssignment = serde_json::from_str(&payload)?;
            if a.assignment_id.to_string() != id
                || a.correlation_id.to_string() != corr
                || a.request_id.to_string() != req
                || a.agent_id.to_string() != ag
                || format!("{:?}", a.status) != stat
            {
                return Err(StorageError::CorruptRecord {
                    entity: "WorkAssignment",
                    id,
                    reason: "Indexed database columns contradict serialized JSON payload".into(),
                });
            }
            assignments.push(a);
        }

        Ok(assignments)
    }

    // =======================================================================
    // Heartbeat Operations (Observational Telemetry)
    // =======================================================================

    /// Appends an observed heartbeat record.
    ///
    /// ### Invariants Enforced
    /// 1. Foreign key integrity: rejects heartbeats for non-existent agents.
    /// 2. Session validity: rejects stale heartbeats whose `instance_nonce` does not match the active instance.
    /// 3. Heartbeat Timing Invariant: enforces `PRIMARY KEY (agent_id, timestamp_ms)`, rejecting duplicate
    ///    records sharing the same millisecond timestamp with `StorageError::DuplicateKey`.
    pub fn append_heartbeat(&self, heartbeat: &HeartbeatRecord) -> Result<(), StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let agent_id_str = heartbeat.agent_id.to_string();

        // 1. Foreign key verification: verify agent exists and retrieve active instance nonce
        let active_nonce: Result<String, rusqlite::Error> = conn.query_row(
            "SELECT instance_nonce FROM agents WHERE agent_id = ?;",
            rusqlite::params![agent_id_str],
            |row| row.get(0),
        );

        let registered_nonce = match active_nonce {
            Ok(nonce) => nonce,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                return Err(StorageError::ForeignKeyViolation {
                    reason: format!("Agent '{}' does not exist in registry", agent_id_str),
                });
            }
            Err(e) => return Err(map_sqlite_err(e)),
        };

        // 2. Reject stale heartbeats belonging to a previous process instance
        if registered_nonce != heartbeat.instance_nonce.to_string() {
            return Err(StorageError::CorruptRecord {
                entity: "HeartbeatRecord",
                id: agent_id_str,
                reason: format!(
                    "Heartbeat instance_nonce '{}' does not match active agent instance_nonce '{}'",
                    heartbeat.instance_nonce, registered_nonce
                ),
            });
        }

        let payload = serde_json::to_string(heartbeat)?;

        conn.execute(
            r#"
            INSERT INTO agent_heartbeats (
                agent_id,
                timestamp_ms,
                sequence_number,
                cpu_usage_permille,
                memory_rss_bytes,
                open_fds,
                payload
            ) VALUES (?, ?, ?, ?, ?, ?, ?);
            "#,
            rusqlite::params![
                agent_id_str,
                heartbeat.timestamp_ms,
                heartbeat.sequence_number,
                heartbeat.metrics.cpu_usage_permille,
                heartbeat.metrics.memory_rss_bytes,
                heartbeat.metrics.open_fds,
                payload,
            ],
        )
        .map_err(map_sqlite_err)?;

        Ok(())
    }

    /// Queries recent heartbeats for an agent, ordered descending by timestamp.
    pub fn list_recent_heartbeats(
        &self,
        agent_id: &AgentId,
        limit: usize,
    ) -> Result<Vec<HeartbeatRecord>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockPoisoned)?;
        let agent_id_str = agent_id.to_string();

        let mut stmt = conn
            .prepare(
                r#"
                SELECT payload
                FROM agent_heartbeats
                WHERE agent_id = ?
                ORDER BY timestamp_ms DESC
                LIMIT ?;
                "#,
            )
            .map_err(map_sqlite_err)?;

        let rows = stmt
            .query_map(rusqlite::params![agent_id_str, limit as i64], |row| {
                row.get::<_, String>(0)
            })
            .map_err(map_sqlite_err)?;

        let mut heartbeats = Vec::new();
        for item in rows {
            let payload = item.map_err(map_sqlite_err)?;
            let hb: HeartbeatRecord = serde_json::from_str(&payload)?;
            heartbeats.push(hb);
        }

        Ok(heartbeats)
    }

    /// Queries an arbitrary SQLite PRAGMA value on the configured connection.
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
