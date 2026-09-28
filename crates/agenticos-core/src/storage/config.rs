use super::error::StorageError;
use rusqlite::Connection;
use std::path::PathBuf;

/// Migration specification for domain database schemas.
#[derive(Debug, Clone)]
pub struct Migration {
    /// Incremental migration version (must start at 1).
    pub version: u32,
    /// Human-readable description of changes.
    pub description: &'static str,
    /// Forward SQL statements to apply.
    pub sql: &'static str,
}

/// Applies standard AgenticOS SQLite production PRAGMAs consistent with ADR-0006.
///
/// Ensures:
/// - WAL mode for concurrent readers and single writer
/// - synchronous = NORMAL for corruption safety
/// - foreign_keys = ON for relational integrity enforcement
/// - busy_timeout = 5000 ms to handle concurrency contention
/// - temp_store = MEMORY
/// - auto_vacuum = INCREMENTAL
pub fn configure_connection(conn: &Connection) -> Result<(), StorageError> {
    // Execute standard AgenticOS SQLite production PRAGMAs
    conn.execute_batch(
        r#"
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA foreign_keys = ON;
        PRAGMA busy_timeout = 5000;
        PRAGMA temp_store = MEMORY;
        "#,
    )?;

    // 1. Verify journal_mode = WAL
    let journal_mode: String = conn.query_row("PRAGMA journal_mode;", [], |row| row.get(0))?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(StorageError::ConfigurationFailed {
            reason: format!(
                "Failed to set journal_mode to WAL, current mode is: {}",
                journal_mode
            ),
        });
    }

    // 2. Verify synchronous = NORMAL (returns 1 in SQLite)
    let sync: i64 = conn.query_row("PRAGMA synchronous;", [], |row| row.get(0))?;
    if sync != 1 {
        return Err(StorageError::ConfigurationFailed {
            reason: format!("Failed to set synchronous to NORMAL (1), got: {}", sync),
        });
    }

    // 3. Verify foreign_keys = ON (returns 1 in SQLite)
    let fk: i64 = conn.query_row("PRAGMA foreign_keys;", [], |row| row.get(0))?;
    if fk != 1 {
        return Err(StorageError::ConfigurationFailed {
            reason: "Failed to enable foreign_keys pragma".into(),
        });
    }

    // 4. Verify busy_timeout = 5000 (5 seconds)
    let busy_timeout: i64 = conn.query_row("PRAGMA busy_timeout;", [], |row| row.get(0))?;
    if busy_timeout != 5000 {
        return Err(StorageError::ConfigurationFailed {
            reason: format!("Failed to set busy_timeout to 5000, got: {}", busy_timeout),
        });
    }

    // 5. Verify temp_store = MEMORY (returns 2 in SQLite)
    let temp_store: i64 = conn.query_row("PRAGMA temp_store;", [], |row| row.get(0))?;
    if temp_store != 2 {
        return Err(StorageError::ConfigurationFailed {
            reason: format!(
                "Failed to set temp_store to MEMORY (2), got: {}",
                temp_store
            ),
        });
    }

    Ok(())
}

/// Configures an Agent Registry database connection with production PRAGMAs and verifies `auto_vacuum = INCREMENTAL`.
///
/// Rules:
/// 1. Queries `PRAGMA auto_vacuum` on every AgentRegistryStore connection.
/// 2. Requires the actual database value to be INCREMENTAL (2).
/// 3. For a brand-new database (`table_count == 0`): configures `auto_vacuum = INCREMENTAL`
///    before schema creation and journal mode initialization, then verifies that the resulting database value is 2.
/// 4. For an existing database (`table_count > 0`): does NOT silently attempt to change `auto_vacuum`.
///    If the existing database reports anything other than 2, fails closed with `StorageError::ConfigurationFailed`.
/// 5. Does NOT automatically run VACUUM as part of ordinary startup recovery.
pub fn configure_agent_registry_connection(conn: &Connection) -> Result<(), StorageError> {
    let table_count: i64 = conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name != 'android_metadata';",
        [],
        |row| row.get(0),
    )?;

    // Brand-new database: configure auto_vacuum = INCREMENTAL before journal mode initialization or table creation
    if table_count == 0 {
        conn.execute_batch("PRAGMA auto_vacuum = INCREMENTAL;")?;
    }

    // Configure standard AgenticOS PRAGMAs (WAL, synchronous, foreign keys, busy timeout, temp store)
    configure_connection(conn)?;

    // On every connection, require actual database value to be INCREMENTAL (2)
    let auto_vacuum: i64 = conn.query_row("PRAGMA auto_vacuum;", [], |row| row.get(0))?;
    if auto_vacuum != 2 {
        return Err(StorageError::ConfigurationFailed {
            reason: format!(
                "Database auto_vacuum mode is {}, but INCREMENTAL (2) is required. Incompatible databases must be migrated or recreated.",
                auto_vacuum
            ),
        });
    }

    Ok(())
}

/// Runs a lightweight integrity check (`PRAGMA quick_check`) on database open per ADR-0006.
pub fn verify_integrity(conn: &Connection) -> Result<(), StorageError> {
    let result: String = conn.query_row("PRAGMA quick_check;", [], |row| row.get(0))?;
    if !result.eq_ignore_ascii_case("ok") {
        return Err(StorageError::DatabaseCorrupted { details: result });
    }
    Ok(())
}

/// Runs a full integrity check (`PRAGMA integrity_check;`) on database open for the Agent Registry.
pub fn verify_full_integrity(conn: &Connection) -> Result<(), StorageError> {
    let result: String = conn.query_row("PRAGMA integrity_check;", [], |row| row.get(0))?;
    if !result.eq_ignore_ascii_case("ok") {
        return Err(StorageError::DatabaseCorrupted { details: result });
    }
    Ok(())
}

/// Runs a foreign key constraint check (`PRAGMA foreign_key_check;`) on database open per ADR-0006.
pub fn verify_foreign_keys(conn: &Connection) -> Result<(), StorageError> {
    let mut stmt = conn.prepare("PRAGMA foreign_key_check;")?;
    let mut rows = stmt.query([])?;
    if let Some(row) = rows.next()? {
        let table: String = row.get(0)?;
        let rowid: i64 = row.get(1)?;
        let parent: String = row.get(2)?;
        let fkid: i64 = row.get(3)?;
        return Err(StorageError::ForeignKeyViolation {
            reason: format!(
                "Foreign key check failed in table '{}' at rowid {} referencing parent '{}' (fkid {})",
                table, rowid, parent, fkid
            ),
        });
    }
    Ok(())
}

/// Deterministically applies linear schema migrations within isolated transactions per ADR-0006.
pub fn apply_migrations(
    conn: &mut Connection,
    migrations: &[Migration],
) -> Result<(), StorageError> {
    let current_version: u32 = conn.query_row("PRAGMA user_version;", [], |row| row.get(0))?;
    let target_version = migrations.len() as u32;

    if current_version > target_version {
        return Err(StorageError::IncompatibleSchemaVersion {
            found: current_version,
            supported: target_version,
        });
    }

    // If database already has migrations applied, verify user_version matches schema_migrations table
    if current_version > 0 {
        let recorded_max: Result<Option<u32>, rusqlite::Error> = conn
            .query_row("SELECT MAX(version) FROM schema_migrations;", [], |row| {
                row.get(0)
            })
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            });

        if let Ok(Some(recorded_version)) = recorded_max {
            if recorded_version != current_version {
                return Err(StorageError::ConfigurationFailed {
                    reason: format!(
                        "PRAGMA user_version ({}) disagrees with schema_migrations table ({})",
                        current_version, recorded_version
                    ),
                });
            }
        }
    }

    if current_version == target_version {
        return Ok(());
    }

    for migration in migrations {
        if migration.version > current_version {
            let tx = conn.transaction()?;

            tx.execute_batch(migration.sql)
                .map_err(|e| StorageError::MigrationFailed {
                    version: migration.version,
                    reason: e.to_string(),
                })?;

            tx.execute(
                "INSERT INTO schema_migrations (version, description) VALUES (?, ?);",
                rusqlite::params![migration.version, migration.description],
            )
            .map_err(|e| StorageError::MigrationFailed {
                version: migration.version,
                reason: e.to_string(),
            })?;

            // PRAGMA user_version cannot be parameterized; format version safely
            let pragma_sql = format!("PRAGMA user_version = {};", migration.version);
            tx.execute_batch(&pragma_sql)
                .map_err(|e| StorageError::MigrationFailed {
                    version: migration.version,
                    reason: e.to_string(),
                })?;

            tx.commit()?;
        }
    }

    Ok(())
}

/// Returns the default runtime data directory according to ADR-0006 ($XDG_DATA_HOME/agenticos/data or ~/.local/share/agenticos/data).
pub fn default_data_dir() -> PathBuf {
    if let Ok(xdg_data_home) = std::env::var("XDG_DATA_HOME") {
        if !xdg_data_home.trim().is_empty() {
            return PathBuf::from(xdg_data_home).join("agenticos").join("data");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.trim().is_empty() {
            return PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("agenticos")
                .join("data");
        }
    }
    PathBuf::from(".local/share/agenticos/data")
}
