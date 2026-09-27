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
    // Execute standard AgenticOS SQLite production PRAGMAs in batch
    conn.execute_batch(
        r#"
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA foreign_keys = ON;
        PRAGMA busy_timeout = 5000;
        PRAGMA temp_store = MEMORY;
        PRAGMA auto_vacuum = INCREMENTAL;
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

/// Runs a lightweight integrity check (`PRAGMA quick_check`) on database open per ADR-0006.
pub fn verify_integrity(conn: &Connection) -> Result<(), StorageError> {
    let result: String = conn.query_row("PRAGMA quick_check;", [], |row| row.get(0))?;
    if !result.eq_ignore_ascii_case("ok") {
        return Err(StorageError::DatabaseCorrupted { details: result });
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
