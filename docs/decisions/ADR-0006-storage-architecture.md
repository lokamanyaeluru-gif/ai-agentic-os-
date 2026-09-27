# ADR-0006: Storage Architecture for AI Agentic OS

* **Status**: PROPOSED  
* **Date**: 2026-09-27  
* **Phase**: 0.3.5  

---

## Context

AI Agentic OS operates as an AI-native desktop control plane above Linux. In this architecture, autonomous agents coordinate multi-step workflows to achieve user-directed goals. To execute predictably, recover cleanly from power interruptions or crashes, and preserve user privacy, AgenticOS requires a cohesive, robust, and local-only storage architecture.

### Architectural Prerequisites from Prior Decisions
* **ADR-0001 (Deterministic Security & Local Operation)**: All system state, memory, models, and policy data reside strictly on local storage. Remote telemetry or cloud database dependencies are strictly disallowed.
* **ADR-0002 (IPC Architecture)**: Internal subsystems communicate over private Unix Domain Sockets; no shared-memory database IPC or unauthenticated network sockets are exposed.
* **ADR-0003 (Sandbox Architecture)**: Capability workers run in isolated Bubblewrap containers under Landlock and seccomp containment. Sandboxed workers are strictly forbidden from directly opening or querying system databases.
* **ADR-0004 (Implementation Language Architecture)**: The trusted control, security, and state-management plane (Layers 2–12) is authored in Rust. Storage engines must embed natively and safely in Rust without external server daemons.
* **ADR-0005 (Policy Engine Architecture)**: Cedar PBAC core + AgenticOS Security Wrapper enforces deterministic authorization. Storage operations are mediated by typed capabilities; policy definitions have strict administrative boundaries.

### Architectural Layering Context
The AgenticOS system architecture establishes 13 distinct layers:
* Layers 1–7: Human Interface, Intent Intelligence, Goal Runtime, Workflow Runtime, Global Agent Manager, Agent Runtime, and Knowledge & Memory.
* Layer 8: Capability Layer (Sandbox Runner).
* Layer 9: Linux Integration & System Services Layer (D-Bus adapters, systemd integration).
* Layer 10: Kernel & System Intelligence.
* Layer 11: Linux Host Operating System.
* Layer 12: Observability & Reliability (audit, tracing, telemetry).
* Layer 13: Hardware Layer.
* **Security & Governance** operates as a cross-cutting architectural responsibility mediating access across these layers rather than occupying a single layer number.

### The Storage Problem Statement
AgenticOS manages diverse categories of state with different operational, consistency, and durability requirements:
1. Relational and structured execution state (goals, workflow DAGs, agent lifecycles, memory graphs).
2. Declarative text files (policies, configurations).
3. Sensitive credentials (API tokens, session secrets).
4. Append-only audit logs.
5. Large binary artifacts (images, compiled binaries, datasets).
6. Derived indexes (full-text search, vector embeddings).
7. Volatile runtime state (IPC sockets, process tracking, ephemeral locks).

Attempting to place all state into a single monolithic database creates write contention across unrelated domains, complicates independent subsystem backups, increases failure blast radius, and tightly couples component lifecycles. Conversely, unmanaged flat files lack transactional guarantees unless custom atomic-write protocols are maintained.

We must establish a storage architecture with unambiguous ownership, clear separation between authoritative and derived state, robust crash recovery, and strict access control.

---

## Foundational Principle: State Classification

AgenticOS classifies all system data into three distinct operational categories:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        DATA CLASSIFICATION MODEL                       │
├────────────────────────────────────────────────────────────────────────┤
│ 1. AUTHORITATIVE STATE                                                 │
│    - The canonical source of truth.                                    │
│    - Requires ACID transactions, explicit schema versions, and backups.│
│    - Examples: Goal DAGs, Cedar policies, Agent state, Audit records.  │
├────────────────────────────────────────────────────────────────────────┤
│ 2. DERIVED STATE                                                       │
│    - Rebuildable indexes, caches, and computed summaries.              │
│    - Never authoritative; can be purged or reconstructed on demand.   │
│    - Examples: SQLite FTS5 search index, vector embeddings, AST cache. │
├────────────────────────────────────────────────────────────────────────┤
│ 3. EPHEMERAL STATE                                                     │
│    - Volatile in-flight runtime data bound to process or boot session. │
│    - Stored in OS/session runtime directory or explicit tmpfs mounts;  │
│      cleaned according to its defined lifecycle.                       │
│    - Examples: UDS socket files, lock files, worker scratch dirs.     │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Detailed Storage Taxonomy

| Storage Category | Primary Technology | Filesystem Location | Persistence | Authoritative Component | Sensitivity |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Core Structured State** | SQLite (WAL mode) | `~/.local/share/agenticos/data/*.db` | Persistent (ACID) | Goal Runtime (L3), Workflow Runtime (L4), Agent Mgr (L5), Knowledge & Memory (L7) | High (User/Task Data) |
| **System Policies** | Declarative Cedar files | `/etc/agenticos/policies/system/` | Persistent (Versioned) | Security & Governance (System Admin) | Critical (System Security) |
| **User Policies** | Declarative Cedar files | `~/.config/agenticos/policies/user/` | Persistent (Versioned) | Security & Governance (User Scoped) | High (User Security) |
| **Configuration** | TOML / KDL files | `/etc/agenticos/` & `~/.config/agenticos/` | Persistent | Configuration Subsystem / Host Integration | Medium (Preferences) |
| **Secrets & Keys** | Encrypted Vault / OS Key Protection | `~/.local/share/agenticos/vault/` | Persistent (Encrypted) | Security & Governance (Secrets Subsystem) | Critical (Confidential) |
| **Audit Trails** | Append-only JSONL files | `/var/log/agenticos/` & `~/.local/share/agenticos/logs/` | Persistent (Append-only) | Observability & Reliability (L12) | Critical (Audit Integrity) |
| **Artifacts & Blobs** | Content-Addressed Store | `~/.local/share/agenticos/blobs/` | Persistent | Knowledge & Memory (L7) | Medium (Data Files) |
| **Search Indexes** | SQLite FTS5 (Derived) | `~/.local/share/agenticos/data/search.db` | Derived (Rebuildable) | Knowledge & Memory (L7) | High (Indexed Content) |
| **Vector Embeddings** | Embedded Vector Index | `~/.local/share/agenticos/data/vectors.db`| Derived (Rebuildable) | Knowledge & Memory (L7) | High (Semantic Cache) |
| **Runtime & IPC State**| `tmpfs` / In-Memory | `/run/user/<uid>/agenticos/` | Ephemeral (Session) | Supervisor IPC Subsystem | High (Live Session) |
| **Worker Scratch** | Container `tmpfs` Mounts | Sandboxed mount namespace | Ephemeral (Per-task)| Capability Layer (L8 Runner) | Ephemeral / Untrusted |

---

## Architectural Evaluation of Candidate Storage Engines

### 1. Core Structured State Engine

* **Candidate 1A: Embedded SQLite (`rusqlite`) - Selected**:
  * *Reliability & Crash Recovery*: Battle-tested across billions of deployments. Write-Ahead Logging (WAL) mode provides atomic commit, crash recovery, and single-writer/multi-reader concurrency without locking readers.
  * *Ecosystem & Rust Integration*: First-class, mature Rust bindings via `rusqlite` with optional bundled SQLite source.
  * *Query Capabilities*: Full SQL engine, relational foreign keys, check constraints, JSON1 extension, and built-in full-text search (FTS5).
  * *Footprint*: Embedded library linked directly into the Rust supervisor binary; requires no external daemon processes.
* **Candidate 1B: Pure Rust Key-Value Store (`redb`) - Evaluated for Specialized KV**:
  * *Properties*: Pure Rust, ACID-compliant, MVCC key-value database licensed under Apache-2.0.
  * *Trade-offs*: Fast single-key and range queries, but lacks relational integrity, secondary indexes, and SQL query expressiveness. Suitable as a specialized internal key-value store, but insufficient as the primary relational store for complex goal DAGs and memory graphs.
* **Candidate 1C: Embedded RocksDB (`rocksdb`) - Rejected**:
  * *Trade-offs*: Heavy C++ codebase with complex build dependencies, high memory overhead, and operational tuning complexity. Designed for multi-terabyte server workloads, not single-user desktop OS environments.
* **Candidate 1D: Sled - Rejected**:
  * *Trade-offs*: Pure Rust embedded database, but has experienced protracted beta status and historical crash-recovery inconsistencies. Not suitable for production-critical state.

### 2. Search & Indexing Engine

* **Candidate 2A: Derived SQLite FTS5 Index (`search.db`) - Selected**:
  * *Architecture*: Global full-text search operates as a dedicated, derived index in `search.db`. It does not participate in synchronous transactions with authoritative databases (`memory.db`, `workflows.db`).
  * *Consistency Model*: Updates to `search.db` are processed asynchronously (or via event triggers) from authoritative state changes.
  * *Rebuildability*: If `search.db` is corrupted, deleted, or desynchronized, it can be regenerated completely from authoritative stores without loss of source data.
* **Candidate 2B: Tantivy (Pure Rust Search Engine) - Evaluated / Deferred for Large-Scale Corpus**:
  * *Properties*: High-performance Lucene-like search library written in pure Rust (MIT license).
  * *Trade-offs*: Outstanding search throughput and linguistic tokenization, but requires managing separate segment files, index commit locks, and background compaction threads. Deferred until document corpus scale exceeds SQLite FTS5 performance thresholds.

### 3. Secret & Credential Storage

* **Candidate 3A: Encrypted Local Vault with OS-Backed Key Protection - Selected**:
  * Secrets are stored in a dedicated, isolated file (`~/.local/share/agenticos/vault/secrets.enc`, mode `0600`).
  * Values are encrypted at rest using authenticated symmetric encryption (ChaCha20-Poly1305 / AES-256-GCM).
  * OS key protection services (e.g. Linux Kernel Keyring or FreeDesktop Secret Service via Layer 9 D-Bus) are used to protect access to the decryption key material.
  * Secrets are never stored in SQLite databases or plaintext configuration files.
  * The exact Key Derivation Function (KDF), key hierarchy, rotation mechanics, and key-storage integration remain TBD for detailed design.

---

## Detailed Component Ownership Boundaries

To preserve architectural boundaries and prevent cross-subsystem state corruption, every storage artifact has an explicit single-owner component:

```
┌────────────────────────────────────────────────────────────────────────┐
│                      STORAGE OWNERSHIP MATRIX                          │
├──────────────────────┬────────────────────────────┬────────────────────┤
│ Storage Artifact     │ Sole Authoritative Owner   │ Access Channel     │
├──────────────────────┼────────────────────────────┼────────────────────┤
│ goals.db             │ Goal Runtime (Layer 3)     │ Layer 3 Domain API │
│ workflows.db         │ Workflow Runtime (Layer 4) │ Layer 4 Domain API │
│ agent_registry.db    │ Global Agent Mgr (Layer 5) │ Layer 5 Domain API │
│ memory.db            │ Knowledge/Memory (Layer 7) │ Layer 7 Domain API │
│ search.db (derived)  │ Knowledge/Memory (Layer 7) │ Layer 7 Search API │
│ policies/*.cedar     │ Security & Governance      │ Security Ingress   │
│ secrets.vault        │ Security & Governance      │ Secret Service API │
│ audit/*.jsonl        │ Observability & Rel (L12)  │ Layer 12 Sink      │
│ blobs/*              │ Knowledge/Memory (Layer 7) │ Capability FD Pass │
│ /run/.../*.sock      │ Supervisor IPC Subsystem   │ UDS Listener       │
└──────────────────────┴────────────────────────────┴────────────────────┘
```

### Specific Ownership Rules

1. **Policy Storage (`/etc/agenticos/policies/` and `~/.config/agenticos/policies/`)**:
   * **Owner**: Security & Governance (cross-cutting).
   * **Write Authority**:
     * Mandatory System Policies: Modifiable *only* by root/administrator via explicit administrative tooling.
     * User Policies: Modifiable *only* by the authenticated user via trusted desktop UI or CLI.
   * **Rule**: Agents, LLMs, and capability workers have **no write authority** over policy files. Any dynamic agent recommendation to change policy must be rendered as an advisory prompt to the user, who must independently author the policy change.
2. **Audit Trails (`/var/log/agenticos/audit.jsonl` and `~/.local/share/agenticos/logs/`)**:
   * **Owner**: Observability & Reliability (Layer 12).
   * **Write Authority**: Append-only; restricted to the trusted Layer 12 audit writer thread.
   * **Rule**: Audit logs use hash-chained records that provide tamper-evidence within a defined trust boundary. Detecting history rewriting requires a protected integrity anchor.
3. **Structured State Databases (`goals.db`, `workflows.db`, `memory.db`)**:
   * **Owner**: Dedicated runtime layer (Goal Runtime, Workflow Runtime, and Knowledge & Memory respectively).
   * **Rule**: No direct cross-database queries or foreign writes. Subsystems communicate via internal typed UDS messages, never by sharing database connection handles or performing direct cross-file SQL joins.
4. **Binary Artifacts (`blobs/*`)**:
   * **Owner**: Knowledge & Memory (Layer 7).
   * **Rule**: Other layers, including sandboxed capability workers, receive mediated access via passed file descriptors or temporary container bind mounts.
5. **Runtime IPC Endpoints (`/run/.../*.sock`)**:
   * **Owner**: Supervisor IPC Subsystem.
   * **Rule**: Bound to the session lifecycle and managed exclusively by the core supervisor.
6. **Sandboxed Worker Access Rule**:
   * **Rule**: Capability workers running in Layer 8 sandboxes have **no direct access to system SQLite databases, secret vaults, or configuration stores**. If a worker requires data, the trusted supervisor extracts the specific required record, passes it over private UDS or file descriptor, and receives the structured result upon completion.

---

## Security Model for Storage

### 1. Principle of Capability-Mediated Storage Access
Agents and LLMs *never* execute raw SQL or arbitrary filesystem operations against internal state stores:
```
LLM / Autonomous Agent
   │ (Emits typed intent, e.g. "Save memory fact")
   ▼
Typed Capability Invocation ("memory.record_fact")
   │
   ▼
Security & Governance Policy Engine (Validates principal and permissions)
   │
   ▼
Knowledge & Memory Runtime (Executes parameterized prepared statement)
   │
   ▼
SQLite Storage (Encapsulated and isolated)
```

### 2. Filesystem Permissions and Layout Standards
User-scoped AgenticOS paths follow the XDG Base Directory Specification. System-wide configuration, policy, logging, and runtime paths use appropriate Linux system locations:

* **User Configuration**: `$XDG_CONFIG_HOME/agenticos/` (`~/.config/agenticos/`, mode `0700`, files mode `0600`).
* **User Authoritative Data**: `$XDG_DATA_HOME/agenticos/` (`~/.local/share/agenticos/`, mode `0700`, files mode `0600`).
* **User Ephemeral Runtime**: `$XDG_RUNTIME_DIR/agenticos/` (`/run/user/<uid>/agenticos/`, mode `0700`, files mode `0600` on `tmpfs`). Ephemeral state is stored in the OS/session runtime directory or explicit tmpfs mounts and is cleaned according to its defined lifecycle.
* **System Global Storage**:
  * System Configuration: `/etc/agenticos/` (mode `0755`, files root:root `0644`).
  * System Policies: `/etc/agenticos/policies/` (mode `0755`, files root:root `0644`).
  * System Audit Logs: `/var/log/agenticos/` (mode `0750`, files root:agenticos `0640`).

### 3. Secret Vault Security
* Passwords, API tokens, and private keys are never stored in plaintext SQLite databases, environment variables, or configuration files.
* Secrets are stored encrypted within a dedicated vault structure.
* Decryption keys are loaded into non-dumpable memory (`mlock` to prevent swapping to disk) and cleared on process termination.

---

## Database Concurrency and WAL Architecture

Every AgenticOS SQLite database instance is configured with hardened production pragmas upon opening:

```sql
-- Pragmas for AgenticOS SQLite Databases
PRAGMA journal_mode = WAL;          -- Write-Ahead Logging for concurrent readers/single writer
PRAGMA synchronous = NORMAL;         -- Consistent and corruption-safe under normal operation
PRAGMA foreign_keys = ON;            -- Enforce relational integrity constraints
PRAGMA busy_timeout = 5000;          -- Busy timeout (5 seconds) to handle lock contention
PRAGMA temp_store = MEMORY;          -- Store temporary tables in memory
PRAGMA auto_vacuum = INCREMENTAL;    -- Reclaim space safely over time
```

### Durability and Concurrency Nuance
1. **Synchronous Mode Precision**:
   * `WAL + NORMAL` is consistent and safe from corruption in normal SQLite operation.
   * However, durability across sudden power loss or operating system crashes is weaker than `FULL`; committed transactions may be lost after such system-level failures.
   * Stores requiring maximum durability across power loss (e.g. security-sensitive state or audit checkpoints) may selectively configure `synchronous = FULL`.
2. **Concurrency Guarantees**:
   * WAL permits concurrent readers and writers in normal operation, but SQLite still allows only one writer at a time.
   * Applications must handle `SQLITE_BUSY` errors and manage checkpoint contention cleanly.
   * Within each layer (e.g. Goal Runtime), write operations are serialized through a dedicated Rust task/actor to eliminate in-process write lock conflicts.

---

## Schema Evolution and Versioning Strategy

To support rolling updates and system upgrades without data loss, all structured databases follow an explicit migration model:

1. **Schema Version Tracking**: Every database tracks its schema version via SQLite's built-in `PRAGMA user_version`.
2. **Deterministic Migration Pipeline**:
   * Migrations are defined in pure Rust as ordered, linear, forward-only SQL scripts bundled into the supervisor binary at compile time.
   * On startup, the runtime inspects `user_version`. If the database is behind the compiled binary version, a transactional migration begins:
     ```sql
     BEGIN IMMEDIATE;
     -- Execute migration steps (e.g. V1 -> V2)
     PRAGMA user_version = 2;
     COMMIT;
     ```
3. **Migration Failure Invariant**: If a migration step fails, the transaction is rolled back immediately, the database file remains in its previous valid state, and the supervisor aborts initialization with an explicit error.
4. **Prohibition of Destructive In-Place Alterations**: Migrations avoid destructive operations (such as dropping tables) without explicit data backup and transformation procedures.

---

## Backup, Restore, and Disaster Recovery Architecture

### 1. Online Backup Architecture
* **SQLite Online Backup API**: Databases are backed up using SQLite's native online backup API (`sqlite3_backup_*`), which safely streams a snapshot of the database while concurrent read/write operations continue in WAL mode.
* **Consistent Multi-File Snapshots**: To create a consistent cross-system backup:
  1. The supervisor requests a quiesce checkpoint across runtime actors.
  2. Each runtime writes a consistent backup snapshot to a staging directory.
  3. Authoritative declarative policy files (`.cedar`) and configuration files (`.toml`) are copied alongside database snapshots.
  4. The staging directory is archived with a cryptographic SHA-256 manifest.

### 2. Disaster Recovery and Corruption Handling
* **Integrity Checks on Startup**: On daemon startup, databases execute a lightweight integrity check (`PRAGMA quick_check`).
* **Automated WAL Recovery**: If the system experienced an ungraceful shutdown, SQLite automatically replays the WAL file on the next open, recovering committed transactions.
* **Corrupted Database Recovery Procedure**: If an authoritative database fails integrity verification:
  1. **Quarantine**: The supervisor immediately quarantines the corrupted database file (`*.db.corrupted.<timestamp>`).
  2. **Cease Access**: The supervisor stops using the corrupted database immediately.
  3. **Restore from Verified Backup**: The primary recovery path is restoring the database from the latest verified backup snapshot.
  4. **Optional Recovery into New Database**: If no backup exists, tools like SQLite `.recover` may be run into a **new, separate database only**. The recovered database must be validated before adoption, as recovery output may be incomplete or invalid.
  5. **Fail-Safe Requirement**: Under no circumstances does the system silently discard corrupted databases or initialize empty databases that would bypass established security policies or state records.

---

## Alternatives Considered and Architectural Rationale

1. **Monolithic Single Database (All-in-One SQLite)**:
   * *Rejected*: Partitioning storage across domain-specific databases provides clear domain ownership, isolates write contention between high-frequency telemetry and core goal planning, allows fine-grained backup schedules, isolates failure domains, and reduces architectural coupling.
2. **Client-Server Relational Database (PostgreSQL / MySQL)**:
   * *Rejected*: Requires running external background daemons, network/socket configuration, substantial memory overhead, and complex administrative maintenance. Incompatible with a lightweight, local-only desktop operating system layer.
3. **Flat-File JSON Storage for All Entities**:
   * *Rejected*: Naive flat-file mutation lacks transactional semantics unless atomic-write protocols (write to temp file, fsync, atomic rename) are deliberately implemented for every mutation. Furthermore, flat files lack secondary indexing and query optimization for complex state lookups.
4. **External Key-Value / Document Stores (e.g. MongoDB, Redis)**:
   * *Rejected*: Excessive operational overhead, non-relational data modeling, and high memory footprints incompatible with desktop resource preservation.

---

## Open Questions and Deferred Items (Phase 0.3.6+ TBD)

The following design details are deferred to Phase 0.3.6 and implementation planning:

1. **Secret Vault Backup and Re-binding**: Determine whether encrypted secret vaults are included in system backup archives, and how restored secrets are re-bound to the local user session or hardware token on a new host.
2. **Policy and Configuration Backup Consistency**: Define synchronization points to ensure that policy bundles, configuration files, and structured databases are captured at matching logical checkpoints.
3. **Protected Audit Integrity Anchors**: Establish the mechanism for anchoring audit log hash chains (e.g. periodic root hashes logged to kernel logs, local hardware security modules, or local user notifications) to detect log history rewriting.
4. **Database Compaction & Retention Policies**: Determining exact retention intervals for historical workflow execution logs and automated VACUUM schedules.
5. **Vector Store Implementation Selection**: Benchmarking embedded vector extensions (`sqlite-vec`) versus pure-Rust in-memory HNSW vector indexes for Layer 7 semantic memory.
6. **Secret Vault Key Derivation**: Finalizing the key derivation function (Argon2id) and OS key-protection integration specifics for decrypting the local secrets vault.
7. **Automated Snapshot Scheduling**: Determining systemd user timer frequency for background incremental database snapshots.
8. **Cross-Database Transaction Coordination**: Defining the exact two-phase commit protocol or saga pattern for workflows spanning multiple runtime stores (e.g. goal completion triggering memory archival).

---

## Consequences

### Positive
* **High Reliability & Crash Resilience**: SQLite WAL mode provides ACID transactions and automatic crash recovery across process interruptions.
* **Clear Architectural Ownership**: Strictly defined ownership prevents cross-layer state corruption and eliminates uncoordinated database sharing.
* **Defense-in-Depth Security**: Sandboxed capability workers have no direct database access; secrets are strictly segregated and encrypted.
* **Separation of Concerns**: Authoritative state is preserved and backed up; derived indexes can be purged and rebuilt on demand; ephemeral state vanishes cleanly according to its lifecycle.
* **No External Server Daemons**: Embeds directly into the Rust supervisor binary, preserving computing resources for local neural models.

### Negative / Trade-offs
* **Multi-File Coordination Overhead**: Managing multiple SQLite databases requires explicit IPC coordination across layers rather than simple SQL table joins.
* **Migration Maintenance**: Each structured database requires dedicated linear migration files and version tracking.
* **Storage Footprint**: Maintaining separate WAL files and content-addressed blob storage requires deliberate disk-space accounting and retention tuning.

---

## References

* SQLite Documentation: Write-Ahead Logging (`https://sqlite.org/wal.html`)
* SQLite Documentation: The Online Backup API (`https://sqlite.org/backup.html`)
* `rusqlite` Rust Crate: Native bindings to SQLite3 (`https://github.com/rusqlite/rusqlite`)
* `redb` Embedded Key-Value Database (`https://github.com/cberner/redb`)
* FreeDesktop XDG Base Directory Specification (`https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html`)
* Linux Kernel Keyring Documentation (`Documentation/security/keys/core.rst`)
