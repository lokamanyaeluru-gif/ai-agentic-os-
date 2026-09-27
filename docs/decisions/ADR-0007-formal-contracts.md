# ADR-0007: Formal Subsystem Contracts and Message Protocols for AI Agentic OS

* **Status**: PROPOSED  
* **Date**: 2026-09-27  
* **Phase**: 0.3.6  

---

## Context

AI Agentic OS structures desktop intelligence and autonomous execution into modular subsystems across 13 architectural layers and cross-cutting security governance. To enable implementation in Rust and sandboxed polyglot capability runtimes without architectural ambiguity, every inter-subsystem boundary requires a formal, typed contract.

### Foundational Architectural Baseline
* **ADR-0001 (Deterministic Security & Local Operation)**: The LLM is never the authorization authority; execution is deterministic and local.
* **ADR-0002 (IPC Architecture)**: Internal subsystem communication is strictly local via Unix Domain Sockets (`AF_UNIX`) using a minimal, versioned, typed protocol; Linux host/desktop integration is mediated via dedicated Layer 10 D-Bus adapters.
* **ADR-0003 (Sandbox Architecture)**: Capability workers run in isolated Bubblewrap containers under Landlock LSM, seccomp-bpf, and cgroups v2 containment.
* **ADR-0004 (Implementation Language Architecture)**: The trusted control plane (Layers 2–12) is authored in Rust; capability workers run out-of-process and sandboxed.
* **ADR-0005 (Policy Engine Architecture)**: Cedar PBAC core + AgenticOS Security Wrapper enforces deterministic authorization with tri-state `ALLOW / DENY / CONFIRM` semantics and cryptographically bound `ApprovalToken` challenges.
* **ADR-0006 (Storage Architecture)**: Separation of authoritative state (SQLite WAL), derived state (rebuildable search/vector indexes), ephemeral state (session tmpfs), and encrypted secret vaults.

### Established 13-Layer Architecture Context
The AgenticOS system architecture establishes 13 distinct layers:
* Layer 1: Human Interface Layer
* Layer 2: Intent Intelligence Layer
* Layer 3: Goal Runtime Layer
* Layer 4: Workflow Runtime Layer
* Layer 5: Global Agent Manager Layer
* Layer 6: Agent Runtime Layer
* Layer 7: Knowledge & Memory Layer
* Layer 8: Capability Layer (Sandbox Runner)
* Layer 9: Applications & Services
* Layer 10: Linux Integration Boundary (D-Bus adapters, systemd integration)
* Layer 11: Kernel & System Intelligence
* Layer 12: Observability & Reliability (audit, tracing, telemetry)
* Layer 13: Hardware Layer
* **Security & Governance** operates as a cross-cutting architectural responsibility mediating policy, token validation, and authorization across layers.

---

## Simplified Capability-Execution Path

The execution diagram below illustrates a **simplified capability-execution path**, not the complete 13-layer pipeline. It traces a single action from human input to host execution, highlighting the interaction between key components without diminishing the architectural roles of Layer 7 (Knowledge & Memory), Layer 9 (Applications & Services), Layer 11 (Kernel & System Intelligence), or Layer 13 (Hardware):

```
[Layer 1: Human Interface]
       │  (1) SubmitIntentRequest
       ▼
[Layer 2: Intent Intelligence]
       │  (2) GoalDeclarationRequest
       ▼
[Layer 3: Goal Runtime]
       │  (3) WorkflowPlanRequest
       ▼
[Layer 4: Workflow Runtime]
       │  (4) AgentTaskAssignment
       ▼
[Layer 5: Global Agent Manager]
       │  (5) AgentExecutionDispatch
       ▼
[Layer 6: Agent Runtime]
       │  (6) CapabilityInvocationRequest (over UDS)
       ▼
[UDS Transport Ingress] ──(Authenticates SO_PEERCRED)──► AuthenticatedPrincipal
       │
       ▼
[Security & Governance (Cross-Cutting)]
       │  (7) Policy Evaluation (Cedar PBAC Core + Wrapper)
       │      ├── DENY    ──► Return PolicyDeniedError to Agent
       │      ├── CONFIRM ──► Confirmation Broker issues Challenge to Layer 1
       │      └── ALLOW   ──► Synthesize Concrete SandboxConstraints
       ▼
[Layer 8: Capability Layer (Sandbox Runner)]
       │  (8) Launch Sandboxed Worker (Bubblewrap + Landlock + seccomp)
       ▼
[Layer 10: Linux Integration Boundary / Host Linux]
       │  (9) Kernel execution / System Service Access
       ▼
[Layer 12: Observability & Reliability] ◄── Telemetry / Audit Event Emission
```

---

## IPC Message Envelope Model

All messages exchanged over internal Unix Domain Sockets adhere to a uniform, envelope-wrapped structure:

```rust
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

pub struct MessageEnvelope {
    /// Explicit contract schema version.
    pub protocol_version: ProtocolVersion,

    /// Globally unique identifier for this specific message.
    pub message_id: Uuid,

    /// Correlation ID linking all causal actions back to the root user goal or task.
    pub correlation_id: Uuid,

    /// Request ID correlating a response directly to a prior request (None for initial requests or events).
    pub request_id: Option<Uuid>,

    /// Wall-clock timestamp (milliseconds since Unix epoch, UTC) for audit and display.
    pub timestamp_ms: u64,

    /// Authenticated principal identity, bound at transport ingress (not self-asserted).
    pub sender: PrincipalContext,

    /// Target subsystem or capability identifier.
    pub destination: String,

    /// Specific typed payload.
    pub payload: MessagePayload,
}

pub enum MessagePayload {
    Request(RequestPayload),
    Response(ResponsePayload),
    Event(EventPayload),
    Error(ErrorPayload),
}
```

### Trust Boundary Rules for Envelope Fields
* **Caller Prohibitions**: A client connecting over UDS **cannot** self-assert its `sender` identity, `timestamp_ms`, or authorization scopes.
* **Ingress Attestation**: The trusted UDS transport ingress inspects kernel socket credentials (`SO_PEERCRED` / `SCM_CREDENTIALS`). It resolves the peer PID/UID/GID against the supervisor process table and injects the authenticated `PrincipalContext` into the envelope before passing the message to internal dispatchers.

---

## Contract Versioning & Evolution

To maintain system stability across software upgrades, all contracts follow strict semantic rules:

1. **Explicit Version Representation**:
   * All contracts declare an explicit `ProtocolVersion { major: u16, minor: u16 }`.
   * Initial baseline version is `1.0`.
2. **Schema Validation and Unknown Fields**:
   * **Security & Control-Plane Contracts**: Strictly **reject unknown fields** during deserialization. Unrecognized fields in security tokens, policy decisions, or capability invocations cause immediate validation errors (`ErrorCode::InvalidRequest`) to prevent schema evasion or ambiguity.
   * **Extensible Application Payloads**: May declare explicit `extensions: Option<HashMap<String, serde_json::Value>>` maps where domain-specific extensibility is required, while the core schema remains strictly validated.
   * **Backward & Forward Compatibility**: Minor version increments (`minor + 1`) indicate backward-compatible additions governed by formal schemas. Major version increments (`major + 1`) indicate breaking changes requiring migration.
3. **Version Negotiation**:
   * During initial UDS connection handshake, client and supervisor exchange supported version ranges:
     ```rust
     pub struct HandshakeRequest {
         pub min_supported_version: ProtocolVersion,
         pub max_supported_version: ProtocolVersion,
         pub client_component_name: String,
     }
     pub struct HandshakeResponse {
         pub agreed_version: ProtocolVersion,
         pub supervisor_version: String,
     }
     ```
   * If no compatible protocol version exists, the connection is rejected immediately with `ErrorCode::IncompatibleProtocolVersion`.

---

## Capability Invocation Contract

When an agent requests host action, it emits a strictly typed `CapabilityInvocationRequest`:

```rust
pub struct ResourceRef {
    /// Resource category/domain (e.g. "Path", "DBusService", "NetworkEndpoint", "Application").
    pub kind: String,

    /// Canonical resource identifier (exact representation governed by policy schema).
    pub identifier: String,
}

pub struct CapabilityInvocationRequest {
    /// Unique invocation request identifier.
    pub request_id: Uuid,

    /// Root correlation ID tracking the causal workflow.
    pub correlation_id: Uuid,

    /// Formal capability identifier (e.g. "fs.read_file", "process.spawn").
    pub capability_id: String,

    /// Version of the capability argument schema.
    pub capability_schema_version: u32,

    /// Conceptual resource reference (exact Cedar entity mapping remains TBD per ADR-0005).
    pub resource: ResourceRef,

    /// Schema-validated structured arguments.
    pub arguments: serde_json::Value,

    /// Absolute wall-clock deadline (UTC milliseconds) for display and logging.
    pub deadline_ms: u64,

    /// Relative execution timeout duration (milliseconds) enforced via monotonic clock.
    pub timeout_duration_ms: u64,

    /// Hash of active policy snapshot under which agent formed request.
    pub policy_snapshot_hash: [u8; 32],

    /// Optional cryptographic approval token if operation required human confirmation.
    pub approval_token: Option<ApprovalToken>,
}
```

### Bounded Execution Limits
* The supervisor enforces an architectural maximum ceiling on `timeout_duration_ms` (e.g. max 300,000 ms / 5 minutes). Requests specifying unbounded or excessive execution times are rejected during validation.

---

## Policy Decision Contract

The Security & Governance layer consumes the authenticated request and evaluates it against the active Cedar policy hierarchy.

### Two-Tier Resolution Architecture
1. **Cedar Core**: Evaluates native PBAC rules to yield `Decision::Allow` or `Decision::Deny`.
2. **Security Governor Wrapper**: Inspects determining policy annotations (`@confirm`), evaluates confirmation scope, and yields the final tripartite decision:

```rust
pub enum PolicyDecision {
    /// Autonomous execution allowed under synthesized sandbox constraints.
    Allow {
        constraints: SandboxConstraints,
        contributing_policies: Vec<String>,
    },

    /// Request denied; contains diagnostic explanation.
    Deny {
        reason: String,
        contributing_policies: Vec<String>,
    },

    /// Request suspended; requires out-of-band human confirmation.
    Confirm {
        challenge_id: Uuid,
        prompt: String,
        blast_radius: BlastRadius,
        required_scope: String,
        contributing_policies: Vec<String>,
    },
}
```

### Synthesized Sandbox Constraints
For `PolicyDecision::Allow`, the Policy Engine produces concrete containment constraints passed to the Layer 8 Sandbox Runner:
```rust
pub struct SandboxConstraints {
    pub read_paths: Vec<PathBuf>,
    pub write_paths: Vec<PathBuf>,
    pub allow_network: bool,
    pub seccomp_profile: String,
    pub max_memory_bytes: u64,
    pub max_cpu_quota_percent: u32,
    pub max_wall_time_ms: u64,
}
```

---

## Human ApprovalToken Contract

The Human UI is an untrusted presentation layer. The trusted **Confirmation Broker (part of cross-cutting Security & Governance)** issues and validates single-use `ApprovalToken` records.

### Canonical ApprovalSubject (Resolution of Circular Hash Dependency)
An `ApprovalToken` cannot hash a `CapabilityInvocationRequest` that itself contains the `ApprovalToken`. To prevent this circular dependency, the request hash is computed strictly over the canonical **`ApprovalSubject`** representation:

```text
CapabilityInvocationRequest
  └──► Extract canonical ApprovalSubject (excluding approval_token)
         └──► Canonical deterministic serialization
                └──► SHA-256
                       └──► request_hash
```

```rust
pub struct ApprovalSubject {
    pub request_id: Uuid,
    pub correlation_id: Uuid,
    pub capability_id: String,
    pub capability_schema_version: u32,
    pub resource: ResourceRef,
    pub arguments: serde_json::Value,
    pub deadline_ms: u64,
    pub timeout_duration_ms: u64,
    pub policy_snapshot_hash: [u8; 32],
}
```

### ApprovalToken Binding Structure & Signed Payload

The cryptographic signature covers all security-relevant fields of the token:
- `single_use_id`
- `request_hash`
- `policy_snapshot_hash`
- `principal`
- `capability`
- `resource`
- `confirmation_reason`
- `issued_at_ms`
- `expires_at_ms`
- `nonce`

```text
ApprovalTokenSignedPayload fields:
  - single_use_id
  - request_hash
  - policy_snapshot_hash
  - principal
  - capability
  - resource
  - confirmation_reason
  - issued_at_ms
  - expires_at_ms
  - nonce
        └──► Canonical deterministic serialization
               └──► Cryptographic signature
```

```rust
pub struct ApprovalTokenSignedPayload {
    /// Unique single-use token ID tracked in replay cache.
    pub single_use_id: Uuid,

    /// SHA-256 hash of canonical ApprovalSubject serialization (excludes approval_token).
    pub request_hash: [u8; 32],

    /// Hash of active policy snapshot when prompt was displayed.
    pub policy_snapshot_hash: [u8; 32],

    /// Authenticated principal authorized by human.
    pub principal: String,

    /// Capability authorized by human.
    pub capability: String,

    /// Resource reference authorized by human.
    pub resource: ResourceRef,

    /// Exact confirmation text shown to human.
    pub confirmation_reason: String,

    /// Unix epoch timestamp (ms) when issued.
    pub issued_at_ms: u64,

    /// Unix epoch timestamp (ms) after which token expires (short TTL, bounded by system max).
    pub expires_at_ms: u64,

    /// Cryptographic random nonce.
    pub nonce: [u8; 16],
}

pub struct ApprovalToken {
    /// Canonical signed payload containing all security-relevant attributes.
    pub payload: ApprovalTokenSignedPayload,

    /// Cryptographic signature from Confirmation Broker private key over canonical serialization of payload.
    pub signature: Vec<u8>,
}
```

### ApprovalToken Signature Contract Metadata
* **Signature Input**: The exact input to the signature algorithm is the canonical serialized byte stream of `ApprovalTokenSignedPayload` (produced via RFC 8785 JCS).
* **Signature Algorithm**: The specific asymmetric signature algorithm is implementation-defined and deferred to Phase 1 implementation planning (TBD) unless already formally selected.
* **Signature Encoding & Representation**: The signature encoding/representation (e.g. raw byte sequence vs. Base64URL string) and verification key distribution/attestation scheme must be explicitly specified before implementation begins.

### Canonical Deterministic Serialization Specification

Because `ApprovalSubject` (which embeds arbitrary structured `arguments: serde_json::Value`) and `ApprovalTokenSignedPayload` form the foundation for cryptographic hashing (SHA-256) and signature verification, "canonical deterministic serialization" cannot be left as an undefined or loose implementation choice.

The system mandates **one canonical serialization algorithm** strictly adhering to **RFC 8785 (JSON Canonicalization Scheme - JCS)** that **MUST be used identically by both the token issuer and verifier**:

1. **Object Key Ordering**:
   * Property names (object keys) MUST be sorted lexicographically by their UTF-16 code units, exactly as specified in RFC 8785 Section 3.2.3.
   * Object keys within nested structures (including dictionary keys inside `arguments`) must follow this identical sorted order recursively.
   * Property-name comparison operates strictly on sequences of UTF-16 code units; UTF-8 byte ordering is not equivalent and must not be used.
2. **Numeric Representation & Constraints**:
   * JSON numbers must satisfy the I-JSON / IEEE 754 double-precision constraints required by RFC 8785.
   * Numeric serialization follows the RFC 8785 / ECMAScript JSON serialization rules.
   * `NaN` and `Infinity` are rejected.
   * Input JSON containing negative zero (-0) MUST be rejected before canonicalization, consistent with the verified RFC 8785 erratum.
   * Higher-precision or longer integer values that cannot be represented appropriately within IEEE 754 double precision MUST be represented using an explicitly defined alternative such as JSON strings, consistent with the application schema.
3. **UTF-8 Output**:
   * The serialized byte stream must be encoded strictly as valid UTF-8 without a Byte Order Mark (BOM).
4. **RFC 8785 String Serialization Rules**:
   * String serialization must conform strictly to RFC 8785 Section 3.2.2.2.
   * Quotation mark and reverse solidus MUST be escaped (as `\"` and `\\`).
   * U+0000 through U+001F MUST use RFC 8785 serialization.
   * U+0008, U+0009, U+000A, U+000C, U+000D use the JSON shorthand escapes `\b`, `\t`, `\n`, `\f`, `\r` respectively.
   * No unnecessary forward-slash escaping (`/` must remain `/`, not `\/`).
   * Other Unicode characters are serialized according to RFC 8785 (emitted as raw unescaped UTF-8 octets).
   * Invalid Unicode such as lone surrogates MUST be rejected.
5. **Null and Boolean Representation**:
   * Literal values must strictly use lowercase ASCII: `true`, `false`, and `null`.
6. **Array Ordering**:
   * Array elements must strictly preserve their exact semantic sequence. Arrays must never be sorted or reordered during canonicalization.
7. **Omission/Presence Rules for Optional Fields**:
   * Optional fields with value `None` must be **completely omitted** from the canonical serialized JSON object (equivalent to Serde `skip_serializing_if = "Option::is_none"`).
   * Optional fields must never be serialized as `"key": null` unless the underlying capability argument schema explicitly mandates a required nullable key.
8. **Whitespace Rules**:
   * Zero extraneous whitespace: No spaces or newlines between keys, colons, commas, or brackets (separators must be strictly `','` and `':'`).

Any implementation that evaluates `ApprovalSubject.request_hash` or verifies `ApprovalToken.signature` must pass the canonical byte stream produced by this exact algorithm. Any byte-level discrepancy between issuer and verifier will fail verification (`ErrorCode::InvalidApprovalToken`).

### Token Verification Flow & Clock Trust Rules
1. **Request Hash Verification**:
   * Receive `CapabilityInvocationRequest`.
   * Extract and omit `approval_token`.
   * Construct canonical `ApprovalSubject` and serialize deterministically.
   * Compute SHA-256 hash.
   * Verify `ApprovalToken.payload.request_hash == computed_hash`.
2. **Signature & Canonical Payload Verification**:
   * Verification reconstructs the exact same canonical `ApprovalTokenSignedPayload` from the token fields.
   * Serializes the payload deterministically to canonical bytes.
   * Verifies the cryptographic signature against the Confirmation Broker public key.
   * Rejects any payload mismatch, tampered field, or invalid signature immediately with `ErrorCode::InvalidApprovalToken`.
3. **Clock Trust & Expiration Enforcement**:
   * **Trusted Clock Authority**: `ApprovalToken` expiry is evaluated **strictly against trusted supervisor / Confirmation Broker time**. Caller-provided or client-asserted timestamps are **never authoritative** for token validity.
   * **Bounded TTL Ceiling**: Token TTL (`expires_at_ms - issued_at_ms`) is bounded by an architectural system maximum (e.g. `MAX_CONFIRMATION_TOKEN_TTL_MS = 60_000` / 60 seconds). Tokens declaring lifetimes exceeding this ceiling are rejected during validation.
   * Validates: `supervisor_now_utc_ms <= ApprovalToken.payload.expires_at_ms`.
   * Monotonic clocks remain reserved for in-flight execution timeouts.
4. **Replay Cache Invariant**:
   * Verify `single_use_id` has not been redeemed previously.
   * Atomically mark `single_use_id` as redeemed in the supervisor's replay cache upon successful authorization.

---

## Comprehensive Error Model

All error responses follow a structured error schema that distinguishes recoverable transient faults from permanent policy or security violations:

```rust
pub enum RetryClassification {
    /// The operation must never be retried automatically.
    Never,

    /// The operation is safe to retry on transient transport/timeout faults.
    Safe,

    /// The operation may be retried only if explicit preconditions/idempotency keys match.
    Conditional,
}

pub struct ErrorPayload {
    /// Standardized error classification code.
    pub code: ErrorCode,

    /// Human-readable explanation.
    pub message: String,

    /// Subsystem originating the error.
    pub source_component: String,

    /// Supervisor/workflow-governed retry classification (not client-asserted).
    pub retry_classification: RetryClassification,

    /// Optional schema version governing structured details.
    pub details_schema_version: Option<u32>,

    /// Schema-validated structured details.
    pub details: Option<serde_json::Value>,
}

pub enum ErrorCode {
    // Client & Validation
    InvalidRequest,
    MalformedArguments,
    IncompatibleProtocolVersion,

    // Security & Policy
    PolicyDenied,
    ConfirmationRequired,
    InvalidApprovalToken,
    TokenReplayDetected,
    PeerAuthenticationFailed,

    // Execution & Sandbox
    CapabilityNotFound,
    SandboxInitializationFailed,
    CapabilityExecutionFailed,
    ResourceCeilingExceeded,

    // Lifecycle & Flow Control
    Timeout,
    Cancelled,
    DependencyFailed,
    StorageFailure,
    InternalError,
}
```

### Safe-Failure Invariants
Implementations **must enforce and test** these architectural failure invariants:
* **Fail-Closed Default**: If any failure occurs during message parsing, peer credential verification, policy evaluation, or sandbox initialization, execution halts immediately with an explicit error.
* **No Unvetted Child Invocation**: If pre-execution checks fail, child capability processes are never spawned.
* **Active Resource Reclamation Invariant**: When a capability worker terminates or errors, the supervisor process actively reaps child process groups and unmounts temporary container directories.

---

## Timeout, Cancellation, and Idempotency Semantics

### 1. Clock Separation & Timeout Enforcement
* **Clocks**:
  * Wall-clock timestamps (`timestamp_ms`, `deadline_ms`) are used strictly for user display, expiration checking, and audit logging.
  * **Clock Trust Rule**: `ApprovalToken` expiry is evaluated strictly against trusted supervisor / Confirmation Broker system time. Caller-provided timestamps are never authoritative for token validity.
  * **Bounded TTL Ceiling**: Approval token TTL is bounded by an architectural system maximum (e.g. max 60 seconds).
  * In-flight execution timeouts are enforced exclusively using the supervisor's **monotonic clock** (`std::time::Instant`), preventing clock skew or NTP jumps from disrupting execution guards.
* **Enforcement**:
  1. The supervisor computes `timeout = min(timeout_duration_ms, max_allowed_system_timeout)`.
  2. The supervisor sets a monotonic timer guard. If the timer expires before worker completion, the supervisor delivers `SIGTERM`, followed by `SIGKILL` if the worker does not terminate within a grace period.

### 2. Cancellation and Rollback Semantics
* **Initiation**: A running operation may be cancelled by the user (via Layer 1 UI), by the Workflow Runtime (DAG failure), or by Security Governance.
* **Rollback Reality**:
  * **Cancellation does not imply rollback unless the capability explicitly supports transactional rollback.**
  * Every mutating capability contract must explicitly declare its behavior across:
    1. *Atomicity*: Whether mutations are all-or-nothing (e.g. atomic filesystem rename).
    2. *Commit Point*: The exact stage at which external state changes become irreversible.
    3. *Compensation / Rollback*: Whether compensating actions exist if cancelled post-commit.
    4. *Uncertain Outcome*: How the system classifies state when communication with the worker is lost mid-mutation.

### 3. Idempotency & Retry Classification

| Operation Class | Behavior on Transient Failure | Idempotency Requirement |
| :--- | :--- | :--- |
| **Read-Only / Pure Query** (`fs.read_file`, `system.query_status`) | Supervisor classifies as `RetryClassification::Safe`. | Naturally idempotent. |
| **Idempotent Mutation** (`fs.create_directory`, `config.set_key`) | Supervisor classifies as `RetryClassification::Safe` using original `request_id`. | Idempotent by design (state matches desired target). |
| **Non-Idempotent Mutation** (`fs.append_file`, `process.spawn`) | Supervisor classifies as `RetryClassification::Never` or `Conditional`. | Non-idempotent; requires compensating action or human confirmation if outcome is uncertain. |

---

## Audit Event Contract

Every security-relevant operation emits an append-only, tamper-evident audit record to Layer 12 (`Observability & Reliability`):

```rust
pub struct AuditRecord {
    /// Monotonically increasing sequence number assigned authoritatively by Layer 12 writer.
    pub sequence_number: u64,

    /// Unique audit event ID.
    pub event_id: Uuid,

    /// SHA-256 hash of the preceding audit record (tamper-evident chaining assigned by Layer 12).
    pub prev_record_hash: [u8; 32],

    /// Authoritative wall-clock timestamp (UTC milliseconds) assigned by Layer 12 writer.
    pub timestamp_ms: u64,

    /// Monotonic elapsed-time measurement captured by Layer 12 for duration/relative-timing analysis.
    /// It is not the authoritative event ordering mechanism; sequence_number provides audit ordering.
    pub monotonic_ns: u64,

    /// Root correlation ID tracking the causal workflow.
    pub correlation_id: Uuid,

    /// Request ID of the specific invocation.
    pub request_id: Option<Uuid>,

    /// Authenticated actor identity.
    pub actor: PrincipalContext,

    /// Classification of event.
    pub event_type: AuditEventType,

    /// Event-specific schema-validated details.
    pub payload: serde_json::Value,
}

pub enum AuditEventType {
    CapabilityRequested,
    PolicyEvaluated,
    ConfirmationChallenged,
    ConfirmationResolved,
    SandboxInitialized,
    CapabilityCompleted,
    SecurityViolation,
    PolicyReloaded,
}
```

### Layer 12 Authoritative Invariants
* The Layer 12 audit writer is the **sole authority** for assigning `sequence_number`, `event_id`, authoritative `timestamp_ms`, `monotonic_ns`, and calculating `prev_record_hash`.
* Audit records are append-only and tamper-evident within the defined trust boundary, requiring an external or protected integrity anchor to detect history truncation.

---

## Serialization & Wire Framing Protocol

### 1. Evaluated Serialization Technologies
* **JSON (`serde_json`) - Baseline Contract Format**:
  * *Inspectability*: Plain text JSON enables inspection, debugging, and tracing during development.
  * *Polyglot Runtimes*: Universally supported across Python, C, and Rust capability workers without requiring binary compiler toolchains.
  * *Schema Tooling*: Integrates natively with `schemars` for automated JSON Schema generation.
* **CBOR (`ciborium`) - Evaluated / Deferred for Streaming Payloads**:
  * Retained as candidate for high-throughput sensor telemetry or streaming binary data.
* **Protocol Buffers / Cap'n Proto - Rejected for Core Control Plane**:
  * Introduces build-time IDL compiler requirements (`protoc`) without compelling architectural benefits for local desktop IPC.

### 2. Robust Length-Prefixed Framing on Unix Domain Sockets
Because `SOCK_STREAM` is a byte-stream transport without message boundaries, internal IPC strictly adheres to a length-prefixed framing protocol:

```
┌───────────────────────────┬───────────────────────────────────────────┐
│ Length Prefix (4 bytes)   │ Payload Data (N bytes)                    │
│ Big-Endian u32            │ UTF-8 Encoded JSON String                 │
└───────────────────────────┴───────────────────────────────────────────┘
```

#### Framing Implementation Requirements
Implementations must strictly enforce:
1. **Length Validation Before Allocation**: The 4-byte length prefix must be read and validated *before* allocating memory buffers for the payload to prevent heap exhaustion.
2. **16 MiB Maximum Frame Ceiling**: Frame length must not exceed 16 MiB (`0x0100_0000` bytes). Any frame declaring a length greater than 16 MiB must be rejected immediately.
3. **Bounded Partial Read/Write Handling**: Sockets must execute bounded loops to read or write the exact declared byte count, properly handling partial frames, `EAGAIN`, and `EINTR` with configurable per-operation timeouts.
4. **Malformed/Truncated Frame Rejection**: If a frame terminates prematurely (truncated payload), contains invalid UTF-8, or cannot be deserialized as valid schema JSON, the frame is rejected, an error is recorded, and the connection is closed.
5. **Resource Limits & Socket Teardown**: Strict limits on concurrent open socket connections, ingress buffer allocations, and idle timeouts are enforced by the supervisor to protect system resources. Any framing protocol violation triggers immediate socket teardown and error emission.

---

## Formal Schema Definition & Validation Technology

AgenticOS establishes **Rust Serde Structs as the Canonical Source of Truth** for contract definitions:

1. **In-Tree Contract Crate**:
   * All envelope types, capability invocation requests, policy decision enums, and error models are authored in `agenticos-contracts`.
   * Compiled directly into the supervisor and native Rust workers.
2. **Polyglot Contract Generation via `schemars`**:
   * The `agenticos-contracts` crate derives `schemars::JsonSchema` on all contract types.
   * Build tooling outputs canonical JSON Schema documents to `/usr/share/agenticos/schemas/v1/`:
     - `CapabilityInvocationRequest.json`
     - `PolicyDecision.json`
     - `ApprovalToken.json`
     - `ApprovalTokenSignedPayload.json`
     - `ApprovalSubject.json`
     - `ErrorPayload.json`
3. **Polyglot Worker Validation**:
   * Out-of-process capability workers (such as Python scripts) validate inputs against these exported JSON schemas using standard validators (e.g. `pydantic` or `jsonschema`), ensuring contract synchronization across language boundaries.

---

## Open Questions and Deferred Items (Phase 1+ TBD)

The following implementation-specific details are deferred to Phase 1:

1. **Exact Cedar Entity Mapping for ResourceRef**: Finalizing the schema representation mapping `ResourceRef` kinds into Cedar entity types and hierarchy attributes.
2. **Streaming Data Protocol**: Defining chunked streaming contracts over UDS for large text generation or interactive terminal input/output.
3. **Replay Cache Durability**: Determining whether redeemed token IDs are persisted across supervisor restarts in an ephemeral database table or rely on expiration.
4. **Binary Blob Passing Protocols**: Finalizing the handshake for passing read-only open file descriptors (`SCM_RIGHTS`) across UDS versus temporary bind mounts.

---

## Consequences

### Positive
* **Unambiguous Subsystem Interfaces**: Eliminates interface mismatch and integration bugs between agents, runtimes, and security supervisors.
* **Deterministic Traceability**: Every request is bound to an authenticated principal, correlation ID, and tamper-evident audit record.
* **Robust Safety Invariants**: Enforces fail-closed error semantics, monotonic timeout guards, and clear cancellation contracts.
* **Polyglot Compatibility**: Canonical JSON schemas generated from Rust types allow non-Rust capability workers to interoperate safely with the core supervisor.

### Negative / Trade-offs
* **Serialization Overhead**: Length-prefixed JSON incurs parsing and string marshaling overhead compared to raw in-memory C structs.
* **Schema Maintenance**: Updating contracts requires disciplined semantic versioning and maintaining backward compatibility across releases.

---

## References

* JSON Schema Specification (`https://json-schema.org/draft/2020-12/schema`)
* Rust `serde` Framework (`https://serde.rs/`)
* Rust `schemars` Library (`https://github.com/GREsau/schemars`)
* RFC 8949: Concise Binary Object Representation (CBOR) (`https://datatracker.ietf.org/doc/html/rfc8949`)
