# Phase 3.2: Capability Execution Boundary Specification

* **Document Version**: 3.2.0
* **Date**: 2026-09-28
* **Phase**: 3.2 (Specification Only — No Implementation)
* **Status**: APPROVED SPECIFICATION / READY FOR PHASE 3.3 IMPLEMENTATION PLANNING
* **Architectural Baseline**: ADR-0001 through ADR-0007, `docs/architecture.md` (canonical layer numbering), `docs/security.md`, `docs/threat-model.md`, `docs/phases/phase-1-complete.md`, `docs/phases/phase-2-complete.md`, `docs/phases/phase-3-capability-layer.md` v3.0.1, Phase 3.1 (Policy Engine implementation)
* **Layer Numbering Authority**: `docs/architecture.md` is canonical. Layer 8 is Security & Governance (gateway); Layer 9 is the Capability Layer (sandbox runner); Layer 10 is the Linux Integration Boundary; Layer 12 is Observability & Reliability.
* **Approved Decisions Implemented Here**:
  1. Data-only; no live runner.
  2. Fixture manifests for `fs.read_file`, `fs.create_directory`, `fs.delete_tree` only (fixtures, not implementations).
  3. Verification contracts + fixture evaluation now; real `stat(2)`-based verification deferred.
  4. In-memory registry backed by declarative bundle data; no new SQLite database.

> **Specification notation**: Rust `struct`/`enum` sketches in this document
> are specification notation for Phase 3.3 implementers, exactly as the
> Phase 1 specification used Rust sketches before implementation. They
> introduce no code, no dependency, and no behavior by themselves.

---

## 1. Objective

Phase 3.2 specifies the deterministic boundary between Layer 8 authorization
output and Layer 9 sandboxed execution: **capability selection** (registry),
**authorization-to-execution handoff** (binding), **sandbox construction
contracts** (validated plan data), and **post-execution verification
contracts** (shapes + fixture evaluation).

Phase 3.2 produces validated data records only. It launches no workers,
installs no filters, creates no namespaces, writes no cgroups, opens no
sockets, and mutates no host state beyond this specification artifact.

## 2. Scope

### In-scope for Phase 3.2 specification

* Capability Registry contract (declarative bundle load, lookup, versioning).
* Fixture manifests for `fs.read_file`, `fs.create_directory`, `fs.delete_tree`.
* `InvocationBinding` handoff joining a Layer 8 `ALLOW` to a manifest.
* `SandboxConstructionPlan` builders emitting validated plan data.
* Worker-process boundary plan (descriptors, stdio, supervision shapes).
* Result, cancellation, idempotency, and verification contracts (+ fixture evaluation).
* Zero-escape / zero-bypass test and E2E acceptance criteria.

### Out of scope (see §29 Non-Goals)

Worker spawning, Bubblewrap invocation, Landlock/seccomp enforcement,
namespace/cgroup writes, live IPC listeners, Agent Runtime, UI, LLM,
networking, shell/root execution, real `stat(2)` verification.

## 3. Architecture Position

Canonical position per `docs/architecture.md`, refining the Phase 3.0 §3 diagram:

```text
[Phase 3.1 Layer 8] ALLOW{constraints, contributing, snapshot_hash} + request
        │  (handoff re-validation: snapshot, token binding, registry lookup)
        ▼
[3.2 Registry: Capability Selection] manifest(id, version) or CapabilityNotFound
        │  (intersection: constraints ∩ manifest scope → least privilege)
        ▼
[3.2 InvocationBinding] frozen, content-hashed handoff record
        │  (profile select P1/P2 by risk tier; plan builders emit validated DATA)
        ▼
[3.2 SandboxConstructionPlan] {bwrap_argv*, landlock_rules*, seccomp_allowlist*,
                               ceilings*, fds, env} (* = validated data, never applied)
        │  ── PHASE 3.2 STOPS HERE ──
        ▼ (deferred to Phase 3.3+)
[Future worker spawn → execution → ExecutionReport → verification → audit chain]
[Layer 10: Linux Integration Boundary] — not traversed in Phase 3.2
[Layer 12: Observability & Reliability] — shapes only, no writer implementation
[Layer 6: Agent Runtime] — untouched deferred consumer
```

Five stages stay distinct: **authorization** (3.1, authoritative, reused
unchanged) → **selection** (3.2 registry) → **construction** (3.2 plan data)
→ **execution** (deferred) → **verification** (contracts now, effects later).

## 4. Trust Boundaries

1. **TB-Registry (Selection integrity):** the registry answers one question —
   *is this capability known, versioned, and load-time vetted?* Unknown IDs,
   unknown versions, and generic/unbounded capabilities are rejected at load
   or lookup. The registry never authorizes; it only describes.
2. **TB-Handoff (Binding integrity):** the binding re-validates the Layer 8
   decision (active snapshot hash, token binding where applicable, manifest
   scope intersection) before any plan is built. A stale, tampered, or
   scope-violating handoff is rejected without producing a plan.
3. **TB-Construction (Plan validity):** every construction plan passes a
   deterministic `validate()` enforcing §13–§19 rules. Invalid plans are
   unrepresentable downstream: future implementers must refuse to launch
   from an unvalidated plan.
4. **TB-Kernel (POSIX, never traversed):** no syscall that mutates
   confinement state is issued in Phase 3.2. No worker exists to escape.

Provenance vs authentication (preserved from Phase 1 §5.1 / Phase 3.0 §4):
worker process identity in future phases comes exclusively from
supervisor-spawned children verified via `SO_PEERCRED` / `socketpair(2)`
descriptors (ADR-0002). Manifest-declared identities are descriptive only.

## 5. Capability Registry Contract

* The registry is an **in-memory index over a declarative bundle**
  (text data loaded at startup / in tests). No SQLite database is created,
  per ADR-0006 ownership discipline and Phase 3.0 §19 (a registry DB has no
  authoritative owner yet; creating one would invent ownership and migrations).
* Bundle entry: one manifest document per capability version. Loading
  validates every manifest; any invalid entry rejects the whole bundle and
  retains the previous registry content (fail-closed load, mirroring
  Phase 3.1 snapshot semantics).
* Lookup `get(capability_id, schema_version)` is exact-match and
  deterministic: unknown ID → `CapabilityNotFound`; known ID with unknown
  version → `CapabilityNotFound` (never silent fallback to another version).
* Load-time rejections (fail-closed, no bypass):
  * generic/unbounded execution declarations (any manifest requesting an
    arbitrary shell, arbitrary script runner, or unparameterized command
    template) — prohibited by ADR-0003 Profile 2;
  * missing risk tier, missing I/O schemas, missing sandbox profile, or
    missing purpose-binary binding;
  * Tier 4 identifiers (`sys.modify_config`, `network.bind_socket`,
    `sys.reboot`, and any raw process/shell spawn) are never registrable —
    deny-by-default list per `security.md` Tier 4;
  * network need declared without an explicit, named local endpoint.

```rust
pub struct CapabilityManifest {
    pub capability_id: String,      // e.g. "fs.read_file" (namespaced)
    pub manifest_version: String,   // manifest document version, e.g. "v1"
    pub capability_schema_version: u32,
    pub risk_tier: RiskTier,        // Tier0..Tier4 per security.md §4
    pub input_schema: serde_json::Value,   // JSON Schema, exact match
    pub output_schema: serde_json::Value,  // JSON Schema, exact match
    pub sandbox_profile: SandboxProfile,   // Profile1 | Profile2
    pub purpose_binary: Option<String>,    // required for Tier 2+
    pub declared_read_scopes: Vec<String>, // opaque scope labels, exact match
    pub declared_write_scopes: Vec<String>,
    pub network_need: Option<String>,      // named local endpoint or None
    pub atomicity: Atomicity,              // Atomic | NonAtomic (see §20)
    pub compensation: Option<String>,      // compensating action ref or None
    pub retry_class: RetryClass,           // Safe | Conditional | Never
}

pub enum RiskTier { Tier0, Tier1, Tier2, Tier3, Tier4 }
pub enum SandboxProfile { Profile1, Profile2 }
```

## 6. Capability Identity and Versioning

* Identity is the pair `(capability_id, capability_schema_version)`.
  `capability_id` uses dotted namespaces (`fs.*`, `process.*`, `sys.*`,
  `network.*`, `application.*`); empty segments, NUL bytes, and lengths
  beyond implementation bounds are rejected at load/lookup.
* Manifest documents carry their own `manifest_version` for bundle
  evolution; registry selection keys on the capability pair, never on
  manifest version alone.
* Deterministic manifest record IDs `{capability_id}@{capability_schema_version}`
  for diagnostics and audit lineage. Rebuilding a registry from identical
  bundle text yields bit-identical lookup behavior.

## 7. Capability Metadata and Schemas

* `input_schema` / `output_schema` are JSON Schemas validated with strict
  unknown-field rejection for control-plane envelopes (ADR-0007 discipline).
* Argument validation against `input_schema` happens at binding time, before
  plan construction; schema violations fail closed with
  `ErrorCode::MalformedArguments` and produce no plan.
* The three fixture manifests (§8) declare minimal schemas over
  `{ "path": String }`-shaped arguments. Schema expressiveness beyond exact
  types, string bounds, and required keys is deferred; no schema-feature TBD
  is resolved here.

## 8. Fixture Manifests (Fixtures Only — No Implementations)

Exactly three fixtures exist, and only as registry/test data. They define
no host behavior, no binaries, and no filesystem effects:

* `fs.read_file` — Tier 0 (read-only query), Profile 1, no confirmation in
  workspace scope. Mirrors ADR-0003 Profile 1's example capability.
* `fs.create_directory` — Tier 1 (non-destructive write), Profile 1.
  Mirrors the `architecture.md` capability contract and the Phase 1/2 demo
  vocabulary (`fs.create_directory` dispatch boundary).
* `fs.delete_tree` — Tier 2 (destructive mutation), Profile 2,
  `CONFIRM`-gated with diff/preview data contract. Mirrors ADR-0005's
  deletion policy examples. **No real deletion semantics, traversal rules,
  or recovery behavior are defined** — the fixture exercises the
  confirm-gated handoff path only.

No other capability may be treated as known by Phase 3.2 tests or fixtures.

## 9. Invocation Lifecycle

```text
Proposed (Layer 4/5 artifact references request + assignment IDs)
  → Validated (schema + registry + handoff checks pass; binding frozen)
  → Planned (construction plan built + validate() passes)
  → [DEFERRED] Launched → Running → Reported → Verified
```

`Proposed → Validated → Planned` are specified and fixture-exercised in
Phase 3.2. `Launched` and beyond are specified as *shapes and transition
rules only* (§21, §25); no transition beyond `Planned` is implemented or
exercised. Terminal states (`Completed` / `Failed` / `Cancelled`) and their
immutability follow the Phase 1/2 state-machine discipline.

## 10. Authorization-to-Execution Handoff (`InvocationBinding`)

* A binding joins exactly one validated request, one Layer 8 `ALLOW`
  decision, and one registry manifest. Construction order:
  1. Re-validate the request (Phase 3.1 structural rules).
  2. Re-check the decision is `ALLOW` (never `DENY`/`CONFIRM`-pending; a
     `CONFIRM` without redeemed bound token rejects the handoff).
  3. Re-check `request.policy_snapshot_hash` against the *currently active*
     Layer 8 snapshot; mismatch rejects the handoff (no silent downgrade).
  4. Registry lookup `(capability_id, capability_schema_version)`; miss →
     `CapabilityNotFound`, no plan.
  5. Intersect Layer 8 constraints with manifest scopes (§11); empty
     required access → handoff rejected fail-closed.
* The binding is frozen and content-hashed (SHA-256 over the canonical
  binding encoding, reusing the Phase 3.1 canonicalization profile and the
  approved `sha2` scope). The binding hash joins the audit lineage chain.

```rust
pub struct InvocationBinding {
    pub binding_id: Uuid,
    pub request_id: Uuid,
    pub correlation_id: Uuid,
    pub capability_id: String,
    pub capability_schema_version: u32,
    pub decision_ref: DecisionRef,   // snapshot hash + contributing policies
    pub manifest_ref: String,        // {capability_id}@{capability_schema_version}
    pub resolved_constraints: ResolvedConstraints, // §11 intersection result
    pub binding_hash: [u8; 32],
}
```

## 11. Resource Scope Handoff

* `ResourceRef{kind, identifier}` remains **opaque** (TBD preserved): the
  handoff carries kind/identifier verbatim into binding and plan data and
  matches them against manifest scopes by **exact string equality only**.
* Intersection rule (least privilege): resolved access = Layer 8 constraints
  ∩ manifest declared scopes. The narrower side wins per field; network
  requires *both* `allow_network` and a manifest `network_need` naming the
  same local endpoint. An empty intersection for any access the manifest
  requires → handoff rejected (fail-closed, `PolicyDenied`-family diagnostic).
* No string-prefix containment, no canonicalization-as-boundary, no path
  hierarchy, and no filesystem authorization occur at this layer — identical
  to the Phase 3.1 guarantee, extended across the handoff by construction.

## 12. `SandboxConstraints` Consumption

* Consumes the Phase 3.1 `SandboxConstraints` record field-for-field
  (`read_paths`, `write_paths`, `allow_network`, `seccomp_profile` label,
  `max_memory_bytes`, `max_cpu_quota_percent`, `max_wall_time_ms`).
* The `seccomp_profile` string is a routing label only in Phase 3.2, exactly
  as in Phase 3.1; allowlist *contents* remain TBD and are never invented.
* Numeric ceilings are implementation-bounded data (NON-NORMATIVE, mirroring
  the Phase 3.1 labeling discipline); enforcement is deferred.

## 13. Worker-Process Boundary (Plan Only)

* Future workers are supervisor-spawned dedicated processes communicating
  over a private anonymous `socketpair(2)` (ADR-0002/ADR-0003). The plan
  records: descriptor passing intent (`SCM_RIGHTS` future set, governed by
  profile), stdio capture plan (piped, bounded buffers), and the
  supervision shape (spawn → sandbox-apply → run → report → reap).
* No spawn, fork, `execve`, descriptor passing, or `waitpid` occurs in
  Phase 3.2. The boundary is specified so a future implementer cannot
  substitute self-spawned, self-attested, or socket-less workers.

## 14. Sandbox Initialization Contract and Fail-Closed Table

* Initialization (future) must apply all confinement *before* capability
  code executes (ADR-0003 default model). Phase 3.2 specifies the
  validation gate that precedes any future initialization:

| Failure | Outcome | Audit |
|---|---|---|
| Unknown capability/version | `CapabilityNotFound`, no binding, no plan | binding-rejected record |
| Stale/tampered decision or token | Handoff rejected, no plan | binding-rejected record |
| Scope intersection empty | Handoff rejected, no plan | binding-rejected record |
| Plan `validate()` fails (shell present, sensitive mount, network without dual authorization, missing `NO_NEW_PRIVS`) | Plan discarded, never launchable | plan-rejected record |
| (Future) init step fails for any reason | Abort, **no un-sandboxed fallback**, structured `SandboxInitializationFailed` | security audit event |
| (Future) worker violates confinement | Kernel terminates/traps; supervisor marks `VIOLATION_TERMINATED`, rolls back pending state | violation record |

## 15. `NO_NEW_PRIVS` Requirement

* Every construction plan must declare `no_new_privs: true` (via
  `PR_SET_NO_NEW_PRIVS` in future enforcement). Plan validation rejects any
  plan lacking it. Setuid transitions, capability amplification, and ambient
  privilege inheritance are unrepresentable in a valid plan.

## 16. Bubblewrap Boundary (Data Only)

* The plan builder emits a validated `bwrap_argv: Vec<String>` for
  Profile 2 fixtures: `--unshare-all`, `--unshare-net`, `--unshare-pid`,
  pristine read-only `/` (`tmpfs`), read-only `/usr` + `/lib`, ephemeral
  `/tmp`, selective workspace bind (mode from resolved constraints),
  minimal `/dev`, and the fixed exclusions from ADR-0003 Profile 2
  (`/home`, `/root`, `/etc/shadow`, `/etc/sudoers`, `/boot` unmounted).
* Validation rules (not values): argv is a fixed vocabulary — any argument
  outside the vocabulary rejects the plan; shell binaries must not appear
  in any exec-visible mount; the workspace bind must be within resolved
  scopes. Bubblewrap version pins remain TBD; `/usr/bin/bwrap` is referenced
  as a path constant only and never executed.

## 17. Landlock Boundary (Data Only)

* The plan carries `landlock_rules` data: ordered `(path_scope, rights_mask)`
  entries using rights constants (`READ_FILE`, `READ_DIR`, `WRITE_FILE`,
  …) with Profile 1 fixtures restricted to read-only masks on the approved
  scope and all write/make/rename/delete/truncate rights stripped.
* Landlock ABI detection, probing, and enforcement remain TBD; no Landlock
  syscall occurs. Rights-mask constant *values* are kernel-UAPI-derived data
  and must be sourced from UAPI definitions when Phase 3.3 implements —
  no invented mask semantics in Phase 3.2 fixtures beyond read-only restriction.

## 18. seccomp Boundary (Data Only)

* The plan carries `seccomp_allowlist` data: a sorted list of syscall names
  plus a sorted explicit-deny list, modeled on ADR-0003's Profile 1/2
  enumerations (e.g., deny `execve`, `ptrace`, `bpf`, unauthorized `socket`
  families for no-network profiles). The allowlist *contents* for any real
  capability remain TBD; fixtures carry the documented example sets only.
* No BPF compilation or installation occurs; `libseccomp` remains a
  flagged future candidate only (never added in Phase 3.2).

## 19. Namespace / cgroup Boundary (Data Only)

* Namespace unshare sets and cgroup v2 ceilings (`MemoryMax`, `CPUQuota`,
  `TasksMax`) plus `RLIMIT_*` data ride in the plan as bounded values.
  Exact numeric ceilings remain TBD (implementation-bounded, NON-NORMATIVE,
  same discipline as Phase 3.1); no namespace creation or cgroup write occurs.

## 20. Capability-Specific Profiles, Timeouts, Cancellation

* Profile selection is deterministic: Tier 0/1 → Profile 1; Tier 2/3 →
  Profile 2; Tier 4 → unregistrable (deny-by-default). Selection inputs are
  exactly `(risk_tier, resolved constraints)`; identical inputs yield
  identical plans byte-for-byte (canonical field ordering).
* Timeout data: `max_wall_time_ms = min(request.timeout, engine maximum)`
  carried from Phase 3.1; monotonic-watchdog enforcement (SIGTERM, then
  SIGKILL after a grace period) is *specified behavior* for the future
  supervisor, not implemented.
* Cancellation is a first-class signal in the lifecycle (§9) but — per
  ADR-0007 — never implies rollback unless the manifest declares
  `atomicity` + `compensation`. Each mutating fixture manifest must declare:
  atomicity class, commit point description, compensation reference (or
  explicit `None`, meaning post-commit cancellation leaves state as-is and
  requires human review).

## 21. Result / Error Contract (Shapes)

* `ExecutionReport{report_id, binding_id, correlation_id, status
  (Success/Failure/Cancelled/ViolationTerminated), output (schema-validated
  JSON or None), error (ErrorPayload or None), wall_time_ms,
  verification_ref}` — shape only; no report is ever produced in Phase 3.2.
* Error reuse is exact: ADR-0007 codes (`SandboxInitializationFailed`,
  `CapabilityExecutionFailed`, `ResourceCeilingExceeded`, `Timeout`,
  `Cancelled`, …) with supervisor-governed retry classes; diagnostics carry
  tier/policy/manifest IDs only — no stderr, no stack traces, no secrets,
  no private host paths beyond caller-supplied identifiers.

## 22. Precondition / Postcondition Verification Contracts

* Reuses `architecture.md` §4.9 `VerificationResultContract` shapes:
  `{verification_id, goal_id, is_satisfied, condition_results[{check, path,
  expected, actual, status}], verification_duration_ms}`.
* Fixture manifests declare `preconditions` / `postconditions` as
  check-expression lists (e.g., `path_exists`, `is_directory`), evaluated in
  Phase 3.2 **only over an injected in-memory filesystem view in fixtures**.
  The production `stat(2)`-backed view binding is explicitly deferred; no
  host filesystem reads occur.
* Verification never trusts worker self-reports: `is_satisfied` derives
  solely from evaluated conditions against declared criteria.

## 23. Execution Audit Lineage

* Chain: `request_id → decision (snapshot hash + contributing policies) →
  binding_id/binding_hash → plan_hash → (future) report_id/verification_id`,
  all under the root `correlation_id`. Every handoff rejection and
  plan-validation failure also emits a rejected-record shape with the same
  lineage keys. Shapes only; the Layer 12 writer, hash chaining, and
  integrity anchors remain deferred (TBD preserved).

## 24. Process Identity and Authentication Boundary

* Future worker PIDs are supervisor-observed facts (spawn return + `waitpid`
  lifecycle), cross-checked against `/proc` start-time disambiguation per
  the Phase 2 `(pid, start_time_ticks, instance_nonce)` discipline. Worker
  self-asserted identity is never accepted; transport attestation
  (`SO_PEERCRED` / inherited `socketpair` descriptors) is the sole
  authenticity source (ADR-0002). Specified now; attested handshakes are
  implemented only alongside a future live supervisor.

## 25. Restart / Crash Supervision Shapes

* Supervisor-side worker lifecycle shapes: `Spawned → Confined → Running →
  Reaped`, with crash detection via descriptor hangup (`POLLHUP`/`read==0`)
  and `waitpid` status capture (specified, not implemented). Orphaned
  bindings (plan built, worker never reported) reconcile to `Failed` with
  lineage intact, mirroring Phase 2's non-destructive reconciliation
  discipline. No duplicate worker spawn on retry unless the capability's
  retry class explicitly permits it.

## 26. Idempotency and Retry

* ADR-0007 classes govern: read-only/pure → `Safe`; idempotent mutations
  (e.g., `fs.create_directory`) → `Safe` keyed by original `request_id`;
  non-idempotent mutations → `Never`/`Conditional` with explicit
  precondition re-checks. Deduplication windows and exactly-once mechanics
  belong to the future runner; Phase 3.2 fixes only the classification
  contract each manifest must declare.

## 27. Sensitive-Capability Handling

* Tier 2+ bindings require a redeemed bound token reference in the binding;
  tokenless Tier 2+ handoffs reject even with `ALLOW` (defense in depth —
  the Policy Engine already emits `CONFIRM`, and the handoff independently
  refuses to plan).
* Tier 2 mutations carry a diff/preview data contract in the binding
  (before-image descriptors as data, renderer-deferred). Tier 3 execution
  carries binary/argv/env disclosure data. Tier 4 is unregistrable.

## 28. Test Strategy, Zero-Escape Tests, E2E Acceptance

* Unit/fixture tests (in-memory, synthetic principals labeled as fixtures):
  registry load accept/reject (generic, Tier 4, missing schema/binary);
  exact-version lookup incl. unknown-version `CapabilityNotFound`; binding
  validation (stale snapshot, tampered decision, scope-empty intersection);
  plan `validate()` rules (shell present, sensitive mount, network without
  dual authorization, missing `NO_NEW_PRIVS`); determinism (identical plan
  bytes across rebuilds); verifier condition evaluation over fixture views.
* Zero-escape / zero-bypass static audit (extends the Phase 3.1 audit):
  production sources must contain no `Command::spawn`, `fork`, `execve`,
  `bwrap` invocation, Landlock/seccomp install calls, `prctl`, namespace /
  cgroup writes, `UnixListener`, `TcpStream`, shell strings, `sudo`,
  LLM/HTTP/UI symbols — plus a structural assertion that no function in
  the new modules returns a live child handle or performs I/O beyond
  test tempdirs.
* E2E acceptance (fixtures, zero host effects): `fs.read_file` ALLOW →
  valid P1 plan (read-only masks, network off, `NO_NEW_PRIVS`); `fs.delete_tree`
  without token → handoff refused at binding (CONFIRM, no plan);
  `fs.delete_tree` with bound token → valid P2 plan data (still zero
  execution); unknown capability → `CapabilityNotFound`; tampered binding →
  rejected; full lineage `request→decision→binding→plan` asserted on every path.

## 29. Explicit Non-Goals

Strictly excluded from Phase 3.2 and reserved for later phases:

* Capability execution of any kind; worker process spawning.
* Bubblewrap invocation; Landlock syscall enforcement; seccomp installation.
* Namespace creation; cgroup writes; `prctl` calls.
* Live IPC listeners; D-Bus services; Agent Runtime implementation.
* Human Interface UI; LLM integration; networking of any kind.
* Shell execution, root execution, sudo escalation, ambient privilege use.
* Real `stat(2)`-backed verification; host filesystem reads outside fixtures.
* New SQLite databases; cross-database joins; secret-vault implementation.
* Cryptographic implementation choices (token algorithm/keys/signing).
* Cloud exposure modes, remote distribution, telemetry, multi-host operation.
  LOCAL-only is normative.
* OS packaging, ISO/installer work, GPU/hardware orchestration.

## 30. Unresolved Decisions / TBDs

Preserved as TBD; Phase 3.2 invents no value for any item. Inherited from
Phase 3.0 §25 (all 15 items: `ResourceRef` → Cedar mapping; token
algorithm/encoding/keys/rotation/attestation; replay durability; shadowing
formalization; admin roles; annotation strictness; store mechanics; vault
backup/KDF; backup consistency; audit anchors; retention/scheduling/cross-DB;
vector store; streaming/blob FD; sandbox ceilings/pins/ABI/allowlists;
confirmation UI transport; audit signing; secret-service integration).
Phase 3.2 additionally defers, without resolving:

1. Manifest bundle file format and on-disk location.
2. Retained-plan cache bounds and eviction policy.
3. Worker-supervision timing constants (spawn grace, SIGTERM→SIGKILL delay).
4. Precondition-expression grammar finalization beyond the fixture checks.
5. Compensation-action DSL (references are opaque strings in Phase 3.2).
6. `seccomp_allowlist` contents for any real capability.
7. Landlock ABI-version policy and rights-mask sourcing confirmation.
8. Bubblewrap version pin and advisory blacklist mechanics.
9. Numeric sandbox ceilings (memory/CPU/tasks) for any real profile.
10. `openat2` resolution-rule selection (`RESOLVE_BENEATH` and related flags).

## 31. Phase 3.3 Implementation Boundary

Phase 3.3 may implement strictly from this specification plus all prior
specifications, without new architectural decisions:

* New crate/module boundary for registry + handoff + plan builders,
  consuming `agenticos-contracts` types (and the Phase 3.1 policy plane
  API) only; no edits to Phase 1/2/3.1 domain semantics, state machines,
  storage schemas, or policy evaluation behavior.
* No new dependencies are authorized by this specification. Pure-data
  builders with deterministic fixtures; no process spawn, no socket dial,
  no filesystem writes outside test tempdirs and fixture dirs.
* Harness must include the zero-escape proof (§28) and E2E fixtures before
  any worker-spawn, filter-install, or broker-signing work begins.
* Any attempt to resolve §30 TBDs requires a spec amendment with ADR update;
  implementation must not silently fix a TBD value in code.

(End of file - total 31 sections)

