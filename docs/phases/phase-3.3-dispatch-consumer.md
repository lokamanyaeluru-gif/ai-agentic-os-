# Phase 3.3: Layer 6 Dispatch Consumer Specification

* **Document Version**: 3.3.0
* **Date**: 2026-09-28
* **Phase**: 3.3 (Specification Only — No Implementation)
* **Status**: APPROVED SPECIFICATION / READY FOR PHASE 3.4 IMPLEMENTATION PLANNING
* **Architectural Baseline**: ADR-0001 through ADR-0007, `docs/architecture.md` (canonical layer numbering), `docs/security.md`, `docs/threat-model.md`, `docs/phases/phase-1-complete.md`, `docs/phases/phase-2-complete.md`, `docs/phases/phase-3-capability-layer.md` v3.0.1, Phase 3.1 (Policy Engine implementation), `docs/phases/phase-3.2-capability-execution-boundary.md` (specification + implementation)
* **Layer Numbering Authority**: `docs/architecture.md` is canonical. Layer 5 is the Global Agent Manager; Layer 6 is the Agent Runtime (dispatch consumer only in this phase); Layer 8 is Security & Governance (sole authorization authority); Layer 9 is the Capability Layer (plan construction boundary).
* **Approved Decisions Implemented Here**:
  1. Phase 3.3 = Layer 6 dispatch consumer (no live execution, no listeners).
  2. Dispatch records are caller-owned; no new database or journal.
  3. Preconditions are recorded-as-declared only; never evaluated against real paths and never fabricated.
  4. Cancellation uses a caller-provided cooperative in-process flag; live signal handling is deferred.

> **Specification notation**: Rust `struct`/`enum` sketches in this document
> are specification notation for Phase 3.4 implementers, exactly as prior
> phase specifications used Rust sketches before implementation. They
> introduce no code, no dependency, and no behavior by themselves.

---

## 1. Objective

Phase 3.3 specifies the deterministic Layer 6 dispatch consumer that closes
the planning-to-plan chain: **claim** a `WorkAssignment` (Layer 5),
**synthesize** a `CapabilityInvocationRequest` (mechanical field mapping, no
model reasoning), **submit** it to the Phase 3.1 Policy Engine, and on
`ALLOW` **bind** and **plan** through the Phase 3.2 boundary — terminating
in a caller-owned `DispatchRecord` at the validated-plan boundary.

Phase 3.3 adds no authority, no execution, and no state store. It reuses
Phase 2 lifecycle transitions, Phase 3.1 evaluation, and Phase 3.2
binding/plan construction exactly as specified and implemented.

## 2. Scope

### In-scope for Phase 3.3 specification

* Dispatch lifecycle (`Claimed → Synthesized → Evaluated → Bound →
  Planned`, plus terminal states).
* Request synthesis contract (exact field-mapping table, §6).
* Evaluation submission rules (attested principal carriage, caller clock).
* Binding + plan construction reuse (no new semantics).
* Assignment lifecycle coordination (existing manager transitions only).
* Cooperative cancellation, timeout carriage, recorded-as-declared
  preconditions.
* `DispatchRecord` / `DispatchError` contracts and audit lineage shapes.
* Determinism rules and test/E2E acceptance criteria.

### Out of scope (see §20 Non-Goals)

Worker spawning, sandbox enforcement, IPC listeners, LLM reasoning, UI,
networking, filesystem effects or reads, shell/root, new databases, new
dependencies, broker token minting, verification effects.

## 3. Architecture Position

Canonical position per `docs/architecture.md`, extending the Phase 3.2 §3 diagram:

```text
[Layer 5: Global Agent Manager] WorkAssignment(Assigned)
        │  (claim: start_assignment → InProgress; cooperative cancel checks)
        ▼
[3.3 Layer 6: Dispatch Consumer] (THIS SPECIFICATION)
        │  (synthesize request: mechanical mapping, §6; no reasoning)
        ▼
[Phase 3.1 Layer 8] evaluate → ALLOW / DENY / CONFIRM (sole authority)
        │  (ALLOW only: bind + build_plan + validate via Phase 3.2)
        ▼
[3.3 DispatchRecord] terminal, caller-owned (Planned / Denied /
                     ConfirmPending / Failed / Cancelled)
        │  (agent released via existing complete/fail/cancel_assignment)
        ▼
[Layer 5 agent] Running → Ready (existing transitions, unchanged)
```

The dispatcher *proposes and conveys*; Layer 8 *disposes*. No path exists
from a dispatch input to execution except through a fresh Layer 8 `ALLOW`
followed by Phase 3.2 binding and plan validation.

## 4. Trust Boundaries

1. **TB-Claim (Assignment integrity):** dispatch operates only on
   assignments observed in `Assigned` status through the manager's own
   accessors. Terminal assignments are never re-dispatched: the manager's
   existing guards reject the transition before any synthesis occurs.
2. **TB-Synthesis (No invention):** every request field derives from the
   assignment, the active policy snapshot, or the caller clock per the §6
   table. No field is modeled, hallucinated, or defaulted from ambition:
   unresolvable fields fail closed (§6 version rule).
3. **TB-Gateway (Layer 8 supremacy):** the synthesized request is submitted
   to `PolicyEngine::evaluate` unmodified by dispatch-side policy logic.
   Dispatch performs no Cedar evaluation, no annotation inspection, and no
   confirmation mediation of its own.
4. **TB-Terminal (No phantom verification):** dispatch records manifest
   pre/postcondition expressions *as declared*. It never evaluates them
   against real paths and never synthesizes `is_satisfied` outcomes.

## 5. Dispatch Lifecycle

```text
Claimed (manager: Assigned → InProgress via start_assignment)
  → Synthesized (request built per §6, or Failed on unresolvable fields)
  → Evaluated (Layer 8 decision obtained)
  → Bound (ALLOW only: binding frozen per Phase 3.2 §10)
  → Planned (plan built + validate() passes; terminal DispatchRecord)
```

Terminal outcomes: `Planned` (validated plan data), `Denied` (Layer 8
`DENY`), `ConfirmPending` (Layer 8 `CONFIRM`; dispatch mints no tokens and
performs no upgrade), `Failed` (any typed error below), `Cancelled`
(cooperative flag observed). Terminal records are immutable; terminal
assignments are released through the existing manager transitions
(`complete_assignment` on `Planned`, `fail_assignment` on `Denied`/`Failed`,
`cancel_assignment` on `Cancelled`), whose guards and semantics are reused
unchanged from Phase 2.

## 6. Request Synthesis Contract

Field mapping from `WorkAssignment` (Phase 2) to
`CapabilityInvocationRequest` (Phase 3.1). Mechanical copy unless noted:

| Request field | Source | Rule |
|---|---|---|
| `request_id` | `assignment.request_id` | Reused verbatim (lineage preservation, ADR-0007). |
| `correlation_id` | `assignment.correlation_id` | Copied verbatim. |
| `capability_id` | `assignment.capability_id` | Copied verbatim. |
| `capability_schema_version` | registry resolution (§6.1) | Only non-mechanical field; see rule. |
| `resource` | `assignment.resource` | Copied verbatim (opaque). |
| `arguments` | `assignment.arguments` | Copied verbatim (schema-checked later at binding). |
| `deadline_ms` | `assigned_at_ms + timeout_duration_ms` | Saturating add; monotonic enforcement deferred. |
| `timeout_duration_ms` | `assignment.timeout_duration_ms` | Copied verbatim (non-zero guaranteed by Phase 2). |
| `policy_snapshot_hash` | active Layer 8 snapshot at synthesis | Fresh read; staleness fails closed downstream. |
| `approval_token` | always `None` | Dispatch mints nothing; Tier 2+ flows therefore terminate `ConfirmPending` (honest by construction — the token→`ALLOW` path stays covered by Phase 3.1/3.2 tests). |

### 6.1 Schema-version resolution rule

`WorkAssignment` carries no `capability_schema_version`. The dispatcher
resolves it deterministically from the Phase 3.2 registry: collect all
registered versions for `assignment.capability_id`; if exactly one exists,
use it; if zero, fail closed (`UnknownCapability`); if more than one, fail
closed (`SynthesisConflict` — no silent version fallback, ever). With the
approved fixture registry (one version per capability) the rule is fully
determined. The missing version field in `WorkAssignment` is recorded as a
Phase 2 modeling fact for a future amendment; it is not patched here.

## 7. Evaluation Submission

* The attested principal passed to `PolicyEngine::evaluate` is
  `assignment.originating_principal` carried verbatim (provenance, per
  Phase 1 §5.1 / Phase 3.0 §4). Production transport attestation binds at
  the future live supervisor; dispatch performs no attestation of its own.
* `now_ms` is the caller-supplied supervisor clock (never sourced from the
  assignment or request). Deterministic tests supply fixed clocks.
* The request is submitted unmodified: dispatch adds no context, strips no
  fields, and interprets no annotations. `DENY` → terminal `Denied` with
  the Layer 8 reason and audit shape attached by reference.

## 8. Binding and Plan Construction Reuse

* On `ALLOW` only, dispatch calls Phase 3.2 `bind()` with the live active
  snapshot hash, then `build_plan()` + `validate()` against the registry
  manifest. All Phase 3.2 rules apply unchanged: exact-version lookup,
  Tier 2+ token presence (absent here by §6 — defense in depth holds),
  schema check, scope intersection, profile selection, plan validation.
* Dispatch introduces no new binding or plan semantics and duplicates no
  validation logic: any divergence between dispatch-constructed and
  directly-constructed bindings for identical inputs is a defect.

## 9. Assignment Lifecycle Coordination

| Dispatch terminal | Manager transition (existing API) | Agent effect (existing) |
|---|---|---|
| `Planned` | `complete_assignment` | `Running → Ready` (reusable) |
| `Denied` / `Failed` | `fail_assignment` with typed reason | `Running → Ready` |
| `Cancelled` | `cancel_assignment` | `Running → Ready` |
| `ConfirmPending` | `fail_assignment` with `ConfirmationRequired` reason (assignment cannot proceed unattended; human flow owns resubmission) | `Running → Ready` |

Claim uses `start_assignment` (`Assigned → InProgress`). Pre-claim status
checks plus the manager's own terminal guards make re-dispatch of terminal
assignments impossible without modifying Phase 2.

## 10. Cancellation (Cooperative, In-Process Only)

* The caller supplies a cooperative cancellation flag
  (`Arc<AtomicBool>` standard-library primitive; no new dependency, no
  signals, no handlers). Dispatch checks it before claim, before synthesis,
  before evaluation submission, and before binding/plan construction.
* An observed flag aborts the dispatch at the next check point: in-flight
  Layer 8 evaluation (synchronous, bounded) is never interrupted mid-call;
  no partial binding or plan is retained. Terminal outcome `Cancelled`;
  manager transition `cancel_assignment`. Cancellation implies no rollback
  (nothing has mutated) and no compensation (nothing has committed).
* Live signal handling (`SIGTERM`/`SIGKILL` supervision, handler threads)
  is deferred with the live supervisor (TBD preserved).

## 11. Timeouts (Carried Data Only)

* Assignment timeouts flow into synthesis (§6 deadline rule) and through to
  plan ceilings as data. No thread sleeps, no watchdog timers, and no
  timeout-driven kills exist in Phase 3.3: nothing runs long enough to time
  out (Cedar evaluation is bounded and terminating; all other stages are
  pure functions). Enforcement belongs to the future live supervisor.

## 12. Preconditions Recorded-as-Declared (Never Fabricated)

* The terminal `Planned` record embeds the manifest's `preconditions` /
  `postconditions` expression lists verbatim alongside the binding and plan
  hashes. Dispatch performs zero condition evaluation: no fixture views
  over real paths (meaningless and misleading), no `is_satisfied` synthesis,
  no worker self-report consumption.
* Rationale: any evaluated-against-nothing `Pass`, or any invented
  `is_satisfied: true`, would be a fabricated verification outcome —
  strictly prohibited by `security.md` §3.8 and the threat model (TH-09,
  TH-10). An unevaluated declaration is honest; a fabricated pass is a
  vulnerability.

## 13. `DispatchRecord` Contract

```rust
pub struct DispatchRecord {
    pub dispatch_id: Uuid,             // fresh per dispatch attempt
    pub assignment_id: AssignmentId,   // Layer 5 lineage
    pub correlation_id: Uuid,          // root causal trace (verbatim)
    pub workflow_id: Uuid,             // Layer 4 lineage (verbatim)
    pub step_id: Uuid,                 // Layer 4 lineage (verbatim)
    pub agent_id: AgentId,             // Layer 5 lineage (verbatim)
    pub outcome: DispatchOutcome,      // terminal outcome (below)
    pub request_id: Uuid,              // reused assignment request_id (§6)
    pub decision_ref: Option<DecisionRef>, // Phase 3.2 type, reused verbatim
    pub binding_hash: Option<[u8; 32]>,         // present iff Bound+
    pub plan_hash: Option<[u8; 32]>,            // present iff Planned
    pub declared_preconditions: Vec<CheckExpr>,  // Phase 3.2 type, as declared (§12)
    pub declared_postconditions: Vec<CheckExpr>, // Phase 3.2 type, as declared (§12)
    pub error: Option<ErrorPayload>,   // terminal failure diagnostics
}

pub enum DispatchOutcome {
    Planned,        // validated plan data attached (hashes present)
    Denied,         // Layer 8 DENY (reason attached)
    ConfirmPending, // Layer 8 CONFIRM, no token minted (challenge attached)
    Failed,         // typed error (mapping in §14)
    Cancelled,      // cooperative flag observed (no error)
}
```

Records are caller-owned values returned to the caller. No store, no
journal, no persistence format is specified (a journal would require
ADR-0006 ownership first).

## 14. Error Contract

* Reuse first: Layer 8 errors (`PolicyError`), boundary errors
  (`CapabilityError`), and manager errors surface verbatim inside
  `DispatchRecord.error`; no rewrapping that loses codes.
* New thin `DispatchError` only for dispatch-local faults:
  `SynthesisConflict` (schema-version ambiguity, §6.1) and
  `ClaimRejected` (assignment not claimable — defense in depth behind
  manager guards), both mapping to `ErrorCode::InvalidRequest` / `Never`.
  No other new error semantics are introduced.

## 15. Audit Lineage (Shapes Only)

* Every terminal record carries the full chain:
  `assignment_id → request_id → decision (snapshot hash + contributing
  policies) → binding_hash → plan_hash`, all under the root
  `correlation_id`, plus the manager-side assignment transitions (already
  persisted by the Layer 5 store) and the Layer 8 audit shape (attached by
  reference, never duplicated or reinterpreted).
* Shapes only: the Layer 12 writer, hash chaining, and integrity anchors
  remain deferred (TBD preserved). Secrets, tokens, and private paths never
  enter diagnostics beyond caller-supplied identifiers.

## 16. Persistence: Caller-Owned Records, No Store

* Dispatch keeps no state between calls beyond the borrowed handles it is
  given (manager, policy engine, registry). Records are returned values;
  retention, journaling, and crash-survival of dispatch records are the
  caller's concern and are not specified here — specifying them would
  require ADR-0006 ownership that does not exist yet.

## 17. Determinism

* Identical inputs (same assignment state, same policy snapshot, same
  registry bundle, same clock, same cancel-flag state) yield identical
  terminal outcomes and identical decisions/bindings/plans modulo fresh
  `dispatch_id` / `binding_id` / `plan_id` / `challenge_id` UUIDs and their
  covering hashes. Diagnostics (reasons, contributing sets) are fully
  deterministic, sorted per Phase 3.1/3.2 discipline.

## 18. Test Strategy

* Synthesis units: field-mapping table row-by-row (id reuse, deadline
  saturating arithmetic incl. overflow edge, version resolution
  zero/one/many, token-always-None, snapshot freshness).
* Lifecycle units: claim guards (terminal re-dispatch refused), per-stage
  cancel injection (flag set before each check point → `Cancelled` + manager
  `cancel_assignment` observed), timeout carriage (deadline math, no sleeps).
* Branch E2E over fixtures: read/create ALLOW→`Planned` with valid plan;
  unknown capability→`Failed(CapabilityNotFound)`; system-kind→`Denied`;
  delete_tree→`ConfirmPending` (never upgraded); stale snapshot→`Failed`;
  scope-mismatch→`Failed`; agent release (`Ready`) asserted after every
  terminal outcome.
* Precondition honesty test: `Planned` records carry manifest expressions
  verbatim and contain no evaluated results.
* Zero-escape static audit (extends Phase 3.1/3.2 lists): no
  spawn/fork/`exec`/socket/listener/shell/sudo/LLM/HTTP/UI symbols, no
  reasoning-loop or prompt-template constructs, no `thread::sleep`/
  timing-based waits, no filesystem I/O beyond test tempdirs, no live-handle
  returns.
* Full-chain E2E: Phase 1 submit → manager `assign_step` → dispatch →
  validated plan, asserting lineage preservation at every hop.

## 19. E2E Acceptance Criteria

Authoritative acceptance is the demo traversal with zero host effects:
input `"Create a project folder called demo"` → Intent → Goal → Workflow →
`WorkAssignment(Assigned)` → dispatch claims → synthesizes
`fs.create_directory` request → Layer 8 `ALLOW` → binding → validated
Profile 1 plan → terminal `Planned` record → agent `Ready`. Plus: DENY,
ConfirmPending, unknown-capability, stale-snapshot, scope-mismatch, and
cancel-injected traversals, each terminating with the specified record and
released agent. Full run asserts zero subprocesses, sockets, filesystem
mutations outside tempdirs, sleeps, and LLM calls.

## 20. Explicit Non-Goals

Strictly excluded and reserved for later phases: worker spawning; sandbox
enforcement; IPC listeners/daemons; LLM reasoning, prompt templates, or
tool loops; UI; networking; filesystem effects or reads (incl. `stat(2)`);
shell/root/sudo; new databases or journals; new dependencies; broker token
minting or verification; verification effects; dispatch-record persistence
formats; Agent Runtime behavior beyond this deterministic dispatch contract
(multi-agent orchestration, streaming, retries orchestration); any change
to Phase 1/2/3.1/3.2 semantics; OS packaging; cloud/telemetry/multi-host.

## 21. Unresolved Decisions / TBDs

Preserved as TBD; Phase 3.3 invents no value. Inherited: all Phase 3.0 §25
and Phase 3.2 §30 items (path/entity mapping, token crypto, replay
durability, shadowing, admin roles, annotation strictness, store mechanics,
vault, backup consistency, audit anchors, retention/scheduling, vector
store, streaming/FD, sandbox ceilings/pins/ABI/allowlists, `openat2`,
confirmation transport, audit signing, secret service, manifest bundle
format, plan-cache bounds, supervision timings, precondition grammar,
compensation DSL). Phase 3.3 additionally defers, without resolving:

1. Live supervisor attestation binding (production principal verification).
2. Dispatch-record persistence format and retention (needs ADR-0006 owner).
3. Multi-assignment workflow orchestration (fan-out/fan-in, ordering).
4. Retry orchestration across dispatch attempts (classification reused,
   orchestration deferred).
5. Agent-side streaming/token protocols (LLM-adjacent, deferred).
6. Timeout/watchdog enforcement mechanics (carried as data only).
7. Cross-phase clock discipline (supervisor clock authority formalization).

## 22. Phase 3.4 Implementation Boundary

Phase 3.4 may implement strictly from this specification plus all prior
specifications, without new architectural decisions:

* New module boundary for the dispatch consumer, borrowing (never owning)
  the manager, policy engine, and registry; no edits to Phase 1/2/3.1/3.2
  semantics, state machines, storage, or evaluation behavior.
* No new dependencies. Pure functions plus borrowed-handle calls; no spawn,
  no dial, no sleep, no filesystem writes outside test tempdirs.
* Harness must include the honesty test (§12/§18), the full-chain E2E
  (§19), and the extended zero-escape proof before any live-supervisor,
  enforcement, or reasoning work begins.
* Any attempt to resolve §21 TBDs requires a spec amendment with ADR update;
  implementation must not silently fix a TBD value in code.

(End of file - total 22 sections)

