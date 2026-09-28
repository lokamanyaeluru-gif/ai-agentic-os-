# Phase 3.0: Policy Engine / Security Governance Specification

* **Document Version**: 3.0.1
* **Date**: 2026-09-28
* **Phase**: 3.0 (Specification Only — No Implementation)
* **Status**: APPROVED SPECIFICATION / READY FOR PHASE 3.1 IMPLEMENTATION PLANNING
* **Amendment 3.0.1 (Dependency-Scope Amendment)**: Authorizes `sha2` as an additional workspace-pinned dependency for SHA-256 hashing only (§26). No SHA-256 requirement changed; no other TBD resolved.
* **Architectural Baseline**: ADR-0001 through ADR-0007, `docs/architecture.md` (canonical layer numbering), `docs/security.md`, `docs/threat-model.md`, `docs/phases/phase-1-complete.md`, `docs/phases/phase-2-complete.md`
* **Layer Numbering Authority**: `docs/architecture.md` is canonical. Where ADR-0006 / ADR-0007 context sections renumber layers differently, this specification follows `architecture.md` and treats those renumbers as documentation drift, not semantic change.

---

## 1. Objective

Phase 3.0 specifies the deterministic Policy Engine / Security Governance evaluation plane (Layer 8) as a standalone, execution-free decision function.

It bridges already-completed planning state (Phase 1: Intent → Goal → Workflow; Phase 2: `WorkAssignment` dispatch contract) to an authoritative tri-state decision (`ALLOW` / `DENY` / `CONFIRM`) over synthetic, schema-validated `CapabilityInvocationRequest` inputs.

Phase 3.0 produces decisions and handoff constraints only. It launches no workers, mutates no host state beyond its own specification artifact, and grants no execution privilege.

## 2. Scope

### In-scope for Phase 3.0 specification

* Formal evaluation input contract (ADR-0007 `CapabilityInvocationRequest` passthrough).
* Cedar PBAC core evaluation semantics (`is_authorized` → `Allow` / `Deny`).
* AgenticOS Security Wrapper semantics: default-deny, forbid-overrides, `@confirm` detection → `CONFIRM`.
* Four-tier policy hierarchy and precedence rules exactly as stated in ADR-0005.
* Policy bundle loading, schema validation, atomic snapshot swap, versioning, and rollback semantics.
* Sandbox handoff constraint shape (`SandboxConstraints`) as data only.
* Audit event shape and error semantics per ADR-0007.
* Evaluation-only test and acceptance criteria with zero-execution proof.

### Out of scope (see §24 Non-Goals)

Capability execution, sandbox runner implementation, Agent Runtime implementation, Human Interface UI, LLM integration, networking, shell/root execution, token signing-key implementation, live IPC daemons.

## 3. Architecture Position

Canonical position per `docs/architecture.md`:

```text
[Layer 4: Workflow Runtime] → WorkflowStep
[Layer 5: Global Agent Manager] → WorkAssignment (dispatch contract only, Phase 2 complete)
        │
        ▼ (Phase 3.0 evaluation input: synthetic CapabilityInvocationRequest)
[Layer 8: Security & Governance — Policy Engine + Security Wrapper] (THIS SPECIFICATION)
        ├── DENY → typed error to caller, no execution
        ├── CONFIRM → challenge record to broker boundary, no execution
        └── ALLOW → SandboxConstraints data to Layer 9 boundary, no launch
[Layer 9: Capability Layer / Sandbox Runner] — HANDOFF ONLY, not implemented
[Layer 10: Linux Integration Boundary] — not traversed in Phase 3.0
[Layer 11: Kernel & System Intelligence] — not implemented
[Layer 12: Observability & Reliability] — audit shape only, no writer daemon implementation
[Layer 6: Agent Runtime] — deferred consumer; Phase 3.0 evaluates synthetic requests, not live agent traffic
[Layer 7: Knowledge & Memory] — untouched
[Layer 1: Human Interface] — untouched
[Layer 13: Hardware] — untouched
```

Phase 3.0 does not create, own, or modify Layer 6, Layer 9, Layer 10, Layer 11, Layer 1, or Layer 13 behavior.

## 4. Trust Boundaries

1. **TB-Input (Untrusted → Control plane):** All evaluation inputs are untrusted candidate data until schema validation, normalization, and transport attestation shape checks pass. Phase 3.0 tests use synthetic fixtures; production transport attestation (`SO_PEERCRED` / `socketpair` per ADR-0002) is referenced but not implemented here.
2. **TB-Gateway (Hard gateway, Layer 8):** The Policy Engine is the sole decision authority. Planning state (`WorkflowStep`, `WorkAssignment`) proposes; only Layer 8 disposes (`ALLOW` / `DENY` / `CONFIRM`). No bypass path exists in this specification.
3. **TB-Sandbox (Isolation):** Referenced as mandatory downstream containment per ADR-0003. Phase 3.0 emits constraints; it does not enforce them in the kernel.
4. **TB-Kernel (POSIX):** Never traversed in Phase 3.0. No syscall, no process spawn, no filesystem mutation outside the spec document itself.

Provenance vs authentication (ADR-0007 / Phase 1 §5.1 preserved): `originating_principal` and copied `PrincipalContext` fields are provenance context only. They are never the authorization authority. Production authorization consumes transport-attested identity at UDS ingress; Phase 3.0 fixtures carry attested-principal shapes explicitly labeled as test fixtures, never as real system state (Phase 2 real-data rule preserved).

## 5. Capability Request Contract

Phase 3.0 consumes the ADR-0007 `CapabilityInvocationRequest` shape as an opaque, strictly validated input:

* Required fields: `request_id`, `correlation_id`, `capability_id`, `capability_schema_version`, `resource: ResourceRef{kind, identifier}`, `arguments: JSON Value`, `deadline_ms`, `timeout_duration_ms`, `policy_snapshot_hash: [u8; 32]`, `approval_token: Option<ApprovalToken>`.
* Deserialization rejects unknown fields (`deny_unknown_fields` discipline preserved from Phase 1/2).
* `capability_id` is a routing/contract string only (e.g. `fs.create_directory`). Naming a capability never executes it.
* `timeout_duration_ms` must be non-zero and bounded: supervisor enforces `min(requested, system_maximum)`. The exact system-maximum value is not fixed by this specification; ADR-0007 cites an example ceiling (e.g. 300,000 ms) as non-normative. Implementations must reject unbounded/missing timeouts with `InvalidRequest`. Tests may use fixed fixture values.
* `policy_snapshot_hash` binds the request to the policy snapshot under which it was formed. Mismatch handling is defined in §11.
* If `approval_token` is present, Phase 3.0 validates its structural presence and binding shape only (see §14). Absence of a valid token where `@confirm` applies yields `CONFIRM`, never `ALLOW`.

No new wire format is introduced. No Protobuf, CBOR, or streaming protocol is adopted for Phase 3.0 (ADR-0007 JSON baseline preserved).

## 6. Cedar Policy Evaluation Model

* Core evaluator is AWS Cedar (`cedar-policy`) as embedded PBAC engine per ADR-0005 (formally modeled core, default-deny, `permit`/`forbid` algebra).
* Evaluation function is `is_authorized()` over `(Principal, Action, Resource, Context)` mapped from the validated request and attested principal fixture.
* Cedar evaluation is pure, deterministic, terminating (non-Turing-complete), and side-effect-free.
* The AgenticOS Security Wrapper surrounds the core and is solely responsible for: input normalization shape checks, hierarchy assembly, annotation inspection, `CONFIRM` derivation, `SandboxConstraints` data synthesis on `Allow` without `@confirm`, diagnostics, and audit shape emission.
* Cedar annotations (e.g. `@confirm`) are metadata only. Cedar does not enforce them. The wrapper enforces §9 semantics.

Phase 3.0 does not modify Cedar semantics and does not introduce a bespoke policy language.

## 7. Default-Deny Behavior

* If no `permit` policy matches the request across all evaluated tiers, the outcome is `DENY`.
* Any evaluation error — missing entity, malformed parameter, schema mismatch, snapshot inconsistency, timeout-guard expiry — yields `DENY` (fail-closed, ADR-0001/ADR-0005/ADR-0007 preserved).
* `DENY` returns a diagnostic reason naming the contributing `forbid` policy ID where applicable, or `DefaultDenyNoMatchingPermit` otherwise. Diagnostics never include secrets, tokens, or private host paths beyond the resource identifier already supplied by the caller.

## 8. Forbid-Overrides Behavior

* Any matching `forbid` yields `DENY` regardless of the number of matching `permit` rules.
* Tier precedence (ADR-0005 preserved):
  1. Mandatory System Policy `forbid` dominates all lower tiers. No user, session, confirmation, or token overrides it.
  2. User Policy `forbid` yields `DENY` unless already denied by system policy.
  3. Session/Context policy may only further restrict; it cannot expand permissions beyond system + user allows.
* Confirmation precedence: if any contributing `permit` carries `@confirm` requiring human approval, the outcome is `CONFIRM` even if another permit lacks `@confirm`. A lower-trust autonomous allow cannot waive a higher-tier confirmation requirement.
* Malformed or unrecognized wrapper metadata (e.g. malformed `@confirm`, `@blast_radius`) fails closed to `DENY`. It never defaults to autonomous execution.

## 9. CONFIRM Detection

* After Cedar returns `Allow`, the wrapper inspects determining policies for `@confirm("true")` (or equivalent confirmed annotation schema validated at bundle load).
* If `@confirm` is present and no structurally valid, unexpired, single-use `ApprovalToken` bound to this request and snapshot is present, the outcome is `CONFIRM` with: `challenge_id`, human-readable `prompt` (from `@confirm_prompt` metadata), `blast_radius`, `required_scope`, and `contributing_policies`.
* If `@confirm` is absent, or a valid bound token is present per §14 structural checks, the wrapper may yield `ALLOW` with synthesized constraints (§15).
* `CONFIRM` suspends execution. It never launches workers, never mints tokens (see §13–§14), and never bypasses §8 forbid rules.

## 10. Policy Bundle Loading and Validation

* System policies: Cedar files under `/etc/agenticos/policies/system/` (root-owned in production; fixtures in tests). User policies: `~/.config/agenticos/policies/user/`. Session/context policies: ephemeral per-workflow overlays that only restrict.
* Every candidate bundle is parsed and checked against the declared Cedar schema (`cedarschema`) using Cedar's static `Validator` before activation. Static checks include syntax, entity/action applicability, and unsatisfiable-rule detection where supported.
* Manifest (`policies.manifest.json` shape) declares activation order and schema bindings. Content addressing via SHA-256 is preserved from ADR-0005.
* If validation fails for any reason, the candidate bundle is rejected, an audit-shaped record is specified for emission, and the active snapshot remains untouched.
* Agents, LLMs, and capability workers have no write authority over policy files (ADR-0006 preserved). Agent recommendations to change policy are advisory prompts to the user only.

## 11. Snapshot/Versioning and Rollback

* The active policy set is an immutable snapshot: `{version, hash, authorizer, policy_set, schema}`.
* Updates use atomic snapshot swap semantics (e.g. `ArcSwap`-style pointer swap in implementation; this specification mandates atomicity, not the concrete type).
* Reload flow: trigger → parse → schema-validate → construct candidate snapshot → atomic swap on success; reject-and-keep-active on failure.
* Rollback: retained prior snapshots addressable by semantic version; rollback is a validated load + atomic swap, integrity-hash-checked.
* `policy_snapshot_hash` binding: requests formed under snapshot H evaluated under snapshot H′ ≠ H must treat H-mismatch as evaluation-context mismatch. Where an `ApprovalToken` is present, snapshot mismatch invalidates the token (§14). Where no token applies, evaluation proceeds under the active snapshot and records both hashes in the audit shape for traceability. No silent downgrade to a weaker snapshot is permitted.
* Previous-version retention and manifest ordering are required; exact retention counts and snapshot schedules remain TBD per ADR-0006 and are not fixed here.

## 12. Resource Model — Explicitly TBD Where Unresolved

* Phase 3.0 consumes `ResourceRef{kind, identifier}` opaquely. `kind` values (e.g. `Path`, `Application`, `NetworkEndpoint`, `DBusService`) and `identifier` strings are passed through to Cedar inputs without asserting a finalized Cedar entity hierarchy.
* The exact Cedar entity representation for Linux paths and other resources — entity hierarchy with `parent` links vs. Cedar custom extension types vs. any other typed modeling — is **explicitly TBD**, per ADR-0005 open item 4 and ADR-0007 open item 1. This specification does not choose among them.
* Consequently, Phase 3.0 policy fixtures must not rely on string-prefix path containment as a security boundary. Canonicalization may be specified as an input-normalization step, but the filesystem containment boundary remains the downstream kernel/sandbox layers per ADR-0003/ADR-0005. No Phase 3.0 decision implies that a Cedar `ALLOW` alone authorizes host access.
* Any future resolution of the resource model requires a schema amendment and re-validation of all policy fixtures. Until then, path-sensitive policies in tests are illustrative routing fixtures only.

## 13. Human Confirmation Broker Boundary

* The Human UI (Layer 1) is an untrusted presentation layer. It has no signing authority and owns no trusted keys.
* The Confirmation Broker is a trusted Layer 8 boundary function. In Phase 3.0 it is specified as a challenge-emission boundary only: it formats the `CONFIRM` challenge (`challenge_id`, `prompt`, `blast_radius`, scope) for downstream delivery. It does not mint or sign tokens in Phase 3.0, does not render UI, and does not execute capabilities.
* User approval/rejection handling, desktop prompt IPC, and session binding mechanics remain deferred (confirmation protocol TBD per `docs/security.md`).
* Denial of a challenge is specified as audit-recorded rejection returning `PolicyDenied`/`ConfirmationRequired` semantics to the caller. Approval handling beyond challenge emission is deferred to the token boundary (§14) and future phases.

## 14. Approval-Token Boundary — No Cryptographic Choice Beyond Existing ADRs

* Structural contract preserved from ADR-0007: `ApprovalSubject` (request fields excluding `approval_token`) → canonical deterministic serialization (RFC 8785 JCS, exact rules in ADR-0007 §Canonical Serialization) → SHA-256 `request_hash`; `ApprovalToken{ payload: ApprovalTokenSignedPayload, signature }` where the signature covers all payload fields (`single_use_id`, `request_hash`, `policy_snapshot_hash`, `principal`, `capability`, `resource`, `confirmation_reason`, `issued_at_ms`, `expires_at_ms`, `nonce`).
* Expiry is evaluated strictly against trusted supervisor/broker time, never caller timestamps. TTL is bounded by an architectural maximum (ADR-0007 cites e.g. 60,000 ms as non-normative example; exact ceiling not fixed here). Over-ceiling TTLs are rejected.
* Replay handling shape: `single_use_id` redemption tracking is required in any future broker implementation; durability (in-memory vs. persisted across restarts) is **explicitly TBD** per ADR-0007 open item 3. Phase 3.0 specifies the invariant (double-redemption must fail) without fixing the store.
* Signature algorithm, signature encoding, key generation, key storage, rotation, and attestation are **explicitly TBD** per ADR-0005 open item 3 and ADR-0007 signature-contract metadata. This specification makes no choice among Ed25519, HMAC-SHA256, or any other mechanism, and introduces no keys, no signing code path, and no verification-key distribution scheme.
* Phase 3.0 evaluation rule: any request requiring confirmation without a structurally valid, hash-matching, unexpired, single-use-bound token yields `CONFIRM`. Token minting and cryptographic verification implementations are deferred. No `CONFIRM` may transition to `ALLOW` in Phase 3.0 on the basis of UI signals alone.

## 15. Sandbox Handoff Contract Only

* On `ALLOW`, the wrapper synthesizes a `SandboxConstraints` data record only: `{read_paths, write_paths, allow_network, seccomp_profile: String label, max_memory_bytes, max_cpu_quota_percent, max_wall_time_ms}` (shape per ADR-0007).
* Constraint values are the minimal set implied by the matched policies and request scope. `allow_network` defaults to false unless an explicit network policy permits a named local endpoint. Exact numeric ceilings are implementation-bounded; this spec mandates boundedness, not specific numbers.
* The record is handed to the Layer 9 boundary as data. No Bubblewrap invocation, no Landlock ruleset application, no seccomp filter compilation, no namespace creation, no cgroup configuration, and no worker spawn occur in Phase 3.0.
* Sandbox initialization failure semantics from ADR-0003 are preserved by reference (fail-closed, no un-sandboxed fallback) for future phases; they are not exercised in Phase 3.0 because no initialization is attempted.

## 16. Audit Event Contract/Shape

* Every evaluation specifies an append-only audit-shaped record for Layer 12, including: `event_type: policy_evaluation`, timestamp shape, `request_id`, `correlation_id`, attested caller shape (`pid/uid/socket_inode/verified_peer` as applicable to fixtures), `principal/action/resource/context`, `decision (ALLOW/DENY/CONFIRM)`, `contributing_policies`, `confirmation_required`, `approval_token_id` (null when absent), and snapshot hashes.
* Layer 12 authoritative invariants preserved by reference: sequence number, event ID, authoritative timestamps, and hash-chain linkage are assigned solely by the Layer 12 writer. Phase 3.0 specifies shapes; it does not implement the writer daemon, file I/O, or integrity anchors (anchors TBD per ADR-0006).
* Secrets, tokens, and private key material must never appear in audit payloads. Redaction discipline from `docs/security.md` / `docs/threat-model.md` is normative.

## 17. Error Semantics

* ADR-0007 error taxonomy reused without modification: `InvalidRequest`, `MalformedArguments`, `IncompatibleProtocolVersion`, `PolicyDenied`, `ConfirmationRequired`, `InvalidApprovalToken`, `TokenReplayDetected`, `PeerAuthenticationFailed`, `CapabilityNotFound`, `SandboxInitializationFailed`, `CapabilityExecutionFailed`, `ResourceCeilingExceeded`, `Timeout`, `Cancelled`, `DependencyFailed`, `StorageFailure`, `InternalError`; with supervisor-governed `RetryClassification (Never/Safe/Conditional)`.
* Phase 3.0 mappings: schema/validation failures → `InvalidRequest/Never`; unknown capability → `CapabilityNotFound/Never`; policy denial → `PolicyDenied/Never`; confirmation suspension → `ConfirmationRequired/Never` (retry only via fresh human-approved resubmission, not automatic retry); evaluation-internal faults → `InternalError/Never` with fail-closed `DENY`; framing/transport violations → connection teardown per ADR-0007 (referenced, not implemented here).
* No raw stderr, stack traces, or credential-bearing paths leak through errors. Agents receive typed codes only.

## 18. Failure/Rollback Behavior

* Fail-closed default: any failure in parsing, validation, entity resolution, Cedar evaluation, annotation handling, snapshot access, or constraint synthesis halts evaluation with `DENY` and specifies an audit-shaped record. No child worker is spawned on any pre-execution failure path.
* Policy reload failure: keep serving the last known-good snapshot; reject candidate; record rejection. Never serve a partially loaded bundle.
* Snapshot mismatch with pending `CONFIRM`: force re-evaluation under the active snapshot; invalidate snapshot-bound tokens.
* Cancellation: evaluation is synchronous and bounded (Cedar termination + implementation timeout guard). Cancellation of a pending human challenge does not imply rollback because no mutation has occurred in Phase 3.0. Mutating-capability rollback semantics (atomicity/commit-point/compensation) remain downstream concerns and are not defined here beyond the ADR-0007 requirement that future mutating contracts declare them.
* Idempotency: evaluation is read-only and naturally idempotent. Resubmission with the same `request_id` re-evaluates deterministically; it never executes.

## 19. Persistence Boundary

* Phase 3.0 owns no new SQLite database. It reads declarative policy files and manifest metadata through the Security & Governance ingress only.
* ADR-0006 ownership preserved: `intents.db` (L2), `goals.db` (L3), `workflows.db` (L4), `agent_registry.db` (L5) remain untouched and unopened by the policy plane. No cross-database joins, no shared connections.
* Secrets vault, audit logs, blobs, search/vector indexes, and runtime sockets are out of scope and unopened.
* Policy-store filesystem permissions, ACLs, atomic swap mechanics, and admin write roles remain TBD per ADR-0005 open items 2 and 6 (referenced, not fixed here) beyond the existing invariant: system policies are administrator-owned, user policies are user-owned, agents have no write authority.

## 20. Security Invariants

Phase 3.0 preserves all Phase 1 and Phase 2 invariants and adds no exception:

1. Local-only: no remote fetch, no telemetry, no cloud policy distribution. LOCAL-only is normative; any cloud exposure mode is deferred and non-normative for this project.
2. Deterministic: same request + same snapshot + same attested principal shape → identical decision and identical diagnostics.
3. LLM never authority; no prompt, embedding, or model output bypasses schema, hierarchy, or confirmation checks.
4. No shell (`sh/bash/zsh`), no `sudo`/root, no `AF_INET`/`AF_INET6` listeners or dials in any Phase 3.0 artifact or test.
5. Planning artifacts propose; Layer 8 disposes. `WorkAssignment` never bypasses policy.
6. Strict schema discipline (`deny_unknown_fields` for control-plane contracts); malformed metadata fails closed.
7. Least privilege in handoff constraints; `allow_network=false` default.
8. Fail-closed on all errors; no un-sandboxed fallback reasoning (no fallback exists in Phase 3.0 at all).
9. Real-data rule for tests: fixtures labeled as fixtures; synthetic principals/requests never persisted as production state.
10. JCS canonicalization (RFC 8785) for any hash/signature-shape computation, exactly per ADR-0007; no alternative serialization introduced.

## 21. Threat Model

Mapped to `docs/threat-model.md` IDs; Phase 3.0 mitigates at the decision layer only (kernel/sandbox mitigations remain downstream and are referenced, not implemented):

* TH-01 Indirect prompt injection → deterministic gate; compromised reasoning still requires explicit `permit` without `forbid`; no shell capability exists to invoke.
* TH-02 Path traversal → opaque `ResourceRef` passthrough + hierarchy `forbid` fixtures where defined; true containment deferred to sandbox/kernel per §12. No prefix-check bypass is introduced here because no new path comparator is introduced.
* TH-03 Arbitrary shell execution → no execution path in Phase 3.0; `ALLOW` emits data only.
* TH-04 Privilege escalation → no root/sudo/key material in evaluation; system `forbid` tier dominates.
* TH-05 Credential theft → blacklisted-path `forbid` shapes retained by reference; redaction in audit/error shapes; secrets never in evaluation inputs.
* TH-06 Symlink/TOCTOU → explicitly not solved at the policy layer; noted as kernel/sandbox responsibility (`openat2`/`RESOLVE_*`, mount namespaces, Landlock) per ADR-0003/ADR-0005. No TOCTOU claim is made for Phase 3.0.
* TH-07 Agent loops/resource exhaustion → bounded evaluation, timeout-guard shape, no auto-retry of `Never` mutations; cgroup enforcement deferred downstream.
* TH-08/TH-09 Supply chain / third-party components → two narrowly scoped dependencies anticipated for implementation: `cedar-policy` (policy engine, Apache-2.0, per ADR-0005) and `sha2` (SHA-256 hashing only, per Amendment 3.0.1); no other new dependency is authorized by this specification. Vetting pipeline from `docs/security.md` remains normative for Phase 3.1, and both additions must be audited before implementation.
* TH-10 Hallucinated mutation / tampered output → pre/post-condition verification and output-schema validation remain downstream; Phase 3.0 contributes deterministic `DENY`/`CONFIRM` gating and lineage preservation (`correlation_id`, `request_id`, snapshot hash).
* Audit tampering → hash-chain shape referenced; integrity anchors TBD per ADR-0006, no anchor invented here.

## 22. Testing Requirements

Evaluation-only harness using synthetic fixtures. All suites must pass with zero warnings under the project's standard toolchain gates (fmt/check/clippy/test) when Phase 3.1 implements from this spec. Required coverage:

1. Default-deny: no matching `permit` → `DENY` with `DefaultDenyNoMatchingPermit`.
2. Forbid-overrides: system `forbid` beats user `permit`; user `forbid` beats session `permit`.
3. Confirmation precedence: `@confirm` permit + plain permit → `CONFIRM` without token.
4. Token-absent vs token-present shape handling: valid structural binding (hash/snapshot/scope match in fixture) → `ALLOW` path; any mismatch/expiry/reuse shape → `CONFIRM` or `InvalidApprovalToken` per §14, never silent `ALLOW`.
5. Malformed annotation/bundle/schema → `DENY`, active snapshot retained.
6. Snapshot mismatch → re-evaluation + token invalidation shape.
7. Unknown capability / malformed arguments / unbounded timeout → typed errors per §17.
8. Determinism: identical fixture replay → bit-identical decision + diagnostics.
9. Zero-execution proof: harness asserts no subprocess spawn, no network dial, no filesystem mutation outside test tempdirs, no shell invocation (static audit + runtime FD/socket accounting in tests).
10. Lineage: `correlation_id`/`request_id`/snapshot hash preserved end-to-end into audit shapes.
11. No crypto agility test beyond shapes: algorithm-specific vectors are forbidden until the TBD in §14 is resolved.

## 23. E2E Acceptance Criteria

Authoritative acceptance uses synthetic `CapabilityInvocationRequest` fixtures only (no agents, no workers, no host mutation):

1. Fixture A (workspace read, permitted without confirm) → `ALLOW` + bounded `SandboxConstraints` data, audit shape recorded, zero host reads outside fixture tempdir.
2. Fixture B (system-path write, forbidden by system tier) → `DENY` citing system `forbid`, even when user/session fixtures permit.
3. Fixture C (destructive mutation with `@confirm`, no token) → `CONFIRM` with challenge shape; no constraint synthesis; no execution.
4. Fixture C + structurally bound fixture token → `ALLOW` path taken only per §14 structural rules; still zero execution; handoff record only.
5. Candidate bundle with syntax/schema error → reload rejected, active snapshot continues serving Fixtures A–C identically.
6. Rollback fixture → prior version reactivation serves deterministically with updated snapshot hash in audit shapes.
7. Full run asserts: zero `Command`/`fork`/`execve`, zero `TcpStream`/`UdpSocket`/HTTP, zero shell strings, zero root/sudo, zero writes outside test tempdirs, zero LLM calls.

Phase 3.0 is accepted only when all criteria hold without implementing Layers 6, 9, 10, 1, or any sandbox primitive.

## 24. Explicit Non-Goals

Strictly excluded from Phase 3.0 and reserved for later phases:

* Capability execution of any kind (filesystem, process, network, application launch).
* Sandbox runner implementation (Bubblewrap, Landlock, seccomp-bpf, namespaces, cgroups).
* Agent Runtime implementation (Layer 6 task loops, context management, live assignment consumption).
* Inter-process IPC daemons (live UDS listeners, D-Bus services).
* Human Interface UI (desktop dialogs, CLI prompts, notification plumbing).
* LLM integration (parsing, reasoning, tool loops, embeddings, vector stores).
* Networking of any kind, including “local-only HTTP” endpoints beyond test loopback fixtures where explicitly required by harness tooling (no production network path specified).
* Shell execution, root execution, sudo escalation, ambient privilege use.
* Cryptographic implementation choices for tokens (algorithm, encoding, key custody, rotation).
* Cloud exposure modes, remote policy distribution, telemetry, or multi-host operation. LOCAL-only is normative.
* OS packaging, ISO/installer work, GPU/hardware orchestration.

## 25. Unresolved Decisions/TBDs

Preserved as TBD; Phase 3.0 invents no value for any item:

1. `ResourceRef` → Cedar entity mapping (ADR-0005 Q4, ADR-0007 Q1) — §12 opaque passthrough.
2. Approval-token signature algorithm, encoding, key hierarchy, storage, rotation, attestation (ADR-0005 Q3, ADR-0007 signature metadata).
3. Replay-cache durability across restarts (ADR-0007 Q3).
4. System vs. user shadowing edge-case formalization beyond §8 tier rules (ADR-0005 Q1).
5. Policy administration roles/groups and write access to `/etc/agenticos/policies/system/` (ADR-0005 Q2).
6. Malformed-annotation schema strictness details beyond fail-closed default (ADR-0005 Q5).
7. Policy-store ownership, permissions, atomic-swap mechanics, audit emission for file updates (ADR-0005 Q6).
8. Secret vault backup/re-binding, KDF/integration specifics (ADR-0006 Q1/Q6) — untouched.
9. Policy/config backup consistency points (ADR-0006 Q2).
10. Audit integrity anchors (ADR-0006 Q3).
11. Retention/compaction, snapshot scheduling, cross-DB coordination (ADR-0006 Q4/Q7/Q8) — untouched.
12. Vector-store selection (ADR-0006 Q5) — untouched.
13. Streaming/blob FD-passing protocols (ADR-0007 Q2/Q4) — untouched.
14. Sandbox profile numeric ceilings, Bubblewrap version pins, Landlock ABI probing, seccomp allowlists (ADR-0003) — untouched.
15. Confirmation UI/transport protocol, audit signing, secret-service integration (`docs/security.md` TBDs) — untouched.

## 26. Phase 3.1 Implementation Boundary

Phase 3.1 may implement strictly from this specification without new architectural decisions:

* New crate/module boundary for the policy plane consuming `agenticos-contracts` types only; no edits to Phase 1/2 domain semantics, state machines, or storage schemas except additive, backward-compatible extension where explicitly required and migration-covered.
* Dependency addition limited to `cedar-policy` (policy-engine dependency, pinned in `Cargo.lock`, audited) and `sha2` (additional dependency used ONLY for the SHA-256 hashing already required by this specification: `policy_snapshot_hash` per §11 and `ApprovalSubject` `request_hash` per §14), plus already-present workspace dependencies. `sha2` must be workspace-pinned and recorded in `Cargo.lock`; its use is restricted to snapshot_hash and request_hash computation. No other cryptographic algorithms, key-management behavior, signature algorithms, key storage, token signing, or token verification may be introduced under this amendment. No `hex` or other encoding dependency is authorized; deterministic hexadecimal formatting must use existing/manual means. No tokio/net/UI/LLM crates authorized by this spec. Dependency additions must be audited before implementation.
* Pure evaluation functions with deterministic fixtures; no process spawn, no socket dial, no filesystem writes outside test tempdirs and policy fixture dirs.
* Harness must include the zero-execution proof (§22.9) and E2E fixtures (§23) before any Layer 6, Layer 9, or broker-signing work begins.
* Any attempt to resolve §25 TBDs requires a spec amendment with ADR update; implementation must not silently fix a TBD value in code.
