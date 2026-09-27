# ADR-0005: Policy and Authorization Engine Architecture for AI Agentic OS

* **Status**: PROPOSED  
* **Date**: 2026-09-27  
* **Phase**: 0.3.4  

---

## Context

AI Agentic OS operates as an AI-native desktop control plane above Linux. In this architecture, autonomous agents driven by Large Language Models (LLMs) synthesize and execute multi-step workflows to achieve user-specified goals.

### Foundational Security Axioms from Prior Architectural Decisions
* **ADR-0001 (Deterministic Security & Local Operation)**: The LLM is never the authorization authority; no raw shell execution is permitted; all actions are mediated deterministically.
* **ADR-0002 (IPC Architecture)**: Internal subsystem communication is strictly local via Unix Domain Sockets (`AF_UNIX`) using a typed protocol; Linux host/desktop integration is mediated via dedicated Layer 10 D-Bus adapters.
* **ADR-0003 (Sandbox Architecture)**: Defense-in-depth containment combining the Policy Engine, systemd/cgroups v2, Bubblewrap namespace isolation, Landlock LSM path access control, and seccomp-bpf syscall filtering. Default execution model: supervisor spawns a dedicated capability worker process, applies sandbox restrictions before capability code executes, executes capability, verifies result, and terminates the worker.
* **ADR-0004 (Implementation Language Architecture)**: The trusted control, security, and system-integration plane (Layers 2–12) is authored in Rust; polyglot capability workers run out-of-process and sandboxed.

### The Capability Invocation Pipeline
Every agent interaction with the host system follows this deterministic pipeline:
```
LLM / Agent
   │ (Emits structured intent over UDS)
   ▼
UDS Ingress (Layer 8/9 boundary)
   │ (Transport-level peer authentication via SO_PEERCRED / SCM_CREDENTIALS)
   ▼
Authenticated Principal & Normalized Request
   │ (Input normalization & pre-evaluation validation)
   ▼
Deterministic Policy Engine (ALLOW / DENY / CONFIRM)
   │ (Consumes authenticated identity; evaluates policy hierarchy)
   ▼
Capability-Specific Sandbox (Bubblewrap + Landlock + seccomp)
   │ (Executes under kernel-enforced least privilege)
   ▼
Linux Kernel & Host OS
   │ (Captures structured result & telemetry)
   ▼
Verification & Audit Gate
```

### Architectural Division of Responsibilities
To maintain system integrity, responsibilities are strictly separated:

1. **UDS Ingress & Transport Authentication**:
   * Accepts local socket connections from agent runtimes and components.
   * Performs transport-level authentication by inspecting kernel peer credentials (`SO_PEERCRED` or `SCM_CREDENTIALS`).
   * Verifies the caller's PID, UID, and GID against the active process registry.
   * Produces an authenticated `Principal` identity before any policy evaluation takes place.
2. **AgenticOS Policy Engine (Layer 8 - Security & Governance)**:
   * Consumes an already authenticated `Principal` and a typed `CapabilityInvocationRequest`.
   * Normalizes and validates input parameters (including path normalization).
   * Evaluates the request against the policy hierarchy (Mandatory System Policies, User Policies, Session Policies).
   * Emits a deterministic tripartite decision: `ALLOW`, `DENY`, or `CONFIRM`.
   * For `ALLOW` decisions, synthesizes concrete `SandboxConstraints` (Landlock masks, Bubblewrap bind mounts, seccomp-bpf profiles).
   * **Crucial Boundary**: The Policy Engine *does not* enforce isolation in the kernel, *does not* execute capability code, and *cannot* grant arbitrary root privileges, arbitrary shell execution, or unrestricted filesystem access.
3. **Capability Sandbox / Kernel (Layer 9 & Linux Kernel)**:
   * Enforces physical containment based on the constraints synthesized by the Policy Engine.
   * Applies Landlock path access rules, Bubblewrap mount namespaces, seccomp-bpf syscall whitelists, and cgroups v2 resource ceilings.
   * Traps unauthorized operations at the kernel level (`EACCES`, `EPERM`, `SIGSYS`).
4. **Human Confirmation Broker & System (Layer 8 Broker & Layer 1 UI)**:
   * **Layer 1 UI**: Renders an un-spoofable, out-of-band desktop prompt; captures human approval/rejection. The UI does *not* possess signing authority.
   * **Confirmation Broker (Layer 8)**: Validates the user action, verifies request context, and issues a cryptographically signed, short-lived, single-use `ApprovalToken`.

---

## Evaluated Candidate Approaches

1. **Option 1: Pure Cedar Engine (`cedar-policy`)**:
   Use AWS Cedar directly as the authorization engine. Cedar is a policy language and SDK written in Rust based on Policy-Based Access Control (PBAC). Cedar has a formally specified Lean model and proofs of relevant properties, together with differential randomized testing between the formalization and the production Rust implementation.
2. **Option 2: Open Policy Agent (OPA) / Rego**:
   Use Open Policy Agent's Rego language, either via an external Go daemon, compiled WebAssembly modules in a Wasm runtime (`wasmtime`), or an in-process Rust interpreter (`regorus`).
3. **Option 3: Native Deterministic Rust Policy Evaluator (Bespoke)**:
   Build a custom, zero-dependency policy evaluator in safe Rust within Layer 8, tailored directly to AgenticOS capability schemas with native tri-state `ALLOW / DENY / CONFIRM` logic.
4. **Option 4: Hybrid Architecture (Cedar PBAC Core + AgenticOS Security Wrapper & Confirmation Broker - Recommended)**:
   Embed AWS Cedar (`cedar-policy`) as the core deterministic PBAC evaluator grounded in its formal Lean model and differential testing, wrapped by a dedicated AgenticOS Security Governor in Rust that manages pre-evaluation path normalization, tri-state `ALLOW / DENY / CONFIRM` semantics, human confirmation workflows, policy hierarchy precedence, and sandbox constraint synthesis.

---

## Evaluation Comparison Matrix (35 Criteria)

| Evaluation Criterion | Option 1: Pure Cedar | Option 2: OPA / Rego | Option 3: Native Rust Evaluator | Option 4: Hybrid (Cedar + AgenticOS Wrapper) (Recommended) |
| :--- | :--- | :--- | :--- | :--- |
| **1. Deterministic Behavior** | **Provably Deterministic**: Non-Turing complete formal model; terminates without unbounded loops. | **Conditionally Deterministic**: Complex Datalog with recursion; queries can degrade or loop without guards. | **Deterministic**: Fixed-depth rule evaluation in native Rust. | **Provably Deterministic**: Core evaluation model is formally proved to terminate; wrapper logic is linear. |
| **2. Default-Deny Behavior** | **Native**: Requests deny unless explicitly matched by a `permit` policy. | **Configurable**: Requires explicit `default allow = false` boilerplate in Rego. | **Native**: Structured `match` defaults to `Deny` if no rules match. | **Native**: Core Cedar engine enforces default-deny; wrapper maintains fail-closed invariants. |
| **3. ALLOW / DENY / CONFIRM Support** | **Binary Only**: Cedar natively returns only `Allow` or `Deny`. Lacks native `Confirm`. | **Arbitrary Output**: Rego rules can return custom strings or JSON objects including `"CONFIRM"`. | **Native Tri-State**: Direct Rust `enum PolicyDecision { Allow, Deny, Confirm }`. | **First-Class Tri-State**: Cedar evaluates authorization; wrapper evaluates `@confirm` metadata and tokens. |
| **4. Principal / Action / Resource / Context** | **First-Class**: Core PBAC design built around `principal`, `action`, `resource`, `context`. | **Generic JSON**: Can model any JSON schema, but lacks specialized PBAC syntax constructs. | **Direct Structs**: Strongly typed Rust domain models. | **First-Class PBAC**: Direct mapping of AgenticOS entities to Cedar schemas with strict typing. |
| **5. Capability-Based Authorization** | **Native**: Actions correspond directly to typed capability IDs (`Action::"fs.read_file"`). | **Flexible**: Mapped via JSON input properties. | **Native**: Directly matches `CapabilityInvocationRequest`. | **Native**: Typed capability requests map directly to Cedar action hierarchies. |
| **6. Filesystem Path Policies** | **Hierarchical Entities**: Supports hierarchy (`in`), but requires explicit entity mapping and path normalization. | **String Manipulation**: Regex/string prefix checks; prone to symlink and path traversal bypasses. | **Native Path Handling**: Direct integration with `std::path::Path` and normalization. | **Robust Defense-in-Depth**: Wrapper normalizes paths; Cedar enforces scopes; kernel sandbox enforces containment. |
| **7. Application Permissions** | **Expressive**: Entity attributes model desktop application identities, desktop files, and AppIDs. | **Supported**: Generic JSON attribute matching. | **Supported**: Custom struct matching. | **Expressive & Auditable**: Typed application entity definitions validated against schema. |
| **8. Network Permissions** | **Extension-Aided**: Cedar provides native `ip()` extension functions for CIDR and address matching. | **Supported**: Built-in CIDR and IP functions. | **Manual**: Requires custom IP parsing and subnet matching logic. | **Robust**: Built-in Cedar `ip()` network types for host, subnet, and port matching. |
| **9. Resource Limits** | **Context-Based**: Can evaluate context limits (e.g. payload size), but delegates enforcement to sandbox. | **Context-Based**: Evaluates context rules. | **Context-Based**: Custom conditions. | **Dual-Tier**: Policy engine validates limits in context; sandbox enforces cgroups ceilings. |
| **10. Human Confirmation Workflows** | **None**: No built-in mechanism for human-in-the-loop workflows. | **Indirect**: Outputs a string requiring external handling. | **Bespoke**: Custom state machine for confirmation challenges. | **Integrated Broker**: Wrapper evaluates `@confirm` metadata, issues challenge, validates signed tokens. |
| **11. Policy Composition** | **Modular**: Policies compose cleanly into policy sets; permit and forbid policies combine safely. | **Package-Based**: Rego packages compose, but order of evaluation can become opaque. | **Sequential**: Custom rule lists or tree structures. | **Modular & Rigorous**: Safe composition guaranteed by Cedar's evaluation algebra. |
| **12. Policy Conflicts** | **Deterministically Defined**: Strict forbid-overrides; any matching `forbid` overrides any `permit`. | **Rule Conflicts**: Conflicting assignments in Rego cause runtime evaluation errors unless guarded. | **Explicit Code**: Precedence implemented manually in match arms. | **Hierarchy-Aware Precedence**: Mandatory system `forbid` overrides all user and session policies. |
| **13. Policy Precedence** | **Deterministic**: Forbid overrides permit; no ambiguous rule ordering dependencies. | **Rule-Order Dependent**: Can depend on rule order and negation logic. | **Explicit**: Manual precedence logic in Rust code. | **Deterministic**: Unambiguous precedence grounded in the formal specification and policy hierarchy. |
| **14. Schema Validation** | **Strict (`cedarschema`)**: Validates entity types, attributes, actions, and contexts at load time. | **Optional**: JSON schema validation possible but external to Rego engine. | **Compile-Time**: Rust type system validates internal structs; custom schema for external files. | **Strict & Declarative**: Cedar schemas validate policies at load time, rejecting malformed policies. |
| **15. Static Policy Analysis** | **Advanced**: Built-in validator detects unsatisfiable conditions, unrecognized entities, and type errors. | **Linters**: External tools (`regal`, `opa check`) provide linting, but lack formal typing proofs. | **Custom**: Requires building a custom static analyzer from scratch. | **Advanced**: Cedar validator runs static analysis prior to activating policy snapshots. |
| **16. Formal Verification** | **Formally Modeled**: Cedar has a formally specified Lean model and proofs of relevant properties. | **None**: No formal mathematical specification or machine-checked correctness proofs. | **None**: Empirical unit tests and fuzzing only. | **Formally Modeled Core**: Cedar has a formally specified Lean model and proofs of properties; wrapper tested with property suites. |
| **17. Testability** | **High**: Unit testing via Cedar CLI, Rust SDK test harnesses, and integration tests. | **High**: OPA provides built-in `opa test` runner for Rego policies. | **High**: Standard `cargo test` harnesses. | **High**: Cedar policy unit tests combined with Rust wrapper end-to-end integration tests. |
| **18. Fuzzability** | **Extensive**: Fuzzed continuously upstream via `cargo-fuzz` and differential testing against Lean model. | **Moderate**: Fuzz testing of Go runtime; less accessible for embedded Rust contexts. | **Custom**: Requires building bespoke fuzz harnesses for the custom evaluator. | **Extensive**: Inherits Cedar's fuzz-tested core; wrapper fuzzed with `cargo-fuzz`. |
| **19. Auditability** | **Structured**: Diagnostics return exact policy IDs contributing to permit or forbid decisions. | **Trace Logs**: OPA produces execution traces, which can be verbose and complex to parse. | **Custom**: Manual event logging. | **Structured & Traceable**: Every decision logs exact Cedar policy IDs, inputs, and cryptographic tokens. |
| **20. Explainability** | **Clear**: Native diagnostic reasons list precisely which policies authorized or blocked an action. | **Variable**: Requires authoring explicit explanation strings in Rego rules. | **Custom**: Manual explanation synthesis. | **Deterministic Explanations**: Clear human-readable reasons generated from policy IDs and metadata. |
| **21. Policy Versioning** | **Artifact-Based**: Policy sets can be versioned, hashed, and cryptographically signed. | **Bundle-Based**: OPA bundles support versioning and signing. | **Custom**: Manual file version tracking. | **Content-Addressed**: Policy files stored with SHA-256 hashes and semantic version tags. |
| **22. Policy Rollback** | **Fast**: In-memory policy sets can be swapped back to previous known-good snapshots. | **Supported**: OPA bundle activation supports rollback. | **Manual**: Manual state reversion. | **Atomic & Safe**: Atomic pointer swap allows immediate reversion to previous immutable policy snapshot. |
| **23. Hot Reload vs Snapshots** | **Immutable Snapshots**: Pre-validates new policy set; swaps pointer atomically without downtime. | **Dynamic Reload**: OPA reloads bundles dynamically. | **Custom**: Requires custom lock/swap mechanism. | **Atomic Snapshot Swap**: `ArcSwap` provides thread-safe, lock-free policy updates with pre-validation. |
| **24. Failure Behavior** | **Fail-Closed**: Any internal evaluation error results in `Decision::Deny`. | **Configurable**: Undefined results can be configured, but errors require careful handling. | **Explicit**: Errors must be explicitly handled. | **Fail-Closed**: Any evaluation anomaly, missing entity, or validation error defaults strictly to `DENY`. |
| **25. Fail-Closed Invariants** | **Strict**: Designed from inception for zero-trust authorization. | **Variable**: Depends on author correctly specifying default rules. | **High**: Dependent on manual implementation rigor. | **Strict**: Dual-layer fail-closed: Cedar core denies by default; wrapper denies on any unexpected state. |
| **26. Performance Overhead** | **Low Overhead**: Low-latency in-memory evaluation in pure compiled Rust. | **High Overhead**: Interpreted Rego or Wasm execution incurs substantial context-switching latency. | **Lowest**: Direct Rust match statements. | **Low Overhead**: Fast in-memory evaluation with no interpreter or VM overhead. |
| **27. Memory Footprint** | **Compact**: In-memory AST and entity store; no garbage collector, no virtual machine. | **Heavy**: Go runtime or Wasm engine (`wasmtime`) requires substantial baseline memory. | **Minimal**: Lightweight Rust structs. | **Compact**: In-memory representation without external runtimes or background daemons. |
| **28. Embedding Inside Rust** | **Native**: First-class Rust crate (`cedar-policy`); clean idiomatic API. | **Poor**: Requires Go sidecar, FFI, Wasm engine, or unverified community interpreter. | **Native**: Written directly in the AgenticOS codebase. | **Native**: Direct in-tree Rust integration with zero FFI or sub-process overhead. |
| **29. Local-Only Operation** | **100% Local**: Fully standalone library; no network connectivity required or attempted. | **Cloud-Centric**: Designed for network-based bundle distribution and remote management. | **100% Local**: Fully offline. | **100% Local**: Completely offline; policy files read exclusively from local trusted storage. |
| **30. Offline Operation** | **Complete**: Zero external telemetry, licensing servers, or remote dependencies. | **Complete**: Can run offline if configured without remote bundle servers. | **Complete**: Completely offline. | **Complete**: Zero remote dependencies; runs on air-gapped systems. |
| **31. Dependency Footprint** | **Audited Crate**: Crate managed via `Cargo.lock` with audited dependency tree. | **Large**: Heavy dependency tree (Go runtime, Wasm compiler, or Wasmtime runtime). | **Zero**: No external policy crates. | **Focused**: Single well-maintained core crate (`cedar-policy`) plus AgenticOS domain logic. |
| **32. Supply-Chain Risk** | **Low**: Backed by AWS open source, security-reviewed, permissive Apache-2.0 license. | **Moderate**: Large Go or Wasm ecosystem dependency chain. | **Lowest**: In-tree code only, but higher risk of internal implementation bugs. | **Low**: High-assurance external core combined with auditable, minimal internal wrapper. |
| **33. Packaging for Ubuntu** | **Native ELF**: Compiles directly into the AgenticOS supervisor binary; packaged in standard `.deb`. | **Complex**: Requires packaging Wasm bundles or auxiliary Go daemons. | **Native ELF**: Compiles into core binary. | **Native ELF**: Single self-contained binary; policies packaged as standard configuration files. |
| **34. Long-Term Maintenance** | **High**: Backed by formal methods community and industry standard adoption. | **High**: Broad community, but cloud-focused trajectory diverges from desktop OS needs. | **High Burden**: Requires maintaining a bespoke authorization engine, parser, and grammar indefinitely. | **Optimal**: Outsources formal logic and parsing to Cedar; maintains only OS-specific wrapper logic. |
| **35. Evolutionary Growth** | **High**: Supports hierarchical roles, multi-agent delegation, and attribute-based access control. | **High**: Extremely expressive, but complex to maintain securely at scale. | **Limited**: Every new authorization feature requires custom language extensions and manual coding. | **High**: Effortlessly scales to multi-agent swarms, cross-agent delegation, and fine-grained resource tags. |

---

## Detailed Evaluation of External Projects

### 1. AWS Cedar (`cedar-policy`)
* **Repository**: `https://github.com/cedar-policy/cedar`
* **License**: Apache-2.0 (Permissive, compatible with AgenticOS architecture)
* **Maintenance & Activity**: Actively maintained by AWS Identity, Automated Reasoning Group, and an open-source community. Frequent releases, active issue triage, comprehensive documentation.
* **Security Considerations**: Cedar has a formally specified Lean model and proofs of relevant properties, together with differential randomized testing between the formalization and the production Rust implementation (`cedar-policy/cedar-spec`). Provably terminates (non-Turing complete, no loops, no recursion).
* **Exact Relevance to AgenticOS**: Serves as the embedded deterministic Policy-Based Access Control (PBAC) evaluation engine for Layer 8 (`Security & Governance`).
* **Runtime Dependency Status**: Compiles directly into the AgenticOS supervisor binary as an in-process Rust crate (`cedar-policy`). It does *not* introduce any external daemon, background service, or network listener.

### 2. Open Policy Agent (OPA)
* **Repository**: `https://github.com/open-policy-agent/opa`
* **License**: Apache-2.0
* **Maintenance & Activity**: CNCF Graduated project, highly active, primary backing by Styra.
* **Security Considerations**: Well-audited for cloud microservice authorization and Kubernetes admission control. However, Rego's expressive Datalog-derived language allows complex queries, potential resource exhaustion without external limits, and lacks machine-checked formal verification.
* **Exact Relevance to AgenticOS**: Evaluated as an alternative declarative policy engine.
* **Runtime Dependency Status**: Excluded from runtime. Running OPA requires either a separate Go daemon (violating ADR-0004) or embedding a WebAssembly runtime (`wasmtime`), adding substantial memory overhead and attack surface.

### 3. Microsoft Regorus (`regorus`)
* **Repository**: `https://github.com/microsoft/regorus`
* **License**: MIT
* **Maintenance & Activity**: Actively maintained by Microsoft for confidential containers and confidential computing.
* **Security Considerations**: Implemented in safe Rust. While it eliminates the Go/Wasm runtime overhead, Rego remains a non-formally-verified, general-purpose logic language without built-in PBAC schemas or automated reasoning.
* **Exact Relevance to AgenticOS**: Evaluated as a potential in-process Rust Rego interpreter.
* **Runtime Dependency Status**: Excluded. Adding a full Rego interpreter is unjustified when Cedar provides a specialized PBAC model in native Rust grounded in a formal specification.

### 4. Lean 4 Formal Specification (`cedar-policy/cedar-spec`)
* **Repository**: `https://github.com/cedar-policy/cedar-spec`
* **License**: Apache-2.0
* **Maintenance & Activity**: Active formal verification project maintained alongside Cedar.
* **Security Considerations**: Cedar has a formally specified Lean model and proofs of relevant properties, together with differential randomized testing between the formalization and the production Rust implementation. It provides proofs of properties for the formal model and serves as the oracle for differential testing against the Rust implementation.
* **Exact Relevance to AgenticOS**: Serves as the theoretical and architectural foundation ensuring that the AgenticOS authorization engine core is grounded in rigorous mathematical specification.
* **Runtime Dependency Status**: None. This is a design-time verification artifact, not a runtime component.

---

## Detailed Architectural Analyses

### 1. Security Analysis
* **Formal Invariants**: Safe authorization requires strict, deterministic guarantees that a request cannot be approved by ambiguity. Cedar's design and formal model establish key invariants:
  1. **Strict Default-Deny**: A request is denied unless an explicit `permit` rule matches.
  2. **Strict Forbid-Overrides**: If a single `forbid` rule matches, the outcome is `DENY`, regardless of how many `permit` rules match.
  3. **Guaranteed Termination**: Cedar policies cannot recurse or loop. Evaluation is guaranteed to finish in bounded execution steps.
* **Input Normalization vs. Containment Boundary (Path Security)**:
  * Path canonicalization (`std::fs::canonicalize` / `realpath`) is an **input normalization and validation step**, *not* the final filesystem security boundary. Normalization prevents trivial relative path tricks (`../`) from obfuscating target resources during policy evaluation.
  * The actual filesystem containment boundary is strictly enforced at the kernel level:
    $$\text{Filesystem Security} = \text{Policy Authorization} + \text{Bubblewrap Mount Namespaces} + \text{Landlock LSM Inode Restrictions} + \text{Race-Resistant Path Handling}$$
  * Where applicable, race-resistant Linux pathname resolution (e.g. `openat2` with `RESOLVE_BENEATH` and `O_NOFOLLOW`) is employed to mitigate Time-of-Check to Time-of-Use (TOCTOU) symlink races.
* **Transport Authentication Boundary**:
  * Peer authentication occurs at the **UDS transport ingress** before reaching the Policy Engine:
    $$\text{UDS Ingress} \longrightarrow \text{Peer Authentication (`SO_PEERCRED`)} \longrightarrow \text{Authenticated Principal} \longrightarrow \text{Policy Engine}$$
  * The Policy Engine consumes an already authenticated `Principal` identity. It is not responsible for low-level socket credential inspection.
* **Containment Independence**: The policy engine decides authorization, but *never* performs execution. If the policy engine returns `ALLOW`, the capability executes inside a restricted Bubblewrap container with Landlock LSM and seccomp-bpf filters applied before capability code runs.

---

## Analysis of the Tri-State Decision Model: ALLOW / DENY / CONFIRM

### 1. Decision States
* **Cedar Core Natively Returns**:
  * `Allow`
  * `Deny`
* **AgenticOS Security Architecture Requires**:
  * `ALLOW`: Autonomous capability execution permitted under synthesized sandbox constraints.
  * `DENY`: Execution strictly forbidden; diagnostic reason logged and returned to caller.
  * `CONFIRM`: Execution suspended; out-of-band human confirmation required.

### 2. Role of Cedar Annotations and Wrapper Responsibility
Cedar annotations (such as `@confirm("true")`) are **metadata only**. Cedar's authorization engine does *not* interpret, parse, or enforce annotations during `is_authorized()` evaluation.

The **AgenticOS Security Wrapper** is solely responsible for:
1. Parsing and validating `@confirm` metadata on policies.
2. Detecting when a matched `permit` policy mandates human confirmation.
3. Checking for the presence of a cryptographically valid, unexpired `ApprovalToken`.
4. Emitting a `CONFIRM` challenge when a valid token is absent.
5. Emitting an `ALLOW` decision with synthesized `SandboxConstraints` when a valid token is verified.
6. Maintaining dedicated unit and property test suites to ensure the wrapper's confirmation semantics cannot be bypassed.

```
                  ┌────────────────────────────────────────┐
                  │       CapabilityInvocationRequest      │
                  └───────────────────┬────────────────────┘
                                      │
                                      ▼
                         [Authenticated Principal  ]
                         [Path Input Normalization ]
                                      │
                                      ▼
                  ┌────────────────────────────────────────┐
                  │       Cedar Core PBAC Evaluation       │
                  │       (`cedar_policy::is_authorized`)  │
                  └───────────────────┬────────────────────┘
                                      │
                   ┌──────────────────┴──────────────────┐
                   │                                     │
           Decision == Deny                      Decision == Allow
                   │                                     │
                   ▼                                     ▼
        ┌─────────────────────┐               [Inspect Determining Policies]
        │   Outcome: DENY     │               [for `@confirm` Annotations  ]
        │(Record diagnostics) │                          │
        └─────────────────────┘               ┌──────────┴──────────┐
                                              │                     │
                                     `@confirm` Present     No `@confirm` Annotation
                                     & No Valid Token       (Or Valid Token Present)
                                              │                     │
                                              ▼                     ▼
                                   ┌─────────────────────┐┌─────────────────────┐
                                   │   Outcome: CONFIRM  ││   Outcome: ALLOW    │
                                   │ (Issue UI Challenge)││(Generate Constraints│
                                   └─────────────────────┘└─────────────────────┘
```

---

## Policy Hierarchy, Precedence, and Conflict Resolution

AgenticOS establishes an explicit, four-tier policy hierarchy evaluated in order of trust:

```
┌────────────────────────────────────────────────────────┐
│ 1. Mandatory System Policy (/etc/agenticos/policies/)  │
├────────────────────────────────────────────────────────┤
│ 2. Non-Overridable Security DENY Rules                 │
├────────────────────────────────────────────────────────┤
│ 3. User Policy (~/.config/agenticos/policies/)         │
├────────────────────────────────────────────────────────┤
│ 4. Session / Context Policy (Ephemeral per Workflow)   │
└────────────────────────────────────────────────────────┘
```

### Hierarchy Tiers
1. **Mandatory System Policy**: Defines inviolable safety guardrails for the host operating system (e.g. blocking modification of `/etc`, `/boot`, `/sys`, raw block devices, and kernel parameters). Stored in root-owned `/etc/agenticos/policies/system/`.
2. **Non-Overridable Security DENY Rules**: Explicit `forbid` rules defined at the system level. A lower-trust user, workflow, or session policy must **NEVER** weaken, override, or bypass a mandatory system `forbid`.
3. **User Policy**: Configured by the human user to govern everyday agent permissions (e.g., scoping workspace paths, establishing which directories require confirmation). Cannot override system `forbid` rules.
4. **Session / Context Policy**: Ephemeral policies scoped to a single workflow, goal, or interactive session. Can restrict permissions further (least privilege), but cannot expand permissions beyond what system and user policies allow.

### Conflict Resolution and Precedence Rules
1. **System Forbid Precedence**: Any matching `forbid` in Mandatory System Policy immediately yields `DENY`. No user policy, session policy, or human confirmation can override this.
2. **User Forbid Precedence**: Any matching `forbid` in User Policy yields `DENY`, unless already denied by system policy.
3. **Confirmation Precedence**: If a request is permitted by a policy set, but at least *one* contributing permit policy carries a `@confirm` annotation, the request requires confirmation. An autonomous allow rule from a lower-trust tier cannot waive a higher-tier confirmation requirement.
4. **Strict Default-Deny**: If no policy explicitly permits the action across all evaluated tiers, the outcome is `DENY`.

---

## Human Confirmation Broker & Approval Token Architecture

### Separation of Presentation from Signing Authority
The Human UI (Layer 1 desktop dialog or CLI modal) is an **untrusted presentation layer**. It does **NOT** own or access the trusted cryptographic signing key.

The trusted workflow proceeds strictly as follows:
```
User action in UI (Approval click)
   │
   ▼
Confirmation Broker (Layer 8 Trusted Supervisor)
   │ (Validates exact request context & active policy version)
   ▼
Issues Cryptographically Signed ApprovalToken
   │ (Single-use, short-lived, request-bound)
   ▼
Policy Engine Re-evaluation -> ALLOW
```

### ApprovalToken Binding Structure
The Confirmation Broker generates an `ApprovalToken` strictly bound to the execution context:
```rust
pub struct ApprovalToken {
    pub single_use_id: Uuid,           // Unique token identifier tracked in replay cache
    pub request_hash: [u8; 32],        // SHA-256 hash of normalized CapabilityInvocationRequest
    pub policy_snapshot_hash: [u8; 32],// Hash of active policy bundle when prompt was shown
    pub principal: String,             // Authenticated caller (e.g. Agent::"cleanup_agent")
    pub capability: String,            // Capability ID (e.g. "fs.delete_tree")
    pub resource: String,              // Canonical resource target
    pub confirmation_reason: String,   // Exact reason presented to the user
    pub issued_at: u64,                // Unix timestamp (seconds)
    pub expires_at: u64,               // Unix timestamp (short TTL, max 60s)
    pub nonce: [u8; 16],               // Cryptographic random nonce
    pub signature: Vec<u8>,            // Ed25519 signature from Confirmation Broker key
}
```

### Replay and Tampering Protections
* **Single-Use Cache**: When an `ApprovalToken` is redeemed, its `single_use_id` is recorded in an in-memory ephemeral cache. Any subsequent presentation of the same token is rejected immediately.
* **Hash Mismatch**: If any argument of the capability invocation request changes between confirmation and execution, the `request_hash` will not match, and the token is rejected.
* **Snapshot Invalidation**: If policies are reloaded while a confirmation prompt is pending, the `policy_snapshot_hash` will mismatch, forcing re-evaluation under the new policies.
* **Expiry**: Tokens expire after a short time window (e.g. 60 seconds). Expired tokens cannot be redeemed.

---

## Policy Model Proposal

### Entity and Schema Model
The AgenticOS schema defines strictly typed entities:
* **`Principal`**: The actor initiating the request:
  * `Agent::"researcher_agent"`
  * `User::"lokamanya"`
  * `Workflow::"code_refactor_wf"`
  * `CapabilityWorker::"worker_pid_1234"`
* **`Action`**: The typed capability identifier:
  * `Action::"fs.read_file"`
  * `Action::"fs.write_file"`
  * `Action::"fs.create_directory"`
  * `Action::"fs.delete"`
  * `Action::"application.open"`
  * `Action::"network.request"`
* **`Resource`**: The target system object:
  * `Path::"/home/lokamanya/workspace"`
  * `Application::"org.mozilla.firefox"`
  * `NetworkEndpoint::"127.0.0.1:11434"`
  * `DBusInterface::"org.freedesktop.Notifications"`
* **`Context`**: Request-specific metadata:
  * `goal_id`: String
  * `step_id`: String
  * `read_only`: Boolean
  * `is_interactive`: Boolean
  * `destination_port`: Long

---

## Policy Examples

> [!NOTE]
> **Conceptual Syntax**: The path-based policy examples below are conceptual representations of policy rules. In Cedar, string path values do not automatically create an entity hierarchy; the exact entity schema, hierarchical parent-child entity definitions (e.g. `PathEntity` with `parent` links or Cedar custom extension types), and context types will be formally defined in the Phase 0.3.5 specification.

### 1. `fs.read_file` (Autonomous Read within Workspace)
Allows agents in the `researcher` group to read files within the designated workspace directory without human confirmation:
```cedar
// Conceptual Policy: Allow autonomous reading within the project workspace
@id("policy-fs-read-workspace")
@description("Permit agents to read files inside the active workspace")
permit (
    principal in AgentGroup::"researcher",
    action == Action::"fs.read_file",
    resource in Path::"/home/lokamanya/AI Agentic OS"
) when {
    context.read_only == true
};
```

### 2. `fs.create_directory` (Autonomous Directory Creation in Scratch Area)
Allows workflows to create scratch directories inside the conversation workspace:
```cedar
// Conceptual Policy: Allow directory creation in designated scratch areas
@id("policy-fs-mkdir-scratch")
@description("Permit creation of scratch directories for workflows")
permit (
    principal in AgentGroup::"developer",
    action == Action::"fs.create_directory",
    resource in Path::"/home/lokamanya/.gemini/antigravity/scratch"
);
```

### 3. `fs.delete` (Deletion with Mandatory Confirmation)
Deletions within user directories are permitted *only* with explicit human confirmation. Deletions outside permitted paths are forbidden:
```cedar
// Conceptual Policy: Require confirmation for deleting files in downloads or workspace
@id("policy-fs-delete-user-files")
@confirm("true")
@confirm_prompt("The agent requested deletion of {resource}. Allow deletion?")
@blast_radius("file_system_modification")
permit (
    principal in AgentGroup::"developer",
    action == Action::"fs.delete",
    resource in Path::"/home/lokamanya/AI Agentic OS"
);

// Conceptual Policy: Strictly forbid deleting system configuration or root files
@id("policy-fs-forbid-system-delete")
forbid (
    principal,
    action == Action::"fs.delete",
    resource in Path::"/etc"
);
```

### 4. `application.open` (Launching Desktop Applications)
Allows agents to open approved desktop applications via FreeDesktop app IDs:
```cedar
// Conceptual Policy: Permit opening registered browser or editor
@id("policy-app-open-whitelisted")
permit (
    principal in AgentGroup::"assistant",
    action == Action::"application.open",
    resource in ApplicationGroup::"approved_browsers"
);
```

### 5. `network.request` (Restricted Local AI Endpoint Access)
Allows outbound HTTP requests *only* to local neural runtime ports (e.g. Ollama on `127.0.0.1:11434`), forbidding external internet traffic unless explicitly granted:
```cedar
// Conceptual Policy: Permit local AI inference connections
@id("policy-network-local-inference")
permit (
    principal in AgentGroup::"worker",
    action == Action::"network.request",
    resource in NetworkEndpoint::"localhost"
) when {
    context.destination_port == 11434
};

// Conceptual Policy: Strictly forbid direct outbound connections to external networks
@id("policy-network-forbid-external")
forbid (
    principal in AgentGroup::"worker",
    action == Action::"network.request",
    resource
) when {
    context.destination_port != 11434
};
```

---

## Sensitive Operation Example Requiring CONFIRM

### Scenario: Deleting Workspace Subdirectory Tree
When an agent attempts a high-impact operation (such as recursively deleting a workspace subdirectory):

1. **Conceptual Cedar Policy**:
```cedar
@id("policy-sensitive-workspace-clean")
@confirm("true")
@confirm_prompt("Agent requested recursive deletion of directory tree at {resource}. Confirm action?")
@blast_radius("destructive_filesystem")
permit (
    principal == Agent::"code_cleanup_agent",
    action == Action::"fs.delete_tree",
    resource in Path::"/home/lokamanya/AI Agentic OS/scratch"
);
```
2. **Evaluation Trace**:
   * Request arrives at UDS ingress; transport credentials verify caller as PID 48210 (`code_cleanup_agent`).
   * Pre-processor normalizes path to verified local inode: `/home/lokamanya/AI Agentic OS/scratch/old_run`.
   * Cedar `is_authorized()` evaluates to `Decision::Allow` under `policy-sensitive-workspace-clean`.
   * Wrapper detects `@confirm("true")` and no valid `ApprovalToken`.
   * Outcome: **`CONFIRM`**.
3. **User Confirmation Interaction**:
   * Confirmation Broker emits challenge to Layer 1 Desktop UI.
   * User sees:
     ```
     [AI Agentic OS - Security Confirmation Required]
     Agent:        code_cleanup_agent
     Goal:         Workspace Cleanup
     Action:       fs.delete_tree
     Target Path:  /home/lokamanya/AI Agentic OS/scratch/old_run
     Blast Radius: High (Permanent filesystem deletion)
     
     [ Approve Once ]   [ Deny Action ]
     ```
   * If User clicks **Deny**: Supervisor records rejection in Layer 12 audit log and returns `PermissionDenied` to agent.
   * If User clicks **Approve Once**: Confirmation Broker validates request context and issues a cryptographically signed `ApprovalToken`.
   * Request re-enters Policy Engine with the token.
   * Wrapper validates signature, non-expiry, and single-use status of the token.
   * Outcome: **`ALLOW`**.
   * Layer 9 spawns a dedicated worker inside a Bubblewrap container with Landlock write access limited strictly to `/home/lokamanya/AI Agentic OS/scratch/old_run`.

---

## Policy Lifecycle: Versioning, Rollback, and Failure Semantics

### 1. Storage and Versioning
* Policies are stored as plain text Cedar files in a versioned local directory: `/etc/agenticos/policies/` (system default) and `~/.config/agenticos/policies/` (user overlays).
* Every active policy set is content-addressed by its SHA-256 hash and tagged with semantic versions (`policies.v1.0.0.cedar`).
* A manifest file (`policies.manifest.json`) defines policy set activation order and schema bindings.

### 2. Hot Reload via Atomic Snapshot Swapping
* The supervisor holds the active policy bundle inside an `ArcSwap<PolicyBundle>`:
```rust
pub struct PolicyBundle {
    pub version: String,
    pub hash: [u8; 32],
    pub authorizer: cedar_policy::Authorizer,
    pub policy_set: cedar_policy::PolicySet,
    pub schema: cedar_policy::Schema,
}
```
* **Hot Reload Workflow**:
  1. A reload trigger is received (file watcher or SIGHUP or IPC admin command).
  2. The candidate policy set is parsed and checked against the schema using Cedar's static `Validator`.
  3. Static analysis checks for syntax errors, unsatisfiable rules, and schema violations.
  4. If validation passes, the new `PolicyBundle` is constructed and atomically swapped into memory using `ArcSwap::store()`.
  5. If validation fails, the candidate set is rejected, an alert is logged to Layer 12, and the existing policy snapshot remains active without interruption.

### 3. Rollback Semantics
* Previous policy versions are retained in local storage.
* An administrator or user can issue an immediate rollback via CLI (`agentic-admin policy rollback --version v1.0.0`).
* The supervisor loads the archived version, validates its integrity hash, and executes an atomic memory swap.

### 4. Failure and Timeout Semantics
* **Fail-Closed on All Errors**: If any step in the evaluation pipeline encounters an unexpected state—such as a missing entity definition, malformed parameter, unresolvable symlink, or parser failure—the engine *strictly* yields **`DENY`**.
* **Bounded Execution Time**: Because Cedar's language is provably non-Turing complete and free of loops, evaluation completes within bounded execution steps. To protect against edge-case starvation, the evaluator executes within a bounded timeout guard. If the guard expires, the evaluation terminates immediately and returns **`DENY`**.

---

## Audit and Explanation Model

Every policy evaluation emits an append-only, tamper-evident audit record to Layer 12 (`Observability & Reliability`):

```json
{
  "event_type": "policy_evaluation",
  "timestamp": "2026-09-27T14:38:00Z",
  "request_id": "req-98f2-4bc1",
  "caller": {
    "pid": 48210,
    "uid": 1000,
    "socket_inode": 394812,
    "verified_peer": true
  },
  "principal": "Agent::\"researcher\"",
  "action": "Action::\"fs.read_file\"",
  "resource": "Path::\"/home/lokamanya/AI Agentic OS/README.md\"",
  "context": {
    "goal_id": "goal-01",
    "step_id": "step-04",
    "read_only": true
  },
  "decision": "ALLOW",
  "contributing_policies": [
    "policy-fs-read-workspace"
  ],
  "confirmation_required": false,
  "approval_token_id": null
}
```

### Explanation Synthesis
When an agent or user requests an explanation for a decision:
* **For `DENY`**: The engine returns the contributing `forbid` policy ID or reports `DefaultDenyNoMatchingPermit`. The user receives:
  `"Action 'fs.delete' on '/etc/hosts' was DENIED by policy 'policy-fs-forbid-system-delete'."`
* **For `CONFIRM`**: The engine returns the `@confirm_prompt` and blast radius metadata to render the desktop dialog.

---

## Recommendation

We adopt **Option 4: Hybrid Architecture (Cedar PBAC Core + AgenticOS Security Wrapper & Confirmation Broker)**.

### Architectural Rationale
1. **Grounded in Formal Specification**: Cedar has a formally specified Lean model and proofs of relevant properties, together with differential randomized testing between the formalization and the production Rust implementation. This provides strong assurance while avoiding the severe security risks of writing custom authorization semantics or AST interpreters from scratch.
2. **First-Class Rust Integration**: Cedar is written in safe Rust. It embeds directly as a Cargo crate into the AgenticOS supervisor binary, maintaining our single-binary architecture with zero external daemons, zero Go runtimes, and zero WebAssembly layers.
3. **Clean Tri-State Resolution**: The AgenticOS Security Wrapper elegantly bridges Cedar's formal binary `Allow`/`Deny` output into AgenticOS's required tri-state `ALLOW / DENY / CONFIRM` model using policy annotations and an out-of-band confirmation broker.
4. **Strict Separation from Sandbox Enforcement**: The Policy Engine handles userspace intent authorization; the Hybrid Sandbox (Bubblewrap, Landlock, seccomp) enforces physical isolation in the Linux kernel. No policy result can bypass kernel containment.

---

## Risks and Mitigations

| Identified Risk | Severity | Mitigation Strategy |
| :--- | :--- | :--- |
| **Path Traversal / Symlink Bypasses** | High | AgenticOS pre-processor normalizes paths; Bubblewrap mount namespaces hide un-bound paths; Landlock enforces inode access; race-resistant kernel pathname resolution (`openat2`) prevents TOCTOU races. |
| **Confirmation Fatigue** | Medium | Calibrate policies so low-risk, read-only, and workspace-scoped actions execute autonomously; restrict `CONFIRM` strictly to high-impact actions (deletions, network calls, external app launches). |
| **Upstream Cedar Crate Drift** | Low | Pin exact `cedar-policy` versions in `Cargo.lock`; run continuous integration tests against pinned schemas and policies. |
| **Stale In-Memory Policies** | Low | Implement pre-validated atomic snapshot swapping (`ArcSwap`); verify checksums before swapping; reject invalid updates automatically. |

---

## Consequences

### Positive
* **High Assurance**: Policy decisions are deterministic, fail-closed, and grounded in Cedar's formally specified PBAC model with differential testing.
* **In-Process Evaluation**: Policy evaluation runs in-process in the trusted supervisor and does not require a separate policy daemon.
* **Robust Human Oversight**: High-risk actions cannot execute autonomously; confirmation prompts are tamper-evident and out-of-band.
* **Maintainable & Extensible**: Adding new capabilities or agents requires adding declarative Cedar policies rather than modifying Rust code.

### Negative / Trade-offs
* **Dependency Footprint**: Incorporates the `cedar-policy` crate into the Layer 8 compilation pipeline.
* **Schema Maintenance**: Requires maintaining a formal `cedarschema` reflecting AgenticOS capability actions and entity types.

---

## Open Questions and Deferred Items (Phase 0.3.5+ TBD)

The following items are deferred to the detailed design and implementation phases:

1. **System vs. User Policy Shadowing Rules**: Formalize exact scoping rules for cases where a user policy attempts to define a `permit` that partially overlaps with a system `forbid` path, ensuring that system deny rules unconditionally dominate without ambiguity.
2. **Policy Administration Permissions**: Define which administrative roles or desktop groups (`root`, `wheel`, or a dedicated `agentic-admin` group) have write permissions to `/etc/agenticos/policies/system/`.
3. **Approval-Token Cryptographic Trust Model**: Determine the exact cryptographic signing algorithm (e.g. Ed25519 vs HMAC-SHA256) and key rotation/storage mechanism for the Confirmation Broker in Layer 8.
4. **Exact Path / Resource Entity Representation**: Define the formal Cedar schema representation for Linux paths (e.g., entity hierarchy with `parent` relations vs Cedar custom extension types) to ensure path matching is robust and avoids string prefix ambiguities.
5. **Handling Malformed Wrapper Metadata**: Define strict schema validation rules for policy annotations (e.g. `@confirm`, `@blast_radius`), ensuring that malformed or unrecognized annotations fail closed to `DENY` rather than defaulting to autonomous execution.
6. **Policy-Store Ownership and Update Permissions**: Specify file permissions, directory ACLs, atomic file swap mechanics, and audit event emission for filesystem-level policy updates on the host OS.
