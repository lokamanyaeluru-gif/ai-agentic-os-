# AI Agentic OS: Security & Governance Specification

> **Phase 0.2: Security Model & Policy Architecture**  
> *Status: Foundational Design / Non-Executable Specification*  
> *Environment: Local Linux / Ubuntu*

---

## 1. Core Security Philosophy

In AI Agentic OS, **security is a non-negotiable, first-class requirement**. 

The fundamental postulate of the system is:
> **The Large Language Model (LLM) or autonomous neural agent must NEVER be the final authorization authority.**

Neural models are probabilistic, nondeterministic, and fundamentally susceptible to prompt injection, jailbreaking, and hallucination. Consequently:
1. An agent or model may only formulate a **Request** for action.
2. A deterministic, formally verified **Policy & Permission Engine** evaluates the request.
3. Every operation must resolve to an explicit authorization outcome: `ALLOW`, `DENY`, or `CONFIRM`.

```
                    +------------------------+
                    |      Neural Agent      |
                    +------------------------+
                                |
                                | Emits: CapabilityInvocationRequest
                                v
               +----------------------------------+
               |   Policy & Permission Engine     |
               | (Deterministic, Non-Neural,      |
               |  Declarative Policy Evaluation)  |
               +----------------------------------+
                     /          |          \
                    /           |           \
             [ALLOW]         [DENY]       [CONFIRM]
                |               |              |
                v               v              v
     +-----------------+  +------------+  +------------------------+
     | Execute inside  |  | Abort with |  | Suspend execution;     |
     | Isolated        |  | Structured |  | Render interactive UI   |
     | Sandbox Runner  |  | Error      |  | for explicit human sign|
     +-----------------+  +------------+  +------------------------+
```

---

## 2. Prohibited vs. Required Architectural Patterns

### Prohibited Pattern: Direct Shell Invocation
```
[LLM] ---> [Unrestricted Shell (bash -c / sh)] ---> [sudo / root] ---> [Linux Kernel]
```
* **Why it is forbidden**:
  * Exposes the entire host system to arbitrary code execution through prompt injection.
  * Eliminates argument validation and fine-grained access control.
  * Shell metacharacters (`|`, `;`, `&&`, `$()`, backticks) bypass syntactic sanitization.
  * Root escalation destroys POSIX multi-user isolation.

### Required Pattern: Sandboxed Capability Invocations
```
[Agent] ---> [Capability Registry] ---> [Policy Engine] ---> [Sandboxed Capability] ---> [Host System]
                                            ^                         |
                                            |                         v
                                    [Audit Event Log]         [Verification Gate]
```
* **Why it is enforced**:
  * Agents never interact with raw shells.
  * Every operation is a discrete, typed capability with strict schema validation.
  * Policies enforce path containment, parameter bounds, and privilege limits.
  * Capability processes run inside Linux sandboxes with restricted system calls and filesystem access.
  * Results are independently verified against pre-declared goals.

---

## 3. Foundational Security Principles

### 3.1. Principle of Least Privilege
Agents are provisioned on demand with the absolute minimum set of capabilities required for their assigned task. A `FileAgent` reading a configuration file receives read-only capability access constrained to that single file or directory. Network access, process spawning, and write capabilities are stripped by default.

### 3.2. Capability-Based Permissions
Privileges are associated with unforgeable, scoped capabilities rather than ambient process identity. A capability specifies:
* The exact operation name (e.g., `fs.read_file`).
* Strict parameter schema (e.g., target path must be canonicalized and checked against allowed paths).
* Resource limits (max execution time, max memory, max read buffer).

### 3.3. Workspace Isolation & Sandboxing
Every capability execution occurs within an isolated sandbox environment. Depending on the capability's risk tier:
* **Filesystem Isolation**: Mount namespaces, Landlock LSM rules, or read-only binds restrict the capability from observing or mutating unrelated parts of the filesystem.
* **Syscall Filtering**: Seccomp-BPF filters block dangerous system calls (e.g., `ptrace`, `chroot`, `mount`, `reboot`).
* **Network Isolation**: Network namespaces with loopback-only or completely detached network stacks prevent covert data exfiltration.

### 3.4. Three-Tier Decision Engine: ALLOW, DENY, CONFIRM
Every capability request is mapped to one of three verdicts:
* **`ALLOW`**: The operation is classified as low risk, idempotent, and entirely within the user's active workspace scope (e.g., reading a workspace file, listing a directory).
* **`DENY`**: The operation violates security policies, attempts path traversal outside workspace boundaries, targets protected system directories (`/etc`, `/boot`, `/usr`, `/root`), or exceeds resource quotas.
* **`CONFIRM`**: The operation mutates state, overwrites files, deletes resources, installs packages, changes configurations, or accesses sensitive personal data (`~/.ssh`, `~/.gnupg`). Execution is halted until the human user explicitly approves the operation via an out-of-band interface.

### 3.5. Audit Logging & Non-Repudiation
Every intent, goal, capability request, permission decision, and execution result is recorded into an append-only, tamper-evident local audit log. 
* Logs are structured (JSONL / SQLite WAL).
* Logs contain correlation IDs tying high-level human requests to exact low-level system actions.
* Sensitive values (passwords, tokens, private keys) are scrubbed before persistence.

### 3.6. Structured Errors & Safe Failure
System failures must fail safely (fail-closed):
* If the policy engine encounters an unknown state or error, it defaults to `DENY`.
* Errors are emitted as structured objects (e.g., `StructuredErrorContract`), preventing information leakage (stack traces containing credentials or private host paths).
* Agents are provided with actionable, typed error codes rather than raw shell stderr.

### 3.7. Retry Limits & Runaway Execution Defense
To prevent agent recursion loops and runaway computational costs:
* Workflows enforce a strict step budget (e.g., max 10 steps per sub-task).
* Capabilities enforce wall-clock timeouts (e.g., 5000ms max for filesystem reads).
* Repeated identical capability failures trigger immediate workflow pause and escalate to the human user.

### 3.8. State Verification & Future Rollback
Actions are paired with verification routines:
* An operation is not deemed successful merely because the capability process exited with code `0`.
* A verification check asserts the physical state of the system against pre-declared acceptance criteria.
* Mutating capabilities must support forward planning for rollback snapshots (e.g., directory backup, file copy-on-write, or Git tracking).

---

## 4. Capability Risk Tiers

| Risk Tier | Examples | Default Policy | Human Confirmation Required? |
| :--- | :--- | :--- | :--- |
| **Tier 0: Read-Only Query** | `fs.inspect_metadata`, `fs.list_directory`, `sys.get_time` | `ALLOW` (if in workspace) | No |
| **Tier 1: Non-Destructive Write** | `fs.create_directory`, `fs.write_new_file` | `ALLOW` (if in workspace) | No (unless outside workspace) |
| **Tier 2: Destructive Mutation** | `fs.overwrite_file`, `fs.delete_file`, `fs.move_file` | `CONFIRM` | **Yes** (presents diff/preview) |
| **Tier 3: Execution & Process** | `process.spawn_sandboxed`, `pkg.query` | `CONFIRM` | **Yes** (presents command, env, binary) |
| **Tier 4: System & Security** | `sys.modify_config`, `network.bind_socket`, `sys.reboot` | `DENY` by default | **Yes** (requires elevated authorization) |

---

## 5. External Project Evaluation

As AI Agentic OS progresses, we will evaluate useful free, public GitHub repositories and reputable open-source technical resources (libraries, tools, specifications) as potential dependencies or architectural references.

### 5.1. Integration Policy for Phase 0.2
> **Strict Policy**: **No external projects, third-party libraries, or remote repositories are integrated or installed in Phase 0.2.** All specifications and architectural definitions are developed natively within this local repository.

### 5.2. Mandatory Pre-Integration Vetting Criteria
Before any third-party code, package, or repository is introduced in subsequent phases, it must pass a formal evaluation covering seven criteria:

```
+-------------------------------------------------------------------------------+
|                       EXTERNAL COMPONENT VETTING PIPELINE                     |
+-------------------------------------------------------------------------------+
  1. LICENSE EVALUATION
     - Permissive open-source license (MIT, Apache 2.0, BSD-3-Clause, ISC).
     - No incompatible, viral (e.g., strict AGPL where unneeded), or proprietary terms.
  2. MAINTENANCE & REPUTATION
     - Active project governance, regular release cadence, responsive maintainers.
     - No abandoned codebases, unaddressed security issues, or single-maintainer risks.
  3. SECURITY & VULNERABILITY HISTORY
     - Review of CVE database, OpenSSF Scorecard, and historical disclosure response.
     - Assessment of past vulnerability frequency and remediation velocity.
  4. DEPENDENCY HEALTH & SUPPLY-CHAIN FOOTPRINT
     - Minimal transitive dependency tree.
     - Pinned dependencies with cryptographic checksum verification (hashes/lockfiles).
     - No dynamic download scripts during build or post-install hooks (`postinstall`).
  5. INTEGRITY & SUSPICIOUS BEHAVIOR ANALYSIS
     - Complete source code audit of target modules.
     - Verification that no phone-home telemetry, analytics, obfuscation, or remote code loading exists.
  6. LINUX / UBUNTU COMPATIBILITY
     - Native compatibility with target Ubuntu LTS environments.
     - Low resource overhead (CPU, memory, startup latency).
  7. NECESSITY & MINIMAL COMPLEXITY
     - Justify whether the external component is strictly necessary or if a lightweight local 
       implementation (under 200 lines) provides greater safety and control.
+-------------------------------------------------------------------------------+
```

---

## 6. Undecided Security Implementations (Explicit "TBD" Registry)

The following security implementations remain intentionally undecided at Phase 0.2:

| Security Component | Status | Decision Needed | Scheduled Phase |
| :--- | :--- | :--- | :--- |
| **Sandbox Technology Selection** | **TBD** | Evaluate bubblewrap (`bwrap`) vs. pure Go/Rust Landlock+seccomp bindings vs. systemd dynamic users. | Phase 0.3 |
| **Cryptographic Audit Signing** | **TBD** | Decide whether audit event logs should be locally signed with an ed25519 system key stored in Linux Keyring. | Phase 0.4 |
| **Human Confirmation Protocol** | **TBD** | Formulate the IPC and UI protocol for prompting the user (e.g., Unix domain socket to desktop notification/modal). | Phase 0.4 |
| **Secret Management Storage** | **TBD** | Integration with Linux Secret Service / Keyring API (libsecret) for zero-plain-text storage of local tokens. | Phase 1.0 |
