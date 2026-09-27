# AI Agentic OS: System Architecture Specification

> **Phase 0.2: Architectural & Conceptual Specification**  
> *Status: Foundational Design / Non-Executable Specification*  
> *Target Platform: Linux / Ubuntu Desktop*

---

## 1. Executive Architecture Overview

**AI Agentic OS** provides an intelligent, deterministic control plane situated above the traditional **Linux / Ubuntu** operating system. The system translates high-level human objectives into verifiable, policy-governed computational actions executed by sandboxed, specialized agents.

The architecture is structured into **13 major architectural layers**, establishing a rigorous hierarchy from the top-level Human Interface down to physical Hardware, with an explicit boundary between AI Agentic OS and host Linux:

```
+-----------------------------------------------------------------------------------+
|                                  USER / HUMAN                                     |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                             1. HUMAN INTERFACE LAYER                              |
|   Multimodal Input | Status Visualization | Diff Presentation | Human Approval UI |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                           2. INTENT INTELLIGENCE LAYER                            |
|       Intent Parsing | Ambiguity Resolution | Scope Extraction | Validation       |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                              3. GOAL RUNTIME LAYER                                |
|   Goal Declaration | Pre/Post-Conditions | Acceptance Criteria | State Tracking   |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                            4. WORKFLOW RUNTIME LAYER                              |
|  Plan Generation | DAG Task Orchestration | State Machine | Dependency Resolution |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                         5. GLOBAL AGENT MANAGER LAYER                             |
|  Agent Registry | Lifecycle Management | Resource Quotas | Least-Privilege Scoping|
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                             6. AGENT RUNTIME LAYER                                |
|   Task Execution | Local Reasoning Steps | Context Management | Capability Request |
+-----------------------------------------------------------------------------------+
                 |                                                   ^
                 v                                                   |
+------------------------------------+             +--------------------------------+
|     7. KNOWLEDGE & MEMORY LAYER    |             | 12. OBSERVABILITY & RELIABILITY|
|  Episodic Context | Semantic Store |             |  Audit Log | Traces | Telemetry|
+------------------------------------+             +--------------------------------+
                 |                                                   ^
                 v                                                   |
+-------------------------------------------------------------------+|
|                      8. SECURITY & GOVERNANCE LAYER (GATEWAY)     ||
|  Capability Registry | Policy/Permission Engine | (ALLOW/DENY/CONFIRM)
+-------------------------------------------------------------------+
                                         | (ALLOW / CONFIRM approved)
                                         v
+-----------------------------------------------------------------------------------+
|                       9. CAPABILITY LAYER (SANDBOX RUNNER)                        |
|   Sandboxing is Mandatory | Isolation Implementation TBD (Decided in Phase 0.3)   |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
======================== AGENTICOS-TO-LINUX EXPLICIT BOUNDARY =======================
+-----------------------------------------------------------------------------------+
|                  10. LINUX INTEGRATION & SYSTEM SERVICES LAYER                    |
|   D-Bus Mediators | Systemd Service Adapters | Desktop Portals | IPC Bridges      |
+-----------------------------------------------------------------------------------+
                 |                                                   ^
                 v                                                   |
+--------------------------------------------------------------------+--------------+
|                          HOST OPERATING SYSTEM: LINUX / UBUNTU                    |
| Kernel Primitives | Scheduling | Virtual Memory | POSIX Filesystem | Drivers      |
+--------------------------------------------------------------------+--------------+
                 |                                                   ^
                 | (Monitors OS Health & Kernel Logs)                |
                 +---------------------------------->+---------------+--------------+
                                                     | 11. KERNEL INTELLIGENCE      |
                                                     | Health Telemetry | eBPF Feeds|
                                                     +------------------------------+
                                         |
                                         v
================================ HARDWARE BOUNDARY ==================================
+-----------------------------------------------------------------------------------+
|                              13. HARDWARE LAYER                                   |
| Physical CPU | System RAM | Non-Volatile Storage | Peripheral Devices & Busses    |
+-----------------------------------------------------------------------------------+
```

---

## 2. Component Boundaries & Isolation

A primary design rule of AI Agentic OS is the strict separation of concerns and privilege boundaries:

| Boundary Domain | What It Owns | What It Is Strictly Prohibited From Doing |
| :--- | :--- | :--- |
| **Linux (Host OS)** | Kernel primitives, process scheduling, POSIX file permissions, physical memory mapping, network socket handling, hardware drivers. | Making autonomous agentic decisions, interpreting natural language prompts. |
| **Hardware** | Physical execution of machine instructions, volatile RAM, non-volatile block storage, physical buses, hardware security modules. | Direct autonomous software orchestration without operating system mediation. (Lowest layer below Linux). |
| **AI Agentic OS** | Intent translation, goal tracking, task graph management, permission policy enforcement, capability sandboxing, and execution verification. | Bypassing Linux kernel security mechanisms, executing raw unvetted commands as root, or owning host kernel primitives. |
| **Linux Integration Boundary (Layer 10)** | Mediating interactions between sandboxed capabilities and host Linux desktop/system services (D-Bus, systemd user services, portals). | Exposing raw kernel interfaces or unmediated root privileges to agents. |
| **Kernel Intelligence (Layer 11)** | Passive observation of host health, kernel logs, thermal status, and resource pressure to advise agent runtimes. | Modifying kernel data structures, altering kernel scheduling, or executing kernel functions. |
| **Observability & Reliability (Layer 12)** | Append-only audit logs, execution traces, metric aggregation, anomaly detection, structured errors, and state verification. | Modifying execution paths, altering payloads, or exposing sensitive credentials. |
| **Agents** | Task-specific problem solving, reasoning within granted scope, proposing actions via formal capability calls. | Directly calling shell interpreters (`/bin/bash`), bypassing the policy engine, self-granting permissions. |
| **Capabilities** | Atomic, deterministic, isolated operations (e.g., `fs.create_directory`, `process.spawn_sandboxed`). | Maintaining arbitrary state, executing outside declared sandbox constraints. |
| **Applications** | User-facing productivity software, background utilities, desktop applications. | Arbitrarily intercepting agent system buses without explicit capability registration. |
| **Security Layer** | Deterministic rule evaluation (`ALLOW`, `DENY`, `CONFIRM`), session credential management, token minting. | Generating creative or heuristic outputs; must be 100% deterministic and auditable. |

---

## 3. Layer-by-Layer Architectural Decomposition

### 3.1. Layer 1: Human Interface Layer
* **Role**: Primary bidirectional interface between human user and AI Agentic OS.
* **Capabilities**: Ingests natural language commands, structured form inputs, voice, and system events. Displays execution status, step-by-step task progress, unified diffs, and confirmation prompts requiring explicit user sign-off.
* **Boundaries**: Strictly non-privileged; passes captured intent to the Intent Intelligence Layer.

### 3.2. Layer 2: Intent Intelligence Layer
* **Role**: Extracts structured semantic intent from unstructured inputs.
* **Capabilities**: Identifies target entities (paths, applications, configurations), classifies operations (read, write, mutate, execute), identifies missing parameters, and surfaces ambiguity back to the user before goal generation.
* **Contract Output**: Produces a validated `IntentContract`.

### 3.3. Layer 3: Goal Runtime Layer
* **Role**: Converts semantic intent into a verifiable, deterministic goal.
* **Capabilities**: Defines exact pre-conditions (e.g., parent directory must exist) and post-conditions (e.g., directory must exist with specific permissions). Tracks goal lifecycle (`PENDING`, `IN_PROGRESS`, `VERIFYING`, `COMPLETED`, `FAILED`).
* **Contract Output**: Produces a `GoalContract`.

### 3.4. Layer 4: Workflow Runtime Layer
* **Role**: Decomposes goals into a Directed Acyclic Graph (DAG) of discrete tasks.
* **Capabilities**: Handles task dependencies, parallel step execution, rollback pathways, and failure recovery policies. Ensures idempotent execution where possible.
* **Contract Output**: Produces a `WorkflowContract`.

### 3.5. Layer 5: Global Agent Manager Layer
* **Role**: Orchestrates agent lifecycle, resource utilization, and specialization.
* **Capabilities**: Provisions specialized subagents (e.g., `FileAgent`, `GitAgent`, `NetworkAgent`), enforces agent execution timeouts, limits memory/CPU allocations, and binds each agent to a least-privilege capability scope.

### 3.6. Layer 6: Agent Runtime Layer
* **Role**: Execution environment where specialized agents perform reasoning and task progression.
* **Capabilities**: Manages agent working memory, tracks step budgets, maintains context windows, and emits capability invocation requests to the Security Layer.
* **Constraint**: Agents **cannot** invoke system syscalls or shell commands directly; they may only emit `CapabilityInvocationRequest` payloads.

### 3.7. Layer 7: Knowledge & Memory Layer
* **Role**: Provides contextual state, system metadata, and long-term memory.
* **Components**:
  * *Episodic Memory*: Session-specific history of actions, outcomes, and user preferences.
  * *Workspace State*: Current active directory, project context, Git status, and active configuration.
  * *System Schema*: Map of available capabilities, installed applications, and system capabilities.

### 3.8. Layer 8: Security & Governance Layer (Policy/Permission Engine)
* **Role**: The non-negotiable security firewall of the operating system.
* **Responsibilities**:
  * Evaluates every `CapabilityInvocationRequest` against security policies.
  * Verifies path boundaries (e.g., path is within `/home/lokamanya/Documents` and outside `/etc`, `/sys`, `/boot`).
  * Yields one of three deterministic verdicts: `ALLOW`, `DENY`, or `CONFIRM`.
  * Emits tamper-evident `AuditEvent` records for all evaluation events.

### 3.9. Layer 9: Capability Layer (Sandboxed Execution)
* **Role**: Provides safe, deterministic implementation and execution of concrete system operations.
* **Mandatory Sandboxing Requirement**: Sandboxing is a strict, mandatory architectural requirement for all capability execution. Running un-sandboxed capabilities is strictly prohibited.
* **Implementation Status**: While the requirement for process, filesystem, and system call isolation is mandatory, the specific sandboxing technology (evaluating Bubblewrap, Landlock LSM + seccomp-bpf, Linux namespaces + cgroups v2, or lightweight containers) remains **TBD until Phase 0.3**.
* **Contract Rule**: Capabilities are discrete, typed modules implementing explicit schemas; they never expose an arbitrary `exec(string)` shell primitive.

### 3.10. Layer 10: Linux Integration Layer (AgenticOS-to-Linux Boundary & System Services)
* **Role**: The explicit architectural mediation boundary separating AI Agentic OS from the host Linux operating system.
* **Integration Points**: Adapts sandboxed capability requests to user-space Linux services, D-Bus session/system buses, systemd user services, desktop portals (Wayland / FreeDesktop), and POSIX system APIs.
* **Boundary Invariant**: AI Agentic OS does **not** own or replace Linux kernel primitives. Linux remains strictly authoritative for kernel execution, process scheduling, memory allocation, device drivers, network sockets, and POSIX filesystem operations.

### 3.11. Layer 11: Kernel & System Intelligence Layer
* **Role**: Distinct architectural responsibility providing continuous, proactive insight into host operating system health, resource consumption, and kernel states.
* **Capabilities**: Ingests host telemetry from unprivileged inspection interfaces (e.g., `/proc`, `/sys`, system logs, unprivileged eBPF telemetry). Detects out-of-memory pressure, disk exhaustion, thermal throttling, and hardware bottlenecks to advise the Global Agent Manager and Agent Runtime before task scheduling.
* **Boundary Invariant**: Strictly observational and analytical; does not alter kernel primitives, modify kernel memory, or usurp Linux scheduling.

### 3.12. Layer 12: Observability & Reliability Layer
* **Role**: Distinct architectural responsibility ensuring total system auditability, non-repudiation, deterministic verification, and safe error recovery.
* **Features**:
  * Append-only local structured audit log with tamper-evident formatting.
  * Correlation IDs tracing high-level user intent down to atomic capability invocations and verification checks.
  * Structured error reporting (`StructuredErrorContract`) providing root-cause diagnostic context without leaking credentials.
  * Independent state verification engines asserting physical postconditions against declared goal criteria.

### 3.13. Layer 13: Hardware Layer
* **Role**: Physical hardware and execution substrate operating as the lowest layer beneath the host Linux operating system.
* **Responsibilities**: Physical CPU execution cores, volatile RAM, non-volatile block storage devices (NVMe/SSD/HDD), physical network controllers, and hardware peripheral buses. Hardware access is strictly mediated by the Linux kernel.

---

## 4. Conceptual Data Contracts & Interfaces

The interfaces below represent the conceptual contracts governing inter-component communication within AI Agentic OS.

### 4.1. Intent Contract (`IntentContract`)
```json
{
  "$schema": "https://ai-agentic-os.local/schemas/intent.v1.json",
  "intent_id": "int-7f9a1b2c-3d4e-4f5a-8b9c-0d1e2f3a4b5c",
  "created_at": "2026-09-27T13:00:00Z",
  "source": {
    "channel": "cli",
    "user_id": "lokamanya",
    "raw_input": "Create a folder called Project in Documents."
  },
  "action_class": "filesystem.create",
  "entities": {
    "target_name": "Project",
    "target_type": "directory",
    "parent_location": "Documents",
    "resolved_parent_path": "/home/lokamanya/Documents"
  },
  "confidence": 0.99,
  "requires_clarification": false,
  "clarification_prompt": null
}
```

### 4.2. Goal Contract (`GoalContract`)
```json
{
  "$schema": "https://ai-agentic-os.local/schemas/goal.v1.json",
  "goal_id": "goal-4a5b6c7d-8e9f-0a1b-2c3d-4e5f6a7b8c9d",
  "intent_id": "int-7f9a1b2c-3d4e-4f5a-8b9c-0d1e2f3a4b5c",
  "status": "PENDING",
  "description": "Ensure directory '/home/lokamanya/Documents/Project' exists with standard user permissions.",
  "preconditions": [
    {
      "check": "path_exists",
      "path": "/home/lokamanya/Documents",
      "expected": true
    },
    {
      "check": "path_exists",
      "path": "/home/lokamanya/Documents/Project",
      "expected": false
    }
  ],
  "postconditions": [
    {
      "check": "is_directory",
      "path": "/home/lokamanya/Documents/Project",
      "expected": true
    },
    {
      "check": "directory_permissions",
      "path": "/home/lokamanya/Documents/Project",
      "expected": "0755"
    }
  ],
  "max_retries": 2,
  "timeout_seconds": 30
}
```

### 4.3. Workflow Contract (`WorkflowContract`)
```json
{
  "$schema": "https://ai-agentic-os.local/schemas/workflow.v1.json",
  "workflow_id": "wf-11223344-5566-7788-99aa-bbccddeeff00",
  "goal_id": "goal-4a5b6c7d-8e9f-0a1b-2c3d-4e5f6a7b8c9d",
  "state": "PLANNED",
  "tasks": [
    {
      "task_id": "task-001",
      "title": "Verify parent directory accessibility",
      "assigned_agent_type": "FileAgent",
      "capability": "fs.inspect_metadata",
      "parameters": {
        "path": "/home/lokamanya/Documents"
      },
      "dependencies": []
    },
    {
      "task_id": "task-002",
      "title": "Create directory Project",
      "assigned_agent_type": "FileAgent",
      "capability": "fs.create_directory",
      "parameters": {
        "path": "/home/lokamanya/Documents/Project",
        "mode": "0755",
        "create_parents": false
      },
      "dependencies": ["task-001"]
    },
    {
      "task_id": "task-003",
      "title": "Verify target directory created",
      "assigned_agent_type": "FileAgent",
      "capability": "fs.inspect_metadata",
      "parameters": {
        "path": "/home/lokamanya/Documents/Project"
      },
      "dependencies": ["task-002"]
    }
  ]
}
```

### 4.4. Agent Contract (`AgentContract`)
```json
{
  "$schema": "https://ai-agentic-os.local/schemas/agent.v1.json",
  "agent_id": "ag-file-99887766",
  "agent_type": "FileAgent",
  "lifecycle_state": "ACTIVE",
  "bound_workflow_id": "wf-11223344-5566-7788-99aa-bbccddeeff00",
  "bound_task_id": "task-002",
  "allocated_resources": {
    "max_steps": 5,
    "timeout_ms": 5000,
    "max_memory_mb": 64
  },
  "allowed_capabilities": [
    "fs.inspect_metadata",
    "fs.create_directory"
  ],
  "workspace_scope": {
    "allowed_root_paths": [
      "/home/lokamanya/Documents"
    ],
    "denied_paths": [
      "/home/lokamanya/.ssh",
      "/home/lokamanya/.gnupg",
      "/etc",
      "/usr",
      "/sys",
      "/dev"
    ]
  }
}
```

### 4.5. Capability Contract (`CapabilityContract`)
```json
{
  "$schema": "https://ai-agentic-os.local/schemas/capability.v1.json",
  "capability_id": "fs.create_directory",
  "version": "1.0.0",
  "description": "Atomically creates a directory on the local filesystem with deterministic permissions.",
  "risk_tier": "TIER_1_STANDARD_WRITE",
  "input_schema": {
    "type": "object",
    "required": ["path"],
    "properties": {
      "path": {
        "type": "string",
        "format": "absolute-path",
        "description": "Absolute filesystem path for the directory."
      },
      "mode": {
        "type": "string",
        "pattern": "^0[0-7]{3}$",
        "default": "0755"
      },
      "create_parents": {
        "type": "boolean",
        "default": false
      }
    }
  },
  "output_schema": {
    "type": "object",
    "required": ["success", "path", "inode"],
    "properties": {
      "success": { "type": "boolean" },
      "path": { "type": "string" },
      "inode": { "type": "integer" }
    }
  },
  "sandbox_requirements": {
    "sandboxing_mandatory": true,
    "requires_network": false,
    "requires_root": false,
    "filesystem_access": "RESTRICTED_WRITE",
    "isolation_engine_selection": "TBD_PHASE_0_3"
  }
}
```

### 4.6. Permission Decision Contract (`PermissionDecisionContract`)
```json
{
  "$schema": "https://ai-agentic-os.local/schemas/permission-decision.v1.json",
  "decision_id": "dec-a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
  "timestamp": "2026-09-27T13:00:02Z",
  "request_id": "req-98765432-10fe-ba98-7654-3210fedcba98",
  "agent_id": "ag-file-99887766",
  "capability_id": "fs.create_directory",
  "target_resource": "/home/lokamanya/Documents/Project",
  "decision": "ALLOW",
  "reason": "Target path '/home/lokamanya/Documents/Project' resides strictly within allowed workspace scope '/home/lokamanya/Documents' and matches declarative write policy.",
  "policy_rule_id": "pol-fs-user-workspace-write-001",
  "confirmation_details": null
}
```

*Note on Verdicts*:
* `ALLOW`: Policy permits execution without human intervention.
* `DENY`: Policy strictly prohibits execution (e.g., path traversal, protected system path).
* `CONFIRM`: Policy requires human user approval before capability invocation (e.g., file overwrite, deletion, configuration edit).

### 4.7. Audit Event Contract (`AuditEventContract`)
```json
{
  "$schema": "https://ai-agentic-os.local/schemas/audit-event.v1.json",
  "event_id": "aud-12345678-9abc-def0-1234-56789abcdef0",
  "timestamp": "2026-09-27T13:00:03Z",
  "correlation_id": "int-7f9a1b2c-3d4e-4f5a-8b9c-0d1e2f3a4b5c",
  "event_type": "CAPABILITY_EXECUTED",
  "severity": "INFO",
  "actor": {
    "agent_id": "ag-file-99887766",
    "agent_type": "FileAgent"
  },
  "action": {
    "capability_id": "fs.create_directory",
    "parameters": {
      "path": "/home/lokamanya/Documents/Project",
      "mode": "0755"
    }
  },
  "authorization": {
    "decision_id": "dec-a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
    "decision": "ALLOW"
  },
  "execution_result": {
    "status": "SUCCESS",
    "execution_time_ms": 1.4,
    "system_error_code": 0
  }
}
```

### 4.8. Structured Error Contract (`StructuredErrorContract`)
```json
{
  "$schema": "https://ai-agentic-os.local/schemas/structured-error.v1.json",
  "error_id": "err-55443322-1100-aa99-8877-665544332211",
  "timestamp": "2026-09-27T13:00:04Z",
  "category": "PERMISSION_DENIED",
  "code": "PATH_TRAVERSAL_DETECTED",
  "message": "Access denied: Target path escapes designated workspace boundary.",
  "details": {
    "target_path": "/home/lokamanya/Documents/../../etc/shadow",
    "canonical_path": "/etc/shadow",
    "allowed_roots": ["/home/lokamanya/Documents"]
  },
  "retryable": false,
  "suggested_recovery": "Restructure target path within the current workspace."
}
```

### 4.9. Verification Result Contract (`VerificationResultContract`)
```json
{
  "$schema": "https://ai-agentic-os.local/schemas/verification-result.v1.json",
  "verification_id": "ver-fedcba98-7654-3210-fedc-ba9876543210",
  "goal_id": "goal-4a5b6c7d-8e9f-0a1b-2c3d-4e5f6a7b8c9d",
  "timestamp": "2026-09-27T13:00:04Z",
  "is_satisfied": true,
  "condition_results": [
    {
      "check": "is_directory",
      "path": "/home/lokamanya/Documents/Project",
      "expected": true,
      "actual": true,
      "status": "PASS"
    },
    {
      "check": "directory_permissions",
      "path": "/home/lokamanya/Documents/Project",
      "expected": "0755",
      "actual": "0755",
      "status": "PASS"
    }
  ],
  "verification_duration_ms": 0.8
}
```

---

## 5. End-to-End Walkthrough Example

### Objective: "Create a folder called Project in Documents."
*(Conceptual trace only — no code execution in Phase 0.2)*

```
[User Input: "Create a folder called Project in Documents."]
                          |
                          v
               [1. Human Interface]
               Validates user session, packages input.
                          |
                          v
             [2. Intent Intelligence]
  - Classifies intent as filesystem creation.
  - Resolves target name: "Project".
  - Resolves target base: "~/Documents" -> "/home/lokamanya/Documents".
  - Generates IntentContract(int-7f9a1b2c).
                          |
                          v
                [3. Goal Runtime]
  - Formulates GoalContract(goal-4a5b6c7d).
  - Precondition: Path "/home/lokamanya/Documents/Project" does NOT exist.
  - Postcondition: Directory "/home/lokamanya/Documents/Project" exists with mode 0755.
                          |
                          v
              [4. Workflow Runtime]
  - Decomposes into DAG:
      Step 1: Check parent exists (fs.inspect_metadata).
      Step 2: Create directory (fs.create_directory).
      Step 3: Verify creation (fs.inspect_metadata).
                          |
                          v
           [5. Global Agent Manager]
  - Selects and provisions specialized FileAgent(ag-file-99887766).
  - Configures restricted capability scope: ["fs.inspect_metadata", "fs.create_directory"].
  - Configures workspace boundary: "/home/lokamanya/Documents".
                          |
                          v
               [6. File Agent Runtime]
  - Executes task Step 2.
  - Formulates CapabilityInvocationRequest(fs.create_directory, path="/home/lokamanya/Documents/Project").
                          |
                          v
      [7. Security & Governance Engine]
  - Evaluates request against policy rule `pol-fs-user-workspace-write-001`.
  - Path canonicalization check: Target path is within `/home/lokamanya/Documents`.
  - Risk assessment: Standard user directory creation in user's personal documents.
  - Verdict: ALLOW.
  - Emits AuditEvent(aud-12345678).
                          |
                          v
         [8. Sandboxed Capability Runner (Layer 9)]
  - Capability `fs.create_directory` is prepared for execution within an isolated sandbox (sandboxing is mandatory; specific engine TBD in Phase 0.3).
  - Sandbox constraints enforce restricted filesystem write access bounded to the authorized workspace path.
                          |
                          v
  === Crosses AgenticOS-to-Linux Boundary (Layer 10: Linux Integration) ===
  - Capability invocation bridges across Layer 10 to issue POSIX `mkdir(2)` system call to host Linux.
                          |
                          v
                [Host Operating System: Linux]
  - Linux kernel handles `mkdir(2)` system call, verifies POSIX user permissions (uid=lokamanya).
  - Kernel filesystem driver (ext4/btrfs) allocates directory inode and writes directory entry.
  - Kernel & System Intelligence (Layer 11) passively observes filesystem telemetry (free space, inode quotas) without interfering with kernel operations.
                          |
                          v
         [Hardware Layer (Layer 13 - Lowest Layer Below Linux)]
  - Physical NVMe/SATA storage controller commits directory metadata changes to physical non-volatile storage.
                          |
                          v
              [Verification Subsystem]
  - Evaluates Postconditions:
      1. Calls `stat(2)` on `/home/lokamanya/Documents/Project`.
      2. Asserts `S_ISDIR(st_mode)` is true.
      3. Asserts mode bits match `0755`.
  - Produces VerificationResultContract: `is_satisfied: true`.
                          |
                          v
     [Observability & Reliability Layer (Layer 12)]
  - Final AuditEvent logged with correlation ID, execution duration, and verification proof.
                          |
                          v
            [Human Interface (Layer 1)]
  - User receives confirmation: "Folder 'Project' successfully created in Documents."
```

---

## 6. Undecided Architecture Areas (Explicit "TBD" Registry)

The following areas are intentionally undecided at Phase 0.2. They will be formally resolved in subsequent phases via Architectural Decision Records (ADRs):

| Architectural Domain | Current Status | Decision Needed | Scheduled Phase |
| :--- | :--- | :--- | :--- |
| **Inter-Process Communication (IPC)** | **TBD** | Choice of IPC mechanism between Agent Manager, Capability Runner, and Policy Engine (Options: Unix Domain Sockets with protobuf/JSON, gRPC over UDS, or D-Bus system/session bus). | Phase 0.3 |
| **Capability Sandboxing Engine** | **TBD** | Selection of isolation primitives on Linux (Options: Bubblewrap, Landlock LSM + seccomp-bpf, Linux Namespaces + cgroups v2, or lightweight container runtimes like runc/crun). | Phase 0.3 |
| **Deterministic Policy Language** | **TBD** | Selection of policy evaluation engine (Options: Embedded Cedar engine, Open Policy Agent / Rego, or tailored zero-dependency JSON-Schema validator). | Phase 0.3 |
| **Memory / Knowledge Storage Engine** | **TBD** | Local storage technology for episodic memory and audit logs (Options: SQLite with WAL mode, DuckDB, or append-only flat-file JSONL with binary indexing). | Phase 0.3 |
| **LLM Provider Abstraction Layer** | **TBD** | Architecture of the inference gateway separating agent logic from specific model providers (e.g., local Ollama/llama.cpp vs. hosted endpoints). | Phase 1.0 |
| **Desktop Environment Integration** | **TBD** | Wayland compositor integration model (e.g., custom Wayland shell extension vs. standalone desktop application window). | Phase 2.0 |
