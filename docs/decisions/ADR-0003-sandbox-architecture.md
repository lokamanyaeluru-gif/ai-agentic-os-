# ADR-0003: Sandbox Architecture for Capability Execution

* **Status**: PROPOSED  
* **Date**: 2026-09-27  
* **Phase**: 0.3.2  

---

## Context

AI Agentic OS provides an intelligent control layer positioned above Linux. In this architecture, autonomous neural agents formulated by Large Language Models (LLMs) execute real-world tasks on the host system.

### Foundational Security Axiom
As established in [`docs/security.md`](file:///home/lokamanya/AI%20Agentic%20OS/docs/security.md) and [`ADR-0001`](file:///home/lokamanya/AI%20Agentic%20OS/docs/decisions/ADR-0001-local-only-and-deterministic-security.md):
> **The LLM or autonomous agent must NEVER be the final authorization authority, and direct shell execution is strictly prohibited.**

The execution pipeline is strictly defined as:
```
LLM / Agent
   │ (Emits typed request)
   ▼
CapabilityInvocationRequest
   │ (Evaluated deterministically)
   ▼
Policy & Permission Engine (ALLOW / DENY / CONFIRM)
   │ (Configures capability-specific sandbox)
   ▼
Capability-Specific Sandbox
   │ (Executes under kernel-enforced least privilege)
   ▼
Linux Kernel / System Primitives
   │ (Captures structured result & telemetry)
   ▼
Verification & Audit Gate
```

Under this model, sandboxing is a **mandatory architectural requirement**. Direct, un-sandboxed execution of capabilities is strictly forbidden. We must determine the sandbox architecture for capability execution.

---

## Evaluated Candidate Approaches

1. **Option 1: Landlock LSM + seccomp-bpf (Direct Access Control & Syscall Filtering)**:
   Applies Linux Security Module (Landlock) rulesets and BPF-based system call filters (`seccomp-bpf`) within a dedicated capability process after `fork()` and before payload execution.
2. **Option 2: Bubblewrap + Linux Namespaces (Containerized Construction)**:
   Uses Bubblewrap (`bwrap`) as an unprivileged sandbox-construction tool to provision dedicated Linux mount, PID, network, IPC, and UTS namespaces with a synthetic root filesystem.
3. **Option 3: systemd Sandboxing Primitives (User Units / Transient Scopes)**:
   Leverages `systemd-run --user` and systemd unit sandboxing directives (`ProtectSystem`, `PrivateTmp`, `NoNewPrivileges`, cgroups v2 resource accounting) to run capability tasks.
4. **Option 4: Multi-Layered Hybrid Architecture (Defense-in-Depth Containment)**:
   Combines the Policy Engine (pre-execution gateway), systemd/cgroups v2 (resource containment & daemon supervision), Bubblewrap (namespace construction for external/high-risk processes), Landlock LSM (fine-grained access control for kernel objects and paths), and seccomp-bpf (syscall restriction).

---

## Evaluation Comparison Matrix (25 Criteria)

| Evaluation Criterion | Option 1: Landlock + seccomp-bpf | Option 2: Bubblewrap + Namespaces | Option 3: systemd User Sandboxing | Option 4: Hybrid Architecture (Recommended) |
| :--- | :--- | :--- | :--- | :--- |
| **1. Filesystem Isolation** | **Fine-Grained Path Restriction**: Restricts read/write/exec to specific directory trees; cannot hide unexposed paths or create clean synthetic `/`. | **Pristine Mount Namespace**: Mounts clean `tmpfs` at `/`; selectively binds only required directories; unmounted paths are invisible. | **Coarse Mount Isolation**: Provides `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp`; lacks dynamic per-request path bindings. | **Comprehensive**: Bubblewrap constructs clean `/` mount namespace; Landlock applies fine-grained path rulesets within bound workspaces. |
| **2. Network Isolation** | **Limited**: Landlock network support (where supported by probed ABI) restricts TCP bind/connect; cannot isolate loopback, raw sockets, or network interfaces. | **Complete**: `--unshare-net` creates private network namespace containing only an isolated loopback interface. | **Standard**: `PrivateNetwork=yes` or `IPAddressDeny=any` restricts network access via systemd. | **Complete**: Network namespaces drop external network interfaces; seccomp blocks unauthorized `socket()` families; Landlock applies port restrictions where supported by probed ABI. |
| **3. Syscall Restriction** | **Native**: `seccomp-bpf` allows fine-grained syscall whitelisting/blacklisting and argument inspection. | **Delegated**: Bubblewrap can apply a passed seccomp BPF filter (`--seccomp`), but does not generate rules natively. | **Standard**: `SystemCallFilter=` provides predefined systemd syscall sets (e.g., `@basic-io`, `@system-service`). | **Native & Granular**: Tailored `seccomp-bpf` filters block unauthorized syscalls (`ptrace`, `bpf`, dangerous `clone3` flags, `execve`). |
| **4. Process Isolation** | **None**: Process runs in host PID namespace; can see host PIDs in `/proc` unless `/proc` is manually managed. | **Complete**: `--unshare-pid` isolates PID namespace; sandboxed process sees itself as PID 1; host processes invisible. | **Partial**: Processes run within dedicated cgroup/scope, but share the user session PID namespace by default. | **Complete**: High-risk capabilities run in isolated PID namespaces; host process tree is completely invisible. |
| **5. Privilege Reduction** | **Dedicated Worker**: Drops Linux capabilities via `cap_set_proc`; drops ambient capabilities. | **Automatic**: Drops capabilities upon entering user namespace; executes as unprivileged user inside container. | **Configurable**: `CapabilityBoundingSet=` and `AmbientCapabilities=` drop privileges via unit settings. | **Multi-Tier**: Drops capabilities at namespace entry and restricts ambient privileges within the worker process. |
| **6. `no_new_privs`** | **Mandatory**: Required by both Landlock and unprivileged seccomp before applying rulesets (`prctl(PR_SET_NO_NEW_PRIVS)`). | **Automatic**: Enforced by Bubblewrap on launch by default. | **Configurable**: Supported via `NoNewPrivileges=yes` directive. | **Guaranteed**: Enforced at multiple boundaries before executing any capability code. |
| **7. Protection Against Arbitrary Command Execution** | **Syscall Level**: seccomp can block `execve`/`execveat` entirely for non-execution capabilities. | **Filesystem Level**: `/bin`, `/usr/bin` can be omitted from mount namespace unless needed. | **Coarse**: System directories marked read-only; binaries remain accessible unless explicitly hidden. | **Dual-Level**: Clean mount namespace omits shell binaries; seccomp blocks `execve` unless explicitly authorized. |
| **8. Protection Against Path Traversal / Symlink Attacks** | **High**: Landlock checks resolved inodes at path walk time; resistant to `../` traversal outside permitted trees. | **Superior**: Path outside bind mounts simply does not exist in the mount namespace; symlinks to unmounted paths fail (`ENOENT`). | **Moderate**: `ProtectHome=yes` protects user home, but relative traversal within allowed bounds requires external checks. | **Defense-in-Depth**: Path validation uses canonicalization as a validation step, while race-resistant kernel pathname resolution (such as `openat2()` with appropriate `RESOLVE_*` restrictions) is used where applicable; Bubblewrap unshares mount namespace; Landlock enforces inode access rules. |
| **9. Suitability for Unprivileged Operation** | **Native**: Landlock and seccomp-bpf are designed specifically for unprivileged user space. | **Native**: Bubblewrap uses unprivileged user namespaces (`CLONE_NEWUSER`); does not require setuid on modern Ubuntu. | **Native**: Works with unprivileged systemd user manager (`systemctl --user`). | **Native**: Entire architecture operates strictly in unprivileged user space without root or sudo. |
| **10. File Descriptor Passing** | **Full**: File descriptors passed across Unix Domain Sockets or inherited across fork remain accessible. | **Full**: FDs passed into `bwrap` remain accessible via `--file`, `--perms`, or standard inherited descriptors. | **Poor**: Passing dynamic, per-request file descriptors into transient `systemd-run` units is difficult and awkward. | **Optimal**: Private `socketpair(2)` and optional `SCM_RIGHTS` descriptors pass seamlessly into capability runners. |
| **11. Compatibility with UDS IPC** | **Full**: Unix Domain Sockets operate seamlessly; `SO_PEERCRED` and `SCM_RIGHTS` supported natively. | **Full**: UDS descriptors passed across boundary operate normally; abstract sockets isolated via `--unshare-net`. | **Moderate**: Connecting dynamic UDS endpoints into transient systemd units requires filesystem socket paths. | **Full**: Fully aligned with ADR-0002; private anonymous `socketpair(2)` connects runtime to sandbox runner. |
| **12. Suitability for Typed Capabilities** | **High**: Dedicated capability worker accepts typed payload, applies Landlock/seccomp profile, executes typed operation. | **High**: Capability runner wrapped inside `bwrap` receives typed parameters over IPC socket. | **Poor**: Systemd units designed for system service command-lines, not structured typed capability payloads. | **Optimal**: Strict mapping between typed capability schemas, required access rules, and tailored sandbox profiles. |
| **13. Capability-Specific Policies** | **High**: Dynamic Landlock rulesets and seccomp filters constructed per capability invocation. | **High**: Mount arguments, environment, and namespaces constructed dynamically per invocation. | **Poor**: Dynamic unit generation creates operational overhead and disk/D-Bus churn. | **Granular**: Every capability invocation receives a dedicated, minimal sandbox profile generated on demand. |
| **14. Resource Limits** | **None**: Landlock and seccomp do not manage CPU, RAM, or task limits (fork bombs). | **Minimal**: Does not enforce cgroup resource limits natively. | **Superior**: First-class cgroups v2 integration (`MemoryMax`, `CPUQuota`, `TasksMax`, `IOReadBytesMax`). | **Integrated**: Systemd/cgroups v2 governs runtime resource ceilings; transient scopes govern worker pools. |
| **15. Observability & Auditing** | **Good**: seccomp `SECCOMP_RET_LOG` logs to auditd/journald; kernel signals recorded. | **Moderate**: Bubblewrap termination status and stdout/stderr capture; lacks internal syscall telemetry. | **Superior**: First-class `journald` logging, cgroup telemetry, and unit status reporting. | **Comprehensive**: Layer 12 Observability captures audit records; journald records cgroups; kernel logs security faults. |
| **16. Failure Behavior** | **Predictable**: Syscall returns `EACCES`, `EPERM`, or terminates with `SIGSYS`. | **Predictable**: Sandbox aborts with clean exit code if initialization fails or child process terminates. | **Complex**: Failed unit enters `failed` state in systemd manager; requires unit cleanup. | **Fail-Closed**: Sandbox initialization failure immediately aborts execution; un-sandboxed fallback is strictly prohibited. |
| **17. Recovery & Restart Behavior** | **Clean**: Worker process terminates; supervising runtime cleans up state. | **Clean**: Worker process and private namespaces are automatically reaped by the kernel on exit. | **Managed**: Systemd handles service restarts, but transient unit cleanup adds complexity. | **Ephemeral & Clean**: Namespaces and processes vanish on termination; runtime detects disconnect via `POLLHUP`. |
| **18. Performance Overhead** | **Low**: Dedicated worker setup with Landlock/seccomp applied before execution takes <1 ms. | **Low**: Process launch overhead (~5–15 ms for `fork/exec` of `bwrap`); acceptable for external tools. | **High**: D-Bus round-trips to systemd user manager add 50–200 ms per invocation. | **Tiered**: Dedicated worker process with direct Landlock/seccomp setup for low-risk capabilities; containerized namespace construction for higher-risk tools. |
| **19. Implementation Complexity** | **Moderate**: Requires direct syscall bindings or wrappers for Landlock and seccomp BPF assembly. | **Low**: Straightforward CLI invocation and argument construction for `bwrap`. | **High**: Managing transient systemd units via D-Bus client libraries is complex and prone to edge-case states. | **Balanced**: Well-scoped components: `bwrap` CLI wrapper + native Landlock/seccomp policy applicator. |
| **20. Ubuntu/Linux Compatibility** | **High**: Landlock available since Linux 5.13; seccomp universal. Runtime probes Landlock ABI, detects supported features, constructs strongest compatible profile, and fails closed if required guarantees are unavailable. | **High**: Pre-installed on Ubuntu (`/usr/bin/bwrap`); supported across all major Linux distributions. | **Native**: Universal on modern systemd-based Linux systems. | **Universal**: Probes Landlock ABI at runtime and tests compatibility across supported Linux kernels without kernel modifications or third-party repositories. |
| **21. Maintenance Burden** | **Low**: In-kernel stable ABIs; no external daemon to maintain. | **Low**: Mature, stable open-source project maintained by container/desktop ecosystem. | **Moderate**: Managing unit lifecycles and systemd version differences across desktop environments. | **Low**: Uses stable Linux kernel primitives and the standard distribution-packaged `bwrap` binary. |
| **22. Dependency Footprint** | **Zero**: Direct kernel system calls; no external packages or runtime libraries needed. | **Minimal**: Single self-contained C binary (`bwrap`, ~80 KB) already present on desktop Ubuntu. | **Zero Additional**: Uses existing systemd user instance. | **Minimal**: In-kernel syscalls + standard `/usr/bin/bwrap` system utility; zero custom kernel modules. |
| **23. Security Track Record** | **Excellent**: In-tree kernel LSM with rigorous peer review; zero architectural vulnerabilities. | **Strong**: Extensively audited by Flatpak/Red Hat; past CVEs addressed quickly; unprivileged by design. | **Strong**: Enterprise-grade service management; regular security audits. | **Superior**: Layered defense ensures that a vulnerability in one mechanism is contained by the others. |
| **24. Future Desktop Integration** | **High**: Independent of display server or desktop environment. | **High**: Natural alignment with Flatpak, Wayland portals, and desktop isolation models. | **High**: Standard for desktop session management. | **Seamless**: Compatible with Wayland, XDG desktop portals, and user session lifecycles. |
| **25. Complete Boundary vs. Partial Component** | **Partial**: Access-control mechanism for filesystem/network and syscall filter; lacks mount/PID isolation. | **Partial**: Construction tool for namespaces; requires external policy to define what to bind mount. | **Partial**: Service manager and resource limiter; too coarse for fine-grained capability isolation. | **Defense-in-Depth Containment Architecture**: Cohesive, multi-layered containment architecture combining semantic policy gating, namespace isolation, syscall filtering, and access-control primitives. Does not imply protection against arbitrary kernel vulnerabilities, but provides robust defense-in-depth across unprivileged execution layers. |

---

## Real-World Reference Projects Evaluation

### 1. Landlock LSM
* **Project**: Landlock Linux Security Module
* **Repository**: Linux Kernel mainline (`https://landlock.io`, `https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git`)
* **License**: GPL-2.0-only
* **Maintenance & Activity**: Highly active; maintained by Mickaël Salaün as an official Linux kernel security subsystem. Supported since Linux 5.13, with progressive ABI expansions across kernel versions.
* **Security Track Record**: Excellent. Kernel-enforced access control designed specifically for unprivileged application sandboxing without setuid binaries or ambient administrative privileges.
* **Compatibility & Probing**: Landlock was introduced in Linux 5.13 and has evolved across multiple ABI versions. AgenticOS must probe the Landlock ABI at runtime, detect supported features, construct the strongest compatible profile, fail closed when required security guarantees cannot be provided, and test compatibility across supported Linux kernels.
* **Role in Architecture**: Access-control mechanism for kernel objects and paths. Restricts filesystem operations (read, write, execute, make directory/file, refer/rename, truncate) and network operations (TCP bind/connect) to strictly declared path descriptors (`O_PATH`).
* **Dependency Requirement**: In-kernel system calls (`landlock_create_ruleset`, `landlock_add_rule`, `landlock_restrict_self`). Requires **zero** external packages or libraries.

### 2. seccomp-bpf & libseccomp
* **Project**: Linux Secure Computing Mode (seccomp-bpf) / libseccomp
* **Repository**: `https://github.com/seccomp/libseccomp`
* **License**: LGPL-2.1-only (libseccomp), GPL-2.0 (kernel)
* **Maintenance & Activity**: Actively maintained as foundational Linux security infrastructure. Universal across container runtimes (Docker, Podman, containerd), web browsers (Chromium, Firefox), and systemd.
* **Security Track Record**: Industry standard for system call attack surface reduction.
* **Role in Architecture**: Syscall restriction mechanism. Intercepts and filters system calls, blocking dangerous syscalls (`ptrace`, `bpf`, `kexec_load`, `mount`, `chroot`, `syslog`, `clone3` namespace flags, unauthorized `socket` domains, and `execve`).
* **Dependency Requirement**: Direct kernel `prctl(PR_SET_SECCOMP)` interface or lightweight `libseccomp` wrapper.

### 3. Bubblewrap (`bwrap`)
* **Project**: Bubblewrap
* **Repository**: `https://github.com/containers/bubblewrap`
* **License**: LGPL-2.0-or-later
* **Maintenance & Activity**: Actively maintained by Red Hat, Flatpak, and GNOME container engineers. Standard foundation for Flatpak desktop sandboxing.
* **Security Track Record & Assessment**: Bubblewrap is a sandbox-construction tool, not a complete security policy. While historically robust and unprivileged by design, past CVEs (e.g., CVE-2020-5291, CVE-2019-8559) highlight the importance of version verification.
* **AgenticOS Requirements for Bubblewrap**:
  1. AgenticOS checks the installed/selected Bubblewrap version at runtime.
  2. AgenticOS checks relevant security advisories and maintains a vulnerability blacklist.
  3. AgenticOS rejects known-vulnerable versions and halts execution if an insecure binary is detected.
  4. AgenticOS pins approved versions for reproducible and verified builds.
* **Role in Architecture**: Sandbox-construction tool. Used to provision private mount namespaces (`tmpfs` root, selective directory bind mounts), unshare network interfaces (`--unshare-net`), and isolate PID trees (`--unshare-pid`) for higher-risk execution profiles.
* **Dependency Requirement**: External binary utility (`/usr/bin/bwrap`). Available out of the box on standard Ubuntu desktop installations.

### 4. systemd User Sandboxing & cgroups v2
* **Project**: systemd
* **Repository**: `https://github.com/systemd/systemd`
* **License**: LGPL-2.1-or-later
* **Maintenance & Activity**: Core system and service manager for Linux, actively maintained by systemd maintainers and Linux distribution vendors.
* **Security Track Record**: Enterprise-grade service isolation and cgroups v2 resource accounting.
* **Role in Architecture**: Resource limiter and daemon supervisor. Enforces memory quotas (`MemoryMax`), CPU quotas (`CPUQuota`), process count ceilings (`TasksMax`), and overall session isolation for long-running AgenticOS background daemons.
* **Dependency Requirement**: Already present as the host init and session manager on Ubuntu.

---

## Threat-Model Mapping

Mapping threats identified in [`docs/threat-model.md`](file:///home/lokamanya/AI%20Agentic%20OS/docs/threat-model.md) to specific sandbox and policy defenses:

| Threat Category | Threat Mechanism | Mitigating Architectural Layer | Specific Defense Mechanism |
| :--- | :--- | :--- | :--- |
| **Prompt Injection (Direct & Indirect)** | Untrusted input instructs agent to destroy data or access private keys. | **Layer 8: Policy Engine**<br>**Layer 9: Sandbox Confinement** | • Policy Engine evaluates target paths against declarative rulesets (`ALLOW/DENY/CONFIRM`).<br>• Sensitive paths (`~/.ssh`, `/etc/shadow`) are never mounted into sandbox.<br>• Landlock denies path access even if path exists in parent environment. |
| **Path Traversal & Symlink Attacks** | Parameter input contains `../../etc/passwd` or symlinks pointing outside workspace. | **Layer 8: Policy Engine**<br>**Layer 9: Bubblewrap & Landlock** | • Path validation uses canonicalization as a validation step, combined with race-resistant kernel pathname resolution (such as `openat2()` with appropriate `RESOLVE_*` restrictions like `RESOLVE_BENEATH` and `RESOLVE_NO_SYMLINKS`) where applicable.<br>• Bubblewrap mounts only the target workspace; paths outside bind mounts simply do not exist (`ENOENT`).<br>• Landlock checks inode hierarchy at path walk time as an independent kernel access-control layer. |
| **Arbitrary Command Execution** | Injection of shell metacharacters (`\|`, `;`, `&&`, `$()`) or execution of untrusted binaries. | **Layer 8: Architectural Mandate**<br>**Layer 9: seccomp-bpf & Mount NS** | • Absolute prohibition of shell interpreters (`/bin/sh`, `/bin/bash`).<br>• Bubblewrap omits shell binaries from sandbox mount namespace.<br>• seccomp-bpf filter returns `SECCOMP_RET_ERRNO(EPERM)` or `SECCOMP_RET_KILL_PROCESS` on unauthorized `execve`/`execveat`. |
| **Excessive Permissions & Privilege Escalation** | Capability process attempts to acquire root or elevate via setuid binaries. | **Kernel / Sandbox Core** | • Mandatory `PR_SET_NO_NEW_PRIVS` prevents setuid transitions.<br>• Capability bounding sets stripped.<br>• Unprivileged user namespace maps process to non-root UID. |
| **Secret Exposure & Credential Theft** | Malicious code attempts to read user SSH keys, cloud tokens, or browser credentials. | **Layer 8: Policy Engine**<br>**Layer 9: Namespace Isolation** | • Hardcoded `DENY` rules in Policy Engine for `~/.ssh`, `~/.gnupg`, `~/.config/gcloud`.<br>• Home directory is not mounted into sandbox; unshared mount namespace hides host user directory.<br>• Secrets are never passed into capability environments. |
| **Network Exfiltration** | Capability attempts to transmit stolen data to external internet endpoints. | **Layer 9: Network Namespace**<br>**Layer 9: seccomp-bpf** | • `--unshare-net` creates private network namespace with only an isolated loopback.<br>• seccomp blocks `socket(AF_INET, ...)` and `socket(AF_INET6, ...)`.<br>• Internal communication restricted to local Unix Domain Socket descriptors. |
| **Fork Bombs & Resource Starvation** | Buggy or malicious capability spawns endless processes or consumes all RAM. | **Layer 10/12: systemd cgroups v2**<br>**Kernel: rlimits** | • `TasksMax` caps maximum child processes.<br>• `MemoryMax` and `setrlimit(RLIMIT_AS)` prevent out-of-memory host crashes.<br>• `CPUQuota` prevents core starvation. |

---

## Decision: Multi-Layered Hybrid Sandbox Architecture

We adopt **Option 4: Multi-Layered Hybrid Architecture** as a **defense-in-depth containment architecture**.

No single mechanism provides a complete containment architecture:
* **Landlock** is an access-control mechanism for kernel objects and path rights.
* **seccomp** is a system call filter.
* **Bubblewrap** is an unprivileged sandbox-construction tool for Linux namespaces.
* **systemd** provides cgroup v2 resource limits and daemon supervision.
* **The AgenticOS Policy Engine** is the deterministic semantic authority.

```
+---------------------------------------------------------------------------------------+
| LAYER 8: POLICY & PERMISSION ENGINE (DETERMINISTIC GATEWAY)                           |
| • Validates typed parameters against JSON Schema.                                     |
| • Validates paths (canonicalization + race-resistant resolution restrictions).         |
| • Evaluates security policy rules: ALLOW (auto), DENY (reject), CONFIRM (prompt user).|
| • Constructs the minimal CapabilitySecurityProfile for execution.                     |
+---------------------------------------------------------------------------------------+
                                           │
                                           │ (ALLOW or Confirmed)
                                           ▼
+---------------------------------------------------------------------------------------+
| LAYER 9: CAPABILITY EXECUTION LIFECYCLE (DEFAULT EXECUTION MODEL)                     |
|                                                                                       |
|   AgenticOS Supervisor                                                                |
|       │ (Spawns dedicated process over private socketpair)                            |
|       ▼                                                                               |
|   Dedicated Capability Worker Process                                                 |
|       │                                                                               |
|       ├─► [Profile 1: Standard / Low-Risk Profile]                                    |
|       │   • Sandbox restrictions (Landlock + seccomp) applied BEFORE code execution   |
|       │   • PR_SET_NO_NEW_PRIVS & dropped capabilities                                |
|       │                                                                               |
|       └─► [Profile 2: Stronger / High-Risk Profile]                                   |
|           • Bubblewrap namespace container (--unshare-all, clean tmpfs /, isolated PID)|
|           • In-container Landlock + seccomp applied BEFORE code execution             |
|       │                                                                               |
|       ▼                                                                               |
|   Capability Execution (Typed, discrete operation)                                    |
|       │                                                                               |
|       ▼                                                                               |
|   Verification & Telemetry Capture                                                    |
|       │                                                                               |
|       ▼                                                                               |
|   Worker Termination (Process reaped; namespaces destroyed)                           |
+---------------------------------------------------------------------------------------+
                                           │
                                           ▼
+---------------------------------------------------------------------------------------+
| SYSTEM SUPERVISION (cgroups v2 & systemd)                                             |
| • MemoryMax, CPUQuota, TasksMax enforce hard resource limits.                         |
| • Terminating workers are reaped cleanly by kernel process/namespace lifecycle.       |
+---------------------------------------------------------------------------------------+
```

---

## Exact Responsibility Allocation

### 1. What Must Remain Enforced by AgenticOS Policy Engine (Layer 8)
The Policy Engine is the **semantic and intent authority**. The kernel has no understanding of human intent, multi-step goals, or workspace definitions:
* **Schema & Type Validation**: Enforces that capability inputs strictly match declared schemas before execution.
* **Semantic Path Validation**: Validates paths using canonicalization as an initial verification step, while capability workers employ race-resistant kernel pathname resolution (such as `openat2()` with appropriate resolution restrictions like `RESOLVE_BENEATH` / `RESOLVE_NO_SYMLINKS`) where applicable when opening files, backed by Landlock and sandbox filesystem isolation as additional layers.
* **Three-Tier Policy Evaluation**: Decides whether an operation is `ALLOW`, `DENY`, or requires human `CONFIRM`.
* **Credential Protection**: Imposes absolute `DENY` rules on sensitive credential stores (`~/.ssh`, `~/.gnupg`, etc.).
* **Profile Construction**: Synthesizes the exact `CapabilitySecurityProfile` (bind mounts, Landlock access masks, syscall whitelists, resource limits) required for the approved operation.

### 2. What Must Be Enforced by the Sandbox & Kernel (Layer 9 & Linux)
The sandbox and Linux kernel form the **enforcement and containment boundary**. They protect against bugs, escapes, or compromised capability runners:
* **Mount & Filesystem Isolation**:
  * Bubblewrap ensures unmounted host paths simply do not exist in the filesystem view.
  * Landlock LSM restricts operations on mounted paths to approved access masks (`LANDLOCK_ACCESS_FS_READ_FILE`, `LANDLOCK_ACCESS_FS_WRITE_FILE`).
* **Syscall Filtering**:
  * `seccomp-bpf` intercepts and blocks unauthorized syscalls before kernel execution begins.
* **Network Isolation**:
  * Linux network namespaces ensure no network interfaces exist for sandboxed code.
* **Privilege & Process Boundaries**:
  * `PR_SET_NO_NEW_PRIVS` prevents privilege escalation.
  * PID namespaces isolate process visibility.
* **Resource Clamping**:
  * cgroups v2 enforce memory and CPU ceilings.

---

## Failure & Violation Semantics

### What Happens When Sandbox Creation Fails
* **Fail-Closed Semantics**: If sandbox initialization fails for *any* reason (e.g., `bwrap` launch error, Landlock ruleset creation failure, seccomp compilation failure, namespace exhaustion):
  1. The execution is **immediately aborted**.
  2. **No un-sandboxed fallback execution is permitted under any circumstances.**
  3. A structured `CapabilityExecutionError` is returned to the runtime with error code `SANDBOX_INITIALIZATION_FAILED`.
  4. A high-priority security audit event is recorded in the Layer 12 audit log.
  5. The overarching workflow or goal enters a suspended failure state awaiting supervisor intervention.

### What Happens When a Capability Attempts a Prohibited Action
* **Kernel-Level Interception**:
  * If a process attempts an unauthorized filesystem operation, Landlock causes the syscall (`openat`, `unlink`, `rename`) to fail immediately with `EACCES` or `EPERM`.
  * If a process invokes a prohibited syscall (e.g., `execve` in a read-only profile, `socket(AF_INET)` in a no-net profile, or `ptrace`), seccomp-bpf triggers the configured policy action:
    * **Default action for severe violations**: `SECCOMP_RET_KILL_PROCESS` (immediate kernel termination of the offending process).
    * **Handled action for non-fatal violations**: `SECCOMP_RET_ERRNO(EPERM)` (returns permission denied to caller).
* **Runtime Response**:
  * The supervising runtime detects process termination via `POLLHUP`/`read() == 0` on the IPC socket or via `waitpid()`.
  * The capability invocation is recorded as `VIOLATION_TERMINATED`.
  * Any pending transactional state changes are rolled back.
  * The agent that requested the capability is notified of the violation; repeated violations trigger automatic agent suspension.

---

## Recommended Sandbox Profiles

### Profile 1: Default Low-Risk Filesystem Capability (e.g., `fs.read_file`)
Designed for efficient, frequent, read-only inspection of approved workspace files:
* **Execution Model**: Dedicated capability worker process spawned by supervisor; sandbox restrictions (Landlock + seccomp) applied BEFORE capability code executes; communicates via private anonymous `socketpair(2)`; executes typed operation; verifies result; terminates immediately.
* **Filesystem Access**:
  * Landlock ruleset applied: read-only access (`LANDLOCK_ACCESS_FS_READ_FILE`, `LANDLOCK_ACCESS_FS_READ_DIR`) restricted strictly to the canonicalized workspace directory descriptor.
  * All write, make, rename, delete, and truncate rights are stripped.
* **Network Access**: None. Sockets blocked via seccomp; Landlock network rules applied where supported by the probed kernel ABI.
* **Syscall Filter (seccomp-bpf)**:
  * Strict whitelist: basic memory allocation (`mmap`, `brk`), basic file reading (`read`, `close`, `fstat`, `lseek`), and IPC (`recvmsg`, `sendmsg` on inherited socket).
  * Explicitly blocked: `execve`, `execveat`, `fork`, `clone`, `clone3`, `socket`, `connect`, `bind`, `ptrace`, `bpf`.
* **Privileges**: `PR_SET_NO_NEW_PRIVS` set; all Linux capabilities dropped.
* **Shell Access**: Prohibited; no shell interpreter exists in the execution path.

### Profile 2: Stronger High-Risk Capability (e.g., Purpose-Specific Execution: `python.run`, `compiler.run`, `test.run`)
Designed for executing purpose-specific external binaries, compilers, or test runners that require temporary workspaces:
* **Prohibition of Generic Execution**: Generic arbitrary-script or arbitrary-command execution capabilities (such as arbitrary script runners or shell invocations) are strictly prohibited. Future execution capabilities must be purpose-specific and typed, such as `python.run`, `compiler.run`, and `test.run`. Each capability must declare its executable binary, arguments, filesystem scope, network requirements, and resource limits.
* **Execution Model**: Dedicated capability worker process launched inside an isolated container constructed via Bubblewrap (`/usr/bin/bwrap`); sandbox restrictions applied BEFORE capability code executes; terminates immediately upon completion and verification.
* **Namespace Isolation**:
  * `--unshare-all`: unshares mount, PID, network, IPC, and UTS namespaces.
  * `--unshare-net`: zero network connectivity (isolated loopback only).
  * `--unshare-pid`: process sees itself as PID 1; host processes invisible.
* **Filesystem Layout**:
  * Root (`/`): Pristine, read-only `tmpfs`.
  * System libraries: Read-only bind mount of `/usr` and `/lib` (`--ro-bind /usr /usr`, `--ro-bind /lib /lib`).
  * Temporary directory: Ephemeral, isolated `tmpfs` mounted at `/tmp` (`--tmpfs /tmp`).
  * Workspace: Selective bind mount of target workspace directory (read-only or read-write as authorized by Policy Engine).
  * Excluded: `/home`, `/root`, `/etc/shadow`, `/etc/sudoers`, `/boot`, `/dev` (only minimal devnodes created via `--dev /dev`).
* **In-Container Confinement**:
  * Landlock applied inside the container to restrict access strictly to the workspace bind mount.
  * seccomp-bpf applied to block kernel attack vectors (`ptrace`, `bpf`, `kexec_load`, namespace re-entry).
* **Resource Limits (cgroups v2 & rlimits)**:
  * Memory ceiling: e.g., 512 MB (`RLIMIT_AS` and cgroup `MemoryMax`).
  * CPU execution timeout: Monotonic watchdog timer (e.g., 10,000 ms hard timeout).
  * Task ceiling: `TasksMax=32` to prevent fork bombs.
* **IPC**: Dedicated anonymous `socketpair(2)` passed across `bwrap` boundary. Optional `SCM_RIGHTS` descriptor passing governed by capability profile.

---

## Consequences

### Positive
* **True Defense-in-Depth**: A bypass or vulnerability in any single mechanism (e.g., a path traversal attempt that evades path canonicalization) is stopped dead by the namespace boundary, race-resistant resolution (`openat2`), and Landlock ruleset.
* **Strict Least Privilege**: Each capability receives only the specific filesystem paths, syscalls, and resources required for its discrete task.
* **Zero Ambient Privilege**: Entire sandboxing subsystem operates in unprivileged user space without setuid binaries, root daemons, or custom kernel patches.
* **Seamless Compatibility**: Perfectly integrates with the local Unix Domain Socket IPC architecture established in ADR-0002.
* **Auditable & Deterministic**: Security boundaries are declared as verifiable code constructs rather than probabilistic model guidelines.

### Negative / Trade-offs
* **Implementation Effort**: Requires implementing Landlock and seccomp rule generators and Bubblewrap argument builders.
* **Process Launch Overhead**: Capabilities invoking `bwrap` incur a 5–15 ms process spawn latency (mitigated by using direct Landlock/seccomp worker setup for high-frequency low-risk read operations).
* **Kernel Version Sensitivity**: Landlock features vary across kernel ABI versions. AgenticOS must probe the Landlock ABI at runtime, detect supported features, construct the strongest compatible profile, fail closed when required security guarantees cannot be provided, and test compatibility across supported kernels.

---

## Phase 4.1 Implementation Amendment (2026-09-29)

Phase 4.1 implements the foundational execution lifecycle and descriptor hygiene contracts:
1. **Worker Process Lifecycle**:
   * Out-of-process isolation: CapabilitySupervisor never executes capability logic directly in the supervisor process.
   * Fork sequence: Supervisor allocates an `AF_UNIX` `SOCK_SEQPACKET` socketpair and two pipes (stdout and stderr), then invokes `fork()`.
2. **File Descriptor Lifecycle**:
   * Child side:
     - Stdin (FD 0) redirected to `/dev/null`.
     - Stdout (FD 1) redirected to `stdout_pipe_write`.
     - Stderr (FD 2) redirected to `stderr_pipe_write`.
     - Worker IPC channel redirected to FD 3.
     - Atomically closes all descriptors $\ge 4$ via `close_range(4, ~0U, 0)` before child entrypoint execution.
   * Supervisor side:
     - Immediately closes `worker_ipc_fd`, `stdout_pipe_write`, `stderr_pipe_write` upon successful spawn.
     - Retains strictly: `supervisor_ipc_fd`, `stdout_pipe_read`, `stderr_pipe_read`.
3. **Diagnostics & Rolling Stdio Buffers**:
   * Supervisor maintains independent 64 KiB rolling ring buffers (`RollingLogBuffer`) for stdout and stderr to prevent memory exhaustion from verbose workers while retaining the most recent diagnostic context via rolling FIFO truncation.
   * Multiplexed non-blocking polling drains pipes until true EOF after process termination.
4. **Process Termination & Escalation Ladder**:
   * Wall clock execution timeout (default 30s, max 300s).
   * Cooperative termination via SIGTERM with a 500ms grace period.
   * Escalation to SIGKILL on grace period expiration, reaped via non-blocking or blocking `waitpid`.

