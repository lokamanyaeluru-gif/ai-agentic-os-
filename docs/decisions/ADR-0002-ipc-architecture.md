# ADR-0002: IPC Architecture for Internal Subsystems and Linux Desktop Integration

* **Status**: PROPOSED  
* **Date**: 2026-09-27  
* **Phase**: 0.3.1  

---

## Context

AI Agentic OS requires an Inter-Process Communication (IPC) architecture to link its architectural layers:
* **Internal Subsystems**: Component-to-component coordination, agent-to-agent communication, agent-to-capability dispatch, and capability-to-sandbox isolation (Layers 1–9, 11–12).
* **Linux Desktop & System Integration**: Interactions with host OS services such as `systemd`, `logind`, `NetworkManager`, Wayland compositors, desktop notifications, and desktop portals (Layer 10).

### Evaluated Options

1. **Option A: Pure Unix Domain Sockets (UDS)**:
   POSIX `AF_UNIX` sockets (`SOCK_STREAM` or `SOCK_SEQPACKET`) with structured message framing and serialized payloads (such as JSON Schema or Protocol Buffers).
2. **Option B: Pure D-Bus**:
   Standard Linux desktop message bus, brokered via `dbus-daemon` or `dbus-broker`, using standard D-Bus wire protocol, bus policy, and XML interfaces.
3. **Option C: Pure gRPC over Unix Domain Sockets**:
   RPC framework using Protocol Buffers and HTTP/2 framing bound to local filesystem paths (`unix:///path/to/socket`).
4. **Option D: Hybrid Split Architecture**:
   Direct Unix Domain Sockets (leveraging private `socketpair` lifecycles and filesystem UDS) for internal AgenticOS communication, paired with dedicated Layer 10 D-Bus Adapters for Linux desktop and host system services.

### Evaluation Criteria

The options were evaluated across 13 core architectural criteria:
1. **Security**: Defense-in-depth, caller verification, access control, and isolation guarantees.
2. **Local-Only Operation**: Enforceability of strictly offline, machine-local communication with zero network exposure.
3. **Permission Control**: Fine-grained, verifiable caller identity and authorization checks.
4. **Reliability**: Deterministic message delivery, predictable buffering, and fault containment.
5. **Typed Contracts**: Explicit, machine-verifiable interface definitions and schema evolution.
6. **Debugging**: Introspectability, observability, and ease of tracing.
7. **Performance**: Latency characteristics, throughput, context switching, and resource overhead.
8. **Linux Integration**: Interoperability with standard modern Linux desktop and system subsystems.
9. **Implementation Complexity**: Implementation burden, operational surface, and architectural footprint.
10. **Suitability for Single-User Linux Desktop**: Alignment with local user session primitives (`/run/user/$UID`).
11. **Future Multi-Agent Communication**: Scalability to concurrent, high-frequency inter-agent message exchanges.
12. **Multi-Language Support**: Portability across potential runtime languages (Rust, Go, Python, C/C++).
13. **Long-Term Maintainability**: Freedom from obsolete patterns, vendor lock-in, and fragile dependencies.

---

## Evaluation Comparison Matrix

| Evaluation Criterion | Option A: Pure UDS | Option B: Pure D-Bus | Option C: Pure gRPC (UDS) | Option D: Hybrid (UDS Internal + Layer 10 D-Bus) |
| :--- | :--- | :--- | :--- | :--- |
| **1. Security** | **High**: Kernel-enforced credentials (`SO_PEERCRED`), point-to-point private endpoints, optional descriptor passing (`SCM_RIGHTS`). | **Standard**: Provides authentication and bus policy; shared session bus requires explicit filtering rules to restrict visibility. | **Good**: Process auth supported over UDS, but its RPC/HTTP2 abstraction is unnecessary for local component IPC and does not naturally support our planned descriptor-delegation model. | **High Isolation**: High isolation for internal traffic via private UDS endpoints; mediated, filtered access to host D-Bus through dedicated Layer 10 adapters. |
| **2. Local-Only Operation** | **Strict**: Kernel POSIX domain; cannot bind to network interfaces. Zero network attack surface. | **Strict**: Confined to local IPC sockets. | **Configurable**: Binds to local socket paths, but HTTP/2 transport retains latent network stack mechanisms. | **Strict**: All internal paths strictly local; Layer 10 bridges only to local host buses. |
| **3. Permission Control** | **Kernel-Level**: Verifiable PID/UID/GID via `SO_PEERCRED`; private `socketpair` inheritance. | **Broker-Enforced**: Policy XML rules evaluated by `dbus-daemon`/`dbus-broker`. | **Application-Level**: Token/metadata-based; OS peer credentials not uniformly exposed across language bindings. | **Dual-Level**: Kernel `SO_PEERCRED` for internal components; standard policy for host D-Bus. |
| **4. Reliability** | **High**: Point-to-point; no intermediary daemon crash can take down independent execution pipelines. | **Moderate**: Dependent on central broker health; broker congestion can stall dependent services. | **High**: Resilient HTTP/2 connection management and streaming retries. | **High**: Core subsystems operate peer-to-peer even if desktop D-Bus broker hangs or restarts. |
| **5. Typed Contracts** | **Protocol Agnostic**: Requires framing and serialization schema (e.g., Protobuf or strict JSON Schema). | **Built-in**: XML introspection interfaces and typed variant signatures. | **Native**: First-class Protocol Buffers (`.proto`) with code-generated stubs. | **Best of Both**: Strong schemas (Protobuf/JSON) internally; standard D-Bus introspection for host integration. |
| **6. Debugging** | **Good**: Standard Linux tooling (`strace`, `lsof`, `ss -x`, `bpftrace`). | **Excellent**: GUI and CLI tools (`busctl`, `d-spy`, `bustle`, `dbus-monitor`). | **Good**: Standard gRPC tracing tools, reflection, and OpenTelemetry hooks. | **Comprehensive**: `strace`/`ss` internally; `busctl`/`d-spy` for all host-level interactions. |
| **7. Performance** | **Low Overhead**: Direct in-kernel buffer copy, minimal context switching, zero serialization tax for raw buffers. | **Moderate**: Broker mediation adds context switches and serialization overhead; higher latency than direct peer-to-peer IPC. | **Moderate**: Protocol overhead from HTTP/2 framing, HPACK header compression, and connection flow control. | **Balanced**: Low-overhead direct peer-to-peer internal coordination; broker routing overhead limited strictly to desktop integration tasks. |
| **8. Linux Integration** | **Poor (Alone)**: Cannot directly talk to `systemd`, `logind`, or desktop portals without custom bridges. | **Native**: Universal Linux desktop/system standard. | **Poor**: Not recognized by Linux desktop environments or `systemd`. | **Native**: Layer 10 bridge seamlessly communicates with all Linux desktop and system services. |
| **9. Implementation Complexity** | **Low**: Minimalist POSIX socket primitives; requires defining a minimal, versioned, typed IPC protocol. | **High**: Heavy dependency on D-Bus wire protocol, type marshaling, and broker lifecycle. | **Very High**: Heavy runtime dependencies, complex build tools, large static binary footprint. | **Balanced**: Minimal, versioned, typed internal UDS protocol + standard D-Bus client library at Layer 10. |
| **10. Suitability for Single-User Desktop** | **High**: Cleanly maps to `/run/user/$UID/agenticos/` private runtime hierarchies. | **High**: Matches XDG desktop session architecture. | **Moderate**: Enterprise microservices design misfit for desktop OS orchestration. | **High**: Cleanly bifurcates internal OS machinery from desktop session interactions. |
| **11. Future Multi-Agent Scaling** | **High**: Scalable point-to-point channels; private endpoints prevent crosstalk. | **Moderate**: Shared bus architecture can become a bottleneck under high-volume inter-agent messaging. | **Good**: Robust streaming RPCs, but higher per-connection memory footprint. | **High**: Dedicated point-to-point UDS channels between agents scale linearly without broker saturation. |
| **12. Multi-Language Support** | **Universal**: Every language supports POSIX domain sockets; schemas compile to any target. | **Good**: Libraries exist for C, Rust (`zbus`), Python, Go, but APIs are complex and idiosyncratic. | **Universal**: First-class code generation for all modern programming languages. | **Universal**: UDS + serialization libraries supported universally across all languages. |
| **13. Long-Term Maintainability** | **High**: POSIX socket APIs and kernel `AF_UNIX` are standard, long-term Linux ABI. | **Stable**: Long-term desktop standard, but maintenance burden of XML configurations. | **Moderate**: Fast-moving ecosystem with periodic dependency updates. | **High**: Built on standard POSIX primitives with isolated, swappable host adapters. |

---

## Real-World Reference Projects Evaluation

1. **Linux Kernel `AF_UNIX` with `SCM_RIGHTS` & `SO_PEERCRED`**:
   * **License**: GPL-2.0-only.
   * **Maintenance**: Actively maintained as a foundational Linux kernel subsystem.
   * **Security Track Record**: Gold standard for local POSIX IPC. `SO_PEERCRED` provides kernel-verified peer PID, UID, and GID. `SCM_RIGHTS` provides an optional kernel capability to transfer open file descriptors.
   * **Relevance**: Fundamental Linux IPC primitive for internal AgenticOS communication.
2. **Flatpak / Bubblewrap (`bwrap`) Sandboxing IPC Architecture**:
   * **License**: LGPL-2.1-or-later.
   * **Maintenance**: Highly active (standard containerized application runtime on Linux desktops).
   * **Security Track Record**: Strong security record across desktop distributions. Bubblewrap uses private anonymous `socketpair(2)` descriptors during initialization and filters host D-Bus communication using proxies (such as `xdg-dbus-proxy`).
   * **Relevance**: Evaluated as a sandbox-construction and reference tool for isolation patterns. It demonstrates the utility of private socketpairs for sandbox initialization and proxying host D-Bus traffic. Bubblewrap serves as a reference tool rather than the complete AgenticOS security boundary; the comprehensive sandbox architecture and technology selection remain TBD for Phase 0.3.
3. **Wayland Display Protocol Architecture (`libwayland`)**:
   * **License**: MIT.
   * **Maintenance**: Active (modern Linux display architecture).
   * **Security Track Record**: Replaced X11's shared memory and ambient event model with dedicated point-to-point Unix domain sockets, transferring pixel buffers via shared memory file descriptors (`memfd_create`) and `SCM_RIGHTS`.
   * **Relevance**: Demonstrates that modern Linux desktop subsystems achieve high performance and strong process isolation using lightweight framing over private UDS with descriptor passing rather than a shared bus.
4. **`dbus-broker` & `zbus`**:
   * **Licenses**: `dbus-broker` (Apache-2.0), `zbus` (MIT).
   * **Maintenance**: Highly active. `dbus-broker` is the default high-performance Linux system bus broker in modern distributions. `zbus` is the modern pure-Rust D-Bus implementation.
   * **Security Track Record**: Provides robust broker-level authentication and policy checks. D-Bus session buses are shared across user session processes, requiring explicit policies to restrict method calls and signal visibility.
   * **Relevance**: Selected as the target implementation pattern for the Layer 10 Linux Integration boundary.
5. **gRPC over UDS (Tonic / gRPC-Go)**:
   * **Licenses**: Apache-2.0 / MIT.
   * **Maintenance**: Highly active.
   * **Security Track Record**: Mature security and authentication model over network and local transports.
   * **Relevance**: Evaluated for internal IPC. gRPC is not selected for our internal IPC because its RPC/HTTP2 abstraction is unnecessary for our local component communication and does not naturally support our planned descriptor-delegation model, while adding substantial library and runtime footprint.

---

## Decision

We adopt **Option D: The Hybrid Split IPC Architecture**.

### 1. Internal AgenticOS IPC (Layers 1–9, 11–12)
All internal communication is routed over **Unix Domain Sockets (`AF_UNIX`)** using a **minimal, versioned, typed IPC protocol**:
* **Point-to-Point Ephemeral Channels**:
  * Capability execution (Layer 9 to Capability Runner) and sandboxed worker coordination can leverage private, anonymous **`socketpair(2)`** descriptors established before process execution or sandboxing.
  * Because communication is confined to the file descriptors held by the parent and child processes, no filesystem socket path is exposed, preventing external connection attempts.
* **Persistent Daemon / Service Channels**:
  * Inter-subsystem services (Global Agent Manager, Knowledge & Memory, Observability) bind to private filesystem sockets residing under `/run/user/$UID/agenticos/*.sock`.
  * Permissions are strictly enforced via POSIX filesystem controls: parent directories set to `0700` and socket nodes set to `0600` (owned exclusively by the user).
  * Socket handshakes verify caller identity via kernel `SO_PEERCRED` before processing requests.
* **Framing and Serialization Protocol**:
  * Sockets utilize `SOCK_SEQPACKET` where preserved message boundaries are required, or length-prefixed framing over `SOCK_STREAM`.
  * The protocol requires minimal, versioned, typed contracts (such as Protocol Buffers or JSON Schema), whose exact serialization and framing implementation will be selected during implementation.
  * Descriptor delegation via **`SCM_RIGHTS`** is an available optional Linux capability to pass specific resources (open file handles, pipes, memory buffers) under least privilege. Exact descriptor delegation rules and sandbox integration remain subject to the sandbox design decision.

### 2. Linux Desktop and System Integration (Layer 10 Boundary)
Host system communication is isolated within dedicated **D-Bus Adapters** in Layer 10:
* D-Bus provides standard authentication and bus policy mechanisms for host system interaction. The Linux Integration Layer interacts with the host **Session Bus** (for desktop notifications, window managers, portals) and the host **System Bus** (for `systemd`, `logind`, `NetworkManager`).
* AgenticOS keeps sensitive internal agent traffic, reasoning, and memory off the shared host bus, restricting D-Bus usage strictly to Layer 10 adapters.
* Internal agent and capability components do not establish direct connections to host D-Bus instances. All desktop and system interactions must originate as typed capability invocations governed by Layer 8 (Security & Governance) and dispatched through Layer 9 to Layer 10 adapters.

---

## Security Implications

1. **Authentication**:
   * **Kernel-Enforced Peer Verification**: On filesystem-bound sockets, the receiving daemon inspects `SO_PEERCRED` upon connection, obtaining the caller's PID, UID, and GID directly from the kernel before accepting requests.
   * **Private Socketpair Lifecycle**: Parent-child capability channels created via `socketpair(2)` rely on private descriptor inheritance across fork/exec. Access is restricted to processes holding the inherited file descriptors without exposing a filesystem node.
2. **Access Control**:
   * Sockets in `/run/user/$UID/agenticos/` are protected by POSIX filesystem permissions (`0700` directory, `0600` socket) restricting access to the user's UID.
   * Point-to-point socket semantics ensure that internal traffic remains confined to connected endpoints, avoiding exposure to third-party processes in the user session.
3. **Sandbox Isolation & Least Privilege**:
   * Sandboxing remains a mandatory architectural requirement for capability execution.
   * Where capability execution requires access to specific files, pipes, or buffers, `SCM_RIGHTS` is an available optional mechanism to pass specific open descriptors under least privilege, rather than granting broad directory access. Exact descriptor delegation rules and mechanisms remain subject to the sandbox design decision.
4. **Attack Surface**:
   * Zero network listening sockets (`AF_INET`/`AF_INET6` are prohibited).
   * No external daemon dependency for internal agent execution.
   * Minimizes vulnerability surface by avoiding complex network protocol parsers (HTTP/2, TLS) in internal processes.

---

## Failure and Recovery Considerations

1. **Crashed Components**:
   * Abrupt termination of a peer closes the socket, causing `read()` or `recvmsg()` to return EOF (`0`) or `POLLHUP`/`EPOLLERR`.
   * Supervising runtimes (Agent Runtime, Workflow Runtime) register socket file descriptors with `epoll(7)` and detect crashes promptly.
   * In-flight requests are marked as `FAILED` with an explicit crash reason; transactional state machines rollback uncommitted actions.
2. **Socket Cleanup & Stale Artifacts**:
   * Filesystem sockets reside in `/run/user/$UID/agenticos/` on `tmpfs`, ensuring clean lifecycle management tied to the user login session.
   * Daemons maintain an advisory lock (`flock` on `.lock` companion files). If a daemon crashes, a new instance detecting `ECONNREFUSED` unlinks the stale socket file and re-binds cleanly.
3. **Reconnection Protocols**:
   * Long-lived clients (e.g., UI connecting to Global Agent Manager) implement exponential backoff reconnection with randomized jitter.
   * Session tokens and sequence numbers allow clients to re-synchronize state upon reconnecting without duplicate execution.
4. **Deadlock Prevention**:
   * All internal socket communication enforces non-blocking I/O (`O_NONBLOCK`) combined with `epoll(7)` event loops.
   * Request-response interactions enforce deterministic timeouts.
   * Bounded message queue buffers prevent memory exhaustion or producer-consumer deadlocks.

---

## Consequences

### Positive
* **Low-Overhead Performance**: Direct point-to-point communication with in-kernel buffering and no intermediary broker context switching for internal traffic.
* **Robust Process & Capability Isolation**: Peer credential verification, private socketpair lifecycles, and optional `SCM_RIGHTS` descriptor passing support fine-grained least-privilege capability execution.
* **Resilience to Desktop Daemon Failures**: Internal OS intelligence, memory, and runtime continue executing reliably even if the desktop D-Bus broker is restarted or temporarily hung.
* **Native Desktop Compatibility**: Layer 10 preserves full compatibility with standard Linux desktops, `systemd`, and desktop portals.
* **Zero Dependency Bloat**: Eliminates the runtime overhead and binary footprint of complex external RPC frameworks.

### Negative / Trade-offs
* **Protocol Implementation Responsibility**: AgenticOS must define and maintain a minimal, versioned, typed IPC protocol and connection management lifecycle rather than adopting an off-the-shelf RPC framework.
* **Dual Paradigms**: Developers working on Layer 10 interact with D-Bus wire protocols and bus policies, while internal runtime developers work with POSIX UDS semantics.
