# ADR-0004: Implementation Language Architecture for AI Agentic OS

* **Status**: PROPOSED  
* **Date**: 2026-09-27  
* **Phase**: 0.3.3  

---

## Context

AI Agentic OS is designed as an AI-native desktop operating system layer positioned above Linux. It acts as an autonomous userspace control and intelligence plane, governing high-level user intent, agent lifecycles, structured memory, deterministic security policies, and sandboxed capability execution.

### Architectural Prerequisites from Previous Decisions
* **ADR-0001 (Deterministic Security & Local Operation)**: The LLM is never the authorization authority; no raw shell execution; deterministic policy engine mediates all actions.
* **ADR-0002 (IPC Architecture)**: Internal subsystem communication is strictly local via Unix Domain Sockets (`AF_UNIX`) using a minimal, versioned, typed protocol; Linux host/desktop integration is mediated via dedicated Layer 10 D-Bus adapters.
* **ADR-0003 (Sandbox Architecture)**: Multi-layered hybrid sandbox containment architecture combining the Policy Engine, systemd/cgroups v2, Bubblewrap namespace isolation, Landlock LSM path access control, and seccomp-bpf syscall filtering. Default execution model: supervisor spawns a dedicated capability worker process, applies sandbox restrictions before capability code executes, executes capability, verifies result, and terminates the worker.

### System Requirements for Implementation Language
To implement this architecture safely, the implementation language for the trusted AgenticOS control, security, and system-integration plane must satisfy systems-level demands:
1. **Memory Safety without Excessive Runtime Overhead**: Protection against buffer overflows, use-after-free, and memory corruption without garbage collection pauses or heavy runtime memory footprints.
2. **Low-Level Linux Systems Programming**: Ability to invoke Linux system calls (`prctl`, `landlock_*`, `openat2`, `clone3`, `seccomp`, `socketpair`, `epoll`), manipulate raw file descriptors, and inspect kernel credentials (`SO_PEERCRED`).
3. **Deterministic Thread & Process Management**: Capability to manage processes across `fork`/`exec` and configure sandboxes before executing child code without multithreading runtime corruption.
4. **Efficient IPC & Async I/O**: Event-driven non-blocking I/O over Unix Domain Sockets with low serialization and context-switching overhead.
5. **Predictable Local Deployment**: Compiles to standalone native ELF binaries that can be cleanly packaged into standard Ubuntu distribution formats (`.deb`).
6. **Local AI Interoperability**: Integration with local LLM runtimes (Ollama, `llama.cpp`, embedded ONNX/Candle) via local HTTP/REST or native C-ABI bindings.

---

## Evaluated Options

1. **Option 1: Pure Rust**:
   Implement the entire system, from control plane to all capabilities, in Rust.
2. **Option 2: Pure Go**:
   Implement the entire system in Go, relying on goroutines, channels, and Go's runtime.
3. **Option 3: Pure Python**:
   Implement the entire system in Python, relying on CPython and dynamic scripts.
4. **Option 4: Deliberate Polyglot Architecture (Rust-First Control Plane + Polyglot Sandboxed Workers)**:
   Implement the trusted AgenticOS control, security, and system-integration plane (Layers 2–12) in **Rust**, while providing strictly isolated, sandboxed capability workers for target execution languages (e.g., dedicated, sandboxed Python or tool workers) communicating exclusively over Unix Domain Sockets. The desktop UI technology remains a separate future decision while allowing a Rust-based UI stack.

---

## Evaluation Comparison Matrix (30 Criteria)

| Evaluation Criterion | Option 1: Pure Rust | Option 2: Pure Go | Option 3: Pure Python | Option 4: Rust-First Control Plane + Polyglot Workers (Recommended) |
| :--- | :--- | :--- | :--- | :--- |
| **1. Memory Safety** | **Compile-Time Safety**: Safe Rust enforces ownership and borrowing at compile time. Unsafe Rust and FFI boundaries require explicit review and containment. | **Runtime Safe**: Garbage-collected; safe from dangling pointers, but nil-pointer panics and data races remain possible. | **Interpreter Safe**: Safe at Python level, but native C extension modules retain C-level memory hazards. | **Strong Baseline**: Core control plane has compile-time memory safety in safe Rust; untrusted code is confined inside sandboxed worker processes. |
| **2. Concurrency Safety** | **Compile-Time Safety**: `Send` and `Sync` traits prevent data races at compile time in safe Rust code. | **Partial**: Goroutines and channels are ergonomic, but shared-memory data races can occur without runtime detection. | **Limited**: Global Interpreter Lock (GIL) limits true multi-core parallel concurrency in standard CPython. | **Robust Concurrency**: Compile-time concurrency safety in supervisor; worker processes run isolated in dedicated OS processes. |
| **3. Linux Systems Programming** | **Direct**: Direct access to POSIX/Linux syscalls (`libc`, `nix`) without runtime interference for kernel primitives. | **Capable with Caveats**: Go handles Linux process management, but some thread-scoped operations can be more complex due to the runtime M:N thread model. | **High-Level**: Requires `ctypes` or C extensions; awkward manipulation of low-level kernel structures and descriptors. | **Direct**: Direct kernel syscall access for supervisor; clean OS process boundary for capability execution. |
| **4. Unix Domain Socket IPC** | **Native & Ergonomic**: Full support for `SOCK_STREAM`, `SOCK_SEQPACKET`, `SO_PEERCRED`, and ancillary control messages (`SCM_RIGHTS`). | **Supported**: Strong UDS stream support; ancillary control messages (`SCM_RIGHTS`) require low-level `syscall` package handling. | **Moderate**: `socket` module supports UDS, but parsing `cmsghdr` for `SCM_RIGHTS` is verbose and dynamic. | **Native & Robust**: Type-safe UDS implementation with low-overhead framing and direct descriptor passing. |
| **5. D-Bus Integration** | **Native (Pure Rust)**: Modern, type-safe, async pure-Rust D-Bus client (`zbus`) without external C library linkage. | **External/CGO**: Relies on `godbus` or CGO bindings to `libdbus`; lacks native type-safe schema code generation. | **C Bindings**: Relies on `pydbus` or `dbus-python` wrapping `libdbus`; dynamic typing and interpreter overhead. | **Native & Isolated**: Layer 10 D-Bus adapters use pure-Rust `zbus`, completely isolated from capability execution. |
| **6. Process Management** | **Precise**: Full control over `fork`, `execve`, pre-exec configuration hooks (`CommandExt`), and signal handling. | **Managed**: Standard `os/exec` handles execution; custom pre-exec sandbox configurations require careful coordination with Go runtime threads. | **High-Level**: `subprocess` module lacks fine-grained pre-exec capability dropping and namespace configuration hooks. | **Precise**: Supervisor has explicit control over worker process creation, namespace initialization, and privilege dropping. |
| **7. Sandbox Integration** | **Direct**: Native bindings to `landlock`, `libseccomp`, and Bubblewrap invocation without runtime interference. | **Complex**: Go can perform sandbox setup, but coordinating thread-scoped security restrictions across goroutines requires `runtime.LockOSThread()`. | **Heavy**: Sandboxing Python processes confines the entire CPython interpreter rather than a minimal worker. | **Optimal**: Supervisor applies Landlock/seccomp directly within dedicated worker processes before payload execution. |
| **8. seccomp Interaction** | **Direct**: Direct BPF filter generation or `libseccomp` integration; applied cleanly in child process before execution. | **Complex**: Go runtime's internal thread management and background syscalls complicate minimal seccomp whitelists. | **Broad**: Python runtime requires a large set of syscalls for module imports, preventing tight minimal syscall whitelists. |
| **9. Landlock Interaction** | **Native**: Direct Landlock syscall bindings; runtime ABI probing and ruleset application without runtime interference. | **Feasible with TSYNC**: Modern Landlock supports multithreaded TSYNC enforcement, though runtime thread coordination remains a design factor. | **Indirect**: Requires external C-types bindings; rarely used in pure Python environments. | **Direct**: Runtime ABI probing and ruleset enforcement implemented natively in supervisor and workers. |
| **10. Filesystem & Security Code** | **Hardened**: Direct support for race-resistant kernel pathname resolution (`openat2` with `RESOLVE_BENEATH`) and strict path handling. | **Moderate**: Standard library path functions do not natively expose advanced Linux `openat2` resolution flags. | **Prone to TOCTOU**: High-level path functions (`os.path`) prone to time-of-check-to-time-of-use symlink races. | **Hardened**: Full access to race-resistant kernel pathname resolution (`openat2`) and Landlock access controls. |
| **11. Performance & Latency** | **Low Overhead**: Native compiled execution; low-latency dispatch; no garbage collection pauses. | **High Throughput**: Fast execution, but periodic GC pauses introduce latency jitter in high-frequency event loops. | **High Overhead**: Slower interpreted execution; dynamic overhead; GC and GIL contention. | **Low Overhead**: Core system operates with low overhead and no GC pauses; fast dispatch for lightweight capabilities. |
| **12. Binary Deployment** | **Self-Contained ELF**: Compiles to standalone native ELF binary with minimal external dependencies. | **Standalone ELF**: Compiles to standalone binary, but embeds the complete Go runtime and garbage collector. | **Complex**: Requires Python interpreter, virtual environments, system shared libraries, and package dependencies. | **Self-Contained ELF**: Core system distributes as a compact native binary; Python runtime invoked only if requested for worker tasks. |
| **13. Startup Time** | **Fast**: Low-overhead execution with no runtime bootstrap or virtual machine initialization. | **Moderate**: Fast initialization of Go runtime and garbage collector. | **High Latency**: Substantial interpreter startup and module import overhead for every worker process. | **Fast**: Low-overhead launch for high-frequency capability workers and responsive desktop IPC. |
| **14. Static Typing** | **Expressive & Strict**: Algebraic data types (enums), pattern matching, trait bounds, and compile-time null safety. | **Simple**: Structs and interfaces; lacks sum types/enums and expressive pattern matching; allows `nil` pointers. | **Dynamic / Optional**: Type hints exist (`mypy`), but are not enforced at runtime; prone to runtime type errors. | **Expressive & Strict**: Strong typing across core workflow state machines; typed schemas for external capability invocations. |
| **15. Error Handling** | **Compiler-Aided**: Fallible operations return `Result`/`Option` with compiler warnings on unused values; developers can still unwrap or ignore if careless. | **Explicit**: `if err != nil`, but lacks compiler enforcement to prevent ignoring returned error values. | **Exception-Based**: Uncaught exceptions can bubble up and terminate background threads unexpectedly. | **Compiler-Aided**: Fallible operations return explicit types in core; errors must be handled or explicitly propagated. |
| **16. Testing & Fuzzing** | **Integrated**: Built-in test runner; LLVM-backed fuzzing (`cargo-fuzz`); undefined behavior detection (`miri`). | **Built-in**: Native test runner and built-in fuzzing support. | **Extensive**: `pytest` ecosystem is mature, but fuzzing and low-level property testing are less integrated. | **Thorough**: Fuzz testing of IPC parsers, policy evaluators, and sandbox rule generators in Rust. |
| **17. Observability & Tracing** | **Structured**: `tracing` crate ecosystem provides async-aware span tracking and structured telemetry. | **Good**: Standard OpenTelemetry libraries; goroutine context propagation requires manual parameter passing. | **Flexible**: Dynamic logging and monkey-patching, but noticeable performance overhead for fine-grained tracing. | **Low Overhead**: Structured audit logging and distributed tracing without runtime performance degradation. |
| **18. Long-Term Maintainability** | **High**: Compiler enforces refactoring invariants; strict ABI stability; backward-compatible edition system. | **High**: Language simplicity aids readability, but lack of sum types leads to verbose boilerplate. | **Moderate**: Large Python codebases degrade in maintainability over time due to dynamic typing and dependency drift. | **High**: Core architecture remains robust across refactors; type system catches breaking changes at compile time. |
| **19. Developer Productivity** | **Steep Initial Curve**: Borrow checker requires upfront architectural rigor; high long-term refactoring velocity. | **High Initial**: Simple syntax, rapid onboarding, fast compilation speed. | **Rapid Initial**: Fast prototyping, but higher debugging cost for runtime type bugs and edge cases. | **Balanced**: Rust for core stability; Python available for high-level scripting tasks in capability workers. |
| **20. Ecosystem Maturity (Systems)** | **Extensive**: Standard language for modern Linux systems programming, CLI tools, and OS components. | **High (Cloud/Network)**: Dominates cloud microservices, but less tailored for desktop OS layers. | **High (Data/AI)**: Dominates machine learning and data science, but weak for low-level systems architecture. | **Well-Aligned**: Leverages Rust's systems ecosystem for OS components while accommodating AI libraries in workers. |
| **21. Linux Desktop Integration** | **Native**: Used by modern Linux desktop projects (Cosmic Desktop, Pop!_OS); native Wayland and FreeDesktop support. | **Limited**: Desktop ecosystem rarely uses Go; poor integration with Wayland, GTK, and desktop portal libraries. | **Legacy**: Widely used for desktop scripts, but higher startup latency and memory footprint impact desktop responsiveness. | **Native**: Clean integration with modern Linux desktop architectures and Wayland compositors. |
| **22. Local AI Runtime Interface** | **Direct**: Direct C-FFI to `llama.cpp` shared libraries; async HTTP to Ollama; native inference via Candle. | **Good**: Ollama is written in Go; easily connects via HTTP client. | **Native**: Direct access to Hugging Face, PyTorch, and local API wrappers. | **Direct & Flexible**: Rust connects to local Ollama/llama.cpp via HTTP/JSON; optional in-process inference via Candle. |
| **23. FFI & Interoperability** | **C ABI Compatibility**: Native C FFI; compiles to static C libraries or consumes C headers without runtime wrappers. | **Costly CGO**: CGO incurs goroutine stack switching overhead; complicates cross-compilation. | **Extensive**: C-API exists, but managing reference counts and GIL acquisition is error-prone. | **Direct**: Native integration with Linux kernel headers, C libraries, and low-level system facilities. |
| **24. Ubuntu Packaging** | **Self-Contained**: Standalone native ELF binary packages cleanly into standard Debian packages (`.deb`). | **Standalone**: Compiles to standalone ELF binary, though embeds the Go runtime. | **Complex**: Requires packaging Python virtual environments, system site-packages, and handling wheel conflicts. | **Self-Contained**: Compact `.deb` package containing core binary; integrates cleanly with systemd user units. |
| **25. Cross-Compilation** | **First-Class**: Native cross-compilation via `cargo build --target` across x86_64, aarch64, and RISC-V. | **First-Class**: Excellent built-in cross-compilation via `GOOS` and `GOARCH`. | **Complex**: Cross-compiling Python packages with C extensions is fragile. | **First-Class**: Straightforward cross-compilation for targeting different Linux architectures (x86_64, ARM64). |
| **26. Dependency Supply Chain** | **Audited & Reproducible**: `Cargo.lock` provides cryptographic checksums; `cargo-audit` detects vulnerabilities. | **Audited**: `go.sum` provides checksum verification; `govulncheck` audits dependencies. | **Vulnerable**: PyPI ecosystem has high frequency of typosquatting, malware injection, and dependency conflicts. | **Hardened**: Core system has minimal, cryptographically locked, audited crates; untrusted packages sandboxed. |
| **27. Long-Running Daemons** | **Predictable**: Stable memory utilization; low baseline memory footprint; no garbage collector pauses. | **Good**: Handles long-running daemons well, but GC heap management can lead to memory growth over time. | **Fragile**: Reference cycles and C extension allocations can lead to memory bloat over extended runtimes. | **Predictable**: Core daemons run with predictable memory utilization and no garbage collector overhead. |
| **28. Short-Lived Workers** | **Fast**: Worker processes start with minimal initialization overhead and low memory footprint. | **Moderate**: Go runtime bootstrap and GC initialization add overhead for micro-tasks. | **Heavy**: Interpreter spin-up and library loading make short-lived micro-capability execution sluggish. | **Fast**: Low-overhead worker spawn for high-frequency capability execution. |
| **29. Memory Footprint** | **Minimal**: Precise allocation; no VM, no garbage collector, low baseline memory overhead. | **Moderate**: Go runtime, garbage collector metadata, and goroutine stacks increase baseline memory. | **Heavy**: CPython interpreter and imported module trees consume substantial memory per process. | **Minimal**: Lightweight baseline memory footprint suitable for local desktop execution. |
| **30. Alignment with AgenticOS** | **Strong**: Meets architectural requirements for safety, determinism, sandboxing, and Linux integration. | **Partial**: Cloud microservice focus creates impedance with low-level Linux desktop sandboxing primitives. | **Unsuitable for Core**: Dynamic typing and lack of low-level systems control make it unsuitable for the security plane. | **Targeted Synergy**: Rust-first control and security plane provides safety; polyglot capabilities provide developer utility. |

---

## Real-World Reference Projects Evaluation

### 1. Cosmic Desktop (System76)
* **Project**: COSMIC Desktop Environment (`cosmic-epoch`, `cosmic-comp`, `cosmic-session`)
* **Repository**: `https://github.com/pop-os/cosmic-epoch`
* **License**: GPL-3.0 / MPL-2.0
* **Maintenance & Activity**: Actively maintained as the primary desktop environment for Pop!_OS and modern Ubuntu.
* **Demonstrated Architectural Proof**: Proves that an entire modern Linux desktop control layer—including the Wayland display compositor, session manager, application runtime, and system integration—can be implemented in Rust with high stability, performance, and memory safety compared to legacy desktop stacks.
* **Security & Reliability**: Greatly reduces memory corruption and race condition vulnerabilities historically prevalent in X11/GNOME C codebases.

### 2. AWS Firecracker
* **Project**: Firecracker MicroVM Runtime
* **Repository**: `https://github.com/firecracker-microvm/firecracker`
* **License**: Apache-2.0
* **Maintenance & Activity**: Production-grade, highly maintained infrastructure powering AWS Lambda and Fargate.
* **Demonstrated Architectural Proof**: Demonstrates that minimal, security-critical Linux system isolation runtimes utilizing `seccomp-bpf`, Linux cgroups, and raw POSIX syscalls are well-suited to Rust. AWS specifically selected Rust over Go and C to eliminate memory safety vulnerabilities while avoiding garbage collection pauses.

### 3. `zbus` (Pure Rust D-Bus)
* **Project**: `zbus`
* **Repository**: `https://github.com/dbus2/zbus`
* **License**: MIT
* **Maintenance & Activity**: Highly active, standard FreeDesktop Rust ecosystem component.
* **Demonstrated Architectural Proof**: Validates that Linux desktop IPC over D-Bus can be executed cleanly without linking to legacy C `libdbus` libraries, providing compile-time type-safe message marshaling and async integration.

### 4. Hugging Face Candle
* **Project**: Candle Minimalist ML Framework
* **Repository**: `https://github.com/huggingface/candle`
* **License**: Apache-2.0 / MIT
* **Maintenance & Activity**: Actively maintained by Hugging Face.
* **Demonstrated Architectural Proof**: Proves that local AI and LLM inference (LLaMA, Mistral, Whisper, BERT) can be executed natively in Rust with GPU acceleration (CUDA, Vulkan, Metal) without requiring Python or heavy external frameworks.

### 5. Ollama & `llama.cpp`
* **Projects**: Ollama (`https://github.com/ollama/ollama`, MIT) and `llama.cpp` (`https://github.com/ggerganov/llama.cpp`, MIT)
* **Demonstrated Architectural Proof**: Demonstrates that local neural models are accessible via local HTTP REST/JSON endpoints (`http://127.0.0.1:11434`) or direct C-ABI shared library links. An operating system control layer does not need to be written in Python to drive local AI models.

---

## Decision

We adopt **Option 4: Deliberate Polyglot Architecture with Rust-First Trusted Control Plane**.

### 1. Trusted Control & Security Plane: Rust
The trusted AI Agentic OS control plane, security infrastructure, and system integration services (Layers 2–12) shall be implemented in **Rust**:
* **Layer 2 (Intent Intelligence)**: Intent parser and schema validator.
* **Layer 3 (Goal Runtime)**: Goal state machine, progress monitor, and verification coordinator.
* **Layer 4 (Workflow Runtime)**: Deterministic DAG execution engine and checkpoint store.
* **Layer 5 (Global Agent Manager)**: Agent registry, lifecycle supervisor, and resource scheduler.
* **Layer 6 (Agent Runtime)**: Execution loop, tool dispatcher, and context builder.
* **Layer 7 (Knowledge & Memory)**: Local embedded SQLite/vector state store and memory manager.
* **Layer 8 (Security & Governance)**: Deterministic Policy & Permission Engine (`ALLOW`, `DENY`, `CONFIRM`), path canonicalizer, and capability manifest validator.
* **Layer 9 (Capability Layer & Sandbox Supervisor)**: Capability registry, Landlock ruleset generator, seccomp BPF filter compiler, Bubblewrap container launcher, and worker process supervisor.
* **Layer 10 (Linux Integration Layer)**: Pure-Rust D-Bus adapters (`zbus`) for host `systemd`, `logind`, `NetworkManager`, and Wayland desktop portals.
* **Layer 11 (Kernel & System Intelligence)**: Linux telemetry reader (`/proc`, `sysfs`, cgroups v2 metrics).
* **Layer 12 (Observability & Reliability)**: Structured append-only audit logger and crash recovery monitor.

### 2. Human Interface (Layer 1) & Desktop UI Technology
* **CLI and Core Daemon Client**: Authored in Rust for tight integration with internal UDS protocols.
* **Desktop UI Technology**: Kept as a separate future implementation decision. While a native Rust-based UI stack (e.g., Slint, iced, or COSMIC libcosmic) is permitted, the architecture does not permanently lock the final user interface presentation layer to Rust, provided that the UI connects to the trusted control plane strictly via the authenticated local IPC interface.

### 3. Polyglot Capability Plane: Isolated Process Sandboxing
AgenticOS explicitly supports polyglot capability execution outside the trusted core:
* **Native Rust Workers**: High-frequency micro-capabilities (such as file reads, system telemetry queries) run as lightweight native worker processes.
* **Sandboxed Python Workers**: Python remains a supported language for out-of-process, sandboxed capability workers (e.g., `python.run` for data analysis, machine learning scripts, or numerical evaluation).
* **Sandboxed Tool Workers**: Purpose-specific tools and external toolchains (e.g., `compiler.run`, `test.run`) run in dedicated containers.
* **Strict Process Boundary**: All capability workers run as dedicated OS processes outside the trusted core, enclosed within Bubblewrap namespaces and Landlock/seccomp profiles, communicating exclusively over private Unix Domain Sockets (`socketpair(2)`).

---

## Detailed Architectural Analyses

### 1. Security Analysis
* **Memory & Concurrency Safety**: Safe Rust provides compile-time memory and concurrency safety for supported safe-Rust code, eliminating buffer overflows, use-after-free, and data races. Unsafe Rust and FFI boundaries are confined to low-level syscall wrappers and require explicit review, testing, and containment.
* **Auditability of Systems Code**: Code requiring raw kernel pointers or low-level POSIX syscalls is isolated in dedicated modules with safe abstractions presented to higher-level domain logic.
* **Deterministic Sandbox Configuration**: In Rust, process creation and pre-exec hooks allow the supervisor to cleanly configure `PR_SET_NO_NEW_PRIVS`, Landlock LSM rulesets, and seccomp filters in the child process before capability code executes.

### 2. Developer Productivity & Maintainability Analysis
* **Compile-Time Invariant Enforcement**: Multi-step workflow graphs, authorization outcomes (`ALLOW`, `DENY`, `CONFIRM`), and state machine transitions are modeled using Rust's algebraic data types (`enum`) and exhaustive pattern matching (`match`).
* **Compiler-Supported Error Handling**: Rust makes fallible operations explicit through `Result` and `Option`. While developers can still deliberately ignore or unwrap results (`.unwrap()`, discarding with `let _`), the compiler flags unhandled results by default, encouraging explicit error propagation and fault handling.
* **Tooling & Code Quality**: Standard tooling (`cargo`, `clippy`, `rustfmt`, `cargo-audit`, `cargo-fuzz`) enforces uniform code quality and automated dependency auditing.

### 3. Deployment & Packaging Analysis
* **Self-Contained Native Artifact**: Rust compiles directly to standalone, native ELF binaries with minimal external library requirements (linking against standard system `libc`).
* **Predictable Resource Footprint**: AgenticOS daemons maintain low baseline memory utilization and fast startup, preserving computing resources for local neural models.
* **Ubuntu Packaging**: The compiled artifacts integrate directly into standard `.deb` packages with systemd user unit definitions (`/usr/lib/systemd/user/agenticos.service`), avoiding fragile virtual environment management.

### 4. AI & LLM Integration Analysis
* **Asynchronous Token Streaming**: Rust's `tokio` async runtime handles concurrent streaming token connections from local LLMs with low scheduling overhead.
* **Decoupled Engine Communication**: Local AI inference runtimes (e.g., Ollama, `llama.cpp` server) communicate over standard local HTTP/REST endpoints (`http://127.0.0.1:11434`). Rust interfaces with these services cleanly using async HTTP clients (`reqwest`, `ureq`).
* **Embedded Inference Flexibility**: In-tree lightweight tokenizers and embedding models can be incorporated via Hugging Face `candle` or `ort` (ONNX Runtime) without adding dynamic interpreter dependencies to the control plane.

### 5. FFI & Interoperability Analysis
* **C ABI Compatibility**: Rust interfaces directly with Linux kernel headers and C libraries without runtime wrappers.
* **Rejection of In-Process CPython Embedding**: We explicitly reject in-process embedding of Python (e.g., via PyO3 or `libpython`) into the core supervisor. In-process embedding would bind the supervisor to Python's GIL, expose the core daemon to segmentation faults from native C extensions, and inflate memory consumption. Process-isolated IPC over UDS provides complete fault isolation.

---

## Reasons Alternatives Were Not Selected

### Why Pure Go Was Not Selected
1. **Thread-Level Security Operations**: Go handles Linux process management, but some security-sensitive thread-scoped operations can be more complex due to the Go runtime M:N thread model. While `runtime.LockOSThread()` binds a goroutine to an OS thread, coordinating thread-scoped security restrictions across goroutines requires careful management.
2. **Process Forking Model**: Go's runtime does not recommend arbitrary `fork()` calls without an immediate `exec()` because multi-threaded runtime structures may be left in an inconsistent state in the child process.
3. **Garbage Collector Characteristics**: Go's runtime garbage collector introduces periodic latency variations and increases baseline memory utilization for background services and short-lived worker processes.

### Why Pure Python Was Not Selected
1. **Unsuitable for Core Security Plane**: Python is dynamically typed and lacks compile-time memory safety enforcement, making it unsuitable for the trusted security and policy enforcement engine.
2. **Startup Latency**: Python requires noticeable time to initialize the interpreter and import standard modules, making it inefficient for high-frequency micro-capability tasks.
3. **Packaging Fragility**: Managing Python virtual environments and C-extension wheels creates installation paths prone to dependency drift and supply chain risks.
4. **Valid for Sandboxed Workers**: While excluded from the trusted core, Python remains fully supported for out-of-process, sandboxed capability workers.

### Why In-Process CPython Embedding Was Rejected
* Embedding Python directly inside the core supervisor process couples the stability of the entire operating system to Python's Global Interpreter Lock (GIL) and exposes the core daemon to crashes from native C extensions.

---

## Risks and Mitigations

| Identified Risk | Severity | Mitigation Strategy |
| :--- | :--- | :--- |
| **Steep Rust Learning Curve** | Medium | Establish clean architectural boundaries; rely on idiomatic standard library types; avoid complex lifetime acrobatics or premature procedural macro complexity. |
| **Compilation Times** | Medium | Structure codebase into a modular Cargo multi-crate workspace; decouple core logic from heavy serialization/networking crates; enable `sccache` in local development. |
| **Async Runtime Overhead (`tokio`)** | Low | Confine asynchronous code strictly to I/O boundaries (UDS IPC, D-Bus event loop, HTTP streaming); keep core domain logic, policy evaluation, and goal state machines synchronous and pure. |
| **Supply Chain Vulnerabilities in Crates** | Medium | Maintain a minimal dependency footprint; enforce `Cargo.lock` check-in; mandate automated `cargo-audit` and `cargo-vet` in CI/CD pipelines. |

---

## Consequences

### Positive
* **Compile-Time Safety**: Safe Rust provides compile-time memory and concurrency safety for the core control plane.
* **Precise Systems Confinement**: Explicit control over POSIX processes, Landlock LSM rulesets, seccomp BPF filters, and Bubblewrap namespaces.
* **Low-Overhead Responsiveness**: Efficient IPC dispatch and fast worker execution deliver a responsive desktop experience.
* **Self-Contained Deployment**: Standalone native ELF binaries enable clean packaging for Ubuntu without external interpreter dependencies.
* **Polyglot Flexibility**: External capability workers in Python, C, or toolchains execute safely inside sandboxed out-of-process containers.

### Negative / Trade-offs
* **Initial Development Overhead**: Rust requires more rigorous upfront architectural planning and explicit type design than dynamic scripting languages.
* **Build Time**: Compiling native Rust binaries with link-time optimization (LTO) takes longer than running interpreted scripts.
