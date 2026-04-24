# Phantom BPF: Enterprise Distributed Tracing Agent

Phantom BPF is a zero-instrumentation distributed tracing agent. It observes
application traffic with eBPF, correlates kernel/userspace events in a C++17
control plane, and exports traces and metrics through OpenTelemetry-compatible
interfaces.

## Operating assumptions

- Target platform: Linux only.
- Development mode: root is acceptable while BPF verifier and hook coverage are
  evolving.
- Production mode: run with granular Linux capabilities where supported:
  `CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN`, and `CAP_SYS_PTRACE`.
- Kernel baseline: Linux 5.8+ for BPF ring buffers.
- BPF stack: libbpf with CO-RE.
- Userspace stack: C++17, CMake, spdlog, nlohmann-json, gtest.
- CI: GitHub Actions on Ubuntu.

## Architecture

### Data Plane

- CO-RE eBPF programs in C.
- kprobes for TCP send/receive paths and low-level network telemetry.
- uprobes for TLS libraries in later phases.
- ring buffer transport for kernel-to-userspace event delivery.

### Control Plane

- C++17 async agent.
- Dedicated event loop for BPF ring buffer polling.
- Lock-free or bounded queues between ingestion, parsing, correlation, and
  export stages.
- Process, thread, socket, and file descriptor correlation in userspace.

### Export Plane

- Initial JSON/stdout debug exporter.
- OTLP traces and RED metrics in later phases.
- Integration targets: Jaeger, Prometheus, Grafana Tempo.

## Phase 1: Foundation & Plaintext HTTP (v0.1.0)

Goal: capture basic unencrypted HTTP/1.1 traffic and deliver structured events
from eBPF to the C++ agent.

### 1.1 Scaffold

- [x] Create repository layout:
  - `src/agent` for C++ userspace.
  - `src/bpf` for eBPF programs.
  - `include/phantom` for shared userspace headers.
  - `include/bpf` for shared kernel/userspace event contracts.
  - `cmake` for build helpers.
  - `.github/workflows` for CI.
- [x] Configure CMake with C++17, warning flags, and Linux-only guardrails.
- [x] Add libbpf discovery and generated skeleton build flow.
- [x] Add CO-RE `vmlinux.h` generation through `bpftool btf dump`.
- [x] Add developer documentation for build and runtime permissions.

### 1.2 Network Probes

- [x] Attach kprobe/kretprobe pairs to `tcp_sendmsg`.
- [x] Attach kprobe/kretprobe pairs to `tcp_recvmsg`.
- [x] Extract PID, TID, command name, socket pointer, direction, and byte count.
- [x] Keep verifier-friendly bounded payload reads.
- [x] Emit dropped-event counters for failed ring buffer reservations.

### 1.3 HTTP Parsing in Kernel

- [x] Implement bounded HTTP/1.1 method detection for `GET`, `POST`, `PUT`,
  `PATCH`, `DELETE`, `HEAD`, and `OPTIONS`.
- [x] Extract the request path prefix within a fixed maximum size.
- [x] Detect response status lines where possible.
- [x] Keep full parsing and reassembly out of kernel until Phase 2.

### 1.4 Userspace Ring Buffer

- [x] Generate libbpf skeleton and load it from the C++ agent.
- [x] Poll `BPF_MAP_TYPE_RINGBUF`.
- [x] Convert raw BPF events into typed C++ records.
- [x] Print structured JSON lines for early validation.
- [x] Handle SIGINT/SIGTERM gracefully.

### 1.5 CI/CD Alpha

- [x] Build BPF objects on GitHub Actions Ubuntu runner.
- [x] Build the C++ agent with CMake.
- [x] Run a smoke test that verifies the agent binary exists.
- [x] Keep CI dependency installation explicit and reproducible.

### 1.6 Release v0.1.0

- [x] Commit each completed feature group.
- [x] Tag `v0.1.0` after Phase 1 is buildable in CI.

## Phase 2: Async Processing & Correlation (v0.2.0)

Goal: make ingestion durable under load and correlate network events with
process/thread/socket context.

- [ ] Build a dedicated ring buffer polling loop with backoff and shutdown
  coordination.
- [ ] Add bounded MPSC queues between ingest and parser workers.
- [ ] Add thread pool for parsing, normalization, and early aggregation.
- [ ] Track socket lifecycle and file descriptor ownership.
- [ ] Track `accept`, `connect`, `close`, `dup`, and `fork/exec` where needed.
- [ ] Correlate events by PID, TID, socket pointer, FD, and timestamp windows.
- [ ] Reassemble fragmented HTTP request/response prefixes in userspace.
- [ ] Add unit tests for parser and correlation state machines.
- [ ] Add docker-compose smoke traffic with Python and Go services.
- [ ] Tag `v0.2.0`.

## Phase 3: OpenTelemetry & Observability (v0.3.0)

Goal: integrate with enterprise observability systems.

- [ ] Add `opentelemetry-cpp` trace exporter.
- [ ] Add OTLP/gRPC or OTLP/HTTP configuration.
- [ ] Generate RED metrics: requests, errors, duration.
- [ ] Add service discovery fields: process name, container id, namespace, PID.
- [ ] Add YAML configuration with validation.
- [ ] Add hot reload for filters and exporter settings.
- [ ] Add docker-compose scenario with Tempo, Prometheus, and Grafana.
- [ ] Add CI assertions for emitted spans and metrics.
- [ ] Tag `v0.3.0`.

## Phase 4: TLS Tracing & Distributed Correlation (v0.4.0)

Goal: trace encrypted and distributed traffic paths end to end.

- [ ] Add OpenSSL/BoringSSL uprobes for `SSL_read` and `SSL_write`.
- [ ] Resolve process-specific library paths.
- [ ] Add opt-in TLS payload capture limits and redaction.
- [ ] Extract incoming W3C `traceparent` headers.
- [ ] Inject or synthesize outgoing trace context where supported.
- [ ] Add HTTP/2 frame parsing for gRPC.
- [ ] Correlate inbound application work with outbound DB/HTTP calls.
- [ ] Add overhead benchmarks and memory limits.
- [ ] Add production hardening docs for capabilities, systemd, and containers.
- [ ] Tag `v0.4.0`.
