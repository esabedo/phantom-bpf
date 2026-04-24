# Phantom BPF

Enterprise distributed tracing agent built on eBPF and C++17.

Phantom BPF is designed for zero-instrumentation tracing: applications do not
need SDKs or code changes for the first capture path. The agent observes Linux
kernel and userspace activity, correlates events in a userspace control plane,
and exports telemetry through OpenTelemetry-compatible pipelines.

## Current status

The project is in Phase 1. The initial target is plaintext HTTP/1.1 capture via
`tcp_sendmsg` and `tcp_recvmsg`, delivered to userspace through a BPF ring
buffer.

## Requirements

- Linux 5.8+.
- CMake 3.22+.
- clang/LLVM with BPF target support.
- libbpf development headers and library.
- bpftool.
- C++17 compiler.

On Ubuntu runners the CI installs the required packages explicitly.

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build
```

The build generates `vmlinux.h` from the host BTF data and then generates a
libbpf skeleton for the BPF program.

## Run

During development, running as root is the most predictable path while probes
and verifier behavior are changing:

```bash
sudo ./build/phantom-agent
```

For production, the target permission model is granular capabilities:

```bash
sudo setcap cap_bpf,cap_perfmon,cap_net_admin,cap_sys_ptrace+ep ./build/phantom-agent
./build/phantom-agent
```

The exact production capability set may be narrowed as probe coverage becomes
more precise.

## Repository layout

```text
src/agent/       C++17 userspace agent
src/bpf/         eBPF programs
include/bpf/     shared event ABI between BPF and userspace
include/phantom/ userspace headers
cmake/           CMake helpers
.github/         CI workflows
```

See [ROADMAP.md](/Users/sabirov/projects/phantom-bpf/ROADMAP.md) for the
release plan.
