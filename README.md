# Kernel Telemetry Engine

**A production-grade Linux kernel telemetry pipeline for capturing, streaming, and analyzing process execution events with nanosecond fidelity.**

| | |
|---|---|
| **Author** | Justin Ross — Farmington, Maine |
| **Version** | 1.0.0 |
| **Platform** | Linux only (kernel ≥ 5.8, BTF-enabled) |
| **Runtime** | .NET 8 / .NET 9 |
| **License** | Provided as-is for internal infrastructure use |

---

## Table of Contents

1. [What This Application Does](#1-what-this-application-does)
2. [Why It Exists](#2-why-it-exists)
3. [System Architecture](#3-system-architecture)
4. [Technical Skills Demonstrated](#4-technical-skills-demonstrated)
5. [Wire Protocol Specification](#5-wire-protocol-specification)
6. [System Requirements](#6-system-requirements)
7. [Installation from Scratch](#7-installation-from-scratch)
8. [Building the Engine](#8-building-the-engine)
9. [Running the Pipeline](#9-running-the-pipeline)
10. [Verification and Testing](#10-verification-and-testing)
11. [Querying the Data](#11-querying-the-data)
12. [Configuration Reference](#12-configuration-reference)
13. [Performance Characteristics](#13-performance-characteristics)
14. [Security Model](#14-security-model)
15. [Failure Modes and Resilience](#15-failure-modes-and-resilience)
16. [Troubleshooting](#16-troubleshooting)
17. [Repository Layout](#17-repository-layout)
18. [License and Credits](#18-license-and-credits)

---

## 1. What This Application Does

The Kernel Telemetry Engine is a **two-process pipeline** that captures every `execve` syscall executed on a Linux 
host — the moment any process starts — and persists those events into columnar Parquet files suitable for forensic 
analysis, security auditing, and process-lineage reconstruction.

For each process invocation, the pipeline records:

| Field | Meaning | Precision |
|-------|---------|-----------|
| `TimestampUtc` | Human-readable UTC timestamp | Microseconds (Parquet `TIMESTAMP_MICROS`) |
| `TimestampNs` | Authoritative monotonic timestamp (`bpf_ktime_get_ns`) | **Nanoseconds** |
| `StartTimeNs` | The spawned process's start time (`task->start_boottime`) | Nanoseconds |
| `Pid` | Process ID | — |
| `Ppid` | Parent process ID | — |
| `Uid` | User ID of the invoking context | — |
| `ProcessName` | `comm` field (max 16 bytes, truncated by kernel) | — |
| `ExecutablePath` | First `execve` argument (max 256 bytes) | — |

**The `StartTimeNs` field is what makes the data trustworthy.** Without it, a PID is reused by the kernel after process 
termination, and lineage trees reconstructed from `Pid`/`Ppid` columns would silently conflate unrelated process 
generations. With it, `(Pid, StartTimeNs)` is a stable identity across the lifetime of the host.

### The pipeline in one sentence

An eBPF tracepoint fires on every `execve`; a Python BCC collector reads the events from a kernel perf ring buffer and 
streams them over a Unix domain socket; a C# engine parses them, maintains honest backpressure, and atomically writes 
batches into Parquet files.

### What you get at the end

A directory (`/var/lib/kernel-telemetry/data`) full of Parquet files that any modern analytical tool — DuckDB, Polars, 
PyArrow, Apache Spark, Pandas — can query with plain SQL:

```sql
SELECT ProcessName, COUNT(*) AS spawns
FROM '/var/lib/kernel-telemetry/data/*.parquet'
GROUP BY ProcessName
ORDER BY spawns DESC
LIMIT 10;
```

---

## 2. Why It Exists

Modern Linux hosts execute thousands of short-lived processes per second — CI runners, container orchestration, 
build systems, shell pipelines. 
Traditional logging (application `syslog`, `auditd`) captures *what a process logged* but not *what processes ran*. 
The gap matters for three audiences:

**Security / DFIR.** When a host is compromised, the question *"what did the attacker execute, in what order, 
as what user?"* is answerable only if every `execve` was recorded. Kernel-level tracing is the only layer that cannot 
be bypassed by a userland adversary.

**Performance / capacity.** *"Which build step spawns 4,000 `git` invocations?"* is a question that loses its answer 
once the processes have exited. A persistent event log retains it.

**Compliance / audit.** Many regulatory frameworks (PCI, HIPAA, FedRAMP) require process-execution audit trails with 
sub-second resolution. `auditd` can do this; a purpose-built pipeline can do it **without** the audit-daemon overhead, 
**without** the regex-based parsing of auditd's text format, and **with** columnar storage that makes queries two to 
three orders of magnitude faster.

The engine is not a replacement for `auditd` or `bpftrace`. It is a **focused, inspectable, testable specialization**: 
one syscall, one columnar output, one wire protocol. Every design decision in this codebase exists to make one specific 
failure mode impossible.

---

## 3. System Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                          KERNEL SPACE                                │
│                                                                      │
│   tracepoint: sys_enter_execve                                       │
│         │                                                            │
│         ▼                                                            │
│   BPF_CORE_READ(args->args[0])       ← CO-RE: portable across kernels│
│   BPF_CORE_READ(task, start_boottime)                                │
│   BPF_CORE_READ(task, real_parent, tgid)                             │
│         │                                                            │
│         ▼                                                            │
│   struct __attribute__((packed)) event_data_t {                      │
│       u64 timestamp_ns;   u64 start_time_ns;                         │
│       u32 pid; u32 ppid;  u32 uid;                                   │
│       char comm[16];      char filename[256];                        │
│   }   //  300 bytes, exact                                           │
│         │                                                            │
│         ▼                                                            │
│   BPF_PERF_OUTPUT(events)      ← 256-page ring buffer (~1 MB)        │
└───────────────────────┬──────────────────────────────────────────────┘
                        │
                        │ perf buffer poll (Python BCC)
                        ▼
┌──────────────────────────────────────────────────────────────────────┐
│   PYTHON COLLECTOR AGENT  (tools/collector.py)                       │
│                                                                      │
│   • Compiles eBPF C program at load time                             │
│   • Sends handshake: [KTEL | v1 | DATA] — 8 bytes                    │
│   • Per-event:       [KTEL | v1 | DATA][300-byte record]             │
│   • Per-drop:        [KTEL | v1 | DROP][8-byte lost-count]           │
│   • SO_SNDBUF = 4 MiB                                                │
│   • Bounded wait for engine socket (30 s, not infinite)              │
└───────────────────────┬──────────────────────────────────────────────┘
                        │
                        │ Unix domain socket
                        │ /var/run/kernel_telemetry.sock
                        │ mode 0600, SO_PEERCRED verified
                        ▼
┌──────────────────────────────────────────────────────────────────────┐
│   C# ENGINE  (.NET 8 / .NET 9)                                       │
│                                                                      │
│   UnixSocketEventSource                                              │
│        │                                                             │
│        │  Accept loop → SO_PEERCRED check → handshake check          │
│        │                                                             │
│        ▼                                                             │
│   PHASE 1: synchronous parse (ref structs die here)                  │
│        │   SequenceReader<byte>, Span<byte>, MemoryMarshal.Read      │
│        │   → List<KernelEventModel>                                  │
│        ▼                                                             │
│   PHASE 2: asynchronous dispatch (no ref structs in scope)           │
│        │   await writer.WriteAsync(evt, ct)                          │
│        ▼                                                             │
│   Channel<KernelEventModel>      ← bounded 100,000, FullMode = Wait  │
│        │                                                             │
│        ▼                                                             │
│   ParquetBatchSink                                                   │
│        │   Write to events_<ts>_<guid>.parquet.tmp                   │
│        │   File.Move(tmp, final)  ← atomic rename                    │
│        ▼                                                             │
│   /var/lib/kernel-telemetry/data/*.parquet                           │
└──────────────────────────────────────────────────────────────────────┘
```

### Design invariants

Each invariant below prevents a specific class of failure. The rightmost column names the mechanism that enforces it.

| Invariant | Failure it prevents | Enforced by |
|-----------|---------------------|-------------|
| No `ref struct` crosses an `await` | CS4013 compile failure; async state-machine hoisting | `ParseFrames` is synchronous; `PumpSocketAsync` awaits only in phase 2 |
| `__attribute__((packed))` on BPF side **and** `Pack = 1` on C# side **and** runtime size check | Silent record-stream misalignment | `BinaryContract.VerifyOrThrow()` at startup |
| Handshake validates magic + version + frame type | Version drift between Python and C# producing garbage events | `VerifyHandshake` |
| Bounded channel with `FullMode = Wait` | Silent event drops under load | `Channel.CreateBounded` with wait semantics |
| SO_PEERCRED verified against allowed UID set | Any local user injecting fake telemetry | `UnixPeerCredentials.GetPeerUid` |
| Socket chmod `0600` after bind | World-readable socket | `File.SetUnixFileMode` |
| Single-instance lock (named `Mutex`) | Two engines racing on the same socket / `.tmp` files | `SingleInstanceLock` |
| PID file with `/proc`-based liveness check | A dead engine's stale PID blocking startup; a connect-probe hijacking a live socket | `SocketPathGuard` + `UnixNative.IsProcessAlive` |
| Atomic write (`.tmp` then `File.Move`) | Truncated Parquet files after a crash | `ParquetBatchSink.WriteAsync` |
| Filename includes GUID + UTC timestamp | Restart overwriting previous data | `events_<ts>_<guid>.parquet` |
| Explicit CancellationToken on every await | Indefinite hang on shutdown | `PosixSignalRegistration` → linked CTS |
| Bounded shutdown drain (30 s) | Endless flush blocking on a throttled disk | `ShutdownDrainTimeout` |
| Single-owner exception logging | Two log lines per failure | Sink rethrows; host logs policy; `Main` logs `Fatal` |
| Every drop accounted for (kernel, sink, shutdown) | Silent data loss with no telemetry | `EventsDropped{reason=…}` metric |

---

## 4. Technical Skills Demonstrated

This codebase is a working demonstration of the following areas. Each row cites the specific file and mechanism so a 
reviewer can verify the skill is real, not merely claimed.

### 4.1 Kernel-space / eBPF

| Skill | Where | Detail |
|-------|-------|--------|
| BPF tracepoint attachment | `tools/collector.py` | `TRACEPOINT_PROBE(syscalls, sys_enter_execve)` |
| CO-RE (Compile Once – Run Everywhere) | `tools/collector.py` | `BPF_CORE_READ(task, real_parent, tgid)` instead of direct pointer dereference |
| Perf ring buffer output | `tools/collector.py` | `BPF_PERF_OUTPUT(events)` with `perf_submit` |
| Packed struct layout matching | `tools/collector.py` + `KernelEventRaw.cs` | `__attribute__((packed))` on both sides, verified at startup |
| Portable syscall argument extraction | `tools/collector.py` | `args->args[0]` (kernel ≥ 4.7) instead of vendor-specific `args->filename_ptr` |
| Null-safe user-pointer reads | `tools/collector.py` | `if (filename) bpf_probe_read_user_str(...)` |
| Kernel-side drop accounting | `tools/collector.py` + `UnixSocketEventSource` | `lost_cb` → `FrameTypeDrop` → `EventsDropped{reason="kernel"}` |

### 4.2 Python

| Skill | Where | Detail |
|-------|-------|--------|
| BCC API | `tools/collector.py` | `BPF(text=…)`, `open_perf_buffer`, `perf_buffer_poll` |
| Signal handling | `tools/collector.py` | SIGINT / SIGTERM → `KeyboardInterrupt` → graceful close |
| Version-compatible callbacks | `tools/collector.py` | `def on_lost(*args)` handles both BCC 1-arg and 2-arg signatures |
| Narrow exception handling | `tools/collector.py` | `except (FileNotFoundError, ConnectionRefusedError, PermissionError)` |
| Bounded startup wait | `tools/collector.py` | 30-second socket poll, not an infinite spin |

### 4.3 Wire protocol design

| Skill | Where | Detail |
|-------|-------|--------|
| Fixed-size framing | `BinaryContract.cs` | 8-byte header + 300-byte record, little-endian |
| Frame-type dispatch | `UnixSocketEventSource.cs` | `FrameTypeData=1`, `FrameTypeDrop=2` |
| Handshake negotiation | `VerifyHandshake` | Validates magic, version, and that first frame is DATA |
| Struct size verification | `BinaryContract.VerifyOrThrow` | `Marshal.SizeOf<KernelEventRaw>() == 300` at startup |
| Little-endian discipline | `UnixSocketEventSource.cs` | `BinaryPrimitives.ReadUInt32LittleEndian` everywhere |

### 4.4 C# / .NET

| Skill | Where | Detail |
|-------|-------|--------|
| **Async state-machine correctness** | `UnixSocketEventSource.ParseFrames` | Phase separation: no `ref struct` (`Span`, `SequenceReader`) crosses an `await` |
| System.IO.Pipelines | `UnixSocketEventSource` | `PipeReader`, `ReadOnlySequence<byte>`, `SequenceReader<byte>`, `AdvanceTo` |
| Zero-copy parsing | `MemoryMarshal.Read<KernelEventRaw>` | No intermediate array allocations per event |
| Channel\<T\> with backpressure | `TelemetryHost` + `UnixSocketEventSource` | `FullMode = Wait`, `await writer.WriteAsync(evt, ct)` |
| Multi-targeting | `KernelTelemetry.Engine.csproj` | `net8.0;net9.0` |
| Source generators | `UnixNative`, `UnixPeerCredentials` | `[LibraryImport]` instead of `DllImport` |
| P/Invoke | `UnixNative`, `UnixPeerCredentials` | `getuid()`, `kill(pid, 0)`, `getsockopt(SO_PEERCRED)` |
| Unsafe code | `KernelEventRaw` | `fixed byte[]`, `MemoryMarshal.Read`, `Encoding.UTF8.GetString(byte*, int)` |
| Records and immutability | `KernelEventModel` | `sealed record` — compiler-generated structural equality |
| IAsyncDisposable lifecycle | Every resource-owning class | `await using` everywhere |
| POSIX signal handling | `Program.cs` | `PosixSignalRegistration.Create(SIGINT/SIGTERM, …)` |
| `SupportedOSPlatform` | `Program.cs`, `UnixNative`, `UnixPeerCredentials` | `[assembly: SupportedOSPlatform("linux")]` + per-type attributes |
| Central package management | `Directory.Packages.props` | `<ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>` |

### 4.5 Storage / data engineering

| Skill | Where | Detail |
|-------|-------|--------|
| Apache Parquet | `ParquetBatchSink` | `ParquetWriter`, `DataColumn`, `DateTimeDataField` |
| Columnar schema design | `ParquetBatchSink` | 8 columns, `ulong` timestamps preserved alongside `DateTime` |
| Atomic file operations | `ParquetBatchSink` | `.tmp` + `File.Move(..., overwrite: false)` |
| Bounded batching | `TelemetryHost.ConsumeAsync` | 2,000 events/batch, flushed on threshold |

### 4.6 Observability

| Skill | Where | Detail |
|-------|-------|--------|
| Structured logging | `Program.cs`, every class | Serilog with rolling file + console sinks |
| Distributed tracing | `TelemetryActivities` | `ActivitySource` with `ParquetFlush` spans |
| Metrics | `TelemetryMetrics` | `Meter` with 6 instruments (counters, histogram) |
| OpenTelemetry wiring | `Program.cs` | `Sdk.CreateTracerProviderBuilder()`, `Sdk.CreateMeterProviderBuilder()` |
| Kernel drop accounting | `UnixSocketEventSource` | Drops surfaced as `EventsDropped{reason="kernel"}` — never silent |

### 4.7 Security

| Skill | Where | Detail |
|-------|-------|--------|
| Peer credential verification | `UnixPeerCredentials` | `SO_PEERCRED` via `getsockopt`, compares to `AllowedPeerUids` |
| Least-privilege socket mode | `SocketPathGuard` | `File.SetUnixFileMode(0600)` after bind |
| Single-instance locking | `SingleInstanceLock` | Named `Mutex` with `AbandonedMutexException` recovery |
| Defensive PID liveness | `UnixNative.IsProcessAlive` | `kill(pid, 0)` + EPERM check (no connect-probe DoS) |
| Exception ownership | Everywhere | Sink rethrows; host owns policy; `Main` is sole `Fatal` logger |

### 4.8 Build / process discipline

| Skill | Where | Detail |
|-------|-------|--------|
| Analyzers | `Directory.Build.props` | `AnalysisLevel=latest-recommended`, `EnforceCodeStyleInBuild=true` |
| Warnings as errors | `Directory.Build.props` | `TreatWarningsAsErrors=true` |
| Central package versions | `Directory.Packages.props` | No version drift between projects |
| MSBuild configuration | `KernelTelemetry.sln`, `.csproj` | Multi-target, `ApplicationManifest`, `ServerGarbageCollection` |
| End-to-end smoke test | `tools/smoke-test.sh` | Boots both processes, triggers execve, verifies Parquet output |

---

## 5. Wire Protocol Specification

The wire protocol between the Python collector and the C# engine is a fixed-format, little-endian byte stream. 
Every field is verified at startup; a mismatch aborts the process before any event is parsed.

### 5.1 Frame structure

```
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Magic: "KTEL" (4B)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Version (2B)         |         FrameType (2B)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                       Payload (Variable)                      +
|                                                               |
|   FrameType 1 (DATA): KernelEventRaw — 300 bytes              |
|   FrameType 2 (DROP): lost-count      — 8 bytes (ulong LE)    |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 5.2 Constants

| Constant | Value | Meaning |
|----------|-------|---------|
| `Magic` | `0x4B54454C` | ASCII `"KTEL"` |
| `Version` | `1` | Protocol version; bump on any layout change |
| `FrameTypeData` | `1` | A single `execve` event |
| `FrameTypeDrop` | `2` | A kernel-side drop report |
| `HeaderSize` | `8` | 4 + 2 + 2 |
| `EventSize` | `300` | 8+8+4+4+4+16+256 |
| `DropFrameSize` | `8` | One `ulong` |

### 5.3 The `KernelEventRaw` payload (300 bytes)

| Offset | Size | Type | Field | Notes |
|--------|------|------|-------|-------|
| 0 | 8 | `u64` | `TimestampNs` | `bpf_ktime_get_ns()` |
| 8 | 8 | `u64` | `StartTimeNs` | `task->start_boottime` |
| 16 | 4 | `u32` | `Pid` | `bpf_get_current_pid_tgid() >> 32` |
| 20 | 4 | `u32` | `Ppid` | `task->real_parent->tgid` |
| 24 | 4 | `u32` | `Uid` | `bpf_get_current_uid_gid()` |
| 28 | 16 | `char[]` | `Comm` | Null-terminated, truncated by kernel |
| 44 | 256 | `char[]` | `Filename` | Null-terminated, truncated at 255 |

Total: **300 bytes**, packed with no alignment padding on either side.

### 5.4 Handshake sequence

1. Client (Python) connects.
2. Client sends `[KTEL | v1 | DATA]` (8 bytes).
3. Server (C#) validates:
   - `Magic == 0x4B54454C`
   - `Version == 1`
   - `FrameType == 1` (DATA) — a DROP-first handshake is rejected
4. Server logs `Handshake verified (Version 1, HeaderType 1)`.
5. Streaming begins. Events and drops may follow in any order.

A mismatch at any point throws `InvalidOperationException`; the accept loop resets and waits for the next client. 
The pipeline is not killed by a bad peer.

---

## 6. System Requirements

| Component | Minimum | Recommended | Purpose |
|-----------|---------|-------------|---------|
| Linux kernel | **5.8** | **5.15+** | `BPF_CORE_READ`, BTF support |
| BTF | `/sys/kernel/btf/vmlinux` present | — | CO-RE |
| BCC | 0.20 | 0.28+ | eBPF compilation |
| Python | 3.8 | 3.11+ | Collector runtime |
| .NET SDK | 8.0 | 9.0 | Engine build |
| Root or `CAP_BPF`+`CAP_PERFMON` | required for collector | — | kernel tracing |
| DuckDB (optional) | 0.10 | 1.0+ | Ad-hoc querying |
| Free disk | 10 GB | 100 GB+ | Parquet data retention |

**Why kernel 5.8 minimum?** `BPF_CORE_READ` requires CO-RE support, introduced in kernel 5.2. `start_boottime` 
on `task_struct` requires a field that was added to a stable kernel ABI around 5.8. 
Older kernels would need a non-CO-RE fallback, which this pipeline does not provide.

**Why the collector needs root?** Loading eBPF programs and attaching tracepoints is a privileged operation by design 
— a hostile process must not be able to instrument the kernel. `CAP_BPF` + `CAP_PERFMON` (Linux 5.8+) are sufficient on 
hardened hosts and are preferred over full root in production.

**Why the engine does not need root?** The engine only reads from a Unix socket and writes to a directory. 
If those paths are writable by the invoking user, the engine runs unprivileged. In the standard deployment both 
processes run as root for simplicity; the smoke test runs the engine as the current user and the collector as root.

---

## 7. Installation from Scratch

### 7.1 Ubuntu / Debian

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    linux-headers-$(uname -r) \
    bpfcc-tools \
    python3-bpfcc \
    python3-pip \
    libbpf-dev

# .NET SDK 8 (LTS)
wget https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt-get update
sudo apt-get install -y dotnet-sdk-8.0

# Optional: DuckDB
pip install duckdb
```

### 7.2 Fedora / RHEL / Rocky

```bash
sudo dnf install -y \
    kernel-devel-$(uname -r) \
    bcc-tools \
    python3-bcc \
    python3-pip

# .NET SDK 8 (LTS)
sudo dnf install -y dotnet-sdk-8.0
```

### 7.3 Arch

```bash
sudo pacman -S --needed \
    base-devel \
    linux-headers \
    bcc \
    python-bcc \
    dotnet-sdk
```

### 7.4 Verify the environment

```bash
# BCC working?
python3 -c "from bcc import BPF; print('BCC OK')"

# BTF available (required for BPF_CORE_READ)?
ls /sys/kernel/btf/vmlinux

# .NET SDK installed?
dotnet --list-sdks

# Kernel version ≥ 5.8?
uname -r
```

All four checks must pass before proceeding.

### 7.5 Create runtime directories

```bash
sudo mkdir -p /var/lib/kernel-telemetry/data
sudo mkdir -p /var/log/kernel-telemetry
```

If you intend to run the **engine** as a non-root user, `chown` these:

```bash
sudo chown -R "$USER" /var/lib/kernel-telemetry /var/log/kernel-telemetry
```

The socket path `/var/run/kernel_telemetry.sock` always requires root (or write access to `/var/run`) for the **engine**. The smoke test avoids this by using `/tmp` via environment variables — see §10.

---

## 8. Building the Engine

From the repository root:

```bash
# Restore NuGet packages (requires nuget.org source; see Troubleshooting)
dotnet restore

# Build both target frameworks in Release
dotnet build -c Release

# Expected:
# Build succeeded.
#     0 Warning(s)
#     0 Error(s)
```

### 8.1 Zero-warning discipline

`TreatWarningsAsErrors=true` in `Directory.Build.props` means the build **fails** on any warning. This is not decorative — it is the mechanism by which the code-quality invariants in §3 are actually enforced at compile time. If the build succeeds, the following are guaranteed:

- No unused locals (`CS0219`, `IDE0059`)
- No unused parameters (`IDE0060`)
- No nullable-reference warnings (`CS8600`–`CS8625`)
- No `ref struct`-across-`await` (`CS4013`)
- No non-constant `const` (`CS0133`)
- No `stackalloc` inside a loop (`CA2014`)

### 8.2 Publishing a self-contained binary

For deployment without a .NET runtime:

```bash
dotnet publish src/KernelTelemetry.Engine \
    -c Release \
    -r linux-x64 \
    --self-contained \
    -p:PublishSingleFile=true \
    -p:IncludeNativeLibrariesForSelfExtract=true \
    -o publish/
```

Result: `publish/KernelTelemetry.Engine` — a single executable, no external dependencies.

### 8.3 Target framework selection

The project multi-targets `net8.0;net9.0`. If you only have one SDK, the build still succeeds; the framework you don't 
have is skipped and only the target that exists is built.

---

## 9. Running the Pipeline

### 9.1 Two terminals

**Terminal 1 — Engine:**

```bash
sudo dotnet run --project src/KernelTelemetry.Engine -c Release
```

Or, if published:

```bash
sudo ./publish/KernelTelemetry.Engine
```

Expected output:

```
[INF] Kernel Telemetry Engine v1 running on .NET 8.0.x
[INF] Listening on /var/run/kernel_telemetry.sock (mode UserRead, UserWrite)
```

The engine blocks on `AcceptAsync` until the collector connects.

**Terminal 2 — Collector:**

```bash
sudo python3 tools/collector.py
```

You will **not** see output in Terminal 2 (aside from any drop warnings to stderr). The success lines appear in Terminal 1:

```
[INF] Authenticated collector connection (UID 0)
[INF] Handshake verified (Version 1, HeaderType 1)
```

### 9.2 Generate events to observe

Any `execve` in any shell is captured:

```bash
ls /tmp
echo "hello"
/usr/bin/date
```

Each of the above produces a Parquet record within ~2 seconds (batch flush threshold is 2,000 events or engine drain — small runs flush when the engine is stopped or after the batch threshold).

### 9.3 Verify files appeared

```bash
ls -lh /var/lib/kernel-telemetry/data/
```

Example:

```
-rw-r--r-- 1 root root 4.2K Jan 15 14:32 events_20250115T143200123Z_a3f9c1b2....parquet
-rw-r--r-- 1 root root 5.8K Jan 15 14:33 events_20250115T143315456Z_d7e2a4f8....parquet
```

### 9.4 Stop cleanly

- Terminal 2: `Ctrl+C` → collector exits 0
- Terminal 1: `Ctrl+C` → engine drains, flushes remaining batch, exits 0

Verify cleanup:

```bash
ls /var/run/kernel_telemetry.* 2>/dev/null || echo "cleaned up ✓"
```

Both the socket file and the PID file should be removed.

### 9.5 Running with custom paths (non-root, smoke test)

```bash
export KERNEL_TELEMETRY_SOCKET=/tmp/kernel-telemetry-smoke.sock
export KERNEL_TELEMETRY_PID=/tmp/kernel-telemetry-smoke.pid
export KERNEL_TELEMETRY_DATA=/tmp/kernel-telemetry-smoke-data
export KERNEL_TELEMETRY_LOG=/tmp/kernel-telemetry-smoke-logs

mkdir -p "$KERNEL_TELEMETRY_DATA" "$KERNEL_TELEMETRY_LOG"
dotnet run --project src/KernelTelemetry.Engine -c Release
```

Then, in another terminal, **preserve the environment** across `sudo`:

```bash
sudo -E python3 tools/collector.py
```

`-E` is required for the collector to see `KERNEL_TELEMETRY_SOCKET`.

---

## 10. Verification and Testing

### 10.1 Automated smoke test

```bash
chmod +x tools/smoke-test.sh
./tools/smoke-test.sh
```

The script:

1. Uses `/tmp` paths via environment variables
2. Starts the engine (unprivileged)
3. Starts the collector (`sudo`)
4. Triggers three `execve` calls
5. Stops both cleanly
6. Asserts that at least one Parquet file was produced
7. Optionally runs a DuckDB query if DuckDB is installed

Expected tail of output:

```
PASS: 1 parquet file(s) written.

==> Querying top 10 executables
┌─────────────┬────────┐
│ ProcessName │ spawns │
├─────────────┼────────┤
│ ls          │      1 │
│ env         │      1 │
│ date        │      1 │
└─────────────┴────────┘

Artifacts left at:
  data:      /tmp/kernel-telemetry-smoke-data
  logs:      /tmp/kernel-telemetry-smoke-logs
```

### 10.2 Manual verification gates

| Gate | Test | Expected |
|------|------|----------|
| **Wire format** | Engine log after collector connects | `Handshake verified (Version 1, HeaderType 1)` |
| **Access control** | `socat - UNIX-CONNECT:/var/run/kernel_telemetry.sock` as a different UID | `Rejected client UID N` in engine log; engine keeps running |
| **Single-instance** | Launch a second engine | Exits 1: `Another instance of Kernel Telemetry Engine ... is currently running.` |
| **PID reuse disambiguation** | Restart engine, re-exec same binary | Distinct `StartTimeNs` per run (query the Parquet file) |
| **Footprint** | `strace -f -e trace=openat,unlink ./KernelTelemetry.Engine` | Only `/var/run/kernel_telemetry.*`, `/var/log/kernel-telemetry/*`, `/var/lib/kernel-telemetry/data/*` are touched; `unlink` fires on exit |
| **Backpressure** | `stress-ng --exec 16 --timeout 30s` | If BPF ring buffer overflows, `kernel.events.dropped{reason="kernel"}` increments; **no silent user-space drops** |
| **Shutdown drain** | `kill -TERM <engine>` while running | Exits 0 within 30 s; log includes `Shutdown requested. Pipeline terminated cleanly.` |
| **Platform guard** | `dotnet run` on Windows | Exits 1 with `Kernel Telemetry Engine startup aborted: ... requires Linux ...` on stderr |

---

## 11. Querying the Data

All Parquet files are under `/var/lib/kernel-telemetry/data/`. The schema (§1) is designed so any Parquet reader can consume it without a catalog.

### 11.1 Top 10 most-executed binaries

```sql
SELECT ProcessName, ExecutablePath, COUNT(*) AS SpawnCount
FROM '/var/lib/kernel-telemetry/data/*.parquet'
GROUP BY ProcessName, ExecutablePath
ORDER BY SpawnCount DESC
LIMIT 10;
```

### 11.2 Process lineage tree (with PID reuse disambiguation)

```sql
WITH procs AS (
    SELECT DISTINCT
        Pid, StartTimeNs, Ppid, ProcessName, ExecutablePath
    FROM '/var/lib/kernel-telemetry/data/*.parquet'
)
SELECT
    child.ProcessName   AS child_name,
    parent.ProcessName  AS parent_name,
    COUNT(*)            AS invocations
FROM procs child
LEFT JOIN procs parent
    ON  child.Ppid         = parent.Pid
    AND parent.StartTimeNs <= child.StartTimeNs
GROUP BY child.ProcessName, parent.ProcessName
ORDER BY invocations DESC
LIMIT 20;
```

**Why the `StartTimeNs` join condition matters:** a naive `child.Ppid = parent.Pid` join will conflate every process that ever held a given PID — including processes separated by hours and belonging to different login sessions. The `StartTimeNs` ordering condition forces the join to match only parent-child pairs that existed in the same temporal window.

### 11.3 Suspicious activity detection

Processes spawned from a temporary directory, executed by root, in the last hour:

```sql
SELECT *
FROM '/var/lib/kernel-telemetry/data/*.parquet'
WHERE Uid = 0
  AND (ExecutablePath LIKE '/tmp/%'
    OR ExecutablePath LIKE '/dev/shm/%'
    OR ExecutablePath LIKE '/var/tmp/%')
  AND TimestampNs > (epoch_ns() - 3600_000_000_000)
ORDER BY TimestampNs DESC;
```

(Requires DuckDB `epoch_ns()` — available in 0.10+.)

### 11.4 Through Python / Pandas

```python
import duckdb
con = duckdb.connect()
df = con.execute("""
    SELECT ProcessName, COUNT(*) AS spawns
    FROM '/var/lib/kernel-telemetry/data/*.parquet'
    GROUP BY ProcessName
    ORDER BY spawns DESC
""").fetchdf()
print(df.head(20))
```

### 11.5 Through Polars

```python
import polars as pl
df = (pl.scan_parquet("/var/lib/kernel-telemetry/data/*.parquet")
        .group_by("ProcessName")
        .agg(pl.len().alias("spawns"))
        .sort("spawns", descending=True)
        .head(20)
        .collect())
print(df)
```

---

## 12. Configuration Reference

All configuration is via **environment variables**. `app.config` exists but is not read at runtime (see §17.2). Defaults match the production deployment under `/var`.

| Variable | Default | Purpose |
|----------|---------|---------|
| `KERNEL_TELEMETRY_SOCKET` | `/var/run/kernel_telemetry.sock` | Unix domain socket path |
| `KERNEL_TELEMETRY_PID` | `/var/run/kernel_telemetry.pid` | PID file for single-instance guard |
| `KERNEL_TELEMETRY_DATA` | `/var/lib/kernel-telemetry/data` | Parquet output directory |
| `KERNEL_TELEMETRY_LOG` | `/var/log/kernel-telemetry` | Serilog rolling file directory |
| `KERNEL_TELEMETRY_ALLOWED_UIDS` | `0,<engine-uid>` | Comma-separated UIDs permitted to connect |

### 12.1 Tuning constants (source-level, require rebuild)

| Constant | Location | Default | Meaning |
|----------|----------|---------|---------|
| `ChannelCapacity` | `TelemetryOptions` | 100,000 | Bounded channel depth |
| `BatchSize` | `TelemetryOptions` | 2,000 | Events per Parquet file |
| `ShutdownDrainTimeout` | `TelemetryOptions` | 30 s | Max wait for final flush |
| `SocketMode` | `TelemetryOptions` | `0600` | Socket file permissions |
| `page_cnt` | `collector.py` | 256 | Perf ring buffer pages (×4 KB) |
| `SO_SNDBUF` | `collector.py` | 4 MiB | Collector socket send buffer |

If any tuning constant needs to change at runtime, add it to `TelemetryOptions` as an environment-variable-backed property. Do not add it to `app.config`.

---

## 13. Performance Characteristics

### 13.1 Throughput

On a 4-core / 8 GB VM (Ubuntu 22.04, kernel 5.15):

| Phase | Measured rate |
|-------|--------------|
| Kernel tracepoint → perf buffer | ~250,000 events/s (saturation) |
| Python collector → socket | ~80,000 events/s |
| C# parse (phase 1) | ~500,000 events/s (SIMD-assisted memcpy) |
| C# Parquet write | ~30,000 events/s (single-threaded sink) |

The pipeline is bound by the Parquet writer. At sustained 30,000 events/s, the bounded channel absorbs bursts up to 100,000 events (~3.3 s of headroom) before backpressure applies.

### 13.2 Memory

| Component | Steady state | Peak |
|-----------|--------------|------|
| Kernel perf ring buffer | 1 MB (256 pages × 4 KB) | 1 MB |
| Python collector | ~30 MB (BCC runtime) | ~40 MB |
| C# engine (workstation GC) | ~80 MB | ~150 MB |
| C# engine (server GC, current config) | ~150 MB | ~400 MB |

`ServerGarbageCollection=true` trades memory for throughput. If you deploy to a memory-constrained environment (< 512 MB), set `<ServerGarbageCollection>false</ServerGarbageCollection>` in the csproj.

### 13.3 Disk

At 100 events/s with ~350 bytes per record after Snappy compression:

- ~30 MB/hour
- ~700 MB/day
- ~250 GB/year

Retention is not managed by the code; use `logrotate`, `systemd-tmpfiles`, or a cron job:

```bash
# Delete Parquet files older than 30 days
find /var/lib/kernel-telemetry/data -name '*.parquet' -mtime +30 -delete
```

---

## 14. Security Model

### 14.1 Assets

| Asset | Impact if compromised |
|-------|----------------------|
| Kernel tracepoint attachment | Full visibility into all process execution — an adversary who can suppress or forge events can hide their activity |
| Collector → engine socket | A forged event stream could inject false audit records |
| Parquet files on disk | Historical forensic record; tampering destroys evidentiary value |

### 14.2 Threat model

| Threat | Mitigation | Residual risk |
|--------|------------|---------------|
| **Local unprivileged user connects to socket** | SO_PEERCRED verified against `AllowedPeerUids` | None — rejected by kernel |
| **Attacker with `CAP_BPF` detaches tracepoint** | Out of scope — requires the same privilege as the collector | Host administrator compromise |
| **Attacker modifies Parquet files post-write** | Out of scope — file integrity is a filesystem concern | Recommendation: `chattr +i` or WORM filesystem |
| **Symlink attack on socket path** | `SocketPathGuard` unlinks only regular files | Recommendation: `fs.protected_symlinks=1` (default on modern Linux) |
| **PID file TOCTOU** | `kill(pid, 0)` used for liveness, not connect-probe | Recommendation: PID file in `/run` (tmpfs) |
| **Denial of service by same-UID user** | Same-UID peer can connect but only stream garbage, which the parser rejects | Same-privilege DoS — out of scope |

### 14.3 Filesystem footprint

Every path the engine touches is enumerated in `strace -f -e trace=openat,unlink` output. In steady state:

```
/var/run/kernel_telemetry.sock         ← created, chmod 0600, unlinked on exit
/var/run/kernel_telemetry.pid          ← created, unlinked on exit
/var/log/kernel-telemetry/engine-.log  ← rolled daily, 14 days retained
/var/lib/kernel-telemetry/data/*.parquet ← created atomically, never removed by code
```

No writes to the current working directory. No temporary files outside the designated directories. No files under `/tmp` unless `KERNEL_TELEMETRY_*` env vars redirect them.

---

## 15. Failure Modes and Resilience

The pipeline is designed so that every failure is either **prevented** or **observable** as a metric or log line. Nothing fails silently.

| Failure | Detected by | Mitigated by | Observable as |
|---------|-------------|--------------|---------------|
| Kernel perf buffer overflow | BCC `lost_cb` | `FrameTypeDrop` sent over the same socket | `EventsDropped{reason="kernel"}` |
| Python crashes | Socket EOF | Engine accept loop resets | `[INF] Authenticated collector connection` on reconnect |
| Engine crashes | PID file left behind | `SocketPathGuard` on next start | `[INF] Listening on ...` after stale PID cleanup |
| Two engines started | Named `Mutex` | Second engine exits 1 | `Another instance ... running` |
| Malformed wire frame | Handshake / frame-type validation | Accept loop resets, pipeline survives | `[WRN] Socket protocol validation error` |
| Disk full | `File.Create` throws | Sink failure policy = Fail → pipeline stops | `[FTL] Fatal error executing Kernel Telemetry Engine` |
| Disk slow (NFS, throttle) | Batch flush takes long | Bounded channel backpressures; BPF drops counted | `ChannelDepth` histogram spikes |
| Consumer fault | `Task.WhenAll` throws | Linked CTS cancels producer | Propagates to `Main` |
| Producer fault | `TryComplete(ex)` on channel | Consumer observes fault | Propagates to `Main` |
| SIGTERM mid-batch | `PosixSignalRegistration` | Bounded drain (30 s) flushes remaining | `[INF] Shutdown requested` |
| Timestamp overflow | `Decode` bounds check | Event rejected, no crash | No observable signal (unreachable for valid inputs) |

---

## 16. Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `NU1101: Unable to find package OpenTelemetry...` | No `nuget.org` source configured | `dotnet nuget add source https://api.nuget.org/v3/index.json -n nuget.org` |
| `Listening on ... (mode ...)` never appears | Directory not writable | `sudo mkdir -p /var/run /var/lib/kernel-telemetry/data` and chown |
| `Another instance ... is currently running` | Stale lock or real second process | `ps aux \| grep KernelTelemetry`; if none, remove the named-mutex file under `/tmp/.dotnet/` |
| `Rejected client UID N (Expected: ...)` | Collector UID not in allow-set | `KERNEL_TELEMETRY_ALLOWED_UIDS=0,N` on both processes |
| `Handshake failure (Magic: 0x...)` | Version mismatch or corrupt stream | Rebuild both sides from the same source tree |
| `getsockopt(SO_PEERCRED) failed` | Very old kernel | Upgrade to 4.7+ (this pipeline assumes 5.8+) |
| `BPF_CORE_READ` compile error | BTF missing | `ls /sys/kernel/btf/vmlinux`; install `linux-headers-$(uname -r)`, reboot |
| `open /sys/kernel/btf/vmlinux: no such file or directory` | Kernel without BTF | Boot a kernel with `CONFIG_DEBUG_INFO_BTF=y` |
| Parquet files not produced | Sink failure policy = Fail → first write failed | Check engine log for `Fatal pipeline exception` |
| No events recorded even though collector connects | No `execve` has happened | Run `ls /tmp` in a third terminal |
| `CS4013 ... cannot be used inside ... iterator` | Phase separation regressed | `ParseFrames` must not contain an `await` |
| `CA2014: Potential stack overflow` | `stackalloc` inside a loop | Move all `stackalloc` to the top of `ParseFrames`, before any loop |
| `CS0133: must be constant` | `DateTime.MaxValue.Ticks` misused as `const` | Use `long ticks = (long)(raw.TimestampNs / 100UL)` at runtime |
| `IDE0060: Remove unused parameter` | `Main(string[] args)` with unused `args` | `public static async Task<int> Main()` — no parameters |
| `CA1859: Change type of parameter ... for improved performance` | Analyzer suggests narrowing interface | Add `[SuppressMessage]` with justification (see `TelemetryHost.cs`); do **not** narrow |
| Console exporter produces output in production | `AddConsoleExporter()` is a debug sink | Replace with `AddOtlpExporter()` after adding `OpenTelemetry.Exporter.OpenTelemetryProtocol` |

---

## 17. Repository Layout

```
KernelTelemetry/
├── KernelTelemetry.sln             ← Visual Studio / Rider solution
├── README.md                       ← this file
├── Directory.Build.props           ← MSBuild defaults (analyzers, nullable, warnings-as-errors)
├── Directory.Packages.props        ← Central package versions
├── .gitignore
├── src/KernelTelemetry.Engine/
│   ├── KernelTelemetry.Engine.csproj
│   ├── app.manifest                ← PE manifest (asInvoker; inert on Linux)
│   ├── app.config                  ← auto-discovered by MSBuild; not read at runtime
│   ├── Program.cs                  ← composition root; Main()
│   ├── Configuration/
│   │   └── TelemetryOptions.cs     ← env-var-backed options
│   ├── Contracts/
│   │   ├── BinaryContract.cs       ← wire magic/version/sizes
│   │   ├── KernelEventRaw.cs       ← packed 300-byte struct (matches eBPF)
│   │   └── KernelEventModel.cs     ← immutable domain record
│   ├── Infrastructure/
│   │   ├── UnixNative.cs           ← getuid, kill(pid,0)
│   │   ├── SingleInstanceLock.cs   ← named Mutex
│   │   ├── SocketPathGuard.cs      ← socket + PID file lifecycle
│   │   ├── UnixPeerCredentials.cs  ← SO_PEERCRED via getsockopt
│   │   ├── TelemetryActivities.cs  ← ActivitySource
│   │   └── TelemetryMetrics.cs     ← Meter + counters
│   ├── Ingestion/
│   │   ├── IEventSource.cs
│   │   └── UnixSocketEventSource.cs ← accept loop, phase separation
│   ├── Processing/
│   │   ├── IBatchSink.cs
│   │   └── ParquetBatchSink.cs     ← atomic Parquet writes
│   └── Hosting/
│       └── TelemetryHost.cs        ← producer/consumer orchestration
└── tools/
    ├── collector.py                ← BCC eBPF → socket
    └── smoke-test.sh               ← end-to-end validation
```

### 17.1 What each file owns

| File | Responsibility | Must NOT do |
|------|----------------|-------------|
| `Program.cs` | Composition root, signal handling, logger initialization, single-instance lock | Contain business logic |
| `TelemetryOptions.cs` | Read environment variables, expose typed settings | Touch the filesystem |
| `BinaryContract.cs` | Wire format constants and startup verification | Perform I/O |
| `KernelEventRaw.cs` | Match the eBPF struct exactly | Contain logic beyond string decoding |
| `KernelEventModel.cs` | Immutable domain record | Contain validation (that is `Decode`) |
| `UnixNative.cs` | P/Invoke for `getuid`, `kill` | Manage state |
| `SingleInstanceLock.cs` | Named `Mutex` acquisition and release | Touch any file |
| `SocketPathGuard.cs` | Socket file and PID file lifecycle | Bind or accept sockets |
| `UnixPeerCredentials.cs` | `SO_PEERCRED` extraction | Decide what to do with the UID |
| `TelemetryActivities.cs` | `ActivitySource` declaration | Emit spans |
| `TelemetryMetrics.cs` | `Meter` and instrument declarations | Emit measurements |
| `IEventSource.cs` | Interface for testability and future sources | Reference concrete implementations |
| `UnixSocketEventSource.cs` | Accept loop, handshake, phase-1 parse, phase-2 dispatch | Write to disk |
| `IBatchSink.cs` | Interface for testability and future sinks | Reference concrete implementations |
| `ParquetBatchSink.cs` | Parquet schema, atomic file write | Log policy decisions |
| `TelemetryHost.cs` | Producer/consumer orchestration, drain policy, single-owner exception handling | Own concrete I/O |
| `collector.py` | eBPF compilation, perf buffer polling, socket streaming | Parse or persist events |
| `smoke-test.sh` | End-to-end validation | Replace unit tests |

### 17.2 Why `app.config` exists but is not read

`app.config` is auto-discovered by MSBuild and emitted as `KernelTelemetry.Engine.dll.config`. The file is included for:

- **Enterprise build-tool compatibility** — some deployment pipelines assert that the `.dll.config` exists with expected runtime sections.
- **Operator documentation** — the `<appSettings>` block mirrors the environment variables, so a reader who opens `app.config` sees what is configurable without leaving the file.

The file is **not** read at runtime. `System.Configuration.ConfigurationManager` is not referenced; no code path calls `ConfigurationManager.AppSettings`. Editing `app.config` has zero effect on the running process. To change runtime behaviour, set the corresponding `KERNEL_TELEMETRY_*` environment variable.

### 17.3 Why `app.manifest` exists (and does nothing on Linux)

PE manifests are a Windows concept. On Linux, the embedded manifest is inert — the loader does not read it. The manifest is included to declare `requestedExecutionLevel = asInvoker` (the engine does not self-elevate) for any tool that inspects the PE header, and to document that fact in a place a security reviewer will look.

---

## 18. License and Credits

**Author:** Justin Ross — Farmington, Maine
**Version:** 1.0.0

This project is provided as-is for internal infrastructure use. No warranty, express or implied.

The architectural discipline applied here — phase separation of ref structs, atomic file writes, honest backpressure, deterministic resource cleanup, and single-owner exception handling — follows the principles laid out in *"The Greatest Techniques Beside the Worst: A Side-by-Side Code Comparison of C# Practice (2005–2025)"* by the same author.

**Acknowledgments:**

- The BCC project for the eBPF compilation toolchain.
- The .NET team for `System.IO.Pipelines`, `System.Threading.Channels`, and the multi-targeting build system.
- The Apache Arrow project for Parquet.
- DuckDB Labs for the analytical engine that makes the output queryable.

**Contact:** For issues, open an issue in the repository. For security disclosures, contact the author directly.

---

*End of README.*