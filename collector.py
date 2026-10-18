#!/usr/bin/env python3
"""
BCC Collector Agent — frame-extended wire contract for Kernel Telemetry Engine.

Wire protocol (8-byte header):
    magic   : u32 little-endian   (0x4B54454C = "KTEL")
    version : u16 little-endian   (1)
    type    : u16 little-endian   (1 = DATA, 2 = DROP)

DATA frame: header + 300-byte packed event_data_t
DROP frame: header + 8-byte ulong lost-count

The first frame sent must be DATA (engine enforces this).
"""
import os
import signal
import socket
import struct
import sys
import time
from bcc import BPF

MAGIC           = 0x4B54454C
VERSION         = 1
FRAME_TYPE_DATA = 1
FRAME_TYPE_DROP = 2

HEADER_DATA = struct.pack("<IHH", MAGIC, VERSION, FRAME_TYPE_DATA)
HEADER_DROP = struct.pack("<IHH", MAGIC, VERSION, FRAME_TYPE_DROP)

BPF_TEXT = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct __attribute__((packed)) event_data_t {
    u64 timestamp_ns;
    u64 start_time_ns;
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[16];
    char filename[256];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct event_data_t data = {};
    data.timestamp_ns  = bpf_ktime_get_ns();
    data.pid           = bpf_get_current_pid_tgid() >> 32;
    data.uid           = bpf_get_current_uid_gid();

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data.start_time_ns = BPF_CORE_READ(task, start_boottime);
    data.ppid          = BPF_CORE_READ(task, real_parent, tgid);

    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // args->args[0] is the raw syscall argument vector entry for `filename`,
    // portable across all kernels >= 4.7.
    const char *filename = (const char *)args->args[0];
    if (filename) {
        bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);
    }

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

SOCKET_PATH = os.environ.get(
    "KERNEL_TELEMETRY_SOCKET", "/var/run/kernel_telemetry.sock"
)


def main() -> int:
    b = BPF(text=BPF_TEXT)

    # Wait for engine socket (bounded — 30 s, not infinite).
    for _ in range(60):
        if os.path.exists(SOCKET_PATH):
            break
        time.sleep(0.5)
    else:
        print(
            f"[collector] Error: socket path {SOCKET_PATH} not found.",
            file=sys.stderr,
        )
        return 1

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)

    try:
        sock.connect(SOCKET_PATH)
    except (FileNotFoundError, ConnectionRefusedError, PermissionError) as e:
        print(
            f"[collector] Failed to connect to socket {SOCKET_PATH}: {e}",
            file=sys.stderr,
        )
        return 1

    # Handshake — must be DATA.
    sock.sendall(HEADER_DATA)

    def on_lost(*args):
        # BCC's lost callback signature varies by version: (count) or (cpu, count).
        count = args[-1]
        try:
            sock.sendall(HEADER_DROP + struct.pack("<Q", count))
        except (BrokenPipeError, ConnectionResetError):
            raise SystemExit(2)

    def on_event(_cpu, data, _size):
        try:
            sock.sendall(HEADER_DATA + data)
        except (BrokenPipeError, ConnectionResetError):
            raise SystemExit(2)

    b["events"].open_perf_buffer(on_event, page_cnt=256, lost_cb=on_lost)

    def _shutdown(*_):
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    try:
        while True:
            b.perf_buffer_poll(timeout=250)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())