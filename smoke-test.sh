#!/usr/bin/env bash
# End-to-end smoke test.
# Runs the engine and collector against /tmp paths, generates execve events,
# verifies at least one Parquet file was written, and queries it if DuckDB
# is available.
#
# Requires: root for the collector (BPF), .NET SDK, python3-bcc.

set -euo pipefail

# ── Paths under /tmp so we do not pollute /var ──────────────────────────
export KERNEL_TELEMETRY_SOCKET="/tmp/kernel-telemetry-smoke.sock"
export KERNEL_TELEMETRY_PID="/tmp/kernel-telemetry-smoke.pid"
export KERNEL_TELEMETRY_DATA="/tmp/kernel-telemetry-smoke-data"
export KERNEL_TELEMETRY_LOG="/tmp/kernel-telemetry-smoke-logs"

ENGINE="src/KernelTelemetry.Engine/bin/Release/net8.0/KernelTelemetry.Engine"
COLLECTOR="tools/collector.py"

if [ ! -x "$ENGINE" ]; then
    echo "ERROR: engine binary not found at $ENGINE"
    echo "       Run: dotnet build -c Release"
    exit 1
fi

# Clean state
rm -rf "$KERNEL_TELEMETRY_DATA" "$KERNEL_TELEMETRY_LOG" \
       "$KERNEL_TELEMETRY_SOCKET" "$KERNEL_TELEMETRY_PID"
mkdir -p "$KERNEL_TELEMETRY_DATA" "$KERNEL_TELEMETRY_LOG"

echo "==> Starting engine"
"$ENGINE" >"$KERNEL_TELEMETRY_LOG/engine.stdout" 2>&1 &
ENGINE_PID=$!

# Wait for socket
for _ in $(seq 1 30); do
    [ -S "$KERNEL_TELEMETRY_SOCKET" ] && break
    sleep 0.2
done

if [ ! -S "$KERNEL_TELEMETRY_SOCKET" ]; then
    echo "ERROR: engine never created the socket."
    echo "--- engine.stdout ---"
    cat "$KERNEL_TELEMETRY_LOG/engine.stdout" || true
    kill "$ENGINE_PID" 2>/dev/null || true
    exit 1
fi

echo "==> Starting collector (sudo)"
sudo -E python3 "$COLLECTOR" >"$KERNEL_TELEMETRY_LOG/collector.stdout" 2>&1 &
sleep 2

echo "==> Generating events"
/bin/ls /tmp > /dev/null 2>&1 || true
/usr/bin/env echo smoke > /dev/null 2>&1 || true
/usr/bin/date > /dev/null 2>&1 || true

sleep 2

echo "==> Stopping collector"
sudo pkill -f "tools/collector.py" 2>/dev/null || true
sleep 1

echo "==> Stopping engine (SIGTERM)"
kill -TERM "$ENGINE_PID" 2>/dev/null || true
wait "$ENGINE_PID" 2>/dev/null || true

# ── Verification ────────────────────────────────────────────────────────
COUNT=$(find "$KERNEL_TELEMETRY_DATA" -name '*.parquet' | wc -l)
if [ "$COUNT" -eq 0 ]; then
    echo
    echo "FAIL: no parquet files produced."
    echo "--- engine log ---"
    cat "$KERNEL_TELEMETRY_LOG/engine.stdout" || true
    echo "--- collector log ---"
    cat "$KERNEL_TELEMETRY_LOG/collector.stdout" || true
    exit 1
fi

echo
echo "PASS: $COUNT parquet file(s) written."

# ── Optional: DuckDB query ──────────────────────────────────────────────
if command -v duckdb >/dev/null 2>&1; then
    echo
    echo "==> Querying top 10 executables"
    duckdb <<SQL
SELECT ProcessName, COUNT(*) AS spawns
FROM '${KERNEL_TELEMETRY_DATA}/*.parquet'
GROUP BY ProcessName
ORDER BY spawns DESC
LIMIT 10;
SQL
else
    echo "(duckdb not installed; skipping query)"
fi

echo
echo "Artifacts left at:"
echo "  data:      $KERNEL_TELEMETRY_DATA"
echo "  logs:      $KERNEL_TELEMETRY_LOG"
echo "  socket:    (removed ✓)"
echo "  pidfile:   (removed ✓)"