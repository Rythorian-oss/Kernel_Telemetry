using System.Runtime.Versioning;
using KernelTelemetry.Engine.Infrastructure;

namespace KernelTelemetry.Engine.Configuration;

[SupportedOSPlatform("linux")]
public sealed class TelemetryOptions
{
    public string SocketPath { get; init; } =
        Environment.GetEnvironmentVariable("KERNEL_TELEMETRY_SOCKET")
        ?? "/var/run/kernel_telemetry.sock";

    public string PidFilePath { get; init; } =
        Environment.GetEnvironmentVariable("KERNEL_TELEMETRY_PID")
        ?? "/var/run/kernel_telemetry.pid";

    public string DataDirectory { get; init; } =
        Environment.GetEnvironmentVariable("KERNEL_TELEMETRY_DATA")
        ?? "/var/lib/kernel-telemetry/data";

    public string LogDirectory { get; init; } =
        Environment.GetEnvironmentVariable("KERNEL_TELEMETRY_LOG")
        ?? "/var/log/kernel-telemetry";

    public int ChannelCapacity { get; init; } = 100_000;
    public int BatchSize { get; init; } = 2_000;

    /// <summary>
    /// UIDs permitted to connect as the collector. The property
    /// deliberately exposes <see cref="IReadOnlySet{T}"/> so external
    /// consumers cannot mutate the allow-list through the property.
    /// </summary>
    public IReadOnlySet<uint> AllowedPeerUids { get; init; } = BuildAllowedPeers();

    public UnixFileMode SocketMode { get; init; } =
        UnixFileMode.UserRead | UnixFileMode.UserWrite;

    public TimeSpan ShutdownDrainTimeout { get; init; } = TimeSpan.FromSeconds(30);

    // CA1859: private factory; no seam; concrete return type lets the JIT
    // devirtualize the assignment without affecting the property's public
    // contract (IReadOnlySet<uint>). Followed rather than suppressed.
    private static HashSet<uint> BuildAllowedPeers()
    {
        string? env = Environment.GetEnvironmentVariable("KERNEL_TELEMETRY_ALLOWED_UIDS");
        if (!string.IsNullOrWhiteSpace(env))
        {
            // Explicit constructor (no collection expressions) — avoids CS8652.
            var fromEnv = new HashSet<uint>();
            foreach (string part in env.Split(',',
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (uint.TryParse(part, out uint uid))
                    fromEnv.Add(uid);
            }
            if (fromEnv.Count > 0)
                return fromEnv;
        }

        // Default: root (the collector needs BPF privileges) plus the
        // engine's own UID (same-user deployments).
        return [0u, UnixNative.GetUid()];
    }
}