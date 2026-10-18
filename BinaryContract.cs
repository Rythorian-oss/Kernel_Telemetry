using System.Runtime.InteropServices;

namespace KernelTelemetry.Engine.Contracts;

/// <summary>
/// Single source of truth for the Python ↔ C# wire contract.
/// Verified at startup; mismatches abort the process.
/// </summary>
public static class BinaryContract
{
    public const uint Magic = 0x4B54454C; // ASCII: "KTEL"
    public const ushort Version = 1;
    public const ushort FrameTypeData = 1;
    public const ushort FrameTypeDrop = 2;
    public const int HeaderSize = 8;   // 4 + 2 + 2
    public const int EventSize = 300; // 8 + 8 + 4 + 4 + 4 + 16 + 256
    public const int DropFrameSize = 8;   // ulong count

    public static void VerifyOrThrow()
    {
        int actual = Marshal.SizeOf<KernelEventRaw>();
        if (actual != EventSize)
        {
            throw new InvalidOperationException(
                $"KernelEventRaw size mismatch: actual {actual} bytes vs expected {EventSize} bytes. " +
                "Python and C# struct layouts have drifted.");
        }
    }

    public static void VerifyPlatformOrThrow()
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException(
                "Kernel Telemetry Engine requires Linux (eBPF and Unix Domain Sockets).");
        }
    }
}