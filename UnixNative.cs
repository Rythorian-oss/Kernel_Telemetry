using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace KernelTelemetry.Engine.Infrastructure;

[SupportedOSPlatform("linux")]
internal static partial class UnixNative
{
    [LibraryImport("libc", EntryPoint = "getuid")]
    public static partial uint GetUid();

    [LibraryImport("libc", EntryPoint = "kill", SetLastError = true)]
    private static partial int kill(int pid, int sig);

    private const int SigZero = 0;

    /// <summary>True if the process exists and is signalable by this process.</summary>
    public static bool IsProcessAlive(int pid)
    {
        if (pid <= 0) return false;
        // kill(pid, 0): 0 = alive, EPERM = alive but not owned, ESRCH = dead.
        return kill(pid, SigZero) == 0 || Marshal.GetLastPInvokeError() == 1;
    }
}