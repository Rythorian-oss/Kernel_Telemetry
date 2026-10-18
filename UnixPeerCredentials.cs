using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace KernelTelemetry.Engine.Infrastructure;

[SupportedOSPlatform("linux")]
internal static partial class UnixPeerCredentials
{
    private const int SolSocket = 1;
    private const int SoPeerCred = 17;

    [StructLayout(LayoutKind.Sequential)]
    private struct UCred
    {
        public uint Pid;
        public uint Uid;
        public uint Gid;
    }

    [LibraryImport("libc", SetLastError = true)]
    private static partial int getsockopt(
        int sockfd, int level, int optname, out UCred optval, ref uint optlen);

    public static uint GetPeerUid(Socket socket)
    {
        // Safe: the caller holds the Socket for the duration of this call.
        int fd = socket.Handle.ToInt32();
        uint len = (uint)Marshal.SizeOf<UCred>();
        int rc = getsockopt(fd, SolSocket, SoPeerCred, out var cred, ref len);
        if (rc != 0)
        {
            throw new InvalidOperationException(
                $"getsockopt(SO_PEERCRED) failed: {Marshal.GetLastPInvokeErrorMessage()}");
        }
        return cred.Uid;
    }
}