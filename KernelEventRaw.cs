using System.Runtime.InteropServices;
using System.Text;

namespace KernelTelemetry.Engine.Contracts;

/// <summary>
/// Binary layout that mirrors the packed eBPF struct <c>event_data_t</c>.
/// <c>Pack = 1</c> on this side and <c>__attribute__((packed))</c> on the
/// BPF side are both required. Verified by <see cref="BinaryContract"/>.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal unsafe struct KernelEventRaw
{
    public ulong TimestampNs;
    public ulong StartTimeNs;
    public uint Pid;
    public uint Ppid;
    public uint Uid;
    public fixed byte Comm[16];
    public fixed byte Filename[256];

    public readonly string GetComm()
    {
        fixed (byte* p = Comm) return Decode(p, 16);
    }

    public readonly string GetFilename()
    {
        fixed (byte* p = Filename) return Decode(p, 256);
    }

    private static string Decode(byte* p, int max)
    {
        int len = 0;
        while (len < max && p[len] != 0) len++;
        return len == 0 ? string.Empty : Encoding.UTF8.GetString(p, len);
    }
}