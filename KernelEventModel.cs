namespace KernelTelemetry.Engine.Contracts;

/// <summary>
/// Immutable domain identity. The compiler-generated Equals/GetHashCode
/// honour the equality contract.
/// </summary>
public sealed record KernelEventModel(
    DateTime TimestampUtc,
    ulong    TimestampNs,
    ulong    StartTimeNs,
    uint     Pid,
    uint     Ppid,
    uint     Uid,
    string   ProcessName,
    string   ExecutablePath);