namespace KernelTelemetry.Engine.Infrastructure;

/// <summary>
/// Owns the socket file and PID file. Liveness is decided by <c>/proc</c>
/// via <see cref="UnixNative.IsProcessAlive"/>, never by a connect probe.
/// The <c>ProcessExit</c> handler is unsubscribed in <see cref="Dispose"/>.
/// </summary>
public sealed class SocketPathGuard : IDisposable
{
    private readonly string _socketPath;
    private readonly string _pidPath;
    private readonly EventHandler _processExitHandler;
    private bool _disposed;

    public SocketPathGuard(string socketPath, string pidPath)
    {
        _socketPath = socketPath;
        _pidPath = pidPath;

        if (File.Exists(pidPath))
        {
            string text = File.ReadAllText(pidPath).Trim();
            if (int.TryParse(text, out int pid) && UnixNative.IsProcessAlive(pid))
            {
                throw new InvalidOperationException(
                    $"Telemetry socket '{socketPath}' is actively owned by process {pid}.");
            }
            TryUnlink(pidPath); 
        }

        if (File.Exists(socketPath))
            TryUnlink(socketPath);

        _processExitHandler = (_, _) =>
        {
            TryUnlink(_socketPath);
            TryUnlink(_pidPath);
        };

        AppDomain.CurrentDomain.ProcessExit += _processExitHandler;
        File.WriteAllText(pidPath, Environment.ProcessId.ToString());
    }

    public void ApplyMode(UnixFileMode mode) => File.SetUnixFileMode(_socketPath, mode);

    private static void TryUnlink(string path)
    {
        try
        {
            if (File.Exists(path)) File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Best-effort: file may already be gone, or permission may have
            // changed. ProcessExit path must never throw.
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        AppDomain.CurrentDomain.ProcessExit -= _processExitHandler;
        TryUnlink(_socketPath);
        TryUnlink(_pidPath);
        GC.SuppressFinalize(this);
    }
}
