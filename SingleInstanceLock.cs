namespace KernelTelemetry.Engine.Infrastructure;

/// <summary>
/// Cross-process exclusivity via a named <see cref="Mutex"/>. A second
/// instance fails at <see cref="WaitOne(TimeSpan)"/> before it touches
/// any file.
/// </summary>
public sealed class SingleInstanceLock : IDisposable
{
    private readonly Mutex _mutex;
    private readonly bool _owns;
    private bool _disposed;

    public SingleInstanceLock(string name)
    {
        _mutex = new Mutex(false, name);
        try
        {
            _owns = _mutex.WaitOne(TimeSpan.Zero);
        }
        catch (AbandonedMutexException)
        {
            _owns = true; // previous owner crashed; lock is ours
        }

        if (!_owns)
        {
            throw new InvalidOperationException(
                $"Another instance of Kernel Telemetry Engine ('{name}') is currently running.");
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_owns) _mutex.ReleaseMutex();
        _mutex.Dispose();
    }
}