using KernelTelemetry.Engine.Contracts;

namespace KernelTelemetry.Engine.Processing;

public interface IBatchSink : IAsyncDisposable
{
    ValueTask WriteAsync(IReadOnlyList<KernelEventModel> batch, CancellationToken ct);
}