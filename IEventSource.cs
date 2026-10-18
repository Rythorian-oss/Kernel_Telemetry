using KernelTelemetry.Engine.Contracts;

namespace KernelTelemetry.Engine.Ingestion;

/// <summary>
/// A one-shot source of kernel events. Implementations are expected to be
/// single-call: invoking <see cref="ReadAllAsync"/> twice throws.
/// </summary>
public interface IEventSource
{
    IAsyncEnumerable<KernelEventModel> ReadAllAsync(CancellationToken ct);
}