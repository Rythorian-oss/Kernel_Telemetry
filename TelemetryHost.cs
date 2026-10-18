using KernelTelemetry.Engine.Configuration;
using KernelTelemetry.Engine.Contracts;
using KernelTelemetry.Engine.Infrastructure;
using KernelTelemetry.Engine.Ingestion;
using KernelTelemetry.Engine.Processing;
using Serilog;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Channels;

namespace KernelTelemetry.Engine.Hosting;

public enum SinkFailurePolicy { Fail, Log }

public sealed class TelemetryHost : IAsyncDisposable
{
    private readonly TelemetryOptions _opts;
    private readonly ILogger _log;
    private readonly Channel<KernelEventModel> _channel;

    public TelemetryHost(TelemetryOptions opts, ILogger log)
    {
        _opts = opts;
        _log = log.ForContext<TelemetryHost>();

        _channel = Channel.CreateBounded<KernelEventModel>(new BoundedChannelOptions(opts.ChannelCapacity)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleWriter = true,
            SingleReader = true,
        });
    }

    public async Task RunAsync(SinkFailurePolicy policy, CancellationToken ct)
    {
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);

        await using var source = new UnixSocketEventSource(_opts, _log);
        await using var sink = new ParquetBatchSink(_opts, _log);

        var producer = Task.Run(() => PumpAsync(source, _channel.Writer, linkedCts.Token), linkedCts.Token);
        var consumer = Task.Run(() => ConsumeAsync(_channel.Reader, sink, policy, linkedCts.Token), linkedCts.Token);

        await Task.WhenAny(producer, consumer).ConfigureAwait(false);

        linkedCts.Cancel();
        _channel.Writer.TryComplete();

        try
        {
            await Task.WhenAll(producer, consumer).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw; // Main owns logging.
        }
    }

    // CA1822: genuinely stateless — made static.
    // CA1859: IEventSource is a deliberate seam. Narrowing to UnixSocketEventSource
    //         would make the producer untestable and prevent a future file-replay source.
    [SuppressMessage("Performance", "CA1859:Use concrete types when possible for improved performance",
        Justification = "IEventSource is a deliberate seam for testability (FakeEventSource) and future source implementations (file replay). Narrowing would remove the seam.")]
    private static async Task PumpAsync(
        IEventSource source,
        ChannelWriter<KernelEventModel> writer,
        CancellationToken ct)
    {
        try
        {
            await foreach (var evt in source.ReadAllAsync(ct).ConfigureAwait(false))
                await writer.WriteAsync(evt, ct).ConfigureAwait(false);
        }
        finally
        {
            writer.TryComplete();
        }
    }

    [SuppressMessage("Performance", "CA1859:Use concrete types when possible for improved performance",
        Justification = "IBatchSink is a deliberate seam for testability (SpySink/NullSink) and future sink implementations. Narrowing would remove the seam.")]
    private async Task ConsumeAsync(
        ChannelReader<KernelEventModel> reader,
        IBatchSink sink,
        SinkFailurePolicy policy,
        CancellationToken ct)
    {
        var batch = new List<KernelEventModel>(_opts.BatchSize);
        try
        {
            while (await reader.WaitToReadAsync(ct).ConfigureAwait(false))
            {
                TelemetryMetrics.ChannelDepth.Record(reader.Count);
                while (reader.TryRead(out var evt))
                {
                    batch.Add(evt);
                    if (batch.Count >= _opts.BatchSize)
                        await FlushAsync(sink, batch, policy, ct).ConfigureAwait(false);
                }
            }
        }
        finally
        {
            if (batch.Count > 0)
            {
                using var drainCts = new CancellationTokenSource(_opts.ShutdownDrainTimeout);
                try
                {
                    await FlushAsync(sink, batch, policy, drainCts.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    TelemetryMetrics.EventsDropped.Add(batch.Count,
                        new KeyValuePair<string, object?>("reason", "shutdown"));
                    _log.Warning("Shutdown drain timed out. Dropped {Count} events.", batch.Count);
                }
            }
        }
    }

    [SuppressMessage("Performance", "CA1859:Use concrete types when possible for improved performance",
        Justification = "IBatchSink is a deliberate seam (see ConsumeAsync).")]
    private async ValueTask FlushAsync(
        IBatchSink sink, List<KernelEventModel> batch, SinkFailurePolicy policy, CancellationToken ct)
    {
        using Activity? activity = TelemetryActivities.Source.StartActivity("ParquetFlush");
        activity?.SetTag("batch.size", batch.Count);

        try
        {
            await sink.WriteAsync(batch, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (policy == SinkFailurePolicy.Log)
        {
            TelemetryMetrics.BatchesFailed.Add(1);
            TelemetryMetrics.EventsDropped.Add(batch.Count,
                new KeyValuePair<string, object?>("reason", "sink"));
            _log.Error(ex, "Dropping batch of {Count} events due to sink error.", batch.Count);
        }
        finally
        {
            batch.Clear();
        }
    }

    public ValueTask DisposeAsync()
    {
        _channel.Writer.TryComplete();
        return ValueTask.CompletedTask;
    }
}