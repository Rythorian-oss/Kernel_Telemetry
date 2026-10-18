using System.Diagnostics.Metrics;

namespace KernelTelemetry.Engine.Infrastructure;

public static class TelemetryMetrics
{
    private static readonly Meter Meter = new("KernelTelemetry.Engine", "1.0.0");

    public static readonly Counter<long> EventsReceived =
        Meter.CreateCounter<long>("kernel.events.received",
            description: "Events decoded from socket");

    public static readonly Counter<long> EventsPersisted =
        Meter.CreateCounter<long>("kernel.events.persisted",
            description: "Events written to Parquet");

    public static readonly Counter<long> EventsDropped =
        Meter.CreateCounter<long>("kernel.events.dropped",
            description: "Events dropped; tagged by reason: shutdown | sink | kernel");

    public static readonly Counter<long> BatchesWritten =
        Meter.CreateCounter<long>("kernel.batches.written");

    public static readonly Counter<long> BatchesFailed =
        Meter.CreateCounter<long>("kernel.batches.failed");

    public static readonly Histogram<int> ChannelDepth =
        Meter.CreateHistogram<int>("kernel.channel.depth");

    public static string MeterName => Meter.Name;
}