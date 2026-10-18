using KernelTelemetry.Engine.Configuration;
using KernelTelemetry.Engine.Contracts;
using KernelTelemetry.Engine.Infrastructure;
using Parquet;
using Parquet.Data;
using Parquet.Schema;
using Serilog;

namespace KernelTelemetry.Engine.Processing;

/// <summary>
/// Writes batches to Parquet. Uses temp-file + rename so a crash never leaves
/// a half-written file, and names files with UTC timestamp + GUID so restarts
/// cannot collide. Does NOT log on failure — the host owns policy.
/// </summary>
public sealed class ParquetBatchSink : IBatchSink
{
    private readonly TelemetryOptions _opts;
    private readonly ILogger _log;
    private readonly ParquetSchema _schema;

    public ParquetBatchSink(TelemetryOptions opts, ILogger log)
    {
        _opts = opts;
        _log = log.ForContext<ParquetBatchSink>();
        Directory.CreateDirectory(_opts.DataDirectory);

        // The authoritative timestamp is TimestampNs (ulong), preserved with full nanosecond resolution. 
        // Parquet.Net maps DateTime to TIMESTAMP_MICROS.
        _schema = new ParquetSchema(
            new DateTimeDataField("TimestampUtc", DateTimeFormat.DateAndTimeMicros),
            new DataField<ulong>("TimestampNs"),
            new DataField<ulong>("StartTimeNs"),
            new DataField<uint>("Pid"),
            new DataField<uint>("Ppid"),
            new DataField<uint>("Uid"),
            new DataField<string>("ProcessName"),
            new DataField<string>("ExecutablePath"));
    }

    public async ValueTask WriteAsync(IReadOnlyList<KernelEventModel> batch, CancellationToken ct)
    {
        if (batch.Count == 0) return;

        var ts = new DateTime[batch.Count];
        var tsNs = new ulong[batch.Count];
        var st = new ulong[batch.Count];
        var pid = new uint[batch.Count];
        var ppid = new uint[batch.Count];
        var uid = new uint[batch.Count];
        var name = new string[batch.Count];
        var path = new string[batch.Count];

        for (int i = 0; i < batch.Count; i++)
        {
            var e = batch[i];
            ts[i] = e.TimestampUtc;
            tsNs[i] = e.TimestampNs;
            st[i] = e.StartTimeNs;
            pid[i] = e.Pid;
            ppid[i] = e.Ppid;
            uid[i] = e.Uid;
            name[i] = e.ProcessName;
            path[i] = e.ExecutablePath;
        }

        string fileName = $"events_{DateTime.UtcNow:yyyyMMddTHHmmssfffZ}_{Guid.NewGuid():N}.parquet";
        string finalPath = Path.Combine(_opts.DataDirectory, fileName);
        string tempPath = finalPath + ".tmp";

        try
        {
            await using (FileStream fs = File.Create(tempPath))
            await using (ParquetWriter writer = await ParquetWriter.CreateAsync(_schema, fs, cancellationToken: ct))
            using (ParquetRowGroupWriter group = writer.CreateRowGroup())
            {
                await group.WriteColumnAsync(new DataColumn(_schema.DataFields[0], ts), ct);
                await group.WriteColumnAsync(new DataColumn(_schema.DataFields[1], tsNs), ct);
                await group.WriteColumnAsync(new DataColumn(_schema.DataFields[2], st), ct);
                await group.WriteColumnAsync(new DataColumn(_schema.DataFields[3], pid), ct);
                await group.WriteColumnAsync(new DataColumn(_schema.DataFields[4], ppid), ct);
                await group.WriteColumnAsync(new DataColumn(_schema.DataFields[5], uid), ct);
                await group.WriteColumnAsync(new DataColumn(_schema.DataFields[6], name), ct);
                await group.WriteColumnAsync(new DataColumn(_schema.DataFields[7], path), ct);
            }

            File.Move(tempPath, finalPath, overwrite: false);
            TelemetryMetrics.BatchesWritten.Add(1);
            TelemetryMetrics.EventsPersisted.Add(batch.Count);
            _log.Debug("Persisted {Count} events to {File}", batch.Count, fileName);
        }
        catch (Exception)
        {
            try
            {
                if (File.Exists(tempPath)) File.Delete(tempPath);
            }
            catch (Exception cleanupEx) when (cleanupEx is IOException or UnauthorizedAccessException)
            {
                // Best-effort: host will log the original failure below.
            }
            throw; // Host owns logging and policy.
        }
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
