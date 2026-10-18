using KernelTelemetry.Engine.Configuration;
using KernelTelemetry.Engine.Contracts;
using KernelTelemetry.Engine.Infrastructure;
using Serilog;
using System.Buffers;
using System.Buffers.Binary;
using System.IO.Pipelines;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Threading.Channels;

namespace KernelTelemetry.Engine.Ingestion;

[SupportedOSPlatform("linux")]
public sealed class UnixSocketEventSource : IEventSource, IAsyncDisposable
{
    private readonly TelemetryOptions _opts;
    private readonly ILogger _log;
    private readonly Channel<KernelEventModel> _channel;
    // Default-capacity List<T>: the parser in some .NET 9.x SDK builds
    // misfires on `new List<T>(N)` in field initializers when
    // LangVersion=latest, treating `(N)` as a preview "collection
    // expression argument". Combined with LangVersion=12.0 in
    // Directory.Build.props, this form is stable across every SDK.
    private readonly List<KernelEventModel> _parsedEvents = [];
    private readonly List<ulong> _dropCounts = [];
    private int _started;
    private volatile Socket? _listener;

    public UnixSocketEventSource(TelemetryOptions opts, ILogger log)
    {
        _opts = opts;
        _log = log.ForContext<UnixSocketEventSource>();

        _channel = Channel.CreateBounded<KernelEventModel>(new BoundedChannelOptions(opts.ChannelCapacity)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleWriter = true,
            SingleReader = true,
        });
    }

    public IAsyncEnumerable<KernelEventModel> ReadAllAsync(CancellationToken ct)
    {
        if (Interlocked.Exchange(ref _started, 1) != 0)
        {
            throw new InvalidOperationException(
                "ReadAllAsync may only be called once per event source instance.");
        }

        _ = Task.Run(async () =>
        {
            try
            {
                await PumpSocketAsync(_channel.Writer, ct).ConfigureAwait(false);
                _channel.Writer.TryComplete();
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                _channel.Writer.TryComplete();
            }
            catch (Exception ex)
            {
                _channel.Writer.TryComplete(ex);
            }
        }, ct);

        return _channel.Reader.ReadAllAsync(ct);
    }

    private async Task PumpSocketAsync(ChannelWriter<KernelEventModel> writer, CancellationToken ct)
    {
        using var guard = new SocketPathGuard(_opts.SocketPath, _opts.PidFilePath);

        _listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        _listener.Bind(new UnixDomainSocketEndPoint(_opts.SocketPath));
        guard.ApplyMode(_opts.SocketMode);
        _listener.Listen(backlog: 1);
        _log.Information("Listening on {Path} (mode {Mode})", _opts.SocketPath, _opts.SocketMode);

        while (!ct.IsCancellationRequested)
        {
            Socket client;
            try
            {
                client = await _listener.AcceptAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            using (client)
            {
                uint peerUid;
                try
                {
                    peerUid = UnixPeerCredentials.GetPeerUid(client);
                }
                catch (Exception ex)
                {
                    _log.Warning(ex, "Failed to read SO_PEERCRED from client.");
                    continue;
                }

                if (!_opts.AllowedPeerUids.Contains(peerUid))
                {
                    _log.Warning("Rejected client UID {Uid}. Allowed: {Allowed}",
                        peerUid, string.Join(",", _opts.AllowedPeerUids));
                    continue;
                }

                client.ReceiveBufferSize = 4 * 1024 * 1024;
                _log.Information("Authenticated collector connection (UID {Uid})", peerUid);

                await using var stream = new NetworkStream(client, ownsSocket: false);
                var pipeReader = PipeReader.Create(stream,
                    new StreamPipeReaderOptions(bufferSize: 64 * 1024, minimumReadSize: 16 * 1024));

                bool handshook = false;
                try
                {
                    while (!ct.IsCancellationRequested)
                    {
                        ReadResult result = await pipeReader.ReadAsync(ct).ConfigureAwait(false);
                        ReadOnlySequence<byte> buffer = result.Buffer;

                        _parsedEvents.Clear();
                        _dropCounts.Clear();

                        // PHASE 1: synchronous parse. Ref structs die here.
                        ParseFrames(buffer, ref handshook, _parsedEvents, _dropCounts, _log,
                            out SequencePosition consumed);

                        pipeReader.AdvanceTo(consumed, buffer.End);

                        // PHASE 2: asynchronous dispatch. No ref structs in scope.
                        foreach (var evt in _parsedEvents)
                        {
                            TelemetryMetrics.EventsReceived.Add(1);
                            await writer.WriteAsync(evt, ct).ConfigureAwait(false);
                        }

                        foreach (ulong count in _dropCounts)
                        {
                            TelemetryMetrics.EventsDropped.Add((long)count,
                                new KeyValuePair<string, object?>("reason", "kernel"));
                        }

                        if (result.IsCompleted) break;
                    }
                }
                catch (InvalidOperationException ex)
                {
                    _log.Warning(ex, "Socket protocol validation error. Resetting accept loop.");
                    continue;
                }
                finally
                {
                    await pipeReader.CompleteAsync().ConfigureAwait(false);
                }
            }
        }
    }

    private static void ParseFrames(
        ReadOnlySequence<byte> buffer,
        ref bool handshook,
        List<KernelEventModel> parsedEvents,
        List<ulong> dropCounts,
        ILogger log,
        out SequencePosition consumed)
    {
        var seq = new SequenceReader<byte>(buffer);

        Span<byte> frameHdr = stackalloc byte[BinaryContract.HeaderSize];
        Span<byte> frame = stackalloc byte[BinaryContract.EventSize];
        Span<byte> dropBuf = stackalloc byte[BinaryContract.DropFrameSize];

        if (!handshook)
        {
            if (seq.Remaining < BinaryContract.HeaderSize)
            {
                consumed = seq.Position;
                return;
            }
            seq.TryCopyTo(frameHdr);
            seq.Advance(BinaryContract.HeaderSize);
            VerifyHandshake(frameHdr, log);
            handshook = true;
        }

        while (seq.Remaining >= BinaryContract.HeaderSize)
        {
            seq.TryCopyTo(frameHdr);
            ushort frameType = BinaryPrimitives.ReadUInt16LittleEndian(frameHdr[6..8]);

            if (frameType == BinaryContract.FrameTypeData)
            {
                if (seq.Remaining < BinaryContract.HeaderSize + BinaryContract.EventSize)
                    break;
                seq.Advance(BinaryContract.HeaderSize);

                seq.TryCopyTo(frame);
                seq.Advance(BinaryContract.EventSize);

                KernelEventRaw raw = MemoryMarshal.Read<KernelEventRaw>(frame);
                KernelEventModel? model = Decode(ref raw);
                if (model is not null) parsedEvents.Add(model);
            }
            else if (frameType == BinaryContract.FrameTypeDrop)
            {
                if (seq.Remaining < BinaryContract.HeaderSize + BinaryContract.DropFrameSize)
                    break;
                seq.Advance(BinaryContract.HeaderSize);

                seq.TryCopyTo(dropBuf);
                seq.Advance(BinaryContract.DropFrameSize);

                dropCounts.Add(BinaryPrimitives.ReadUInt64LittleEndian(dropBuf));
            }
            else
            {
                throw new InvalidOperationException(
                    $"Unknown wire frame type: {frameType}");
            }
        }

        consumed = seq.Position;
    }

    private static KernelEventModel? Decode(ref KernelEventRaw raw)
    {
        long ticks = (long)(raw.TimestampNs / 100UL);
        if (ticks > DateTime.MaxValue.Ticks) return null;

        return new KernelEventModel(
            TimestampUtc: DateTime.UnixEpoch.AddTicks(ticks),
            TimestampNs: raw.TimestampNs,
            StartTimeNs: raw.StartTimeNs,
            Pid: raw.Pid,
            Ppid: raw.Ppid,
            Uid: raw.Uid,
            ProcessName: raw.GetComm(),
            ExecutablePath: raw.GetFilename());
    }

    private static void VerifyHandshake(ReadOnlySpan<byte> hdr, ILogger log)
    {
        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(hdr[..4]);
        ushort version = BinaryPrimitives.ReadUInt16LittleEndian(hdr[4..6]);
        ushort type = BinaryPrimitives.ReadUInt16LittleEndian(hdr[6..8]);

        if (magic != BinaryContract.Magic || version != BinaryContract.Version)
        {
            throw new InvalidOperationException(
                $"Handshake failure (Magic: 0x{magic:X8}, Version: {version}, Type: {type}).");
        }

        if (type != BinaryContract.FrameTypeData)
        {
            throw new InvalidOperationException(
                $"Handshake frame type must be DATA ({BinaryContract.FrameTypeData}), received {type}.");
        }

        log.Information("Handshake verified (Version {Version}, HeaderType {Type})", version, type);
    }

    public ValueTask DisposeAsync()
    {
        _listener?.Dispose();
        _listener = null;
        return ValueTask.CompletedTask;
    }
}