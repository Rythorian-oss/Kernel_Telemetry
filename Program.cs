using KernelTelemetry.Engine.Configuration;
using KernelTelemetry.Engine.Contracts;
using KernelTelemetry.Engine.Hosting;
using KernelTelemetry.Engine.Infrastructure;
using OpenTelemetry;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;
using Serilog;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

[assembly: SupportedOSPlatform("linux")]

namespace KernelTelemetry.Engine;

public static class Program
{
    public static async Task<int> Main()
    {
        // Platform and wire-contract verification must run "BEFORE" any
        // Linux-only API is touched (TelemetryOptions calls getuid()).
        try
        {
            BinaryContract.VerifyPlatformOrThrow();
            BinaryContract.VerifyOrThrow();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Kernel Telemetry Engine startup aborted: {ex.Message}");
            return 1;
        }

        var opts = new TelemetryOptions();

        try
        {
            Directory.CreateDirectory(opts.LogDirectory);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Cannot create log directory '{opts.LogDirectory}': {ex.Message}");
            return 1;
        }

        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Information()
            .WriteTo.Console()
            .WriteTo.File(
                Path.Combine(opts.LogDirectory, "engine-.log"),
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 14,
                shared: false)
            .CreateLogger();

        // NOTE: Console exporter is for local/demo use.
        // For production, add OpenTelemetry.Exporter.OpenTelemetryProtocol
        // to the project and replace AddConsoleExporter() with AddOtlpExporter().
        using var tracerProvider = Sdk.CreateTracerProviderBuilder()
            .AddSource(TelemetryActivities.SourceName)
            .AddConsoleExporter()
            .Build();

        using var meterProvider = Sdk.CreateMeterProviderBuilder()
            .AddMeter(TelemetryMetrics.MeterName)
            .AddConsoleExporter()
            .Build();

        using var cts = new CancellationTokenSource();
        using var sigint = PosixSignalRegistration.Create(PosixSignal.SIGINT, ctx => { ctx.Cancel = true; cts.Cancel(); });
        using var sigterm = PosixSignalRegistration.Create(PosixSignal.SIGTERM, ctx => { ctx.Cancel = true; cts.Cancel(); });

        try
        {
            Log.Information("Kernel Telemetry Engine v{Version} running on .NET {Runtime}",
                BinaryContract.Version, Environment.Version);

            using var instanceLock = new SingleInstanceLock("KernelTelemetry.Engine");
            await using var host = new TelemetryHost(opts, Log.Logger);
            await host.RunAsync(SinkFailurePolicy.Fail, cts.Token).ConfigureAwait(false);
            return 0;
        }
        catch (OperationCanceledException) when (cts.IsCancellationRequested)
        {
            Log.Information("Shutdown requested. Pipeline terminated cleanly.");
            return 0;
        }
        catch (Exception ex)
        {
            Log.Fatal(ex, "Fatal error executing Kernel Telemetry Engine.");
            return 1;
        }
        finally
        {
            await Log.CloseAndFlushAsync().ConfigureAwait(false);
        }
    }
}
