using System.Diagnostics;

namespace KernelTelemetry.Engine.Infrastructure;

public static class TelemetryActivities
{
    public const string SourceName = "KernelTelemetry.Engine";
    public static readonly ActivitySource Source = new(SourceName, "1.0.0");
}