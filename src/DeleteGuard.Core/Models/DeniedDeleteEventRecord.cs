using DeleteGuard.Core.Driver;

namespace DeleteGuard.Core.Models;

public sealed class DeniedDeleteEventRecord
{
    public Guid EventId { get; init; } = Guid.NewGuid();
    public DateTimeOffset ObservedUtc { get; init; }
    public ulong DriverSequence { get; init; }
    public uint ProcessId { get; init; }
    public string? ProcessName { get; init; }
    public DriverDeleteOperation Operation { get; init; }
    public string NtPath { get; init; } = string.Empty;
    public string TargetPath { get; init; } = string.Empty;
    public bool CanApprove { get; init; }
}
