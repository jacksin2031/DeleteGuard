namespace DeleteGuard.Core.Models;

public sealed record AuditEntry
{
    public required DateTimeOffset TimestampUtc { get; init; }
    public required string Action { get; init; }
    public required string TargetPath { get; init; }
    public required string Result { get; init; }
    public required string ActorSid { get; init; }
    public string? Detail { get; init; }
}
