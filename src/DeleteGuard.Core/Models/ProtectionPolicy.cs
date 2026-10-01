namespace DeleteGuard.Core.Models;

public sealed record ProtectionPolicy
{
    public required Guid Id { get; init; }
    public required string RootPath { get; init; }
    public required DateTimeOffset CreatedUtc { get; init; }
    public required string CreatedBySid { get; init; }
    public required string GuardSid { get; init; }
    public required bool InsertedAclRule { get; init; }
    public bool Enabled { get; init; } = true;
}
