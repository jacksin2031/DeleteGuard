using System.Text.Json.Serialization;

namespace DeleteGuard.Core.Models;

/// <summary>How a protected folder is guarded.</summary>
public enum ProtectionMode
{
    /// <summary>Nothing inside can be deleted by ordinary programs (NTFS ACL plus the driver).</summary>
    Full = 0,

    /// <summary>
    /// Ordinary deletes, renames and edits work; deleting more than a threshold within a time window is
    /// blocked. Enforced only by the minifilter driver, with no NTFS ACL fallback.
    /// </summary>
    BulkGuard = 1
}

public sealed record ProtectionPolicy
{
    public const int DefaultBulkThreshold = 25;
    public const int DefaultBulkWindowSeconds = 10;
    public const int MinBulkThreshold = 1;
    public const int MaxBulkThreshold = 100_000;
    public const int MinBulkWindowSeconds = 1;
    public const int MaxBulkWindowSeconds = 3600;

    public required Guid Id { get; init; }
    public required string RootPath { get; init; }
    public required DateTimeOffset CreatedUtc { get; init; }
    public required string CreatedBySid { get; init; }
    public required string GuardSid { get; init; }
    public required bool InsertedAclRule { get; init; }
    public bool Enabled { get; init; } = true;

    /// <summary>Policies written by older versions have no mode and are full protection.</summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public ProtectionMode Mode { get; init; } = ProtectionMode.Full;

    /// <summary>BulkGuard only: deletions allowed per window before further ones are blocked.</summary>
    public int BulkThreshold { get; init; } = DefaultBulkThreshold;

    /// <summary>BulkGuard only: window length in seconds.</summary>
    public int BulkWindowSeconds { get; init; } = DefaultBulkWindowSeconds;
}
