using DeleteGuard.Core.Localization;

namespace DeleteGuard.Core.Models;

/// <summary>
/// Per-user Agent preferences. These only affect notifications and approval
/// prompts. They never change what the kernel/ACL layers deny, and every value
/// is clamped to a safe range so a tampered settings file cannot turn the
/// approval prompt into an unbounded stream of dialogs.
/// </summary>
public sealed record AgentSettings
{
    public const int MinPromptsPerWindow = 1;
    public const int MaxPromptsPerWindowLimit = 5;
    public const int MinPromptWindowSeconds = 15;
    public const int MaxPromptWindowSeconds = 600;
    public const int MinPromptMaxAgeSeconds = 5;
    public const int MaxPromptMaxAgeSeconds = 60;
    public const int MinNoticeCooldownSeconds = 5;
    public const int MaxNoticeCooldownSeconds = 300;

    /// <summary>Show the approve/deny dialog for blocked deletions. Deletions stay blocked either way.</summary>
    public bool ShowApprovalPrompts { get; init; } = true;

    public int MaxPromptsPerWindow { get; init; } = 3;
    public int PromptWindowSeconds { get; init; } = 30;

    /// <summary>Events older than this are never turned into a prompt.</summary>
    public int PromptMaxAgeSeconds { get; init; } = 20;

    public bool ShowNamespaceNotices { get; init; } = true;
    public bool ShowThrottleNotices { get; init; } = true;
    public int NoticeCooldownSeconds { get; init; } = 15;

    /// <summary>"auto" (follow the Windows UI language) or a supported language code such as "zh-TW".</summary>
    public string Language { get; init; } = Loc.Auto;

    public static AgentSettings Default { get; } = new();

    public AgentSettings Normalize() => this with
    {
        Language = Loc.NormalizeSetting(Language),
        MaxPromptsPerWindow = Math.Clamp(MaxPromptsPerWindow, MinPromptsPerWindow, MaxPromptsPerWindowLimit),
        PromptWindowSeconds = Math.Clamp(PromptWindowSeconds, MinPromptWindowSeconds, MaxPromptWindowSeconds),
        PromptMaxAgeSeconds = Math.Clamp(PromptMaxAgeSeconds, MinPromptMaxAgeSeconds, MaxPromptMaxAgeSeconds),
        NoticeCooldownSeconds = Math.Clamp(NoticeCooldownSeconds, MinNoticeCooldownSeconds, MaxNoticeCooldownSeconds)
    };
}
