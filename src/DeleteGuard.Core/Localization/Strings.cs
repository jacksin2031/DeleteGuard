namespace DeleteGuard.Core.Localization;

/// <summary>
/// Translation tables. English is the source of truth: every other table must contain exactly
/// the same keys with the same {n} placeholders (enforced by LocalizationTests).
/// </summary>
internal static partial class Strings
{
    private static IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>>? _tables;

    // Built on first use rather than in a static initializer: initializer order across the
    // partial-class files (one per language) is unspecified, so the per-language fields
    // cannot be read while the type initializer is still running.
    internal static IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>> Tables =>
        _tables ??= new Dictionary<string, IReadOnlyDictionary<string, string>>(StringComparer.OrdinalIgnoreCase)
        {
            [Loc.English] = English,
            [Loc.TraditionalChinese] = TraditionalChinese,
            [Loc.SimplifiedChinese] = SimplifiedChinese,
            [Loc.Japanese] = Japanese,
            [Loc.Korean] = Korean,
            [Loc.Spanish] = Spanish,
            [Loc.French] = French,
            [Loc.German] = German,
            [Loc.PortugueseBrazil] = PortugueseBrazil,
            [Loc.Russian] = Russian
        };
}
