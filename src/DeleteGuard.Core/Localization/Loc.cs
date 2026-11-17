using System.Globalization;

namespace DeleteGuard.Core.Localization;

public sealed record LanguageOption(string Code, string NativeName);

/// <summary>
/// Minimal localization for user-facing text. Strings are keyed tables per language
/// (see <see cref="Strings"/>); a missing key falls back to English and finally to the
/// key itself, so a translation gap can never crash the UI.
/// </summary>
public static class Loc
{
    public const string Auto = "auto";
    public const string English = "en";
    public const string TraditionalChinese = "zh-TW";
    public const string SimplifiedChinese = "zh-CN";
    public const string Japanese = "ja";
    public const string Korean = "ko";
    public const string Spanish = "es";
    public const string French = "fr";
    public const string German = "de";
    public const string PortugueseBrazil = "pt-BR";
    public const string Russian = "ru";

    private static readonly object Sync = new();
    private static string _current = English;

    /// <summary>Concrete languages, in the order shown in language pickers (excluding "auto").</summary>
    public static IReadOnlyList<LanguageOption> Supported { get; } = new[]
    {
        new LanguageOption(English, "English"),
        new LanguageOption(TraditionalChinese, "繁體中文"),
        new LanguageOption(SimplifiedChinese, "简体中文"),
        new LanguageOption(Japanese, "日本語"),
        new LanguageOption(Korean, "한국어"),
        new LanguageOption(Spanish, "Español"),
        new LanguageOption(French, "Français"),
        new LanguageOption(German, "Deutsch"),
        new LanguageOption(PortugueseBrazil, "Português (Brasil)"),
        new LanguageOption(Russian, "Русский")
    };

    /// <summary>The resolved concrete language currently in use.</summary>
    public static string Current
    {
        get
        {
            lock (Sync)
            {
                return _current;
            }
        }
    }

    public static bool IsValidSetting(string? setting) =>
        string.Equals(setting, Auto, StringComparison.OrdinalIgnoreCase) ||
        Supported.Any(option => string.Equals(option.Code, setting, StringComparison.OrdinalIgnoreCase));

    /// <summary>Normalizes a stored setting to "auto" or one supported code (unknown values become "auto").</summary>
    public static string NormalizeSetting(string? setting)
    {
        if (string.IsNullOrWhiteSpace(setting))
        {
            return Auto;
        }

        var match = Supported.FirstOrDefault(option =>
            string.Equals(option.Code, setting.Trim(), StringComparison.OrdinalIgnoreCase));
        return match?.Code ?? Auto;
    }

    /// <summary>Applies a setting ("auto" follows the Windows UI language) and returns the resolved language.</summary>
    public static string SetLanguage(string? setting, CultureInfo? uiCulture = null)
    {
        var resolved = Resolve(setting, uiCulture ?? CultureInfo.CurrentUICulture);
        lock (Sync)
        {
            _current = resolved;
        }

        return resolved;
    }

    public static string Resolve(string? setting, CultureInfo uiCulture)
    {
        var normalized = NormalizeSetting(setting);
        return normalized == Auto ? FromCulture(uiCulture) : normalized;
    }

    /// <summary>Maps a Windows UI culture to the closest supported language (English when none fits).</summary>
    public static string FromCulture(CultureInfo culture)
    {
        var name = culture.Name;
        if (name.StartsWith("zh", StringComparison.OrdinalIgnoreCase))
        {
            var traditional = name.Contains("Hant", StringComparison.OrdinalIgnoreCase) ||
                              name.EndsWith("-TW", StringComparison.OrdinalIgnoreCase) ||
                              name.EndsWith("-HK", StringComparison.OrdinalIgnoreCase) ||
                              name.EndsWith("-MO", StringComparison.OrdinalIgnoreCase);
            return traditional ? TraditionalChinese : SimplifiedChinese;
        }

        return culture.TwoLetterISOLanguageName.ToLowerInvariant() switch
        {
            "ja" => Japanese,
            "ko" => Korean,
            "es" => Spanish,
            "fr" => French,
            "de" => German,
            "pt" => PortugueseBrazil,
            "ru" => Russian,
            _ => English
        };
    }

    public static string T(string key) => Lookup(Current, key);

    public static string T(string key, params object[] args) =>
        string.Format(CultureInfo.CurrentCulture, Lookup(Current, key), args);

    public static string In(string language, string key) => Lookup(language, key);

    private static string Lookup(string language, string key)
    {
        if (Strings.Tables.TryGetValue(language, out var table) && table.TryGetValue(key, out var value))
        {
            return value;
        }

        if (Strings.Tables[English].TryGetValue(key, out var fallback))
        {
            return fallback;
        }

        return key;
    }
}
