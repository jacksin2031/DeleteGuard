using System.Globalization;
using System.Text.RegularExpressions;
using DeleteGuard.Core.Localization;
using DeleteGuard.Core.Models;
using Xunit;

namespace DeleteGuard.Core.Tests;

public sealed class LocalizationTests
{
    private static readonly Regex Placeholder = new(@"\{(\d+)\}", RegexOptions.Compiled);

    public static IEnumerable<object[]> Languages() =>
        Loc.Supported.Select(option => new object[] { option.Code });

    [Fact]
    public void EveryLanguageIsRegistered_AndOptionsAreUnique()
    {
        Assert.Equal(10, Loc.Supported.Count);
        Assert.Equal(Loc.Supported.Count, Loc.Supported.Select(option => option.Code).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        foreach (var option in Loc.Supported)
        {
            Assert.True(Strings.Tables.ContainsKey(option.Code), $"No string table for {option.Code}");
            Assert.False(string.IsNullOrWhiteSpace(option.NativeName));
        }
    }

    [Theory]
    [MemberData(nameof(Languages))]
    public void Table_HasExactlyTheEnglishKeys(string language)
    {
        var english = Strings.Tables[Loc.English].Keys.ToHashSet(StringComparer.Ordinal);
        var other = Strings.Tables[language].Keys.ToHashSet(StringComparer.Ordinal);

        Assert.Empty(english.Except(other));
        Assert.Empty(other.Except(english));
    }

    [Theory]
    [MemberData(nameof(Languages))]
    public void Table_PlaceholdersMatchEnglish_AndNoValueIsBlank(string language)
    {
        foreach (var (key, englishValue) in Strings.Tables[Loc.English])
        {
            var value = Strings.Tables[language][key];
            Assert.False(string.IsNullOrWhiteSpace(value), $"{language}:{key} is blank");

            var expected = Placeholder.Matches(englishValue).Select(match => match.Value).OrderBy(x => x).ToArray();
            var actual = Placeholder.Matches(value).Select(match => match.Value).OrderBy(x => x).ToArray();
            Assert.True(expected.SequenceEqual(actual), $"{language}:{key} placeholders {string.Join(",", actual)} != {string.Join(",", expected)}");
        }
    }

    [Theory]
    [MemberData(nameof(Languages))]
    public void Table_EveryValueFormatsWithoutThrowing(string language)
    {
        foreach (var (key, _) in Strings.Tables[Loc.English])
        {
            var value = Strings.Tables[language][key];
            _ = string.Format(CultureInfo.InvariantCulture, value, "a", "b", "c");
        }
    }

    [Theory]
    [InlineData("en-US", "en")]
    [InlineData("zh-TW", "zh-TW")]
    [InlineData("zh-HK", "zh-TW")]
    [InlineData("zh-Hant", "zh-TW")]
    [InlineData("zh-CN", "zh-CN")]
    [InlineData("zh-SG", "zh-CN")]
    [InlineData("zh-Hans", "zh-CN")]
    [InlineData("ja-JP", "ja")]
    [InlineData("ko-KR", "ko")]
    [InlineData("es-MX", "es")]
    [InlineData("fr-CA", "fr")]
    [InlineData("de-AT", "de")]
    [InlineData("pt-PT", "pt-BR")]
    [InlineData("pt-BR", "pt-BR")]
    [InlineData("ru-RU", "ru")]
    [InlineData("sv-SE", "en")]
    public void FromCulture_MapsWindowsLanguageToSupportedOne(string windows, string expected) =>
        Assert.Equal(expected, Loc.FromCulture(CultureInfo.GetCultureInfo(windows)));

    [Fact]
    public void Resolve_AutoFollowsCulture_ExplicitWins_UnknownBecomesAuto()
    {
        var german = CultureInfo.GetCultureInfo("de-DE");
        Assert.Equal("de", Loc.Resolve("auto", german));
        Assert.Equal("ja", Loc.Resolve("ja", german));
        Assert.Equal("zh-TW", Loc.Resolve("ZH-tw", german));
        Assert.Equal("de", Loc.Resolve("klingon", german));
        Assert.Equal("de", Loc.Resolve(null, german));
        Assert.Equal("auto", Loc.NormalizeSetting("nonsense"));
        Assert.True(Loc.IsValidSetting("auto"));
        Assert.False(Loc.IsValidSetting("klingon"));
    }

    [Fact]
    public void Lookup_FallsBackToEnglishThenKey()
    {
        Assert.Equal("Settings", Loc.In("xx", "tab.settings"));
        Assert.Equal("no.such.key", Loc.In("de", "no.such.key"));
        Assert.Equal("Einstellungen", Loc.In("de", "tab.settings"));
    }

    [Fact]
    public void T_UsesCurrentLanguage_AndFormatsArguments()
    {
        var before = Loc.Current;
        try
        {
            Loc.SetLanguage("fr");
            Assert.Equal("Protégé : X", Loc.T("add.success", "X"));
            Loc.SetLanguage("en");
            Assert.Equal("Protected: X", Loc.T("add.success", "X"));
        }
        finally
        {
            Loc.SetLanguage(before);
        }
    }

    [Fact]
    public void Settings_Language_IsNormalizedAndRoundTrips()
    {
        Assert.Equal("auto", AgentSettings.Default.Language);
        Assert.Equal("auto", new AgentSettings { Language = "garbage" }.Normalize().Language);
        Assert.Equal("pt-BR", new AgentSettings { Language = "PT-br" }.Normalize().Language);
    }
}

/// <summary>Keeps the MSI's own localization files in step with each other and with the app languages.</summary>
public sealed class InstallerLocalizationTests
{
    private static readonly string[] Cultures =
        { "en-US", "zh-TW", "zh-CN", "ja-JP", "ko-KR", "es-ES", "fr-FR", "de-DE", "pt-BR", "ru-RU" };

    private static string LocalizationDirectory()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, "installer", "Localization");
            if (Directory.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new DirectoryNotFoundException("installer/Localization was not found above the test output directory.");
    }

    private static System.Xml.Linq.XDocument Load(string culture) =>
        System.Xml.Linq.XDocument.Load(Path.Combine(LocalizationDirectory(), culture + ".wxl"));

    private static Dictionary<string, string> Strings(string culture) =>
        Load(culture).Root!.Elements()
            .Where(element => element.Name.LocalName == "String")
            .ToDictionary(element => (string)element.Attribute("Id")!, element => (string)element.Attribute("Value")!);

    public static IEnumerable<object[]> InstallerCultures() => Cultures.Select(culture => new object[] { culture });

    [Fact]
    public void EveryAppLanguage_HasAnInstallerCulture()
    {
        // Each app language code ("zh-TW", "ja", "pt-BR"...) must map to one installer culture file.
        foreach (var option in Loc.Supported)
        {
            var language = option.Code.Split('-')[0];
            Assert.Contains(Cultures, culture => culture.StartsWith(language, StringComparison.OrdinalIgnoreCase));
        }

        Assert.Equal(Loc.Supported.Count, Cultures.Length);
    }

    [Theory]
    [MemberData(nameof(InstallerCultures))]
    public void WxlFile_MatchesEnglishIds_HasNoBlankValues_AndRightCulture(string culture)
    {
        var english = Strings("en-US");
        var other = Strings(culture);

        Assert.Equal(culture, (string?)Load(culture).Root!.Attribute("Culture"));
        Assert.Empty(english.Keys.Except(other.Keys));
        Assert.Empty(other.Keys.Except(english.Keys));
        foreach (var (id, value) in other)
        {
            Assert.False(string.IsNullOrWhiteSpace(value), $"{culture}:{id} is blank");
        }

        Assert.True(int.TryParse(other["LCID"], out var lcid) && lcid > 0, $"{culture}: LCID must be a number");
        Assert.Equal(lcid, CultureInfo.GetCultureInfo(culture).LCID);
    }
}
