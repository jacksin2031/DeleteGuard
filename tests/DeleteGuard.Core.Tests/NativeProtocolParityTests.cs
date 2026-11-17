using System.Text.RegularExpressions;
using DeleteGuard.Core.Driver;
using Xunit;

namespace DeleteGuard.Core.Tests;

/// <summary>
/// Compares the native minifilter protocol header against the managed enums so the
/// two cannot drift apart silently (the values are wire-level ABI).
/// </summary>
public sealed class NativeProtocolParityTests
{
    [Fact]
    public void ProtocolVersion_MatchesNativeHeader()
    {
        var header = ReadHeader();
        var match = Regex.Match(header, @"#define\s+DG_PROTOCOL_VERSION\s+(\d+)u");
        Assert.True(match.Success, "DG_PROTOCOL_VERSION not found in DeleteGuardFilter.h");
        Assert.Equal(DriverProtocol.Version, uint.Parse(match.Groups[1].Value));

        var maxPath = Regex.Match(header, @"#define\s+DG_MAX_PATH_CHARS\s+(\d+)");
        Assert.True(maxPath.Success, "DG_MAX_PATH_CHARS not found in DeleteGuardFilter.h");
        Assert.Equal(DriverProtocol.MaxPathChars, int.Parse(maxPath.Groups[1].Value));
    }

    [Fact]
    public void ClientRole_MatchesNativeHeader() =>
        AssertEnumParity<DriverClientRole>("DG_CLIENT_ROLE", "DgClientRole");

    [Fact]
    public void CommandType_MatchesNativeHeader() =>
        AssertEnumParity<DriverCommandType>("DG_COMMAND_TYPE", "DgCommand");

    [Fact]
    public void EventType_MatchesNativeHeader() =>
        AssertEnumParity<DriverEventType>("DG_EVENT_TYPE", "DgEvent");

    [Fact]
    public void DeleteOperation_MatchesNativeHeader() =>
        AssertEnumParity<DriverDeleteOperation>("DG_DELETE_OPERATION", "DgDeleteOperation");

    private static void AssertEnumParity<TEnum>(string nativeTypeName, string memberPrefix)
        where TEnum : struct, Enum
    {
        var native = ParseNativeEnum(ReadHeader(), nativeTypeName, memberPrefix);
        var managed = Enum.GetValues<TEnum>()
            .ToDictionary(value => value.ToString(), value => Convert.ToUInt32(value));

        Assert.Equal(
            native.OrderBy(pair => pair.Key).ToArray(),
            managed.OrderBy(pair => pair.Key).ToArray());
    }

    private static Dictionary<string, uint> ParseNativeEnum(string header, string nativeTypeName, string memberPrefix)
    {
        var block = Regex.Match(
            header,
            @"typedef\s+enum\s+_" + Regex.Escape(nativeTypeName) + @"\s*\{(?<body>[^}]*)\}\s*" + Regex.Escape(nativeTypeName) + ";",
            RegexOptions.Singleline);
        Assert.True(block.Success, $"{nativeTypeName} enum not found in DeleteGuardFilter.h");

        var result = new Dictionary<string, uint>(StringComparer.Ordinal);
        foreach (Match member in Regex.Matches(block.Groups["body"].Value, @"(?<name>\w+)\s*=\s*(?<value>\d+)"))
        {
            var name = member.Groups["name"].Value;
            Assert.StartsWith(memberPrefix, name, StringComparison.Ordinal);
            result.Add(name[memberPrefix.Length..], uint.Parse(member.Groups["value"].Value));
        }

        Assert.NotEmpty(result);
        return result;
    }

    private static string ReadHeader()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, "drivers", "DeleteGuard.Filter", "DeleteGuardFilter.h");
            if (File.Exists(candidate))
            {
                return File.ReadAllText(candidate);
            }
        }

        throw new FileNotFoundException("DeleteGuardFilter.h was not found above the test output directory.");
    }
}
