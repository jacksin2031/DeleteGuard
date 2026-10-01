using Xunit;
using DeleteGuard.Core.Models;
using DeleteGuard.Core.Security;

namespace DeleteGuard.Core.Tests;

public sealed class PathRulesTests
{
    [Fact]
    public void Descendant_IsMatched()
    {
        Assert.True(PathRules.IsSameOrDescendant(@"C:\Data\Project\file.txt", @"C:\Data"));
    }

    [Fact]
    public void PrefixSibling_IsNotMatched()
    {
        Assert.False(PathRules.IsSameOrDescendant(@"C:\Database", @"C:\Data"));
    }

    [Fact]
    public void FindDeepestPolicy_PrefersMostSpecificRoot()
    {
        var policies = new[]
        {
            Policy(@"C:\Data"),
            Policy(@"C:\Data\Critical")
        };

        var match = PathRules.FindDeepestPolicy(policies, @"C:\Data\Critical\a.txt");

        Assert.NotNull(match);
        Assert.Equal(PathRules.Normalize(@"C:\Data\Critical"), PathRules.Normalize(match!.RootPath));
    }

    private static ProtectionPolicy Policy(string root) => new()
    {
        Id = Guid.NewGuid(),
        RootPath = root,
        CreatedUtc = DateTimeOffset.UtcNow,
        CreatedBySid = "S-1-5-21-test",
        GuardSid = "S-1-1-0",
        InsertedAclRule = true
    };
}
