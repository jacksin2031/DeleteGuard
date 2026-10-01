using Xunit;
using DeleteGuard.Core.Models;
using DeleteGuard.Core.Services;

namespace DeleteGuard.Core.Tests;

public sealed class PolicyStoreTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "DeleteGuard.Tests", Guid.NewGuid().ToString("N"));

    [Fact]
    public void Upsert_And_Remove_RoundTrip()
    {
        var store = new PolicyStore(_directory);
        var policy = new ProtectionPolicy
        {
            Id = Guid.NewGuid(),
            RootPath = @"C:\Data",
            CreatedUtc = DateTimeOffset.UtcNow,
            CreatedBySid = "S-1-5-21-test",
            GuardSid = "S-1-1-0",
            InsertedAclRule = true
        };

        store.Upsert(policy);
        Assert.Single(store.Load());
        Assert.Equal(policy.Id, store.FindExact(@"C:\Data\")!.Id);

        store.Remove(policy.Id);
        Assert.Empty(store.Load());
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }
}
