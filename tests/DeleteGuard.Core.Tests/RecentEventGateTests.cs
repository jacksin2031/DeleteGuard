using DeleteGuard.Core.Services;
using Xunit;

namespace DeleteGuard.Core.Tests;

public sealed class RecentEventGateTests
{
    [Fact]
    public void DuplicateWithinWindow_IsRejected()
    {
        var gate = new RecentEventGate(
            TimeSpan.FromSeconds(2),
            TimeSpan.FromSeconds(30),
            maxEntries: 512,
            StringComparer.OrdinalIgnoreCase);
        var now = DateTimeOffset.Parse("2026-10-01T00:00:00Z");

        Assert.True(gate.TryAccept("123|1|C:\\Protected\\a.txt", now));
        Assert.False(gate.TryAccept("123|1|c:\\protected\\A.TXT", now.AddSeconds(1)));
        Assert.Equal(1, gate.Count);
    }

    [Fact]
    public void SameKeyAfterDuplicateWindow_IsAccepted()
    {
        var gate = new RecentEventGate(
            TimeSpan.FromSeconds(2),
            TimeSpan.FromSeconds(30),
            maxEntries: 512);
        var now = DateTimeOffset.Parse("2026-10-01T00:00:00Z");

        Assert.True(gate.TryAccept("key", now));
        Assert.True(gate.TryAccept("key", now.AddSeconds(2)));
        Assert.Equal(1, gate.Count);
    }

    [Fact]
    public void UniqueFlood_IsHardCapped()
    {
        var gate = new RecentEventGate(
            TimeSpan.FromSeconds(2),
            TimeSpan.FromSeconds(30),
            maxEntries: 512);
        var now = DateTimeOffset.Parse("2026-10-01T00:00:00Z");

        for (var index = 0; index < 2_000; index++)
        {
            Assert.True(gate.TryAccept($"unique-{index}", now.AddMilliseconds(index)));
            Assert.InRange(gate.Count, 1, 512);
        }

        Assert.Equal(512, gate.Count);
    }

    [Fact]
    public void ExpiredEntries_AreRemovedBeforeOldestEviction()
    {
        var gate = new RecentEventGate(
            TimeSpan.FromSeconds(1),
            TimeSpan.FromSeconds(5),
            maxEntries: 2);
        var now = DateTimeOffset.Parse("2026-10-01T00:00:00Z");

        Assert.True(gate.TryAccept("old-a", now));
        Assert.True(gate.TryAccept("old-b", now.AddSeconds(1)));
        Assert.True(gate.TryAccept("fresh", now.AddSeconds(10)));

        Assert.Equal(1, gate.Count);
    }
}
