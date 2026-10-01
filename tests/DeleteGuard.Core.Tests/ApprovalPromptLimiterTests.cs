using DeleteGuard.Core.Services;
using Xunit;

namespace DeleteGuard.Core.Tests;

public sealed class ApprovalPromptLimiterTests
{
    [Fact]
    public void FourthPromptWithinWindow_IsRejected()
    {
        var limiter = new ApprovalPromptLimiter(3, TimeSpan.FromSeconds(30));
        var now = DateTimeOffset.Parse("2026-10-01T00:00:00Z");

        Assert.True(limiter.TryAcquire(now));
        Assert.True(limiter.TryAcquire(now.AddSeconds(1)));
        Assert.True(limiter.TryAcquire(now.AddSeconds(2)));
        Assert.False(limiter.TryAcquire(now.AddSeconds(3)));
        Assert.Equal(3, limiter.Count);
    }

    [Fact]
    public void WindowExpiry_AllowsNewPromptAndPrunesExpiredEntries()
    {
        var limiter = new ApprovalPromptLimiter(3, TimeSpan.FromSeconds(30));
        var now = DateTimeOffset.Parse("2026-10-01T00:00:00Z");

        Assert.True(limiter.TryAcquire(now));
        Assert.True(limiter.TryAcquire(now.AddSeconds(1)));
        Assert.True(limiter.TryAcquire(now.AddSeconds(2)));

        // At t=31, both t=0 and t=1 are at least 30 seconds old and are
        // outside the rolling window. t=2 remains, then the new prompt is added.
        Assert.True(limiter.TryAcquire(now.AddSeconds(31)));
        Assert.Equal(2, limiter.Count);
    }

    [Fact]
    public void PromptExactlyAtWindowBoundary_ExpiresOldestEntry()
    {
        var limiter = new ApprovalPromptLimiter(1, TimeSpan.FromSeconds(30));
        var now = DateTimeOffset.Parse("2026-10-01T00:00:00Z");

        Assert.True(limiter.TryAcquire(now));
        Assert.False(limiter.TryAcquire(now.AddSeconds(29.999)));
        Assert.True(limiter.TryAcquire(now.AddSeconds(30)));
        Assert.Equal(1, limiter.Count);
    }

    [Fact]
    public void Constructor_RejectsInvalidLimits()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new ApprovalPromptLimiter(0, TimeSpan.FromSeconds(30)));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new ApprovalPromptLimiter(3, TimeSpan.Zero));
    }
}
