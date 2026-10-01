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
    public void WindowExpiry_AllowsNewPromptAndPrunesOldEntries()
    {
        var limiter = new ApprovalPromptLimiter(3, TimeSpan.FromSeconds(30));
        var now = DateTimeOffset.Parse("2026-10-01T00:00:00Z");

        Assert.True(limiter.TryAcquire(now));
        Assert.True(limiter.TryAcquire(now.AddSeconds(1)));
        Assert.True(limiter.TryAcquire(now.AddSeconds(2)));
        Assert.True(limiter.TryAcquire(now.AddSeconds(31)));
        Assert.Equal(3, limiter.Count);
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
