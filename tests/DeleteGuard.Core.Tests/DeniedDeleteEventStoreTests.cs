using DeleteGuard.Core.Driver;
using DeleteGuard.Core.Models;
using DeleteGuard.Core.Services;
using Xunit;

namespace DeleteGuard.Core.Tests;

public sealed class DeniedDeleteEventStoreTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "DeleteGuard.Tests", Guid.NewGuid().ToString("N"));

    [Fact]
    public void AppendAndReadLast_RoundTripsEvent()
    {
        var store = new DeniedDeleteEventStore(_directory);
        var record = new DeniedDeleteEventRecord
        {
            EventId = Guid.NewGuid(),
            ObservedUtc = DateTimeOffset.UtcNow,
            DriverSequence = 42,
            ProcessId = 1234,
            ProcessName = "test-process",
            Operation = DriverDeleteOperation.Disposition,
            NtPath = @"\Device\HarddiskVolume1\Data\file.txt",
            TargetPath = @"D:\Data\file.txt",
            CanApprove = true
        };

        store.Append(record);

        var read = Assert.Single(store.ReadLast(10));
        Assert.Equal(record.EventId, read.EventId);
        Assert.Equal(record.DriverSequence, read.DriverSequence);
        Assert.Equal(record.ProcessId, read.ProcessId);
        Assert.Equal(record.TargetPath, read.TargetPath);
        Assert.True(read.CanApprove);
    }

    [Fact]
    public void ReadLast_ReturnsOnlyRequestedTail()
    {
        var store = new DeniedDeleteEventStore(_directory);
        for (ulong i = 1; i <= 5; i++)
        {
            store.Append(new DeniedDeleteEventRecord
            {
                EventId = Guid.NewGuid(),
                ObservedUtc = DateTimeOffset.UtcNow,
                DriverSequence = i,
                ProcessId = 1,
                Operation = DriverDeleteOperation.Disposition,
                NtPath = $@"\Device\HarddiskVolume1\Data\{i}.txt",
                TargetPath = $@"D:\Data\{i}.txt",
                CanApprove = true
            });
        }

        var tail = store.ReadLast(2);
        Assert.Equal(new ulong[] { 4, 5 }, tail.Select(item => item.DriverSequence));
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_directory))
            {
                Directory.Delete(_directory, recursive: true);
            }
        }
        catch
        {
        }
    }
}
