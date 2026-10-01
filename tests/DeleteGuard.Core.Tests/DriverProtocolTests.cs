using System.Runtime.InteropServices;
using DeleteGuard.Core.Driver;
using Xunit;

namespace DeleteGuard.Core.Tests;

public sealed class DriverProtocolTests
{
    [Fact]
    public void ProtocolLayouts_MatchNativeDefinitions()
    {
        Assert.Equal(8, DriverProtocol.ConnectContextSize);
        Assert.Equal(1056, DriverProtocol.CommandSize);
        Assert.Equal(8, DriverProtocol.ReplySize);
        Assert.Equal(1064, DriverProtocol.EventSize);
        Assert.Equal(16, DriverProtocol.FilterMessageHeaderSize);
        Assert.Equal(1080, DriverProtocol.EventEnvelopeSize);

        Assert.Equal(8, Marshal.SizeOf<DriverConnectContext>());
        Assert.Equal(1056, Marshal.SizeOf<DriverCommand>());
        Assert.Equal(1064, Marshal.SizeOf<DriverEvent>());
    }

    [Fact]
    public void CommandCreate_RejectsOversizedPath()
    {
        var path = new string('x', DriverProtocol.MaxPathChars);
        Assert.Throws<PathTooLongException>(() => DriverCommand.Create(DriverCommandType.AddRoot, path));
    }

    [Fact]
    public void NtPathConverter_RoundTripsDriveLetterPath()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var input = Path.GetFullPath(Path.GetTempPath()).TrimEnd('\\');
        var ntPath = NtPathConverter.ToNtPath(input);

        Assert.True(ntPath.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase), ntPath);
        Assert.True(NtPathConverter.TryFromNtPath(ntPath, out var roundTrip), ntPath);
        Assert.Equal(input, roundTrip.TrimEnd('\\'), ignoreCase: true);
    }
}
