using System.Runtime.InteropServices;
using DeleteGuard.Core.Driver;

namespace DeleteGuard.Core.Tests;

public sealed class DriverProtocolTests
{
    [Fact]
    public void CommandLayout_MatchesNativeProtocol()
    {
        Assert.Equal(1056, DriverProtocol.CommandSize);
        Assert.Equal(8, DriverProtocol.ReplySize);
        Assert.Equal(1056, Marshal.SizeOf<DriverCommand>());
    }

    [Fact]
    public void CommandCreate_RejectsOversizedPath()
    {
        var path = new string('x', DriverProtocol.MaxPathChars);
        Assert.Throws<PathTooLongException>(() => DriverCommand.Create(DriverCommandType.AddRoot, path));
    }

    [Fact]
    public void NtPathConverter_MapsDriveLetterPathToDevicePath()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var ntPath = NtPathConverter.ToNtPath(Path.GetTempPath());
        Assert.True(ntPath.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase), ntPath);
    }
}
