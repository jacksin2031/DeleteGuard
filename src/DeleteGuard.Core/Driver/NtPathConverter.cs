using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using DeleteGuard.Core.Security;

namespace DeleteGuard.Core.Driver;

public static class NtPathConverter
{
    public static string ToNtPath(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("NT path conversion is available only on Windows.");
        }

        var normalized = PathRules.Normalize(path);
        var root = Path.GetPathRoot(normalized)
            ?? throw new InvalidOperationException("Unable to resolve the path root.");

        if (root.Length < 2 || root[1] != ':')
        {
            throw new NotSupportedException("DeleteGuard v0.2 minifilter currently supports drive-letter paths only.");
        }

        var drive = root[..2];
        var buffer = new StringBuilder(4096);
        var result = QueryDosDevice(drive, buffer, buffer.Capacity);
        if (result == 0)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"QueryDosDevice failed for {drive}.");
        }

        var raw = buffer.ToString();
        var nullIndex = raw.IndexOf('\0');
        var device = (nullIndex >= 0 ? raw[..nullIndex] : raw).TrimEnd('\\');
        if (device.Length == 0)
        {
            throw new InvalidOperationException($"QueryDosDevice returned an empty target for {drive}.");
        }

        var remainder = normalized[root.Length..].TrimStart('\\');
        var ntPath = remainder.Length == 0 ? device : $"{device}\\{remainder}";
        if (ntPath.Length >= DriverProtocol.MaxPathChars)
        {
            throw new PathTooLongException($"NT path exceeds {DriverProtocol.MaxPathChars - 1} characters.");
        }

        return ntPath;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDevice(
        string lpDeviceName,
        StringBuilder lpTargetPath,
        int ucchMax);
}
