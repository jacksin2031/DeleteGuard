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
            throw new NotSupportedException("DeleteGuard minifilter currently supports drive-letter paths only.");
        }

        var drive = root[..2];
        var device = QueryDeviceTarget(drive);
        var remainder = normalized[root.Length..].TrimStart('\\');
        var ntPath = remainder.Length == 0 ? device : $"{device}\\{remainder}";
        if (ntPath.Length >= DriverProtocol.MaxPathChars)
        {
            throw new PathTooLongException($"NT path exceeds {DriverProtocol.MaxPathChars - 1} characters.");
        }

        return ntPath;
    }

    public static bool TryFromNtPath(string ntPath, out string path)
    {
        path = ntPath;
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(ntPath))
        {
            return false;
        }

        string? bestDrive = null;
        string? bestDevice = null;

        for (var letter = 'A'; letter <= 'Z'; letter++)
        {
            var drive = $"{letter}:";
            try
            {
                var device = QueryDeviceTarget(drive);
                if (!IsSameOrDescendantNtPath(ntPath, device))
                {
                    continue;
                }

                if (bestDevice is null || device.Length > bestDevice.Length)
                {
                    bestDrive = drive;
                    bestDevice = device;
                }
            }
            catch (Win32Exception)
            {
                // The drive letter is not currently mapped.
            }
        }

        if (bestDrive is null || bestDevice is null)
        {
            return false;
        }

        var remainder = ntPath.Length == bestDevice.Length
            ? string.Empty
            : ntPath[bestDevice.Length..].TrimStart('\\');
        path = remainder.Length == 0 ? $"{bestDrive}\\" : $"{bestDrive}\\{remainder}";
        return true;
    }

    private static bool IsSameOrDescendantNtPath(string candidate, string root)
    {
        if (!candidate.StartsWith(root, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return candidate.Length == root.Length ||
               (candidate.Length > root.Length && candidate[root.Length] == '\\');
    }

    private static string QueryDeviceTarget(string drive)
    {
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

        return device;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDevice(
        string lpDeviceName,
        StringBuilder lpTargetPath,
        int ucchMax);
}
