using System.Runtime.InteropServices;

namespace DeleteGuard.Core.Driver;

public enum DriverCommandType : uint
{
    Ping = 0,
    ResetRoots = 1,
    AddRoot = 2,
    RemoveRoot = 3,
    Grant = 4,
    Revoke = 5
}

public static class DriverProtocol
{
    public const uint Version = 2;
    public const int MaxPathChars = 520;
    public const string PortName = @"\DeleteGuardPort";
    public const uint MaxGrantTtlMilliseconds = 30_000;

    public static int CommandSize => Marshal.SizeOf<DriverCommand>();
    public static int ReplySize => Marshal.SizeOf<DriverReply>();
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct DriverCommand
{
    public uint Version;
    public DriverCommandType Type;
    public uint ProcessId;
    public uint TtlMilliseconds;

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = DriverProtocol.MaxPathChars)]
    public string Path;

    public static DriverCommand Create(
        DriverCommandType type,
        string? path = null,
        uint processId = 0,
        uint ttlMilliseconds = 0)
    {
        path ??= string.Empty;
        if (path.Length >= DriverProtocol.MaxPathChars)
        {
            throw new PathTooLongException($"Driver path exceeds {DriverProtocol.MaxPathChars - 1} characters.");
        }

        return new DriverCommand
        {
            Version = DriverProtocol.Version,
            Type = type,
            ProcessId = processId,
            TtlMilliseconds = ttlMilliseconds,
            Path = path
        };
    }
}

[StructLayout(LayoutKind.Sequential)]
public struct DriverReply
{
    public int Status;
    public uint RootCount;
}
