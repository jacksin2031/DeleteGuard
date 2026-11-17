using System.Runtime.InteropServices;

namespace DeleteGuard.Core.Driver;

public enum DriverClientRole : uint
{
    Command = 1,
    Event = 2
}

public enum DriverCommandType : uint
{
    Ping = 0,
    ResetRoots = 1,
    AddRoot = 2,
    RemoveRoot = 3,
    Grant = 4,
    Revoke = 5,

    /// <summary>AddRoot with the bulk-delete guard: ProcessId carries the threshold, TtlMilliseconds the window.</summary>
    AddBulkGuardRoot = 6
}

public enum DriverEventType : uint
{
    DeleteDenied = 1,
    RenameDenied = 2,
    HardLinkDenied = 3
}

public enum DriverDeleteOperation : uint
{
    Disposition = 1,
    DeleteOnClose = 2,
    MoveOut = 3,
    ReplaceProtectedDestination = 4,
    RenameProtectedAncestor = 5,
    HardLinkOut = 6,
    ReplaceProtectedLinkDestination = 7,

    /// <summary>Too many deletions inside a bulk-guard folder; the event names the folder, not a file.</summary>
    BulkDelete = 8
}

public static class DriverEventRules
{
    /// <summary>
    /// Only a plain denied delete of one specific target may become an approved Broker deletion.
    /// Namespace denials (rename/link) and bulk-delete events must never be approvable: a bulk event
    /// names the whole protected folder, so approving it would delete that folder.
    /// </summary>
    public static bool IsApprovableDelete(DriverEventType type, DriverDeleteOperation operation) =>
        type == DriverEventType.DeleteDenied &&
        operation is DriverDeleteOperation.Disposition or DriverDeleteOperation.DeleteOnClose;
}

public static class DriverProtocol
{
    public const uint Version = 4;
    public const int MaxPathChars = 520;
    public const string PortName = @"\DeleteGuardPort";
    public const uint MaxGrantTtlMilliseconds = 30_000;
    public const uint SynchronousPortFlag = 0x00000001;

    public static int ConnectContextSize => Marshal.SizeOf<DriverConnectContext>();
    public static int CommandSize => Marshal.SizeOf<DriverCommand>();
    public static int ReplySize => Marshal.SizeOf<DriverReply>();
    public static int EventSize => Marshal.SizeOf<DriverEvent>();
    public static int FilterMessageHeaderSize => Marshal.SizeOf<FilterMessageHeader>();
    public static int EventEnvelopeSize => checked(FilterMessageHeaderSize + EventSize);
}

[StructLayout(LayoutKind.Sequential)]
public struct DriverConnectContext
{
    public uint Version;
    public DriverClientRole Role;

    public static DriverConnectContext Create(DriverClientRole role) => new()
    {
        Version = DriverProtocol.Version,
        Role = role
    };
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

    /// <summary>Creates AddBulkGuardRoot: block deletions beyond <paramref name="threshold"/> within <paramref name="windowMilliseconds"/>.</summary>
    public static DriverCommand CreateBulkGuardRoot(string path, uint threshold, uint windowMilliseconds) =>
        Create(DriverCommandType.AddBulkGuardRoot, path, threshold, windowMilliseconds);

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

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct DriverEvent
{
    public uint Version;
    public DriverEventType Type;
    public uint ProcessId;
    public DriverDeleteOperation Operation;
    public ulong Sequence;

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = DriverProtocol.MaxPathChars)]
    public string Path;
}

[StructLayout(LayoutKind.Sequential)]
public struct FilterMessageHeader
{
    public uint ReplyLength;
    public ulong MessageId;
}
