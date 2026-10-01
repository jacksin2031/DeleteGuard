using System.Runtime.InteropServices;
using DeleteGuard.Core.Models;

namespace DeleteGuard.Core.Driver;

public sealed class FilterPortClient : IDisposable
{
    private IntPtr _port;

    private FilterPortClient(IntPtr port)
    {
        _port = port;
    }

    public static bool TryConnect(out FilterPortClient? client)
    {
        client = null;
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        var context = DriverConnectContext.Create(DriverClientRole.Command);
        var contextSize = Marshal.SizeOf<DriverConnectContext>();
        var contextBuffer = Marshal.AllocHGlobal(contextSize);

        try
        {
            Marshal.StructureToPtr(context, contextBuffer, fDeleteOld: false);
            var hr = FilterConnectCommunicationPort(
                DriverProtocol.PortName,
                0,
                contextBuffer,
                checked((ushort)contextSize),
                IntPtr.Zero,
                out var port);

            if (hr < 0 || port == IntPtr.Zero || port == new IntPtr(-1))
            {
                return false;
            }

            client = new FilterPortClient(port);
            return true;
        }
        finally
        {
            Marshal.DestroyStructure<DriverConnectContext>(contextBuffer);
            Marshal.FreeHGlobal(contextBuffer);
        }
    }

    public DriverReply Ping() => Send(DriverCommand.Create(DriverCommandType.Ping));

    public void SyncPolicies(IEnumerable<ProtectionPolicy> policies)
    {
        Send(DriverCommand.Create(DriverCommandType.ResetRoots));

        var count = 0;
        foreach (var policy in policies.Where(policy => policy.Enabled))
        {
            count++;
            if (count > 64)
            {
                throw new InvalidOperationException("DeleteGuard minifilter supports at most 64 active roots.");
            }

            var ntPath = NtPathConverter.ToNtPath(policy.RootPath);
            Send(DriverCommand.Create(DriverCommandType.AddRoot, ntPath));
        }
    }

    public void AddRoot(string path) =>
        Send(DriverCommand.Create(DriverCommandType.AddRoot, NtPathConverter.ToNtPath(path)));

    public void RemoveRoot(string path) =>
        Send(DriverCommand.Create(DriverCommandType.RemoveRoot, NtPathConverter.ToNtPath(path)));

    public void GrantDelete(uint processId, string path, TimeSpan ttl)
    {
        var milliseconds = checked((uint)Math.Ceiling(ttl.TotalMilliseconds));
        if (milliseconds == 0 || milliseconds > DriverProtocol.MaxGrantTtlMilliseconds)
        {
            throw new ArgumentOutOfRangeException(nameof(ttl), $"Grant TTL must be between 1 ms and {DriverProtocol.MaxGrantTtlMilliseconds} ms.");
        }

        Send(DriverCommand.Create(
            DriverCommandType.Grant,
            NtPathConverter.ToNtPath(path),
            processId,
            milliseconds));
    }

    public void RevokeDelete(uint processId, string path) =>
        Send(DriverCommand.Create(
            DriverCommandType.Revoke,
            NtPathConverter.ToNtPath(path),
            processId));

    public DriverReply Send(DriverCommand command)
    {
        ThrowIfDisposed();

        var inputSize = Marshal.SizeOf<DriverCommand>();
        var outputSize = Marshal.SizeOf<DriverReply>();
        var input = Marshal.AllocHGlobal(inputSize);
        var output = Marshal.AllocHGlobal(outputSize);

        try
        {
            Marshal.StructureToPtr(command, input, fDeleteOld: false);
            var hr = FilterSendMessage(
                _port,
                input,
                checked((uint)inputSize),
                output,
                checked((uint)outputSize),
                out var bytesReturned);

            if (hr < 0)
            {
                Marshal.ThrowExceptionForHR(hr);
            }

            if (bytesReturned < outputSize)
            {
                throw new InvalidOperationException("DeleteGuard minifilter returned a truncated reply.");
            }

            var reply = Marshal.PtrToStructure<DriverReply>(output);
            if (reply.Status < 0)
            {
                throw new InvalidOperationException($"DeleteGuard minifilter rejected command {command.Type}: NTSTATUS 0x{unchecked((uint)reply.Status):X8}.");
            }

            return reply;
        }
        finally
        {
            Marshal.DestroyStructure<DriverCommand>(input);
            Marshal.FreeHGlobal(input);
            Marshal.FreeHGlobal(output);
        }
    }

    public void Dispose()
    {
        var port = Interlocked.Exchange(ref _port, IntPtr.Zero);
        if (port != IntPtr.Zero && port != new IntPtr(-1))
        {
            CloseHandle(port);
        }

        GC.SuppressFinalize(this);
    }

    private void ThrowIfDisposed()
    {
        if (_port == IntPtr.Zero)
        {
            throw new ObjectDisposedException(nameof(FilterPortClient));
        }
    }

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    private static extern int FilterConnectCommunicationPort(
        string lpPortName,
        uint dwOptions,
        IntPtr lpContext,
        ushort wSizeOfContext,
        IntPtr lpSecurityAttributes,
        out IntPtr hPort);

    [DllImport("fltlib.dll")]
    private static extern int FilterSendMessage(
        IntPtr hPort,
        IntPtr lpInBuffer,
        uint dwInBufferSize,
        IntPtr lpOutBuffer,
        uint dwOutBufferSize,
        out int lpBytesReturned);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);
}
