using System.Runtime.InteropServices;

namespace DeleteGuard.Core.Driver;

public sealed class FilterEventClient : IDisposable
{
    private IntPtr _port;

    private FilterEventClient(IntPtr port)
    {
        _port = port;
    }

    public static bool TryConnect(out FilterEventClient? client)
    {
        client = null;
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        var context = DriverConnectContext.Create(DriverClientRole.Event);
        var contextSize = Marshal.SizeOf<DriverConnectContext>();
        var contextBuffer = Marshal.AllocHGlobal(contextSize);

        try
        {
            Marshal.StructureToPtr(context, contextBuffer, fDeleteOld: false);
            var hr = FilterConnectCommunicationPort(
                DriverProtocol.PortName,
                DriverProtocol.SynchronousPortFlag,
                contextBuffer,
                checked((ushort)contextSize),
                IntPtr.Zero,
                out var port);

            if (hr < 0 || port == IntPtr.Zero || port == new IntPtr(-1))
            {
                return false;
            }

            client = new FilterEventClient(port);
            return true;
        }
        finally
        {
            Marshal.DestroyStructure<DriverConnectContext>(contextBuffer);
            Marshal.FreeHGlobal(contextBuffer);
        }
    }

    public DriverEvent ReadNext()
    {
        ThrowIfDisposed();

        var buffer = Marshal.AllocHGlobal(DriverProtocol.EventEnvelopeSize);
        try
        {
            var hr = FilterGetMessage(
                _port,
                buffer,
                checked((uint)DriverProtocol.EventEnvelopeSize),
                IntPtr.Zero);

            if (hr < 0)
            {
                Marshal.ThrowExceptionForHR(hr);
            }

            var eventPointer = IntPtr.Add(buffer, DriverProtocol.FilterMessageHeaderSize);
            var driverEvent = Marshal.PtrToStructure<DriverEvent>(eventPointer);
            if (driverEvent.Version != DriverProtocol.Version)
            {
                throw new InvalidOperationException(
                    $"DeleteGuard event protocol mismatch. Driver={driverEvent.Version}, client={DriverProtocol.Version}.");
            }

            if (driverEvent.Type != DriverEventType.DeleteDenied)
            {
                throw new InvalidOperationException($"Unsupported DeleteGuard event type: {driverEvent.Type}.");
            }

            if (string.IsNullOrWhiteSpace(driverEvent.Path))
            {
                throw new InvalidOperationException("DeleteGuard driver returned an event without a path.");
            }

            return driverEvent;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
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
            throw new ObjectDisposedException(nameof(FilterEventClient));
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
    private static extern int FilterGetMessage(
        IntPtr hPort,
        IntPtr lpMessageBuffer,
        uint dwMessageBufferSize,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);
}
