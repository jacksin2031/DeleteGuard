using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public static class DeleteGuardHardLinkProbe
{
    private static readonly IntPtr InvalidHandleValue = new IntPtr(-1);
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const int FileLinkInformationEx = 72;
    private const int FileLinkReplaceIfExists = 1;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateHardLink(
        string newFileName,
        string existingFileName,
        IntPtr securityAttributes);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("ntdll.dll")]
    private static extern int NtSetInformationFile(
        IntPtr fileHandle,
        out IoStatusBlock ioStatusBlock,
        IntPtr fileInformation,
        uint length,
        int fileInformationClass);

    [StructLayout(LayoutKind.Sequential)]
    private struct IoStatusBlock
    {
        public IntPtr Status;
        public UIntPtr Information;
    }

    public static int CreateHardLinkError(string aliasPath, string sourcePath)
    {
        if (CreateHardLink(aliasPath, sourcePath, IntPtr.Zero))
        {
            return 0;
        }

        return Marshal.GetLastWin32Error();
    }

    public static int ReplaceWithHardLinkStatus(string sourcePath, string targetPath)
    {
        IntPtr handle = CreateFile(
            Path.GetFullPath(sourcePath),
            0,
            FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            0,
            IntPtr.Zero);

        if (handle == InvalidHandleValue)
        {
            throw new InvalidOperationException(
                "CreateFileW failed: " + Marshal.GetLastWin32Error());
        }

        try
        {
            string ntTarget = @"\??\" + Path.GetFullPath(targetPath);
            byte[] fileName = Encoding.Unicode.GetBytes(ntTarget);
            int rootOffset = IntPtr.Size == 8 ? 8 : 4;
            int lengthOffset = rootOffset + IntPtr.Size;
            int nameOffset = lengthOffset + sizeof(uint);
            int total = checked(nameOffset + fileName.Length);
            IntPtr buffer = Marshal.AllocHGlobal(total);

            try
            {
                for (int offset = 0; offset < total; offset++)
                {
                    Marshal.WriteByte(buffer, offset, 0);
                }

                Marshal.WriteInt32(buffer, 0, FileLinkReplaceIfExists);
                Marshal.WriteIntPtr(buffer, rootOffset, IntPtr.Zero);
                Marshal.WriteInt32(buffer, lengthOffset, fileName.Length);
                Marshal.Copy(fileName, 0, IntPtr.Add(buffer, nameOffset), fileName.Length);

                IoStatusBlock iosb;
                return NtSetInformationFile(
                    handle,
                    out iosb,
                    buffer,
                    (uint)total,
                    FileLinkInformationEx);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        finally
        {
            CloseHandle(handle);
        }
    }
}
