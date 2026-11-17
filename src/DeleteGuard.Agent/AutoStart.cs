using Microsoft.Win32;

namespace DeleteGuard.Agent;

/// <summary>Per-user "start with Windows" registration (HKCU Run). Needs no elevation.</summary>
internal static class AutoStart
{
    public const string BackgroundArgument = "--background";

    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "DeleteGuardAgent";

    public static bool IsEnabled()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath);
            return key?.GetValue(ValueName) is string value && value.Length > 0;
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            return false;
        }
    }

    public static void Set(bool enabled)
    {
        using var key = Registry.CurrentUser.CreateSubKey(RunKeyPath, writable: true)
            ?? throw new InvalidOperationException("Unable to open the per-user Run registry key.");

        if (enabled)
        {
            var exe = Environment.ProcessPath
                ?? throw new InvalidOperationException("Unable to resolve the Agent executable path.");
            key.SetValue(ValueName, $"\"{exe}\" {BackgroundArgument}", RegistryValueKind.String);
        }
        else
        {
            key.DeleteValue(ValueName, throwOnMissingValue: false);
        }
    }
}
