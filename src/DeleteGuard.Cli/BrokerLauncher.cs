using System.ComponentModel;
using System.Diagnostics;

namespace DeleteGuard.Cli;

internal static class BrokerLauncher
{
    public static string ResolveBrokerPath()
    {
        var overridePath = Environment.GetEnvironmentVariable("DELETEGUARD_BROKER_PATH");
        if (!string.IsNullOrWhiteSpace(overridePath))
        {
            return Path.GetFullPath(overridePath);
        }

        return Path.Combine(AppContext.BaseDirectory, "DeleteGuard.Broker.exe");
    }

    public static int RunElevated(params string[] arguments)
    {
        var broker = ResolveBrokerPath();
        if (!File.Exists(broker))
        {
            Console.Error.WriteLine($"DeleteGuard broker not found: {broker}");
            Console.Error.WriteLine("Build/package the broker beside deleteguard.exe or set DELETEGUARD_BROKER_PATH.");
            return 4;
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = broker,
            UseShellExecute = true,
            Verb = "runas",
            WorkingDirectory = Environment.CurrentDirectory
        };

        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        try
        {
            using var process = Process.Start(startInfo);
            if (process is null)
            {
                Console.Error.WriteLine("Failed to start elevated broker.");
                return 4;
            }

            process.WaitForExit();
            return process.ExitCode;
        }
        catch (Win32Exception exception) when (exception.NativeErrorCode == 1223)
        {
            Console.Error.WriteLine("Administrator approval was cancelled.");
            return 5;
        }
    }
}
