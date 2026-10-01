using System.Security.Principal;
using DeleteGuard.Core.Security;
using DeleteGuard.Core.Services;

namespace DeleteGuard.Cli;

internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            PrintHelp();
            return 0;
        }

        try
        {
            return args[0].ToLowerInvariant() switch
            {
                "protect" => RunProtectedMutation("protect", args),
                "unprotect" => RunProtectedMutation("unprotect", args),
                "delete" => RunProtectedMutation("delete", args),
                "list" => ListPolicies(),
                "status" => Status(args),
                "audit" => Audit(args),
                "doctor" => Doctor(),
                "version" or "--version" or "-v" => Version(),
                _ => UnknownCommand(args[0])
            };
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"Error: {exception.Message}");
            return 1;
        }
    }

    private static int RunProtectedMutation(string command, string[] args)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine($"Usage: deleteguard {command} <path>{(command == "protect" ? " [--allow-volume-root]" : string.Empty)}");
            return 2;
        }

        var forwarded = new List<string> { command, Path.GetFullPath(args[1]) };
        if (command == "protect" && args.Skip(2).Any(arg => string.Equals(arg, "--allow-volume-root", StringComparison.OrdinalIgnoreCase)))
        {
            forwarded.Add("--allow-volume-root");
        }

        return BrokerLauncher.RunElevated(forwarded.ToArray());
    }

    private static int ListPolicies()
    {
        var store = new PolicyStore();
        var policies = store.Load();
        if (policies.Count == 0)
        {
            Console.WriteLine("No protected paths.");
            return 0;
        }

        foreach (var policy in policies.OrderBy(policy => policy.RootPath, StringComparer.OrdinalIgnoreCase))
        {
            var acl = TryGetAclState(policy.RootPath);
            Console.WriteLine($"{policy.RootPath}\t{(policy.Enabled ? "enabled" : "disabled")}\tacl={acl}\tcreated={policy.CreatedUtc:O}");
        }

        return 0;
    }

    private static int Status(string[] args)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("Usage: deleteguard status <path>");
            return 2;
        }

        var path = Path.GetFullPath(args[1]);
        var store = new PolicyStore();
        var policy = store.FindForPath(path);
        if (policy is null)
        {
            Console.WriteLine($"UNPROTECTED  {path}");
            return 3;
        }

        Console.WriteLine($"PROTECTED    {path}");
        Console.WriteLine($"Policy root: {policy.RootPath}");
        Console.WriteLine($"ACL state:   {TryGetAclState(policy.RootPath)}");
        Console.WriteLine($"Policy id:   {policy.Id}");
        return 0;
    }

    private static int Audit(string[] args)
    {
        var count = 20;
        if (args.Length >= 2 && (!int.TryParse(args[1], out count) || count <= 0 || count > 500))
        {
            Console.Error.WriteLine("Usage: deleteguard audit [1-500]");
            return 2;
        }

        foreach (var line in new AuditLogger().ReadLast(count))
        {
            Console.WriteLine(line);
        }

        return 0;
    }

    private static int Doctor()
    {
        Console.WriteLine($"Windows:        {OperatingSystem.IsWindows()}");
        Console.WriteLine($"Elevated:       {IsElevated()}");
        Console.WriteLine($"Broker:         {BrokerLauncher.ResolveBrokerPath()}");
        Console.WriteLine($"Broker exists:  {File.Exists(BrokerLauncher.ResolveBrokerPath())}");
        Console.WriteLine($"Policy store:   {new PolicyStore().PolicyFile}");
        Console.WriteLine("Protection:     NTFS ACL MVP (DENY DELETE + DELETE_CHILD)");
        return OperatingSystem.IsWindows() && File.Exists(BrokerLauncher.ResolveBrokerPath()) ? 0 : 3;
    }

    private static int Version()
    {
        Console.WriteLine(typeof(Program).Assembly.GetName().Version?.ToString() ?? "0.0.0");
        return 0;
    }

    private static string TryGetAclState(string path)
    {
        try
        {
            return AclProtector.HasGuardRule(path) ? "present" : "missing";
        }
        catch (Exception exception)
        {
            return $"unknown({exception.GetType().Name})";
        }
    }

    private static bool IsElevated()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static bool IsHelp(string value) => value is "help" or "--help" or "-h" or "/?";

    private static int UnknownCommand(string command)
    {
        Console.Error.WriteLine($"Unknown command: {command}");
        PrintHelp();
        return 2;
    }

    private static void PrintHelp()
    {
        Console.WriteLine("DeleteGuard MVP - administrator-gated deletion protection for NTFS paths");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  deleteguard protect <path> [--allow-volume-root]");
        Console.WriteLine("  deleteguard unprotect <path>");
        Console.WriteLine("  deleteguard delete <path>");
        Console.WriteLine("  deleteguard status <path>");
        Console.WriteLine("  deleteguard list");
        Console.WriteLine("  deleteguard audit [count]");
        Console.WriteLine("  deleteguard doctor");
        Console.WriteLine();
        Console.WriteLine("Ordinary Explorer/cmd/PowerShell/app deletion attempts are denied by NTFS ACL.");
        Console.WriteLine("Use 'deleteguard delete' to request a UAC-approved one-time deletion.");
    }
}
