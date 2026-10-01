using System.Security.Principal;
using DeleteGuard.Core.Models;
using DeleteGuard.Core.Security;
using DeleteGuard.Core.Services;

namespace DeleteGuard.Broker;

internal static class Program
{
    private static readonly string DataDirectory = RuntimePaths.DefaultDataDirectory;
    private static readonly PolicyStore Store = new(DataDirectory, secureDirectory: true);
    private static readonly AuditLogger Audit = new(DataDirectory);

    private static int Main(string[] args)
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("DeleteGuard broker runs only on Windows.");
            return 10;
        }

        if (!IsElevated())
        {
            Console.Error.WriteLine("DeleteGuard broker requires administrator privileges.");
            return 11;
        }

        if (args.Length < 2)
        {
            Console.Error.WriteLine("Broker usage: <protect|unprotect|delete> <path> [options]");
            return 2;
        }

        using var mutex = new Mutex(initiallyOwned: false, name: "Global\\DeleteGuard.Broker.Mutation");
        if (!mutex.WaitOne(TimeSpan.FromSeconds(30)))
        {
            Console.Error.WriteLine("Another DeleteGuard administrative operation is already running.");
            return 12;
        }

        try
        {
            RuntimePaths.EnsureSecureDataDirectory(DataDirectory);
            var command = args[0].ToLowerInvariant();
            var path = PathRules.Normalize(args[1]);
            return command switch
            {
                "protect" => Protect(path, args.Skip(2).ToArray()),
                "unprotect" => Unprotect(path),
                "delete" => Delete(path),
                _ => 2
            };
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"DeleteGuard: {exception.Message}");
            TryAudit(new AuditEntry
            {
                TimestampUtc = DateTimeOffset.UtcNow,
                Action = args[0],
                TargetPath = args[1],
                Result = "error",
                ActorSid = CurrentSid(),
                Detail = exception.ToString()
            });
            return 1;
        }
        finally
        {
            mutex.ReleaseMutex();
        }
    }

    private static int Protect(string path, IReadOnlyCollection<string> options)
    {
        if (!Directory.Exists(path))
        {
            throw new DirectoryNotFoundException(path);
        }

        var attributes = File.GetAttributes(path);
        if (attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new NotSupportedException("Protecting a reparse-point root is not supported in the MVP.");
        }

        AclProtector.EnsureNtfs(path);
        ValidateVolumeRoot(path, options);

        var policies = Store.Load();
        var existing = policies.FirstOrDefault(policy => string.Equals(
            PathRules.Normalize(policy.RootPath),
            path,
            StringComparison.OrdinalIgnoreCase));
        if (existing is not null)
        {
            Console.WriteLine($"Already protected: {path}");
            return 0;
        }

        var overlap = policies.FirstOrDefault(policy =>
            PathRules.IsSameOrDescendant(path, policy.RootPath) ||
            PathRules.IsSameOrDescendant(policy.RootPath, path));
        if (overlap is not null)
        {
            throw new InvalidOperationException($"Overlapping protection roots are not supported in the MVP. Existing root: {overlap.RootPath}");
        }

        if (AclProtector.HasGuardRule(path))
        {
            throw new InvalidOperationException("An equivalent unmanaged DeleteGuard ACL already exists on this path.");
        }

        var inserted = AclProtector.Apply(path);
        if (!inserted)
        {
            throw new InvalidOperationException("Failed to insert the DeleteGuard ACL rule.");
        }

        var policy = new ProtectionPolicy
        {
            Id = Guid.NewGuid(),
            RootPath = path,
            CreatedUtc = DateTimeOffset.UtcNow,
            CreatedBySid = CurrentSid(),
            GuardSid = new SecurityIdentifier(WellKnownSidType.WorldSid, null).Value,
            InsertedAclRule = inserted,
            Enabled = true
        };

        try
        {
            Store.Upsert(policy);
        }
        catch
        {
            if (inserted)
            {
                AclProtector.Remove(path);
            }

            throw;
        }

        WriteAudit("protect", path, "allowed", "guard ACL inserted");
        Console.WriteLine($"Protected: {path}");
        return 0;
    }

    private static int Unprotect(string path)
    {
        var policy = Store.FindExact(path)
            ?? throw new InvalidOperationException("No protection policy exists for this exact path.");

        if (policy.InsertedAclRule && Directory.Exists(policy.RootPath))
        {
            AclProtector.Remove(policy.RootPath);
        }

        Store.Remove(policy.Id);
        WriteAudit("unprotect", path, "allowed", null);
        Console.WriteLine($"Unprotected: {path}");
        return 0;
    }

    private static int Delete(string path)
    {
        var policy = Store.FindForPath(path)
            ?? throw new UnauthorizedAccessException("Target is not under a DeleteGuard-protected path.");

        if (!File.Exists(path) && !Directory.Exists(path))
        {
            throw new FileNotFoundException("Target does not exist.", path);
        }

        var deletingRoot = string.Equals(
            PathRules.Normalize(path),
            PathRules.Normalize(policy.RootPath),
            StringComparison.OrdinalIgnoreCase);

        var deleteSucceeded = false;
        try
        {
            if (policy.InsertedAclRule && Directory.Exists(policy.RootPath))
            {
                AclProtector.Remove(policy.RootPath);
            }

            if (File.Exists(path))
            {
                File.Delete(path);
            }
            else
            {
                Directory.Delete(path, recursive: true);
            }

            deleteSucceeded = true;
        }
        finally
        {
            if (deleteSucceeded && deletingRoot)
            {
                Store.Remove(policy.Id);
            }
            else if (policy.InsertedAclRule && Directory.Exists(policy.RootPath) && !AclProtector.HasGuardRule(policy.RootPath))
            {
                AclProtector.Apply(policy.RootPath);
            }
        }

        WriteAudit("delete", path, "allowed", deletingRoot ? "protected root deleted" : $"policy={policy.Id}");
        Console.WriteLine($"Deleted: {path}");
        return 0;
    }

    private static void ValidateVolumeRoot(string path, IReadOnlyCollection<string> options)
    {
        if (!PathRules.IsVolumeRoot(path))
        {
            return;
        }

        var systemRoot = Path.GetPathRoot(Environment.SystemDirectory)
            ?? throw new InvalidOperationException("Unable to resolve system volume.");
        if (string.Equals(PathRules.Normalize(path), PathRules.Normalize(systemRoot), StringComparison.OrdinalIgnoreCase))
        {
            throw new NotSupportedException("DeleteGuard MVP refuses to protect the Windows system-volume root.");
        }

        if (!options.Any(option => string.Equals(option, "--allow-volume-root", StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException("Protecting an entire data-volume root requires --allow-volume-root.");
        }
    }

    private static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static string CurrentSid() =>
        WindowsIdentity.GetCurrent().User?.Value ?? "unknown";

    private static void WriteAudit(string action, string target, string result, string? detail) =>
        TryAudit(new AuditEntry
        {
            TimestampUtc = DateTimeOffset.UtcNow,
            Action = action,
            TargetPath = target,
            Result = result,
            ActorSid = CurrentSid(),
            Detail = detail
        });

    private static void TryAudit(AuditEntry entry)
    {
        try
        {
            Audit.Write(entry);
        }
        catch
        {
            // The requested filesystem operation result must not be masked by audit I/O failure.
        }
    }
}
