using System.Security.Principal;
using DeleteGuard.Core.Driver;
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
        catch (DriverUnavailableException exception)
        {
            Console.Error.WriteLine($"DeleteGuard: {exception.Message}");
            TryAudit(new AuditEntry
            {
                TimestampUtc = DateTimeOffset.UtcNow,
                Action = args[0],
                TargetPath = args[1],
                Result = "error",
                ActorSid = CurrentSid(),
                Detail = exception.Message
            });
            return 13;
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
            throw new NotSupportedException("Protecting a reparse-point root is not supported.");
        }

        AclProtector.EnsureNtfs(path);
        ValidateVolumeRoot(path, options);

        var bulkGuard = options.Any(option => string.Equals(option, "--bulk-guard", StringComparison.OrdinalIgnoreCase));
        var bulkThreshold = ParseIntOption(options, "--threshold=", ProtectionPolicy.DefaultBulkThreshold, ProtectionPolicy.MinBulkThreshold, ProtectionPolicy.MaxBulkThreshold);
        var bulkWindowSeconds = ParseIntOption(options, "--window=", ProtectionPolicy.DefaultBulkWindowSeconds, ProtectionPolicy.MinBulkWindowSeconds, ProtectionPolicy.MaxBulkWindowSeconds);
        if (bulkGuard)
        {
            RequireDriver();
        }

        var policies = Store.Load();
        var existing = policies.FirstOrDefault(policy => string.Equals(
            PathRules.Normalize(policy.RootPath),
            path,
            StringComparison.OrdinalIgnoreCase));
        if (existing is not null)
        {
            Console.WriteLine($"Already protected: {path}");
            TrySyncDriverPolicies();
            return 0;
        }

        var overlap = policies.FirstOrDefault(policy =>
            PathRules.IsSameOrDescendant(path, policy.RootPath) ||
            PathRules.IsSameOrDescendant(policy.RootPath, path));
        if (overlap is not null)
        {
            throw new InvalidOperationException($"Overlapping protection roots are not supported. Existing root: {overlap.RootPath}");
        }

        if (AclProtector.HasGuardRule(path))
        {
            throw new InvalidOperationException("An equivalent unmanaged DeleteGuard ACL already exists on this path.");
        }

        // Bulk-guard folders get no NTFS ACL: the ACL's DELETE right would also block renames and
        // overwrite-saves, which this mode exists to leave alone. The driver is the only enforcement.
        var inserted = bulkGuard ? false : AclProtector.Apply(path);
        if (!bulkGuard && !inserted)
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
            Enabled = true,
            Mode = bulkGuard ? ProtectionMode.BulkGuard : ProtectionMode.Full,
            BulkThreshold = bulkThreshold,
            BulkWindowSeconds = bulkWindowSeconds
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

        bool driverSynced;
        try
        {
            driverSynced = TrySyncDriverPolicies();
            if (bulkGuard && !driverSynced)
            {
                throw new DriverUnavailableException("The DeleteGuard driver stopped responding; the bulk-delete guard was not enabled.");
            }
        }
        catch when (bulkGuard)
        {
            // The folder would otherwise be recorded as protected while nothing enforces it.
            Store.Remove(policy.Id);
            throw;
        }

        if (bulkGuard)
        {
            WriteAudit(
                "protect",
                path,
                "allowed",
                $"bulk-delete guard: more than {bulkThreshold} deletions in {bulkWindowSeconds}s are blocked; minifilter synced");
            Console.WriteLine($"Protected (bulk-delete guard, {bulkThreshold} deletions / {bulkWindowSeconds} s): {path}");
            Console.WriteLine("Kernel enforcement: active. There is no ACL fallback for this mode.");
            return 0;
        }

        WriteAudit(
            "protect",
            path,
            "allowed",
            driverSynced ? "guard ACL inserted; minifilter synced" : "guard ACL inserted; minifilter unavailable");
        Console.WriteLine($"Protected: {path}");
        Console.WriteLine(driverSynced
            ? "Kernel enforcement: active"
            : "Kernel enforcement: unavailable; ACL fallback remains active");
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
        var driverSynced = TrySyncDriverPolicies();
        WriteAudit(
            "unprotect",
            path,
            "allowed",
            driverSynced ? "minifilter synced" : "minifilter unavailable");
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

        FilterPortClient? driver = null;
        var driverGrantActive = false;
        var deleteSucceeded = false;
        var processId = checked((uint)Environment.ProcessId);
        using var renewalCancellation = new CancellationTokenSource();
        Task? renewal = null;

        try
        {
            if (FilterPortClient.TryConnect(out driver) && driver is not null)
            {
                // Synchronize before the ACL is ever relaxed. If the driver is present but
                // rejects synchronization/granting, fail closed instead of silently falling back.
                driver.SyncPolicies(Store.Load());
                driver.GrantDelete(processId, path, TimeSpan.FromSeconds(15));
                driverGrantActive = true;

                // A large deletion can outlast the 15 s grant, and an expired grant would make the
                // driver block (or, for a bulk-guard folder, count) the rest of it.
                renewal = RenewGrantUntilCancelled(driver, processId, path, renewalCancellation.Token);
            }

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
            renewalCancellation.Cancel();
            try
            {
                renewal?.Wait(TimeSpan.FromSeconds(3));
            }
            catch (AggregateException)
            {
                // Renewal is best effort; cleanup below reports real driver errors.
            }

            if (deleteSucceeded && deletingRoot)
            {
                Store.Remove(policy.Id);
            }
            else if (policy.InsertedAclRule && Directory.Exists(policy.RootPath) && !AclProtector.HasGuardRule(policy.RootPath))
            {
                AclProtector.Apply(policy.RootPath);
            }

            if (driver is not null)
            {
                try
                {
                    if (driverGrantActive)
                    {
                        driver.RevokeDelete(processId, path);
                    }

                    driver.SyncPolicies(Store.Load());
                }
                catch (Exception exception)
                {
                    TryAudit(new AuditEntry
                    {
                        TimestampUtc = DateTimeOffset.UtcNow,
                        Action = "driver-cleanup",
                        TargetPath = path,
                        Result = "error",
                        ActorSid = CurrentSid(),
                        Detail = exception.ToString()
                    });
                }
                finally
                {
                    driver.Dispose();
                }
            }
        }

        WriteAudit(
            "delete",
            path,
            "allowed",
            driverGrantActive
                ? $"kernel-grant pid={processId}; policy={policy.Id}"
                : $"acl-fallback; policy={policy.Id}");
        Console.WriteLine($"Deleted: {path}");
        Console.WriteLine(driverGrantActive
            ? "Kernel grant: used and revoked"
            : "Kernel grant: minifilter unavailable; ACL fallback path used");
        return 0;
    }

    private static Task RenewGrantUntilCancelled(FilterPortClient driver, uint processId, string path, CancellationToken token) =>
        Task.Run(async () =>
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(5), token);
                }
                catch (OperationCanceledException)
                {
                    return;
                }

                try
                {
                    driver.GrantDelete(processId, path, TimeSpan.FromSeconds(15));
                }
                catch (Exception)
                {
                    // Best effort: if renewal fails the delete simply meets the normal block.
                }
            }
        });

    private static int ParseIntOption(IReadOnlyCollection<string> options, string prefix, int fallback, int min, int max)
    {
        var option = options.FirstOrDefault(value => value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
        if (option is null)
        {
            return fallback;
        }

        if (!int.TryParse(option[prefix.Length..], out var value) || value < min || value > max)
        {
            throw new ArgumentOutOfRangeException(prefix.TrimEnd('='), $"{prefix.TrimEnd('=')} must be a whole number from {min} to {max}.");
        }

        return value;
    }

    /// <summary>The bulk-delete guard is enforced only by the driver, so it must be reachable now.</summary>
    private static void RequireDriver()
    {
        if (!FilterPortClient.TryConnect(out var probe) || probe is null)
        {
            throw new DriverUnavailableException(
                "The bulk-delete guard needs the DeleteGuard minifilter driver, which is not loaded (or is an older protocol version). " +
                "Without it this folder would not be protected, so nothing was changed.");
        }

        using (probe)
        {
            probe.Ping();
        }
    }

    private static bool TrySyncDriverPolicies()
    {
        if (!FilterPortClient.TryConnect(out var driver) || driver is null)
        {
            return false;
        }

        using (driver)
        {
            driver.SyncPolicies(Store.Load());
            return true;
        }
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
            throw new NotSupportedException("DeleteGuard refuses to protect the Windows system-volume root.");
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
