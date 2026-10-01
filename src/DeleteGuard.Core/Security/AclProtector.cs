using System.Security.AccessControl;
using System.Security.Principal;

namespace DeleteGuard.Core.Security;

public static class AclProtector
{
    public static readonly FileSystemRights GuardRights =
        FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles;

    private static SecurityIdentifier GuardIdentity =>
        new(WellKnownSidType.WorldSid, null);

    public static bool Apply(string rootPath)
    {
        EnsureWindows();
        var root = PathRules.Normalize(rootPath);
        var directory = new DirectoryInfo(root);
        if (!directory.Exists)
        {
            throw new DirectoryNotFoundException(root);
        }

        if (HasGuardRule(directory))
        {
            return false;
        }

        var security = directory.GetAccessControl(AccessControlSections.Access);
        security.AddAccessRule(CreateGuardRule());
        directory.SetAccessControl(security);
        return true;
    }

    public static bool Remove(string rootPath)
    {
        EnsureWindows();
        var root = PathRules.Normalize(rootPath);
        var directory = new DirectoryInfo(root);
        if (!directory.Exists)
        {
            return false;
        }

        var security = directory.GetAccessControl(AccessControlSections.Access);
        var rules = security.GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier))
            .OfType<FileSystemAccessRule>()
            .Where(IsGuardRule)
            .ToArray();

        foreach (var rule in rules)
        {
            security.RemoveAccessRuleSpecific(rule);
        }

        if (rules.Length > 0)
        {
            directory.SetAccessControl(security);
        }

        return rules.Length > 0;
    }

    public static bool HasGuardRule(string rootPath)
    {
        EnsureWindows();
        var directory = new DirectoryInfo(PathRules.Normalize(rootPath));
        return directory.Exists && HasGuardRule(directory);
    }

    public static void EnsureNtfs(string path)
    {
        EnsureWindows();
        var root = Path.GetPathRoot(PathRules.Normalize(path))
            ?? throw new InvalidOperationException("Unable to determine volume root.");
        var drive = new DriveInfo(root);
        if (!string.Equals(drive.DriveFormat, "NTFS", StringComparison.OrdinalIgnoreCase))
        {
            throw new NotSupportedException($"DeleteGuard MVP requires NTFS. Volume {root} uses {drive.DriveFormat}.");
        }
    }

    private static bool HasGuardRule(DirectoryInfo directory)
    {
        var security = directory.GetAccessControl(AccessControlSections.Access);
        return security.GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier))
            .OfType<FileSystemAccessRule>()
            .Any(IsGuardRule);
    }

    private static bool IsGuardRule(FileSystemAccessRule rule) =>
        rule.AccessControlType == AccessControlType.Deny &&
        rule.IdentityReference.Equals(GuardIdentity) &&
        (rule.FileSystemRights & GuardRights) == GuardRights &&
        rule.InheritanceFlags.HasFlag(InheritanceFlags.ContainerInherit) &&
        rule.InheritanceFlags.HasFlag(InheritanceFlags.ObjectInherit);

    private static FileSystemAccessRule CreateGuardRule() => new(
        GuardIdentity,
        GuardRights,
        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
        PropagationFlags.None,
        AccessControlType.Deny);

    private static void EnsureWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("DeleteGuard ACL protection is available only on Windows.");
        }
    }
}
