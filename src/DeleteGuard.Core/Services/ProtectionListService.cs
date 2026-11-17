using DeleteGuard.Core.Security;

namespace DeleteGuard.Core.Services;

public enum AclState
{
    Present,
    Missing,
    FolderMissing,
    Unknown
}

public sealed record ProtectionEntry(
    Guid Id,
    string RootPath,
    bool Enabled,
    DateTimeOffset CreatedUtc,
    AclState Acl);

/// <summary>Read-only view of the configured protection roots and the health of their ACL layer.</summary>
public sealed class ProtectionListService
{
    private readonly PolicyStore _store;
    private readonly Func<string, AclState> _aclProbe;

    public ProtectionListService(PolicyStore? store = null, Func<string, AclState>? aclProbe = null)
    {
        _store = store ?? new PolicyStore();
        _aclProbe = aclProbe ?? ProbeAcl;
    }

    public IReadOnlyList<ProtectionEntry> List() => _store.Load()
        .OrderBy(policy => policy.RootPath, StringComparer.OrdinalIgnoreCase)
        .Select(policy => new ProtectionEntry(
            policy.Id,
            policy.RootPath,
            policy.Enabled,
            policy.CreatedUtc,
            _aclProbe(policy.RootPath)))
        .ToArray();

    private static AclState ProbeAcl(string rootPath)
    {
        try
        {
            if (!Directory.Exists(rootPath))
            {
                return AclState.FolderMissing;
            }

            return AclProtector.HasGuardRule(rootPath) ? AclState.Present : AclState.Missing;
        }
        catch (Exception)
        {
            return AclState.Unknown;
        }
    }
}
