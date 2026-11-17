using DeleteGuard.Core.Models;
using DeleteGuard.Core.Security;

namespace DeleteGuard.Core.Services;

public enum ProtectionRejection
{
    None,
    Empty,
    InvalidPath,
    NetworkPath,
    NotFound,
    NotADirectory,
    ReparsePoint,
    NotNtfs,
    SystemVolumeRoot,
    AlreadyProtected,
    Overlaps
}

/// <param name="Rejection">None when the request may be sent to the Broker.</param>
/// <param name="Path">Normalized path (empty when the input could not be normalized).</param>
/// <param name="IsVolumeRoot">True when the Broker needs --allow-volume-root, which the UI must confirm explicitly.</param>
/// <param name="Detail">Conflicting root or filesystem name, where relevant.</param>
public sealed record ProtectionCheck(
    ProtectionRejection Rejection,
    string Path,
    bool IsVolumeRoot = false,
    string? Detail = null)
{
    public bool Accepted => Rejection == ProtectionRejection.None;
}

/// <summary>
/// Pre-flight checks mirroring the Broker's protect rules, so the UI can reject an
/// invalid request without showing a pointless UAC prompt. The Broker still performs
/// every check itself; this class is never an authorization source.
/// </summary>
public sealed class ProtectionRequestValidator
{
    private readonly Func<IReadOnlyList<ProtectionPolicy>> _policies;
    private readonly Action<string> _ensureNtfs;
    private readonly string? _systemRoot;

    public ProtectionRequestValidator(
        Func<IReadOnlyList<ProtectionPolicy>> policies,
        Action<string>? ensureNtfs = null,
        string? systemRoot = null)
    {
        _policies = policies ?? throw new ArgumentNullException(nameof(policies));
        _ensureNtfs = ensureNtfs ?? AclProtector.EnsureNtfs;
        _systemRoot = systemRoot ?? System.IO.Path.GetPathRoot(Environment.SystemDirectory);
    }

    public ProtectionCheck Validate(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return new ProtectionCheck(ProtectionRejection.Empty, string.Empty);
        }

        string path;
        try
        {
            path = PathRules.Normalize(input);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return new ProtectionCheck(ProtectionRejection.InvalidPath, string.Empty);
        }

        if (path.StartsWith(@"\\", StringComparison.Ordinal))
        {
            return new ProtectionCheck(ProtectionRejection.NetworkPath, path);
        }

        if (File.Exists(path))
        {
            return new ProtectionCheck(ProtectionRejection.NotADirectory, path);
        }

        if (!Directory.Exists(path))
        {
            return new ProtectionCheck(ProtectionRejection.NotFound, path);
        }

        if (File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint))
        {
            return new ProtectionCheck(ProtectionRejection.ReparsePoint, path);
        }

        try
        {
            _ensureNtfs(path);
        }
        catch (NotSupportedException exception)
        {
            return new ProtectionCheck(ProtectionRejection.NotNtfs, path, Detail: exception.Message);
        }

        var isVolumeRoot = PathRules.IsVolumeRoot(path);
        if (isVolumeRoot && _systemRoot is not null &&
            string.Equals(path, PathRules.Normalize(_systemRoot), StringComparison.OrdinalIgnoreCase))
        {
            return new ProtectionCheck(ProtectionRejection.SystemVolumeRoot, path, IsVolumeRoot: true);
        }

        var policies = _policies();
        var exact = policies.FirstOrDefault(policy =>
            string.Equals(PathRules.Normalize(policy.RootPath), path, StringComparison.OrdinalIgnoreCase));
        if (exact is not null)
        {
            return new ProtectionCheck(ProtectionRejection.AlreadyProtected, path, isVolumeRoot);
        }

        var overlap = policies.FirstOrDefault(policy =>
            PathRules.IsSameOrDescendant(path, policy.RootPath) ||
            PathRules.IsSameOrDescendant(policy.RootPath, path));
        if (overlap is not null)
        {
            return new ProtectionCheck(ProtectionRejection.Overlaps, path, isVolumeRoot, overlap.RootPath);
        }

        return new ProtectionCheck(ProtectionRejection.None, path, isVolumeRoot);
    }
}
