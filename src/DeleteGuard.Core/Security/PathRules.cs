using DeleteGuard.Core.Models;

namespace DeleteGuard.Core.Security;

public static class PathRules
{
    public static string Normalize(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("Path cannot be empty.", nameof(path));
        }

        var full = Path.GetFullPath(path.Trim());
        var root = Path.GetPathRoot(full);
        if (root is not null && string.Equals(full, root, StringComparison.OrdinalIgnoreCase))
        {
            return full;
        }

        return full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }

    public static bool IsSameOrDescendant(string candidate, string root)
    {
        var normalizedCandidate = Normalize(candidate);
        var normalizedRoot = Normalize(root);

        if (string.Equals(normalizedCandidate, normalizedRoot, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var prefix = normalizedRoot.EndsWith(Path.DirectorySeparatorChar)
            ? normalizedRoot
            : normalizedRoot + Path.DirectorySeparatorChar;

        return normalizedCandidate.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsVolumeRoot(string path)
    {
        var normalized = Normalize(path);
        var root = Path.GetPathRoot(normalized);
        return root is not null && string.Equals(normalized, root, StringComparison.OrdinalIgnoreCase);
    }

    public static ProtectionPolicy? FindDeepestPolicy(IEnumerable<ProtectionPolicy> policies, string path)
    {
        var normalized = Normalize(path);
        return policies
            .Where(policy => policy.Enabled && IsSameOrDescendant(normalized, policy.RootPath))
            .OrderByDescending(policy => Normalize(policy.RootPath).Length)
            .FirstOrDefault();
    }
}
