using System.Text.Json;
using DeleteGuard.Core.Models;
using DeleteGuard.Core.Security;

namespace DeleteGuard.Core.Services;

public sealed class PolicyStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    public PolicyStore(string? dataDirectory = null, bool secureDirectory = false)
    {
        DataDirectory = dataDirectory ?? RuntimePaths.DefaultDataDirectory;
        SecureDirectory = secureDirectory;
        PolicyFile = Path.Combine(DataDirectory, "policies.json");
    }

    public string DataDirectory { get; }
    public string PolicyFile { get; }
    private bool SecureDirectory { get; }

    public IReadOnlyList<ProtectionPolicy> Load()
    {
        if (!File.Exists(PolicyFile))
        {
            return Array.Empty<ProtectionPolicy>();
        }

        using var stream = File.OpenRead(PolicyFile);
        return JsonSerializer.Deserialize<List<ProtectionPolicy>>(stream, JsonOptions)
            ?? new List<ProtectionPolicy>();
    }

    public ProtectionPolicy? FindExact(string rootPath) =>
        Load().FirstOrDefault(policy => string.Equals(
            PathRules.Normalize(policy.RootPath),
            PathRules.Normalize(rootPath),
            StringComparison.OrdinalIgnoreCase));

    public ProtectionPolicy? FindForPath(string path) => PathRules.FindDeepestPolicy(Load(), path);

    public void Upsert(ProtectionPolicy policy)
    {
        var policies = Load().ToList();
        var index = policies.FindIndex(item => item.Id == policy.Id || string.Equals(
            PathRules.Normalize(item.RootPath),
            PathRules.Normalize(policy.RootPath),
            StringComparison.OrdinalIgnoreCase));

        if (index >= 0)
        {
            policies[index] = policy;
        }
        else
        {
            policies.Add(policy);
        }

        Save(policies);
    }

    public void Remove(Guid id)
    {
        var policies = Load().Where(policy => policy.Id != id).ToList();
        Save(policies);
    }

    private void Save(IReadOnlyCollection<ProtectionPolicy> policies)
    {
        if (SecureDirectory)
        {
            RuntimePaths.EnsureSecureDataDirectory(DataDirectory);
        }
        else
        {
            Directory.CreateDirectory(DataDirectory);
        }

        var temp = PolicyFile + ".tmp";
        using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            JsonSerializer.Serialize(stream, policies, JsonOptions);
            stream.Flush(flushToDisk: true);
        }

        File.Move(temp, PolicyFile, overwrite: true);
    }
}
