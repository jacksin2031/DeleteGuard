using DeleteGuard.Core.Models;
using DeleteGuard.Core.Services;
using Xunit;

namespace DeleteGuard.Core.Tests;

public sealed class ManagementCoreTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "DeleteGuard.MgmtTests", Guid.NewGuid().ToString("N"));

    public ManagementCoreTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    // ---- AgentSettings / AgentSettingsStore ----

    [Fact]
    public void Settings_Normalize_ClampsEveryRange()
    {
        var wild = new AgentSettings
        {
            MaxPromptsPerWindow = 9999,
            PromptWindowSeconds = 1,
            PromptMaxAgeSeconds = 100000,
            NoticeCooldownSeconds = -5
        }.Normalize();

        Assert.Equal(AgentSettings.MaxPromptsPerWindowLimit, wild.MaxPromptsPerWindow);
        Assert.Equal(AgentSettings.MinPromptWindowSeconds, wild.PromptWindowSeconds);
        Assert.Equal(AgentSettings.MaxPromptMaxAgeSeconds, wild.PromptMaxAgeSeconds);
        Assert.Equal(AgentSettings.MinNoticeCooldownSeconds, wild.NoticeCooldownSeconds);
    }

    [Fact]
    public void SettingsStore_MissingFile_ReturnsDefaults()
    {
        var store = new AgentSettingsStore(Path.Combine(_root, "none", "settings.json"));
        Assert.Equal(AgentSettings.Default, store.Load());
    }

    [Fact]
    public void SettingsStore_RoundTripsAndNormalizes()
    {
        var store = new AgentSettingsStore(Path.Combine(_root, "s", "settings.json"));
        var saved = store.Save(new AgentSettings
        {
            ShowApprovalPrompts = false,
            MaxPromptsPerWindow = 2,
            ShowNamespaceNotices = false,
            NoticeCooldownSeconds = 9999
        });

        Assert.Equal(AgentSettings.MaxNoticeCooldownSeconds, saved.NoticeCooldownSeconds);

        var loaded = store.Load();
        Assert.False(loaded.ShowApprovalPrompts);
        Assert.Equal(2, loaded.MaxPromptsPerWindow);
        Assert.False(loaded.ShowNamespaceNotices);
        Assert.Equal(saved, loaded);
    }

    [Fact]
    public void SettingsStore_CorruptFile_FallsBackToDefaults_AndTamperedValuesAreClamped()
    {
        var file = Path.Combine(_root, "c", "settings.json");
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);

        File.WriteAllText(file, "{ not json");
        Assert.Equal(AgentSettings.Default, new AgentSettingsStore(file).Load());

        File.WriteAllText(file, "{\"maxPromptsPerWindow\": 100000, \"promptWindowSeconds\": 0}");
        var loaded = new AgentSettingsStore(file).Load();
        Assert.Equal(AgentSettings.MaxPromptsPerWindowLimit, loaded.MaxPromptsPerWindow);
        Assert.Equal(AgentSettings.MinPromptWindowSeconds, loaded.PromptWindowSeconds);
    }

    // ---- ProtectionRequestValidator ----

    [Fact]
    public void Validator_AcceptsExistingFolder()
    {
        var folder = Directory.CreateDirectory(Path.Combine(_root, "ok")).FullName;
        var result = Validator().Validate(folder + @"\");

        Assert.True(result.Accepted, result.Rejection.ToString());
        Assert.Equal(folder, result.Path);
        Assert.False(result.IsVolumeRoot);
    }

    [Fact]
    public void Validator_RejectsEmptyMissingFileAndNetworkPaths()
    {
        var file = Path.Combine(_root, "a.txt");
        File.WriteAllText(file, "x");
        var validator = Validator();

        Assert.Equal(ProtectionRejection.Empty, validator.Validate("  ").Rejection);
        Assert.Equal(ProtectionRejection.NotFound, validator.Validate(Path.Combine(_root, "missing")).Rejection);
        Assert.Equal(ProtectionRejection.NotADirectory, validator.Validate(file).Rejection);
        Assert.Equal(ProtectionRejection.NetworkPath, validator.Validate(@"\\server\share\folder").Rejection);
    }

    [Fact]
    public void Validator_RejectsReparsePointRoot()
    {
        var target = Directory.CreateDirectory(Path.Combine(_root, "target")).FullName;
        var link = Path.Combine(_root, "link");
        try
        {
            Directory.CreateSymbolicLink(link, target);
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or IOException)
        {
            return; // symlink creation needs developer mode/elevation on some machines
        }

        Assert.Equal(ProtectionRejection.ReparsePoint, Validator().Validate(link).Rejection);
    }

    [Fact]
    public void Validator_RejectsNonNtfs()
    {
        var folder = Directory.CreateDirectory(Path.Combine(_root, "fat")).FullName;
        var validator = new ProtectionRequestValidator(
            () => Array.Empty<ProtectionPolicy>(),
            ensureNtfs: _ => throw new NotSupportedException("requires NTFS"));

        var result = validator.Validate(folder);
        Assert.Equal(ProtectionRejection.NotNtfs, result.Rejection);
        Assert.Equal("requires NTFS", result.Detail);
    }

    [Fact]
    public void Validator_RejectsDuplicateAndOverlappingRoots()
    {
        var parent = Directory.CreateDirectory(Path.Combine(_root, "parent")).FullName;
        var child = Directory.CreateDirectory(Path.Combine(parent, "child")).FullName;
        var sibling = Directory.CreateDirectory(Path.Combine(_root, "parent2")).FullName;
        var validator = Validator(Policy(parent));

        Assert.Equal(ProtectionRejection.AlreadyProtected, validator.Validate(parent).Rejection);

        var inside = validator.Validate(child);
        Assert.Equal(ProtectionRejection.Overlaps, inside.Rejection);
        Assert.Equal(parent, inside.Detail);

        Assert.True(validator.Validate(sibling).Accepted, "a prefix-sharing sibling must not count as overlap");
        Assert.Equal(ProtectionRejection.Overlaps, Validator(Policy(child)).Validate(parent).Rejection);
    }

    [Fact]
    public void Validator_VolumeRoot_NeedsExplicitFlag_AndSystemRootIsRefused()
    {
        var driveRoot = Path.GetPathRoot(_root)!;
        var data = Validator(systemRoot: @"Z:\").Validate(driveRoot);
        Assert.True(data.Accepted);
        Assert.True(data.IsVolumeRoot);

        var system = Validator(systemRoot: driveRoot).Validate(driveRoot);
        Assert.Equal(ProtectionRejection.SystemVolumeRoot, system.Rejection);
    }

    // ---- ProtectionListService ----

    [Fact]
    public void ProtectionList_IsSortedAndReportsAclState()
    {
        var store = new PolicyStore(Path.Combine(_root, "data"));
        store.Upsert(Policy(@"C:\Zeta"));
        store.Upsert(Policy(@"C:\Alpha"));

        var list = new ProtectionListService(store, path => path.EndsWith("Alpha", StringComparison.Ordinal)
            ? AclState.Present
            : AclState.Missing).List();

        Assert.Equal(new[] { @"C:\Alpha", @"C:\Zeta" }, list.Select(entry => entry.RootPath));
        Assert.Equal(AclState.Present, list[0].Acl);
        Assert.Equal(AclState.Missing, list[1].Acl);
    }

    [Fact]
    public void ProtectionList_DefaultProbe_FlagsMissingFolder()
    {
        var store = new PolicyStore(Path.Combine(_root, "data2"));
        store.Upsert(Policy(Path.Combine(_root, "gone")));

        var entry = Assert.Single(new ProtectionListService(store).List());
        Assert.Equal(AclState.FolderMissing, entry.Acl);
    }

    // ---- BrokerClient ----

    [Fact]
    public async Task BrokerClient_MissingBroker_ReportsFailureWithoutLaunching()
    {
        var client = new BrokerClient(Path.Combine(_root, "DeleteGuard.Broker.exe"), new AuditLogger(_root));
        Assert.False(client.Exists);

        var result = await client.ProtectAsync(_root, allowVolumeRoot: false);

        Assert.False(result.Succeeded);
        Assert.Equal(BrokerFailure.BrokerMissing, result.Failure);
    }

    private ProtectionRequestValidator Validator(ProtectionPolicy? policy = null, string? systemRoot = null) =>
        new(
            () => policy is null ? Array.Empty<ProtectionPolicy>() : new[] { policy },
            ensureNtfs: _ => { },
            systemRoot: systemRoot ?? @"Z:\");

    private static ProtectionPolicy Policy(string root) => new()
    {
        Id = Guid.NewGuid(),
        RootPath = root,
        CreatedUtc = DateTimeOffset.UtcNow,
        CreatedBySid = "S-1-5-21-test",
        GuardSid = "S-1-1-0",
        InsertedAclRule = true
    };
}
