using System.Text.Json;
using DeleteGuard.Core.Models;

namespace DeleteGuard.Core.Services;

/// <summary>
/// Reads and writes the per-user Agent settings file. A missing, unreadable or
/// corrupt file always yields the defaults, and loaded values are normalized.
/// </summary>
public sealed class AgentSettingsStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    public AgentSettingsStore(string? settingsFile = null)
    {
        SettingsFile = settingsFile ?? DefaultSettingsFile;
    }

    public static string DefaultSettingsFile => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "DeleteGuard",
        "settings.json");

    public string SettingsFile { get; }

    public AgentSettings Load()
    {
        try
        {
            if (!File.Exists(SettingsFile))
            {
                return AgentSettings.Default;
            }

            using var stream = File.OpenRead(SettingsFile);
            var loaded = JsonSerializer.Deserialize<AgentSettings>(stream, JsonOptions);
            return (loaded ?? AgentSettings.Default).Normalize();
        }
        catch (Exception exception) when (exception is JsonException or IOException or UnauthorizedAccessException or NotSupportedException)
        {
            return AgentSettings.Default;
        }
    }

    /// <summary>Saves the normalized settings and returns what was actually stored.</summary>
    public AgentSettings Save(AgentSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var normalized = settings.Normalize();

        var directory = Path.GetDirectoryName(SettingsFile)
            ?? throw new InvalidOperationException("Unable to resolve the settings directory.");
        Directory.CreateDirectory(directory);

        var temp = SettingsFile + ".tmp";
        using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            JsonSerializer.Serialize(stream, normalized, JsonOptions);
            stream.Flush(flushToDisk: true);
        }

        File.Move(temp, SettingsFile, overwrite: true);
        return normalized;
    }
}
