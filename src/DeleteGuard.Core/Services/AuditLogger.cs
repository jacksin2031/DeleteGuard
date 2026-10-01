using System.Text.Json;
using DeleteGuard.Core.Models;

namespace DeleteGuard.Core.Services;

public sealed class AuditLogger
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public AuditLogger(string? dataDirectory = null)
    {
        DataDirectory = dataDirectory ?? RuntimePaths.DefaultDataDirectory;
        LogFile = Path.Combine(DataDirectory, "audit.jsonl");
    }

    public string DataDirectory { get; }
    public string LogFile { get; }

    public void Write(AuditEntry entry)
    {
        Directory.CreateDirectory(DataDirectory);
        var json = JsonSerializer.Serialize(entry, JsonOptions);
        File.AppendAllText(LogFile, json + Environment.NewLine);
    }

    public IReadOnlyList<string> ReadLast(int count)
    {
        if (count <= 0 || !File.Exists(LogFile))
        {
            return Array.Empty<string>();
        }

        return File.ReadLines(LogFile).TakeLast(count).ToArray();
    }
}
