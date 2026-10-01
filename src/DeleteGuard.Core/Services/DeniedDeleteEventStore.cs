using System.Text;
using System.Text.Json;
using DeleteGuard.Core.Models;

namespace DeleteGuard.Core.Services;

public sealed class DeniedDeleteEventStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly object _writeLock = new();

    public DeniedDeleteEventStore(string? dataDirectory = null)
    {
        var directory = dataDirectory ?? RuntimePaths.DefaultDataDirectory;
        EventFile = Path.Combine(directory, "denied-events.jsonl");
    }

    public string EventFile { get; }

    public void Append(DeniedDeleteEventRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        var directory = Path.GetDirectoryName(EventFile)
            ?? throw new InvalidOperationException("Unable to resolve DeleteGuard event directory.");
        RuntimePaths.EnsureSecureDataDirectory(directory);

        var line = JsonSerializer.Serialize(record, JsonOptions) + Environment.NewLine;
        lock (_writeLock)
        {
            using var stream = new FileStream(
                EventFile,
                FileMode.Append,
                FileAccess.Write,
                FileShare.Read,
                bufferSize: 4096,
                FileOptions.WriteThrough);
            using var writer = new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            writer.Write(line);
        }
    }

    public IReadOnlyList<DeniedDeleteEventRecord> ReadLast(int count)
    {
        if (count <= 0)
        {
            return Array.Empty<DeniedDeleteEventRecord>();
        }

        if (!File.Exists(EventFile))
        {
            return Array.Empty<DeniedDeleteEventRecord>();
        }

        var queue = new Queue<DeniedDeleteEventRecord>(Math.Min(count, 256));
        try
        {
            using var stream = new FileStream(
                EventFile,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);

            string? line;
            while ((line = reader.ReadLine()) is not null)
            {
                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                try
                {
                    var record = JsonSerializer.Deserialize<DeniedDeleteEventRecord>(line, JsonOptions);
                    if (record is null)
                    {
                        continue;
                    }

                    if (queue.Count == count)
                    {
                        queue.Dequeue();
                    }

                    queue.Enqueue(record);
                }
                catch (JsonException)
                {
                    // Ignore an incomplete/corrupt line rather than breaking the approval agent.
                }
            }
        }
        catch (IOException)
        {
            return Array.Empty<DeniedDeleteEventRecord>();
        }

        return queue.ToArray();
    }
}
