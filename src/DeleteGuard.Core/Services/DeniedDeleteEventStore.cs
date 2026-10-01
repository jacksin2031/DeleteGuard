using System.Text;
using System.Text.Json;
using DeleteGuard.Core.Models;

namespace DeleteGuard.Core.Services;

public sealed class DeniedDeleteEventStore
{
    public const long MaxEventFileBytes = 4 * 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly object _writeLock = new();

    public DeniedDeleteEventStore(string? dataDirectory = null)
    {
        var directory = dataDirectory ?? RuntimePaths.DefaultDataDirectory;
        EventFile = Path.Combine(directory, "denied-events.jsonl");
        RotatedEventFile = Path.Combine(directory, "denied-events.1.jsonl");
    }

    public string EventFile { get; }
    public string RotatedEventFile { get; }

    public void Append(DeniedDeleteEventRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        var directory = Path.GetDirectoryName(EventFile)
            ?? throw new InvalidOperationException("Unable to resolve DeleteGuard event directory.");

        if (!Directory.Exists(directory))
        {
            RuntimePaths.EnsureSecureDataDirectory(directory);
        }

        var line = JsonSerializer.Serialize(record, JsonOptions) + Environment.NewLine;
        lock (_writeLock)
        {
            RotateIfNeeded(Encoding.UTF8.GetByteCount(line));

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

        var queue = new Queue<DeniedDeleteEventRecord>(Math.Min(count, 256));
        ReadIntoQueue(RotatedEventFile, count, queue);
        ReadIntoQueue(EventFile, count, queue);
        return queue.ToArray();
    }

    private void RotateIfNeeded(int incomingBytes)
    {
        if (!File.Exists(EventFile))
        {
            return;
        }

        var length = new FileInfo(EventFile).Length;
        if (length + incomingBytes <= MaxEventFileBytes)
        {
            return;
        }

        if (File.Exists(RotatedEventFile))
        {
            File.Delete(RotatedEventFile);
        }

        File.Move(EventFile, RotatedEventFile);
    }

    private static void ReadIntoQueue(
        string path,
        int count,
        Queue<DeniedDeleteEventRecord> queue)
    {
        if (!File.Exists(path))
        {
            return;
        }

        try
        {
            using var stream = new FileStream(
                path,
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
            // Notification history is best effort; enforcement remains in the ACL/minifilter layers.
        }
    }
}
