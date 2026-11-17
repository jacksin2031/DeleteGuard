using System.ComponentModel;
using System.Diagnostics;
using System.Text.Json;
using DeleteGuard.Core.Models;

namespace DeleteGuard.Core.Services;

public enum BrokerFailure
{
    None,
    BrokerMissing,
    Cancelled,
    StartFailed,
    NotElevated,
    Busy,

    /// <summary>The bulk-delete guard was requested but the minifilter driver is not loaded.</summary>
    DriverUnavailable,
    Failed
}

/// <param name="Detail">First line of the Broker's recorded error, when it left one in the audit log.</param>
public sealed record BrokerResult(BrokerFailure Failure, int ExitCode, string? Detail = null)
{
    public bool Succeeded => Failure == BrokerFailure.None;
}

/// <summary>
/// Launches DeleteGuard.Broker.exe through UAC. The caller never elevates: every
/// protect/unprotect/delete is approved by the user in the Windows UAC prompt.
/// </summary>
public sealed class BrokerClient
{
    private const int UacCancelled = 1223;

    private readonly AuditLogger _audit;

    public BrokerClient(string? brokerPath = null, AuditLogger? audit = null)
    {
        BrokerPath = brokerPath ?? Path.Combine(AppContext.BaseDirectory, "DeleteGuard.Broker.exe");
        _audit = audit ?? new AuditLogger();
    }

    public string BrokerPath { get; }
    public bool Exists => File.Exists(BrokerPath);

    public Task<BrokerResult> ProtectAsync(string path, bool allowVolumeRoot) =>
        ProtectAsync(path, allowVolumeRoot, ProtectionMode.Full, 0, 0);

    /// <param name="bulkThreshold">BulkGuard only: deletions allowed per window.</param>
    /// <param name="bulkWindowSeconds">BulkGuard only: window length in seconds.</param>
    public Task<BrokerResult> ProtectAsync(string path, bool allowVolumeRoot, ProtectionMode mode, int bulkThreshold, int bulkWindowSeconds)
    {
        var options = new List<string>();
        if (allowVolumeRoot)
        {
            options.Add("--allow-volume-root");
        }

        if (mode == ProtectionMode.BulkGuard)
        {
            options.Add("--bulk-guard");
            options.Add($"--threshold={bulkThreshold}");
            options.Add($"--window={bulkWindowSeconds}");
        }

        return Task.Run(() => Run("protect", path, options.ToArray()));
    }

    public Task<BrokerResult> UnprotectAsync(string path) =>
        Task.Run(() => Run("unprotect", path));

    public Task<BrokerResult> DeleteAsync(string path) =>
        Task.Run(() => Run("delete", path));

    public BrokerResult Run(string command, string path, params string[] options)
    {
        if (!Exists)
        {
            return new BrokerResult(BrokerFailure.BrokerMissing, -1);
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = BrokerPath,
            UseShellExecute = true,
            Verb = "runas",
            WorkingDirectory = Path.GetDirectoryName(BrokerPath) ?? Environment.CurrentDirectory
        };
        startInfo.ArgumentList.Add(command);
        startInfo.ArgumentList.Add(path);
        foreach (var option in options)
        {
            startInfo.ArgumentList.Add(option);
        }

        var started = DateTimeOffset.UtcNow;
        try
        {
            using var process = Process.Start(startInfo);
            if (process is null)
            {
                return new BrokerResult(BrokerFailure.StartFailed, -1);
            }

            process.WaitForExit();
            return Classify(process.ExitCode, command, path, started);
        }
        catch (Win32Exception exception) when (exception.NativeErrorCode == UacCancelled)
        {
            return new BrokerResult(BrokerFailure.Cancelled, -1);
        }
        catch (Exception exception) when (exception is Win32Exception or InvalidOperationException)
        {
            return new BrokerResult(BrokerFailure.StartFailed, -1, exception.Message);
        }
    }

    private BrokerResult Classify(int exitCode, string command, string path, DateTimeOffset started)
    {
        return exitCode switch
        {
            0 => new BrokerResult(BrokerFailure.None, 0),
            11 => new BrokerResult(BrokerFailure.NotElevated, exitCode),
            12 => new BrokerResult(BrokerFailure.Busy, exitCode),
            13 => new BrokerResult(BrokerFailure.DriverUnavailable, exitCode),
            _ => new BrokerResult(BrokerFailure.Failed, exitCode, FindRecordedError(command, path, started))
        };
    }

    private string? FindRecordedError(string command, string path, DateTimeOffset started)
    {
        try
        {
            var options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
            foreach (var line in _audit.ReadLast(20).Reverse())
            {
                var entry = JsonSerializer.Deserialize<AuditEntry>(line, options);
                if (entry is null ||
                    entry.TimestampUtc < started.AddSeconds(-2) ||
                    !string.Equals(entry.Result, "error", StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(entry.Action, command, StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(entry.TargetPath, path, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var firstLine = entry.Detail?.Split('\n', 2)[0].Trim();
                return string.IsNullOrEmpty(firstLine) ? null : firstLine;
            }
        }
        catch (Exception exception) when (exception is JsonException or IOException or UnauthorizedAccessException)
        {
            // The audit log is advisory here; the exit code is the source of truth.
        }

        return null;
    }
}
