using System.Diagnostics;
using DeleteGuard.Core.Driver;
using DeleteGuard.Core.Models;
using DeleteGuard.Core.Services;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace DeleteGuard.EventRelay;

public sealed class RelayWorker : BackgroundService
{
    private const string MutationMutexName = "Global\\DeleteGuard.Broker.Mutation";
    private readonly ILogger<RelayWorker> _logger;
    private readonly DeniedDeleteEventStore _eventStore;
    private readonly object _clientLock = new();
    private readonly RecentEventGate _recent = new(
        duplicateWindow: TimeSpan.FromSeconds(2),
        retentionWindow: TimeSpan.FromSeconds(30),
        maxEntries: 512,
        comparer: StringComparer.OrdinalIgnoreCase);
    private FilterEventClient? _eventClient;

    public RelayWorker(ILogger<RelayWorker> logger, DeniedDeleteEventStore eventStore)
    {
        _logger = logger;
        _eventStore = eventStore;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Yield();
        RuntimePaths.EnsureSecureDataDirectory(RuntimePaths.DefaultDataDirectory);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (!TrySyncPolicies())
                {
                    await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken);
                    continue;
                }

                if (!FilterEventClient.TryConnect(out var client) || client is null)
                {
                    await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken);
                    continue;
                }

                lock (_clientLock)
                {
                    _eventClient = client;
                }

                _logger.LogInformation("Connected to DeleteGuard minifilter event channel.");

                using (client)
                {
                    while (!stoppingToken.IsCancellationRequested)
                    {
                        var driverEvent = client.ReadNext();
                        Persist(driverEvent);
                    }
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                if (!stoppingToken.IsCancellationRequested)
                {
                    _logger.LogWarning(exception, "DeleteGuard event relay disconnected; retrying.");
                    try
                    {
                        await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                }
            }
            finally
            {
                lock (_clientLock)
                {
                    _eventClient = null;
                }
            }
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        lock (_clientLock)
        {
            _eventClient?.Dispose();
            _eventClient = null;
        }

        await base.StopAsync(cancellationToken);
    }

    private bool TrySyncPolicies()
    {
        using var mutationMutex = new Mutex(initiallyOwned: false, name: MutationMutexName);
        var acquired = false;

        try
        {
            try
            {
                acquired = mutationMutex.WaitOne(TimeSpan.FromSeconds(5));
            }
            catch (AbandonedMutexException)
            {
                acquired = true;
            }

            if (!acquired)
            {
                _logger.LogInformation("Deferred policy synchronization because an administrative mutation is in progress.");
                return false;
            }

            if (!FilterPortClient.TryConnect(out var commandClient) || commandClient is null)
            {
                return false;
            }

            using (commandClient)
            {
                commandClient.SyncPolicies(new PolicyStore().Load());
            }

            return true;
        }
        catch (Exception exception)
        {
            _logger.LogWarning(exception, "Unable to synchronize DeleteGuard policies while reconnecting event relay.");
            return false;
        }
        finally
        {
            if (acquired)
            {
                mutationMutex.ReleaseMutex();
            }
        }
    }

    private void Persist(DriverEvent driverEvent)
    {
        var now = DateTimeOffset.UtcNow;
        var key = $"{driverEvent.ProcessId}|{(uint)driverEvent.Operation}|{driverEvent.Path}";

        if (!_recent.TryAccept(key, now))
        {
            return;
        }

        var mapped = NtPathConverter.TryFromNtPath(driverEvent.Path, out var targetPath);
        var destructiveRename = driverEvent.Operation is
            DriverDeleteOperation.RenameOut or
            DriverDeleteOperation.RenameReplace;
        var canApprove = mapped && !destructiveRename;
        var record = new DeniedDeleteEventRecord
        {
            EventId = Guid.NewGuid(),
            ObservedUtc = now,
            DriverSequence = driverEvent.Sequence,
            ProcessId = driverEvent.ProcessId,
            ProcessName = TryGetProcessName(driverEvent.ProcessId),
            Operation = driverEvent.Operation,
            NtPath = driverEvent.Path,
            TargetPath = mapped ? targetPath : driverEvent.Path,
            CanApprove = canApprove
        };

        _eventStore.Append(record);
        _logger.LogInformation(
            "Recorded denied protected operation {Operation} event {EventId} pid={ProcessId} path={Path}",
            record.Operation,
            record.EventId,
            record.ProcessId,
            record.TargetPath);
    }

    private static string? TryGetProcessName(uint processId)
    {
        try
        {
            using var process = Process.GetProcessById(checked((int)processId));
            return process.ProcessName;
        }
        catch
        {
            return null;
        }
    }
}
