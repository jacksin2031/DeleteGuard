using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using DeleteGuard.Core.Models;
using DeleteGuard.Core.Services;

namespace DeleteGuard.Agent;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using var mutex = new Mutex(initiallyOwned: true, name: "Local\\DeleteGuard.Agent", out var createdNew);
        if (!createdNew)
        {
            return;
        }

        ApplicationConfiguration.Initialize();
        Application.Run(new ApprovalContext());
    }
}

internal sealed class ApprovalContext : ApplicationContext
{
    private readonly DeniedDeleteEventStore _store = new();
    private readonly HashSet<Guid> _known = new();
    private readonly ApprovalPromptLimiter _promptLimiter = new(
        maxPrompts: 3,
        window: TimeSpan.FromSeconds(30));
    private readonly NotifyIcon _notifyIcon;
    private readonly System.Windows.Forms.Timer _timer;
    private bool _polling;
    private DateTimeOffset _lastThrottleNoticeUtc = DateTimeOffset.MinValue;

    public ApprovalContext()
    {
        foreach (var record in _store.ReadLast(200))
        {
            _known.Add(record.EventId);
        }

        var menu = new ContextMenuStrip();
        menu.Items.Add("Exit", null, (_, _) => ExitThread());

        _notifyIcon = new NotifyIcon
        {
            Icon = SystemIcons.Shield,
            Text = "DeleteGuard approval agent",
            Visible = true,
            ContextMenuStrip = menu
        };

        _timer = new System.Windows.Forms.Timer
        {
            Interval = 750,
            Enabled = true
        };
        _timer.Tick += (_, _) => Poll();
    }

    protected override void ExitThreadCore()
    {
        _timer.Stop();
        _timer.Dispose();
        _notifyIcon.Visible = false;
        _notifyIcon.Dispose();
        base.ExitThreadCore();
    }

    private void Poll()
    {
        if (_polling)
        {
            return;
        }

        _polling = true;
        _timer.Stop();

        try
        {
            foreach (var record in _store.ReadLast(100).OrderBy(record => record.ObservedUtc))
            {
                // Mark an event known before any filtering so a throttled or stale event
                // can never be replayed later as a fresh approval opportunity.
                if (!_known.Add(record.EventId))
                {
                    continue;
                }

                // A modal prompt can keep this loop blocked for an arbitrary time.
                // Re-read the clock for every event so the freshness and rate-limit
                // decisions reflect the actual time at which UI would be shown.
                var decisionTime = DateTimeOffset.UtcNow;
                if (decisionTime - record.ObservedUtc > TimeSpan.FromSeconds(20))
                {
                    continue;
                }

                if (!record.CanApprove)
                {
                    _notifyIcon.ShowBalloonTip(
                        5000,
                        "DeleteGuard blocked a deletion",
                        $"A protected delete was denied, but its NT path could not be mapped to a drive-letter path: {record.NtPath}",
                        ToolTipIcon.Warning);
                    continue;
                }

                if (!_promptLimiter.TryAcquire(decisionTime))
                {
                    ShowThrottleNotice(decisionTime);
                    continue;
                }

                Prompt(record);
            }

            if (_known.Count > 4096)
            {
                _known.Clear();
                foreach (var record in _store.ReadLast(200))
                {
                    _known.Add(record.EventId);
                }
            }
        }
        finally
        {
            _polling = false;
            _timer.Start();
        }
    }

    private void ShowThrottleNotice(DateTimeOffset now)
    {
        if (now - _lastThrottleNoticeUtc < TimeSpan.FromSeconds(15))
        {
            return;
        }

        _lastThrottleNoticeUtc = now;
        _notifyIcon.ShowBalloonTip(
            6000,
            "DeleteGuard is limiting approval prompts",
            "Many protected deletion attempts were blocked. Automatic approval dialogs are temporarily rate-limited. Protected data remains blocked; use 'deleteguard delete <path>' for an explicit administrator-approved deletion.",
            ToolTipIcon.Warning);
    }

    private void Prompt(DeniedDeleteEventRecord record)
    {
        var process = string.IsNullOrWhiteSpace(record.ProcessName)
            ? $"PID {record.ProcessId}"
            : $"{record.ProcessName} (PID {record.ProcessId})";

        var result = MessageBox.Show(
            $"DeleteGuard blocked a deletion request.\n\n" +
            $"Target:\n{record.TargetPath}\n\n" +
            $"Process: {process}\n" +
            $"Operation: {record.Operation}\n\n" +
            "Approve deleting this target?\n\n" +
            "If you choose Yes, Windows will show a UAC administrator prompt. " +
            "The original application has already received Access Denied; DeleteGuard will perform the approved deletion through its elevated broker.",
            "DeleteGuard deletion approval",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning,
            MessageBoxDefaultButton.Button2);

        if (result != DialogResult.Yes)
        {
            return;
        }

        LaunchBroker(record.TargetPath);
    }

    private static void LaunchBroker(string targetPath)
    {
        var broker = Path.Combine(AppContext.BaseDirectory, "DeleteGuard.Broker.exe");
        if (!File.Exists(broker))
        {
            MessageBox.Show(
                $"DeleteGuard broker was not found:\n{broker}",
                "DeleteGuard",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            return;
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = broker,
            UseShellExecute = true,
            Verb = "runas",
            WorkingDirectory = Environment.CurrentDirectory
        };
        startInfo.ArgumentList.Add("delete");
        startInfo.ArgumentList.Add(targetPath);

        try
        {
            Process.Start(startInfo)?.Dispose();
        }
        catch (Win32Exception exception) when (exception.NativeErrorCode == 1223)
        {
            // The user cancelled the UAC prompt. The original delete remains denied.
        }
        catch (Exception exception)
        {
            MessageBox.Show(
                $"Unable to start the DeleteGuard broker.\n\n{exception.Message}",
                "DeleteGuard",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }
    }
}
