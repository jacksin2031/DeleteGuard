using System.Drawing;
using DeleteGuard.Core.Driver;
using DeleteGuard.Core.Localization;
using DeleteGuard.Core.Models;
using DeleteGuard.Core.Services;

namespace DeleteGuard.Agent;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var background = args.Any(arg => string.Equals(arg, AutoStart.BackgroundArgument, StringComparison.OrdinalIgnoreCase));

        using var mutex = new Mutex(initiallyOwned: true, name: "Local\\DeleteGuard.Agent", out var createdNew);
        if (!createdNew)
        {
            // Already running: ask the running Agent to open its window, unless this is just a login auto-start.
            if (!background)
            {
                try
                {
                    using var signal = EventWaitHandle.OpenExisting(ApprovalContext.ShowWindowEventName);
                    signal.Set();
                }
                catch (WaitHandleCannotBeOpenedException)
                {
                }
            }

            return;
        }

        ApplicationConfiguration.Initialize();
        Application.Run(new ApprovalContext(showWindow: !background));
    }
}

internal sealed class ApprovalContext : ApplicationContext
{
    public const string ShowWindowEventName = "Local\\DeleteGuard.Agent.ShowWindow";

    private readonly DeniedDeleteEventStore _store = new();
    private readonly HashSet<Guid> _known = new();
    private readonly AgentSettingsStore _settingsStore = new();
    private readonly BrokerClient _broker = new();
    private readonly Control _ui = new();
    private readonly EventWaitHandle _showWindowSignal;
    private readonly RegisteredWaitHandle _showWindowRegistration;
    private readonly ToolStripItem _openItem;
    private readonly ToolStripItem _exitItem;
    private AgentSettings _settings;
    private ApprovalPromptLimiter _promptLimiter;
    private ManagementForm? _window;
    private readonly NotifyIcon _notifyIcon;
    private readonly System.Windows.Forms.Timer _timer;
    private bool _polling;
    private DateTimeOffset _lastThrottleNoticeUtc = DateTimeOffset.MinValue;
    private DateTimeOffset _lastUnmappableNoticeUtc = DateTimeOffset.MinValue;
    private DateTimeOffset _lastNamespaceNoticeUtc = DateTimeOffset.MinValue;

    public ApprovalContext(bool showWindow)
    {
        _settings = _settingsStore.Load();
        Loc.SetLanguage(_settings.Language);
        _promptLimiter = CreateLimiter(_settings);

        foreach (var record in _store.ReadLast(200))
        {
            _known.Add(record.EventId);
        }

        // A handle is needed so other threads can marshal onto the UI thread.
        _ = _ui.Handle;
        _showWindowSignal = new EventWaitHandle(false, EventResetMode.AutoReset, ShowWindowEventName);
        _showWindowRegistration = ThreadPool.RegisterWaitForSingleObject(
            _showWindowSignal,
            (_, _) => _ui.BeginInvoke(ShowWindow),
            null,
            Timeout.Infinite,
            executeOnlyOnce: false);

        var menu = new ContextMenuStrip();
        _openItem = menu.Items.Add(string.Empty, null, (_, _) => ShowWindow());
        _openItem.Font = new Font(_openItem.Font, FontStyle.Bold);
        menu.Items.Add(new ToolStripSeparator());
        _exitItem = menu.Items.Add(string.Empty, null, (_, _) => ExitThread());

        _notifyIcon = new NotifyIcon
        {
            Icon = SystemIcons.Shield,
            Visible = true,
            ContextMenuStrip = menu
        };
        _notifyIcon.DoubleClick += (_, _) => ShowWindow();
        ApplyTrayText();

        _timer = new System.Windows.Forms.Timer
        {
            Interval = 750,
            Enabled = true
        };
        _timer.Tick += (_, _) => Poll();

        if (showWindow)
        {
            _ui.BeginInvoke(ShowWindow);
        }
    }

    private static ApprovalPromptLimiter CreateLimiter(AgentSettings settings) => new(
        maxPrompts: settings.MaxPromptsPerWindow,
        window: TimeSpan.FromSeconds(settings.PromptWindowSeconds));

    private void ApplyTrayText()
    {
        _openItem.Text = Loc.T("tray.open");
        _exitItem.Text = Loc.T("tray.exit");
        _notifyIcon.Text = Loc.T("tray.tooltip");
    }

    private void ShowWindow()
    {
        _window ??= new ManagementForm(_settingsStore, _broker, ApplySettings);
        _window.ShowAndActivate();
    }

    private void ApplySettings(AgentSettings settings)
    {
        var previousLanguage = Loc.Current;
        _settings = settings;
        _promptLimiter = CreateLimiter(settings);

        Loc.SetLanguage(settings.Language);
        ApplyTrayText();
        if (Loc.Current != previousLanguage && _window is not null)
        {
            // The window was built with the old language. Rebuild it (after the current click handler
            // returns) on the Settings tab, in the same place on screen.
            var old = _window;
            var tab = old.SelectedTab;
            var location = old.Location;
            _window = null;
            _ui.BeginInvoke(() =>
            {
                old.Dispose();
                _window = new ManagementForm(_settingsStore, _broker, ApplySettings, tab)
                {
                    StartPosition = FormStartPosition.Manual,
                    Location = location
                };
                _window.ShowAndActivate();
            });
        }
    }

    protected override void ExitThreadCore()
    {
        _timer.Stop();
        _timer.Dispose();
        _showWindowRegistration.Unregister(null);
        _showWindowSignal.Dispose();
        _notifyIcon.Visible = false;
        _notifyIcon.Dispose();
        _window?.Dispose();
        _ui.Dispose();
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
                if (!_known.Add(record.EventId))
                {
                    continue;
                }

                var decisionTime = DateTimeOffset.UtcNow;
                if (decisionTime - record.ObservedUtc > TimeSpan.FromSeconds(_settings.PromptMaxAgeSeconds))
                {
                    continue;
                }

                if (!record.CanApprove)
                {
                    if (record.Operation is DriverDeleteOperation.MoveOut
                        or DriverDeleteOperation.ReplaceProtectedDestination
                        or DriverDeleteOperation.RenameProtectedAncestor
                        or DriverDeleteOperation.HardLinkOut
                        or DriverDeleteOperation.ReplaceProtectedLinkDestination)
                    {
                        ShowNamespaceNotice(record, decisionTime);
                    }
                    else
                    {
                        ShowUnmappableNotice(record, decisionTime);
                    }
                    continue;
                }

                if (!_settings.ShowApprovalPrompts)
                {
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

    private void ShowNamespaceNotice(DeniedDeleteEventRecord record, DateTimeOffset now)
    {
        if (!_settings.ShowNamespaceNotices)
        {
            return;
        }

        if (now - _lastNamespaceNoticeUtc < TimeSpan.FromSeconds(_settings.NoticeCooldownSeconds))
        {
            return;
        }

        _lastNamespaceNoticeUtc = now;
        var description = record.Operation switch
        {
            DriverDeleteOperation.MoveOut => Loc.T("notice.namespace.moveOut"),
            DriverDeleteOperation.ReplaceProtectedDestination => Loc.T("notice.namespace.replaceRename"),
            DriverDeleteOperation.RenameProtectedAncestor => Loc.T("notice.namespace.ancestor"),
            DriverDeleteOperation.HardLinkOut => Loc.T("notice.namespace.hardLink"),
            DriverDeleteOperation.ReplaceProtectedLinkDestination => Loc.T("notice.namespace.replaceLink"),
            _ => Loc.T("notice.namespace.generic")
        };

        _notifyIcon.ShowBalloonTip(
            6000,
            Loc.T("notice.namespace.title"),
            Loc.T("notice.namespace.body", description, record.TargetPath),
            ToolTipIcon.Warning);
    }

    private void ShowUnmappableNotice(DeniedDeleteEventRecord record, DateTimeOffset now)
    {
        if (now - _lastUnmappableNoticeUtc < TimeSpan.FromSeconds(_settings.NoticeCooldownSeconds))
        {
            return;
        }

        _lastUnmappableNoticeUtc = now;
        _notifyIcon.ShowBalloonTip(
            5000,
            Loc.T("notice.unmappable.title"),
            Loc.T("notice.unmappable.body", record.NtPath),
            ToolTipIcon.Warning);
    }

    private void ShowThrottleNotice(DateTimeOffset now)
    {
        if (!_settings.ShowThrottleNotices)
        {
            return;
        }

        if (now - _lastThrottleNoticeUtc < TimeSpan.FromSeconds(_settings.NoticeCooldownSeconds))
        {
            return;
        }

        _lastThrottleNoticeUtc = now;
        _notifyIcon.ShowBalloonTip(
            6000,
            Loc.T("notice.throttle.title"),
            Loc.T("notice.throttle.body"),
            ToolTipIcon.Warning);
    }

    private void Prompt(DeniedDeleteEventRecord record)
    {
        var process = string.IsNullOrWhiteSpace(record.ProcessName)
            ? $"PID {record.ProcessId}"
            : $"{record.ProcessName} (PID {record.ProcessId})";

        var result = MessageBox.Show(
            Loc.T("prompt.body", record.TargetPath, process, record.Operation.ToString()),
            Loc.T("prompt.title"),
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning,
            MessageBoxDefaultButton.Button2);

        if (result != DialogResult.Yes)
        {
            return;
        }

        LaunchBroker(record.TargetPath);
    }

    private async void LaunchBroker(string targetPath)
    {
        var result = await _broker.DeleteAsync(targetPath);
        if (result.Succeeded || result.Failure == BrokerFailure.Cancelled)
        {
            return;
        }

        var reason = result.Failure switch
        {
            BrokerFailure.BrokerMissing => Loc.T("prompt.brokerMissing", _broker.BrokerPath),
            _ => Loc.T("prompt.failed", result.ExitCode) +
                 (string.IsNullOrWhiteSpace(result.Detail) ? string.Empty : $"\n\n{result.Detail}")
        };
        MessageBox.Show(reason, "DeleteGuard", MessageBoxButtons.OK, MessageBoxIcon.Error);
    }
}
