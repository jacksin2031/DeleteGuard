using System.Drawing;
using System.Text.Json;
using DeleteGuard.Core.Localization;
using DeleteGuard.Core.Models;
using DeleteGuard.Core.Services;

namespace DeleteGuard.Agent;

/// <summary>
/// Management window: protected-folder list, settings and activity history.
/// The window never elevates; every change to protection goes through the Broker's UAC prompt.
/// All text comes from <see cref="Loc"/>; the window is rebuilt when the language changes.
/// </summary>
internal sealed class ManagementForm : Form
{
    private const int ContentWidth = 680;

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly AgentSettingsStore _settingsStore;
    private readonly BrokerClient _broker;
    private readonly ProtectionListService _list;
    private readonly ProtectionRequestValidator _validator;
    private readonly AuditLogger _audit = new();
    private readonly DeniedDeleteEventStore _events = new();
    private readonly Action<AgentSettings> _settingsApplied;

    private readonly Label _brokerStatus = new();
    private readonly TabControl _tabs = new();

    private readonly ListView _protectedList = new();
    private readonly Label _emptyHint = new();
    private readonly Button _addButton = new();
    private readonly Button _removeButton = new();
    private readonly Button _refreshButton = new();
    private readonly Label _busyLabel = new();

    private readonly CheckBox _showPrompts = new();
    private readonly NumericUpDown _maxPrompts = new();
    private readonly NumericUpDown _promptWindow = new();
    private readonly NumericUpDown _promptMaxAge = new();
    private readonly CheckBox _namespaceNotices = new();
    private readonly CheckBox _throttleNotices = new();
    private readonly NumericUpDown _noticeCooldown = new();
    private readonly CheckBox _autoStart = new();
    private readonly ComboBox _language = new();
    private readonly Label _settingsStatus = new();

    private readonly ComboBox _logSource = new();
    private readonly ListView _logList = new();

    private bool _busy;

    public ManagementForm(
        AgentSettingsStore settingsStore,
        BrokerClient broker,
        Action<AgentSettings> settingsApplied,
        int initialTab = 0)
    {
        _settingsStore = settingsStore;
        _broker = broker;
        _settingsApplied = settingsApplied;

        var policyStore = new PolicyStore();
        _list = new ProtectionListService(policyStore);
        _validator = new ProtectionRequestValidator(policyStore.Load);

        Text = Loc.T("app.title");
        Icon = SystemIcons.Shield;
        AutoScaleMode = AutoScaleMode.Dpi;
        Font = PickFont();
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(760, 520);
        ClientSize = new Size(900, 660);

        BuildLayout();
        LoadSettingsIntoControls(_settingsStore.Load());
        _tabs.SelectedIndex = Math.Clamp(initialTab, 0, _tabs.TabCount - 1);
        Activated += (_, _) => RefreshAll();
    }

    /// <summary>Index of the visible tab, so a rebuilt window can return to it.</summary>
    public int SelectedTab => _tabs.SelectedIndex;

    /// <summary>A font family that covers the active language's script.</summary>
    private static Font PickFont()
    {
        var family = Loc.Current switch
        {
            Loc.TraditionalChinese => "Microsoft JhengHei UI",
            Loc.SimplifiedChinese => "Microsoft YaHei UI",
            Loc.Japanese => "Yu Gothic UI",
            Loc.Korean => "Malgun Gothic",
            _ => "Segoe UI"
        };
        return new Font(family, 9f);
    }

    /// <summary>The window lives in the tray: closing hides it instead of ending the Agent.</summary>
    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (e.CloseReason == CloseReason.UserClosing)
        {
            e.Cancel = true;
            Hide();
            return;
        }

        base.OnFormClosing(e);
    }

    public void ShowAndActivate()
    {
        if (!Visible)
        {
            Show();
        }

        if (WindowState == FormWindowState.Minimized)
        {
            WindowState = FormWindowState.Normal;
        }

        Activate();
        BringToFront();
    }

    // ------------------------------------------------------------------ layout

    private void BuildLayout()
    {
        _brokerStatus.Dock = DockStyle.Top;
        _brokerStatus.Height = 34;
        _brokerStatus.Padding = new Padding(12, 6, 12, 0);

        _tabs.Dock = DockStyle.Fill;
        _tabs.Padding = new Point(14, 6);
        _tabs.TabPages.Add(BuildProtectionTab());
        _tabs.TabPages.Add(BuildSettingsTab());
        _tabs.TabPages.Add(BuildActivityTab());

        Controls.Add(_tabs);
        Controls.Add(_brokerStatus);
    }

    private TabPage BuildProtectionTab()
    {
        var page = new TabPage(Loc.T("tab.protected")) { Padding = new Padding(12) };

        var intro = new Label
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            MaximumSize = new Size(840, 0),
            Padding = new Padding(0, 0, 0, 8),
            UseCompatibleTextRendering = true,
            Text = Loc.T("list.intro")
        };

        _protectedList.Dock = DockStyle.Fill;
        _protectedList.View = View.Details;
        _protectedList.FullRowSelect = true;
        _protectedList.MultiSelect = false;
        _protectedList.HideSelection = false;
        _protectedList.GridLines = false;
        _protectedList.Columns.Add(Loc.T("list.col.folder"), 400);
        _protectedList.Columns.Add(Loc.T("list.col.state"), 170);
        _protectedList.Columns.Add(Loc.T("list.col.created"), 160);
        _protectedList.SelectedIndexChanged += (_, _) => UpdateButtons();
        _protectedList.DoubleClick += (_, _) => RemoveSelected();

        _emptyHint.Dock = DockStyle.Top;
        _emptyHint.Height = 56;
        _emptyHint.ForeColor = SystemColors.GrayText;
        _emptyHint.TextAlign = ContentAlignment.MiddleCenter;
        _emptyHint.Text = Loc.T("list.empty");
        _emptyHint.Visible = false;

        var buttons = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            Height = 58,
            FlowDirection = FlowDirection.LeftToRight,
            Padding = new Padding(0, 10, 0, 0)
        };

        ConfigureButton(_addButton, Loc.T("btn.add"), (_, _) => AddFolder());
        ConfigureButton(_removeButton, Loc.T("btn.remove"), (_, _) => RemoveSelected());
        ConfigureButton(_refreshButton, Loc.T("btn.refresh"), (_, _) => RefreshAll());
        _busyLabel.AutoSize = true;
        _busyLabel.Margin = new Padding(12, 7, 0, 0);
        _busyLabel.ForeColor = SystemColors.GrayText;

        buttons.Controls.AddRange(new Control[] { _addButton, _removeButton, _refreshButton, _busyLabel });

        page.Controls.Add(_protectedList);
        page.Controls.Add(_emptyHint);
        page.Controls.Add(intro);
        page.Controls.Add(buttons);
        return page;
    }

    private TabPage BuildSettingsTab()
    {
        var page = new TabPage(Loc.T("tab.settings")) { Padding = new Padding(12), AutoScroll = true };

        var panel = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            AutoScroll = true
        };

        var note = new Label
        {
            AutoSize = true,
            MaximumSize = new Size(ContentWidth, 0),
            Margin = new Padding(3, 0, 3, 12),
            UseCompatibleTextRendering = true,
            Text = Loc.T("settings.note")
        };

        ConfigureCheck(_showPrompts, Loc.T("settings.showPrompts"));
        _showPrompts.CheckedChanged += (_, _) => UpdateSettingsEnabled();

        ConfigureNumeric(_maxPrompts, AgentSettings.MinPromptsPerWindow, AgentSettings.MaxPromptsPerWindowLimit);
        ConfigureNumeric(_promptWindow, AgentSettings.MinPromptWindowSeconds, AgentSettings.MaxPromptWindowSeconds);
        ConfigureNumeric(_promptMaxAge, AgentSettings.MinPromptMaxAgeSeconds, AgentSettings.MaxPromptMaxAgeSeconds);
        ConfigureNumeric(_noticeCooldown, AgentSettings.MinNoticeCooldownSeconds, AgentSettings.MaxNoticeCooldownSeconds);

        var promptGroup = Group(Loc.T("group.prompts"), new Control[]
        {
            _showPrompts,
            Row(Loc.T("settings.maxPrompts"), _maxPrompts, Loc.T("unit.times")),
            Row(Loc.T("settings.window"), _promptWindow, Loc.T("unit.seconds")),
            Row(Loc.T("settings.maxAge"), _promptMaxAge, Loc.T("unit.seconds"))
        });

        ConfigureCheck(_namespaceNotices, Loc.T("settings.nsNotices"));
        ConfigureCheck(_throttleNotices, Loc.T("settings.throttleNotices"));

        var noticeGroup = Group(Loc.T("group.notices"), new Control[]
        {
            _namespaceNotices,
            _throttleNotices,
            Row(Loc.T("settings.cooldown"), _noticeCooldown, Loc.T("unit.seconds"))
        });

        ConfigureCheck(_autoStart, Loc.T("settings.autostart"));
        var startupGroup = Group(Loc.T("group.startup"), new Control[] { _autoStart });

        _language.DropDownStyle = ComboBoxStyle.DropDownList;
        _language.Width = 260;
        _language.Items.Clear();
        _language.Items.Add(new LanguageItem(Loc.Auto, Loc.T("lang.auto")));
        foreach (var option in Loc.Supported)
        {
            _language.Items.Add(new LanguageItem(option.Code, option.NativeName));
        }

        var languageRow = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.LeftToRight };
        languageRow.Controls.Add(RowLabel(Loc.T("settings.language")));
        languageRow.Controls.Add(_language);
        var languageGroup = Group(Loc.T("group.language"), new Control[] { languageRow });

        var save = new Button { Text = Loc.T("btn.save"), AutoSize = true, Padding = new Padding(10, 3, 10, 3) };
        save.Click += (_, _) => SaveSettings();
        var reset = new Button { Text = Loc.T("btn.reset"), AutoSize = true, Padding = new Padding(10, 3, 10, 3) };
        reset.Click += (_, _) => LoadSettingsIntoControls(AgentSettings.Default, keepAutoStart: true);
        _settingsStatus.AutoSize = true;
        _settingsStatus.Margin = new Padding(12, 7, 0, 0);

        // Save/reset stay pinned below the scrolling area so they are always reachable.
        var actions = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            Height = 54,
            FlowDirection = FlowDirection.LeftToRight,
            Padding = new Padding(0, 8, 0, 0)
        };
        actions.Controls.AddRange(new Control[] { save, reset, _settingsStatus });

        panel.Controls.AddRange(new Control[] { note, languageGroup, promptGroup, noticeGroup, startupGroup });
        page.Controls.Add(panel);
        page.Controls.Add(actions);
        return page;
    }

    private TabPage BuildActivityTab()
    {
        var page = new TabPage(Loc.T("tab.activity")) { Padding = new Padding(12) };

        _logSource.DropDownStyle = ComboBoxStyle.DropDownList;
        _logSource.Items.AddRange(new object[] { Loc.T("log.source.audit"), Loc.T("log.source.events") });
        _logSource.SelectedIndex = 0;
        _logSource.Width = 320;
        _logSource.SelectedIndexChanged += (_, _) => RefreshLog();

        var refresh = new Button { Text = Loc.T("btn.refresh"), AutoSize = true };
        refresh.Click += (_, _) => RefreshLog();

        var top = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 36, FlowDirection = FlowDirection.LeftToRight };
        top.Controls.AddRange(new Control[] { _logSource, refresh });

        _logList.Dock = DockStyle.Fill;
        _logList.View = View.Details;
        _logList.FullRowSelect = true;
        _logList.GridLines = false;

        page.Controls.Add(_logList);
        page.Controls.Add(top);
        return page;
    }

    private static void ConfigureButton(Button button, string text, EventHandler onClick)
    {
        button.Text = text;
        button.AutoSize = true;
        button.Padding = new Padding(10, 3, 10, 3);
        button.Click += onClick;
    }

    private static void ConfigureNumeric(NumericUpDown control, int min, int max)
    {
        control.Minimum = min;
        control.Maximum = max;
        control.Width = 70;
    }

    private static GroupBox Group(string title, Control[] children)
    {
        var flow = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            AutoSize = true,
            Padding = new Padding(8, 4, 8, 4)
        };
        flow.Controls.AddRange(children);

        var box = new GroupBox
        {
            Text = title,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            MinimumSize = new Size(ContentWidth, 0),
            Padding = new Padding(6)
        };
        box.Controls.Add(flow);
        return box;
    }

    private static Control Row(string label, NumericUpDown input, string unit)
    {
        var row = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.LeftToRight };
        row.Controls.Add(RowLabel(label));
        row.Controls.Add(input);
        row.Controls.Add(new Label { Text = unit, AutoSize = true, Margin = new Padding(4, 6, 0, 0) });
        return row;
    }

    /// <summary>Label column of a settings row: fixed minimum width, wraps instead of truncating long translations.</summary>
    private static Label RowLabel(string text) => new()
    {
        Text = text,
        AutoSize = true,
        MinimumSize = new Size(380, 0),
        MaximumSize = new Size(380, 0),
        Margin = new Padding(3, 6, 3, 6),
        UseCompatibleTextRendering = true
    };

    /// <summary>
    /// WinForms CheckBox does not wrap reliably when auto-sized, so measure the translated text and
    /// give the box a fixed width with exactly the height the wrapped text needs.
    /// </summary>
    private void ConfigureCheck(CheckBox box, string text)
    {
        const int glyphAndPadding = 28;
        var width = ContentWidth - 40;
        var measured = TextRenderer.MeasureText(
            text,
            Font,
            new Size(width - glyphAndPadding, int.MaxValue),
            TextFormatFlags.WordBreak | TextFormatFlags.NoPadding);

        box.Text = text;
        box.AutoSize = false;
        box.UseCompatibleTextRendering = true;
        box.Size = new Size(width, Math.Max(24, measured.Height + 8));
        box.Margin = new Padding(3, 3, 3, 6);
    }

    private sealed record LanguageItem(string Code, string Display)
    {
        public override string ToString() => Display;
    }

    // ------------------------------------------------------------- protection

    private void RefreshAll()
    {
        _brokerStatus.Text = _broker.Exists
            ? Loc.T("status.brokerFound")
            : Loc.T("status.brokerMissing", _broker.BrokerPath);
        _brokerStatus.ForeColor = _broker.Exists ? SystemColors.ControlText : Color.Firebrick;

        RefreshProtectionList();
        RefreshLog();
        UpdateButtons();
    }

    private void RefreshProtectionList()
    {
        var selected = SelectedEntry()?.Id;
        _protectedList.BeginUpdate();
        try
        {
            _protectedList.Items.Clear();
            IReadOnlyList<ProtectionEntry> entries;
            try
            {
                entries = _list.List();
            }
            catch (Exception exception) when (exception is IOException or JsonException or UnauthorizedAccessException)
            {
                _emptyHint.Text = Loc.T("list.loadError", exception.Message);
                _emptyHint.Visible = true;
                return;
            }

            _emptyHint.Text = Loc.T("list.empty");
            _emptyHint.Visible = entries.Count == 0;

            foreach (var entry in entries)
            {
                var item = new ListViewItem(entry.RootPath) { Tag = entry };
                item.SubItems.Add(DescribeState(entry));
                item.SubItems.Add(entry.CreatedUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm"));
                if (entry.Acl != AclState.Present || !entry.Enabled)
                {
                    item.ForeColor = entry.Acl == AclState.Unknown ? SystemColors.GrayText : Color.Firebrick;
                }

                item.Selected = entry.Id == selected;
                _protectedList.Items.Add(item);
            }
        }
        finally
        {
            FitColumns(_protectedList);
            _protectedList.EndUpdate();
        }
    }

    private static string DescribeState(ProtectionEntry entry)
    {
        if (!entry.Enabled)
        {
            return Loc.T("state.disabled");
        }

        return entry.Acl switch
        {
            AclState.Present => Loc.T("state.protected"),
            AclState.Missing => Loc.T("state.aclMissing"),
            AclState.FolderMissing => Loc.T("state.folderMissing"),
            _ => Loc.T("state.unknown")
        };
    }

    private ProtectionEntry? SelectedEntry() =>
        _protectedList.SelectedItems.Count == 1 ? _protectedList.SelectedItems[0].Tag as ProtectionEntry : null;

    private void UpdateButtons()
    {
        _addButton.Enabled = !_busy && _broker.Exists;
        _removeButton.Enabled = !_busy && _broker.Exists && SelectedEntry() is not null;
        _refreshButton.Enabled = !_busy;
    }

    private async void AddFolder()
    {
        if (_busy)
        {
            return;
        }

        using var dialog = new FolderBrowserDialog
        {
            Description = Loc.T("add.dialogDescription"),
            UseDescriptionForTitle = true,
            ShowNewFolderButton = false
        };
        if (dialog.ShowDialog(this) != DialogResult.OK)
        {
            return;
        }

        var check = _validator.Validate(dialog.SelectedPath);
        if (!check.Accepted)
        {
            MessageBox.Show(this, DescribeRejection(check), Loc.T("add.errorTitle"), MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var warning = check.IsVolumeRoot
            ? Loc.T("add.confirmVolume", check.Path)
            : Loc.T("add.confirmFolder", check.Path);
        var confirm = MessageBox.Show(
            this,
            warning + Loc.T("add.confirmBody"),
            Loc.T("add.confirmTitle"),
            MessageBoxButtons.YesNo,
            check.IsVolumeRoot ? MessageBoxIcon.Warning : MessageBoxIcon.Question,
            MessageBoxDefaultButton.Button2);
        if (confirm != DialogResult.Yes)
        {
            return;
        }

        await RunBrokerAsync(
            () => _broker.ProtectAsync(check.Path, check.IsVolumeRoot),
            Loc.T("add.success", check.Path),
            Loc.T("add.title"));
    }

    private async void RemoveSelected()
    {
        var entry = SelectedEntry();
        if (_busy || entry is null || !_broker.Exists)
        {
            return;
        }

        var confirm = MessageBox.Show(
            this,
            Loc.T("remove.confirm", entry.RootPath),
            Loc.T("remove.confirmTitle"),
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning,
            MessageBoxDefaultButton.Button2);
        if (confirm != DialogResult.Yes)
        {
            return;
        }

        await RunBrokerAsync(
            () => _broker.UnprotectAsync(entry.RootPath),
            Loc.T("remove.success", entry.RootPath),
            Loc.T("remove.title"));
    }

    private async Task RunBrokerAsync(Func<Task<BrokerResult>> action, string successText, string title)
    {
        _busy = true;
        UpdateButtons();
        _busyLabel.Text = Loc.T("busy.waiting");

        try
        {
            var result = await action();
            if (result.Succeeded)
            {
                _busyLabel.Text = successText;
            }
            else if (result.Failure == BrokerFailure.Cancelled)
            {
                _busyLabel.Text = Loc.T("busy.cancelled");
            }
            else
            {
                _busyLabel.Text = string.Empty;
                MessageBox.Show(this, DescribeFailure(result), title, MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
        finally
        {
            _busy = false;
            RefreshAll();
        }
    }

    internal static string DescribeRejection(ProtectionCheck check) => check.Rejection switch
    {
        ProtectionRejection.Empty => Loc.T("reject.empty"),
        ProtectionRejection.InvalidPath => Loc.T("reject.invalidPath"),
        ProtectionRejection.NetworkPath => Loc.T("reject.networkPath"),
        ProtectionRejection.NotFound => Loc.T("reject.notFound", check.Path),
        ProtectionRejection.NotADirectory => Loc.T("reject.notADirectory"),
        ProtectionRejection.ReparsePoint => Loc.T("reject.reparsePoint"),
        ProtectionRejection.NotNtfs => Loc.T("reject.notNtfs", check.Detail ?? string.Empty),
        ProtectionRejection.SystemVolumeRoot => Loc.T("reject.systemVolumeRoot"),
        ProtectionRejection.AlreadyProtected => Loc.T("reject.alreadyProtected", check.Path),
        ProtectionRejection.Overlaps => Loc.T("reject.overlaps", check.Detail ?? string.Empty),
        _ => Loc.T("reject.generic")
    };

    internal static string DescribeFailure(BrokerResult result)
    {
        var text = result.Failure switch
        {
            BrokerFailure.BrokerMissing => Loc.T("failure.brokerMissing"),
            BrokerFailure.StartFailed => Loc.T("failure.startFailed"),
            BrokerFailure.NotElevated => Loc.T("failure.notElevated"),
            BrokerFailure.Busy => Loc.T("failure.busy"),
            _ => Loc.T("failure.failed", result.ExitCode)
        };

        return string.IsNullOrWhiteSpace(result.Detail) ? text : $"{text}\n\n{result.Detail}";
    }

    // --------------------------------------------------------------- settings

    private void LoadSettingsIntoControls(AgentSettings settings, bool keepAutoStart = false)
    {
        _showPrompts.Checked = settings.ShowApprovalPrompts;
        _maxPrompts.Value = settings.MaxPromptsPerWindow;
        _promptWindow.Value = settings.PromptWindowSeconds;
        _promptMaxAge.Value = settings.PromptMaxAgeSeconds;
        _namespaceNotices.Checked = settings.ShowNamespaceNotices;
        _throttleNotices.Checked = settings.ShowThrottleNotices;
        _noticeCooldown.Value = settings.NoticeCooldownSeconds;
        SelectLanguage(settings.Language);
        if (!keepAutoStart)
        {
            _autoStart.Checked = AutoStart.IsEnabled();
        }

        UpdateSettingsEnabled();
        _settingsStatus.Text = string.Empty;
    }

    private void SelectLanguage(string code)
    {
        foreach (LanguageItem item in _language.Items)
        {
            if (string.Equals(item.Code, code, StringComparison.OrdinalIgnoreCase))
            {
                _language.SelectedItem = item;
                return;
            }
        }

        _language.SelectedIndex = 0;
    }

    private void UpdateSettingsEnabled()
    {
        _maxPrompts.Enabled = _showPrompts.Checked;
        _promptWindow.Enabled = _showPrompts.Checked;
        _promptMaxAge.Enabled = _showPrompts.Checked;
    }

    private void SaveSettings()
    {
        try
        {
            var language = (_language.SelectedItem as LanguageItem)?.Code ?? Loc.Auto;
            var saved = _settingsStore.Save(new AgentSettings
            {
                ShowApprovalPrompts = _showPrompts.Checked,
                MaxPromptsPerWindow = (int)_maxPrompts.Value,
                PromptWindowSeconds = (int)_promptWindow.Value,
                PromptMaxAgeSeconds = (int)_promptMaxAge.Value,
                ShowNamespaceNotices = _namespaceNotices.Checked,
                ShowThrottleNotices = _throttleNotices.Checked,
                NoticeCooldownSeconds = (int)_noticeCooldown.Value,
                Language = language
            });

            if (_autoStart.Checked != AutoStart.IsEnabled())
            {
                AutoStart.Set(_autoStart.Checked);
            }

            _settingsStatus.ForeColor = SystemColors.ControlText;
            _settingsStatus.Text = Loc.T("settings.saved", DateTime.Now.ToString("HH:mm:ss"));

            // May rebuild (and dispose) this window when the language changed, so it must be the last step.
            _settingsApplied(saved);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            _settingsStatus.ForeColor = Color.Firebrick;
            _settingsStatus.Text = Loc.T("settings.saveFailed");
            MessageBox.Show(this, Loc.T("settings.saveError", exception.Message), "DeleteGuard", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    // --------------------------------------------------------------- activity

    private void RefreshLog()
    {
        _logList.BeginUpdate();
        try
        {
            _logList.Items.Clear();
            _logList.Columns.Clear();

            if (_logSource.SelectedIndex == 0)
            {
                _logList.Columns.Add(Loc.T("col.time"), 140);
                _logList.Columns.Add(Loc.T("col.action"), 80);
                _logList.Columns.Add(Loc.T("col.result"), 80);
                _logList.Columns.Add(Loc.T("col.path"), 300);
                _logList.Columns.Add(Loc.T("col.detail"), 200);
                foreach (var line in ReadSafely(() => _audit.ReadLast(200)).Reverse())
                {
                    AuditEntry? entry;
                    try
                    {
                        entry = JsonSerializer.Deserialize<AuditEntry>(line, JsonOptions);
                    }
                    catch (JsonException)
                    {
                        continue;
                    }

                    if (entry is null)
                    {
                        continue;
                    }

                    var item = new ListViewItem(entry.TimestampUtc.ToLocalTime().ToString("MM-dd HH:mm:ss"));
                    item.SubItems.Add(entry.Action);
                    item.SubItems.Add(entry.Result);
                    item.SubItems.Add(entry.TargetPath);
                    item.SubItems.Add(entry.Detail?.Split('\n', 2)[0].Trim() ?? string.Empty);
                    if (string.Equals(entry.Result, "error", StringComparison.OrdinalIgnoreCase))
                    {
                        item.ForeColor = Color.Firebrick;
                    }

                    _logList.Items.Add(item);
                }
            }
            else
            {
                _logList.Columns.Add(Loc.T("col.time"), 140);
                _logList.Columns.Add(Loc.T("col.process"), 150);
                _logList.Columns.Add(Loc.T("col.operation"), 190);
                _logList.Columns.Add(Loc.T("col.path"), 320);
                foreach (var record in ReadSafely(() => _events.ReadLast(200)).Reverse())
                {
                    var item = new ListViewItem(record.ObservedUtc.ToLocalTime().ToString("MM-dd HH:mm:ss"));
                    item.SubItems.Add(string.IsNullOrWhiteSpace(record.ProcessName) ? $"PID {record.ProcessId}" : record.ProcessName);
                    item.SubItems.Add(record.Operation.ToString());
                    item.SubItems.Add(record.TargetPath);
                    _logList.Items.Add(item);
                }
            }
        }
        finally
        {
            FitColumns(_logList);
            _logList.EndUpdate();
        }
    }

    /// <summary>Size each column to its content (never narrower than its header); the last column takes the remaining width.</summary>
    private static void FitColumns(ListView list)
    {
        if (list.Columns.Count == 0)
        {
            return;
        }

        list.AutoResizeColumns(ColumnHeaderAutoResizeStyle.HeaderSize);
        var headerWidths = list.Columns.Cast<ColumnHeader>().Select(column => column.Width).ToArray();
        list.AutoResizeColumns(ColumnHeaderAutoResizeStyle.ColumnContent);
        for (var i = 0; i < list.Columns.Count; i++)
        {
            list.Columns[i].Width = Math.Max(list.Columns[i].Width, headerWidths[i]) + 12;
        }

        list.Columns[^1].Width = -2;
    }

    private static IReadOnlyList<T> ReadSafely<T>(Func<IReadOnlyList<T>> read)
    {
        try
        {
            return read();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return Array.Empty<T>();
        }
    }
}
