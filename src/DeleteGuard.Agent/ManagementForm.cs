using System.Drawing;
using System.Text.Json;
using DeleteGuard.Core.Models;
using DeleteGuard.Core.Services;

namespace DeleteGuard.Agent;

/// <summary>
/// Management window: protected-folder list, settings and activity history.
/// The window never elevates; every change to protection goes through the Broker's UAC prompt.
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
    private readonly Label _settingsStatus = new();

    private readonly ComboBox _logSource = new();
    private readonly ListView _logList = new();

    private bool _busy;

    public ManagementForm(
        AgentSettingsStore settingsStore,
        BrokerClient broker,
        Action<AgentSettings> settingsApplied)
    {
        _settingsStore = settingsStore;
        _broker = broker;
        _settingsApplied = settingsApplied;

        var policyStore = new PolicyStore();
        _list = new ProtectionListService(policyStore);
        _validator = new ProtectionRequestValidator(policyStore.Load);

        Text = "DeleteGuard 管理";
        Icon = SystemIcons.Shield;
        AutoScaleMode = AutoScaleMode.Dpi;
        Font = new Font("Microsoft JhengHei UI", 9f);
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(760, 520);
        ClientSize = new Size(900, 660);

        BuildLayout();
        LoadSettingsIntoControls(_settingsStore.Load());
        Activated += (_, _) => RefreshAll();
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
        var page = new TabPage("保護清單") { Padding = new Padding(12) };

        var intro = new Label
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            MaximumSize = new Size(840, 0),
            Padding = new Padding(0, 0, 0, 8),
            Text = "列在這裡的資料夾無法被一般程式刪除。新增或移除保護都需要 Windows 系統管理員核准（UAC）。"
        };

        _protectedList.Dock = DockStyle.Fill;
        _protectedList.View = View.Details;
        _protectedList.FullRowSelect = true;
        _protectedList.MultiSelect = false;
        _protectedList.HideSelection = false;
        _protectedList.GridLines = false;
        _protectedList.Columns.Add("資料夾", 400);
        _protectedList.Columns.Add("狀態", 170);
        _protectedList.Columns.Add("建立時間", 160);
        _protectedList.SelectedIndexChanged += (_, _) => UpdateButtons();
        _protectedList.DoubleClick += (_, _) => RemoveSelected();

        _emptyHint.Dock = DockStyle.Top;
        _emptyHint.Height = 56;
        _emptyHint.ForeColor = SystemColors.GrayText;
        _emptyHint.TextAlign = ContentAlignment.MiddleCenter;
        _emptyHint.Text = "尚未保護任何資料夾。按「新增資料夾…」開始。";
        _emptyHint.Visible = false;

        var buttons = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            Height = 58,
            FlowDirection = FlowDirection.LeftToRight,
            Padding = new Padding(0, 10, 0, 0)
        };

        ConfigureButton(_addButton, "新增資料夾…", (_, _) => AddFolder());
        ConfigureButton(_removeButton, "移除保護", (_, _) => RemoveSelected());
        ConfigureButton(_refreshButton, "重新整理", (_, _) => RefreshAll());
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
        var page = new TabPage("設定") { Padding = new Padding(12), AutoScroll = true };

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
            Text = "這些設定只影響通知與提示的呈現。保護本身（拒絕刪除、重新命名、硬連結）不受影響；核准刪除一律需要 UAC。"
        };

        _showPrompts.Text = "攔截到刪除時，顯示核准／拒絕對話方塊";
        _showPrompts.AutoSize = true;
        _showPrompts.CheckedChanged += (_, _) => UpdateSettingsEnabled();

        ConfigureNumeric(_maxPrompts, AgentSettings.MinPromptsPerWindow, AgentSettings.MaxPromptsPerWindowLimit);
        ConfigureNumeric(_promptWindow, AgentSettings.MinPromptWindowSeconds, AgentSettings.MaxPromptWindowSeconds);
        ConfigureNumeric(_promptMaxAge, AgentSettings.MinPromptMaxAgeSeconds, AgentSettings.MaxPromptMaxAgeSeconds);
        ConfigureNumeric(_noticeCooldown, AgentSettings.MinNoticeCooldownSeconds, AgentSettings.MaxNoticeCooldownSeconds);

        var promptGroup = Group("核准提示", new Control[]
        {
            _showPrompts,
            Row("每個時間窗內最多提示次數", _maxPrompts, "次"),
            Row("時間窗長度", _promptWindow, "秒"),
            Row("超過此時間的事件不再提示", _promptMaxAge, "秒")
        });

        _namespaceNotices.Text = "重新命名／移動／硬連結被阻擋時顯示通知";
        _namespaceNotices.AutoSize = true;
        _throttleNotices.Text = "提示被限流時顯示通知";
        _throttleNotices.AutoSize = true;

        var noticeGroup = Group("通知", new Control[]
        {
            _namespaceNotices,
            _throttleNotices,
            Row("同類通知最短間隔", _noticeCooldown, "秒")
        });

        _autoStart.Text = "登入 Windows 時自動在背景啟動 Agent（系統匣）";
        _autoStart.AutoSize = true;
        var startupGroup = Group("啟動", new Control[] { _autoStart });

        var save = new Button { Text = "儲存設定", AutoSize = true, Padding = new Padding(10, 3, 10, 3) };
        save.Click += (_, _) => SaveSettings();
        var reset = new Button { Text = "還原預設值", AutoSize = true, Padding = new Padding(10, 3, 10, 3) };
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

        panel.Controls.AddRange(new Control[] { note, promptGroup, noticeGroup, startupGroup });
        page.Controls.Add(panel);
        page.Controls.Add(actions);
        return page;
    }

    private TabPage BuildActivityTab()
    {
        var page = new TabPage("活動紀錄") { Padding = new Padding(12) };

        _logSource.DropDownStyle = ComboBoxStyle.DropDownList;
        _logSource.Items.AddRange(new object[] { "管理操作（稽核紀錄）", "被攔截的事件" });
        _logSource.SelectedIndex = 0;
        _logSource.Width = 280;
        _logSource.SelectedIndexChanged += (_, _) => RefreshLog();

        var refresh = new Button { Text = "重新整理", AutoSize = true };
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
        row.Controls.Add(new Label { Text = label, AutoSize = false, Width = 340, Height = 26, TextAlign = ContentAlignment.MiddleLeft });
        row.Controls.Add(input);
        row.Controls.Add(new Label { Text = unit, AutoSize = true, Margin = new Padding(4, 6, 0, 0) });
        return row;
    }

    // ------------------------------------------------------------- protection

    private void RefreshAll()
    {
        _brokerStatus.Text = _broker.Exists
            ? "Broker：已找到　|　保護層：NTFS ACL"
            : $"找不到 DeleteGuard.Broker.exe（{_broker.BrokerPath}）　—　無法新增或移除保護";
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
                _emptyHint.Text = $"無法讀取保護清單：{exception.Message}";
                _emptyHint.Visible = true;
                return;
            }

            _emptyHint.Text = "尚未保護任何資料夾。按「新增資料夾…」開始。";
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
            return "已停用";
        }

        return entry.Acl switch
        {
            AclState.Present => "保護中",
            AclState.Missing => "ACL 遺失（保護可能失效）",
            AclState.FolderMissing => "資料夾不存在",
            _ => "狀態未知"
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
            Description = "選擇要保護的資料夾",
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
            MessageBox.Show(this, DescribeRejection(check), "無法保護此資料夾", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var warning = check.IsVolumeRoot
            ? $"您選擇的是整個磁碟區：\n{check.Path}\n\n保護整個磁碟區會影響該磁碟上所有程式的刪除、重新命名與覆寫儲存，請確定這是您要的。\n\n"
            : $"將保護：\n{check.Path}\n\n";
        var confirm = MessageBox.Show(
            this,
            warning +
            "• 此資料夾內的檔案無法被一般程式刪除（會顯示「存取被拒」）\n" +
            "• 也可能阻擋資料夾內的重新命名、移動，以及部分程式的覆寫儲存\n" +
            "• 需要系統管理員核准（UAC）\n\n繼續？",
            "確認新增保護",
            MessageBoxButtons.YesNo,
            check.IsVolumeRoot ? MessageBoxIcon.Warning : MessageBoxIcon.Question,
            MessageBoxDefaultButton.Button2);
        if (confirm != DialogResult.Yes)
        {
            return;
        }

        await RunBrokerAsync(() => _broker.ProtectAsync(check.Path, check.IsVolumeRoot), $"已保護：{check.Path}", "新增保護");
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
            $"將解除保護：\n{entry.RootPath}\n\n解除後，此資料夾內的檔案可以被一般方式刪除。需要系統管理員核准（UAC）。\n\n繼續？",
            "確認移除保護",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning,
            MessageBoxDefaultButton.Button2);
        if (confirm != DialogResult.Yes)
        {
            return;
        }

        await RunBrokerAsync(() => _broker.UnprotectAsync(entry.RootPath), $"已解除保護：{entry.RootPath}", "移除保護");
    }

    private async Task RunBrokerAsync(Func<Task<BrokerResult>> action, string successText, string title)
    {
        _busy = true;
        UpdateButtons();
        _busyLabel.Text = "等待 UAC 核准並執行中…";

        try
        {
            var result = await action();
            if (result.Succeeded)
            {
                _busyLabel.Text = successText;
            }
            else if (result.Failure == BrokerFailure.Cancelled)
            {
                _busyLabel.Text = "已取消（未通過 UAC 核准），沒有任何變更。";
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

    private static string DescribeRejection(ProtectionCheck check) => check.Rejection switch
    {
        ProtectionRejection.Empty => "請選擇一個資料夾。",
        ProtectionRejection.InvalidPath => "路徑格式不正確。",
        ProtectionRejection.NetworkPath => "不支援網路路徑（UNC）。請選擇本機 NTFS 磁碟上的資料夾。",
        ProtectionRejection.NotFound => $"資料夾不存在：\n{check.Path}",
        ProtectionRejection.NotADirectory => "只能保護資料夾，不能保護單一檔案。",
        ProtectionRejection.ReparsePoint => "此資料夾是連結點／符號連結（reparse point），目前不支援。請選擇連結指向的實際資料夾。",
        ProtectionRejection.NotNtfs => $"只支援 NTFS 磁碟。\n\n{check.Detail}",
        ProtectionRejection.SystemVolumeRoot => "不允許保護 Windows 系統磁碟的根目錄。請改選其中的特定資料夾。",
        ProtectionRejection.AlreadyProtected => $"此資料夾已受保護：\n{check.Path}",
        ProtectionRejection.Overlaps => $"與既有的保護範圍重疊：\n{check.Detail}\n\n目前不支援巢狀的保護範圍。請先移除既有保護，或改選其他資料夾。",
        _ => "無法保護此資料夾。"
    };

    private static string DescribeFailure(BrokerResult result)
    {
        var text = result.Failure switch
        {
            BrokerFailure.BrokerMissing => "找不到 DeleteGuard.Broker.exe。",
            BrokerFailure.StartFailed => "無法啟動 DeleteGuard Broker。",
            BrokerFailure.NotElevated => "Broker 沒有取得系統管理員權限。",
            BrokerFailure.Busy => "另一個 DeleteGuard 管理操作正在進行，請稍後再試。",
            _ => $"操作失敗（代碼 {result.ExitCode}）。"
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
        if (!keepAutoStart)
        {
            _autoStart.Checked = AutoStart.IsEnabled();
        }

        UpdateSettingsEnabled();
        _settingsStatus.Text = string.Empty;
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
            var saved = _settingsStore.Save(new AgentSettings
            {
                ShowApprovalPrompts = _showPrompts.Checked,
                MaxPromptsPerWindow = (int)_maxPrompts.Value,
                PromptWindowSeconds = (int)_promptWindow.Value,
                PromptMaxAgeSeconds = (int)_promptMaxAge.Value,
                ShowNamespaceNotices = _namespaceNotices.Checked,
                ShowThrottleNotices = _throttleNotices.Checked,
                NoticeCooldownSeconds = (int)_noticeCooldown.Value
            });

            if (_autoStart.Checked != AutoStart.IsEnabled())
            {
                AutoStart.Set(_autoStart.Checked);
            }

            _settingsApplied(saved);
            _settingsStatus.ForeColor = SystemColors.ControlText;
            _settingsStatus.Text = $"已儲存並立即生效（{DateTime.Now:HH:mm:ss}）";
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            _settingsStatus.ForeColor = Color.Firebrick;
            _settingsStatus.Text = "儲存失敗";
            MessageBox.Show(this, $"無法儲存設定：\n{exception.Message}", "DeleteGuard", MessageBoxButtons.OK, MessageBoxIcon.Error);
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
                _logList.Columns.Add("時間", 140);
                _logList.Columns.Add("動作", 80);
                _logList.Columns.Add("結果", 80);
                _logList.Columns.Add("路徑", 300);
                _logList.Columns.Add("說明", 200);
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
                _logList.Columns.Add("時間", 140);
                _logList.Columns.Add("程序", 150);
                _logList.Columns.Add("操作", 190);
                _logList.Columns.Add("路徑", 320);
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
