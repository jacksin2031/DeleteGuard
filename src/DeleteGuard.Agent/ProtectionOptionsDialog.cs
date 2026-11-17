using System.Drawing;
using DeleteGuard.Core.Localization;
using DeleteGuard.Core.Models;

namespace DeleteGuard.Agent;

/// <summary>Asks how a newly added folder should be protected: fully, or with the bulk-delete guard.</summary>
internal sealed class ProtectionOptionsDialog : Form
{
    private const int ContentWidth = 660;

    private readonly RadioButton _full = new();
    private readonly RadioButton _bulk = new();
    private readonly NumericUpDown _threshold = new();
    private readonly NumericUpDown _window = new();
    private readonly Panel _bulkSettings = new();

    public ProtectionOptionsDialog(string folderPath, Font font)
    {
        Text = Loc.T("add.mode.title");
        Font = font;
        AutoScaleMode = AutoScaleMode.Dpi;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;
        StartPosition = FormStartPosition.CenterParent;

        var flow = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Padding = new Padding(16, 14, 16, 8)
        };

        flow.Controls.Add(Wrapped(folderPath, bold: true));

        ConfigureRadio(_full, Loc.T("add.mode.full.title"));
        _full.Checked = true;
        flow.Controls.Add(_full);
        flow.Controls.Add(Wrapped(Loc.T("add.mode.full.desc"), indent: 26));

        ConfigureRadio(_bulk, Loc.T("add.mode.bulk.title"));
        flow.Controls.Add(_bulk);
        flow.Controls.Add(Wrapped(Loc.T("add.mode.bulk.desc"), indent: 26));

        _threshold.Minimum = ProtectionPolicy.MinBulkThreshold;
        _threshold.Maximum = ProtectionPolicy.MaxBulkThreshold;
        _threshold.Value = ProtectionPolicy.DefaultBulkThreshold;
        _threshold.Width = 80;
        _window.Minimum = ProtectionPolicy.MinBulkWindowSeconds;
        _window.Maximum = ProtectionPolicy.MaxBulkWindowSeconds;
        _window.Value = ProtectionPolicy.DefaultBulkWindowSeconds;
        _window.Width = 70;

        var settingsRow = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.LeftToRight, Margin = new Padding(26, 0, 0, 8) };
        settingsRow.Controls.Add(InlineLabel(Loc.T("add.mode.threshold")));
        settingsRow.Controls.Add(_threshold);
        settingsRow.Controls.Add(InlineLabel(Loc.T("add.mode.window")));
        settingsRow.Controls.Add(_window);
        settingsRow.Controls.Add(InlineLabel(Loc.T("unit.seconds")));
        _bulkSettings.AutoSize = true;
        _bulkSettings.Controls.Add(settingsRow);
        flow.Controls.Add(_bulkSettings);

        _bulk.CheckedChanged += (_, _) => UpdateEnabled();
        UpdateEnabled();

        var ok = new Button { Text = Loc.T("btn.ok"), DialogResult = DialogResult.OK, AutoSize = true, Padding = new Padding(14, 3, 14, 3) };
        var cancel = new Button { Text = Loc.T("btn.cancel"), DialogResult = DialogResult.Cancel, AutoSize = true, Padding = new Padding(14, 3, 14, 3) };
        var buttons = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            FlowDirection = FlowDirection.RightToLeft,
            Height = 62,
            Padding = new Padding(16, 8, 16, 8)
        };
        buttons.Controls.Add(cancel);
        buttons.Controls.Add(ok);

        AcceptButton = ok;
        CancelButton = cancel;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        Controls.Add(flow);
        Controls.Add(buttons);
    }

    public ProtectionMode Mode => _bulk.Checked ? ProtectionMode.BulkGuard : ProtectionMode.Full;
    public int Threshold => (int)_threshold.Value;
    public int WindowSeconds => (int)_window.Value;

    private void UpdateEnabled() => _bulkSettings.Enabled = _bulk.Checked;

    private static void ConfigureRadio(RadioButton radio, string text)
    {
        radio.Text = text;
        radio.AutoSize = true;
        radio.Font = new Font(radio.Font, FontStyle.Bold);
        radio.Margin = new Padding(3, 10, 3, 2);
    }

    private static Label InlineLabel(string text) => new()
    {
        Text = text,
        AutoSize = true,
        Margin = new Padding(3, 6, 6, 0),
        UseCompatibleTextRendering = true
    };

    private static Label Wrapped(string text, int indent = 0, bool bold = false)
    {
        var label = new Label
        {
            Text = text,
            AutoSize = true,
            MaximumSize = new Size(ContentWidth - indent, 0),
            Margin = new Padding(3 + indent, 0, 3, 6),
            UseCompatibleTextRendering = true
        };
        if (bold)
        {
            label.Font = new Font(label.Font, FontStyle.Bold);
        }

        return label;
    }
}
