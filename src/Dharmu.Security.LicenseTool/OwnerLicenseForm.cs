using System.Drawing;

namespace Dharmu.Security.LicenseTool;

internal sealed class OwnerLicenseForm : Form
{
    private readonly TextBox _ledger = new() { Dock = DockStyle.Fill, ReadOnly = true };
    private readonly TextBox _request = new() { Dock = DockStyle.Fill, ReadOnly = true };
    private readonly TextBox _trust = new() { Dock = DockStyle.Fill, ReadOnly = true };
    private readonly TextBox _slot = new() { Dock = DockStyle.Fill, PlaceholderText = "Leave empty for existing issuer-v1" };
    private readonly CheckBox _tpm = new() { Text = "Issuer uses TPM (match the existing key)", AutoSize = true };
    private readonly TextBox _product = new() { Dock = DockStyle.Fill, PlaceholderText = "Exact product code" };
    private readonly TextBox _customer = new() { Dock = DockStyle.Fill };
    private readonly TextBox _productId = new() { Dock = DockStyle.Fill };
    private readonly TextBox _days = new() { Dock = DockStyle.Fill, Text = "365" };
    private readonly CheckBox _lifetime = new() { Text = "Lifetime", AutoSize = true };
    private readonly TextBox _license = new() { Dock = DockStyle.Fill };
    private readonly ComboBox _operation = new() { DropDownStyle = ComboBoxStyle.DropDownList, Dock = DockStyle.Fill };
    private readonly TextBox _result = new() { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Height = 150 };
    private readonly Button _export = new() { Text = "Export signed license copy", AutoSize = true, Enabled = false };
    private string? _lastSignedFile;
    private string? _lastLedger;
    private readonly Dictionary<string, Control> _fields = new();

    public OwnerLicenseForm()
    {
        Text = "Dharmu Security — Owner License Manager";
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(760, 660);
        MinimumSize = new Size(620, 560);
        AutoScaleMode = AutoScaleMode.Dpi;
        BackColor = Color.White;
        ForeColor = Color.Black;
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(16), ColumnCount = 1, AutoScroll = true };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        Controls.Add(layout);

        Add(new Label { Text = "Owner-only — use the existing signing key and authoritative ledger", AutoSize = true, Font = new Font(Font, FontStyle.Bold) });
        Field("Issuer key slot", _slot);
        Add(_tpm);
        Field("Authoritative ledger directory", Picker(_ledger, () => ChooseFolder(_ledger)));
        Field("Trusted old public keys (optional, for rotation)", Picker(_trust, () => ChooseFolder(_trust)));
        _operation.Items.AddRange(new object[] { "Issue", "Renew", "Revoke", "List", "History", "Initialize / export public key", "Rotate", "Replace retired device" });
        Field("Operation", _operation);
        Field("Signed activation request", Picker(_request, ChooseRequest));
        Field("Product code", _product);
        Field("Customer ID", _customer);
        Field("Product ID", _productId);
        Field("Validity days", _days);
        Field("Lifetime entitlement", _lifetime);
        Field("License ID", _license);
        var run = new Button { Text = "Execute selected operation", Dock = DockStyle.Top, AutoSize = true, Height = 34 };
        run.Click += (_, _) => Execute();
        Add(run);
        _export.Click += (_, _) => Export();
        Add(_export);
        Add(_result);
        _operation.SelectedIndexChanged += (_, _) => UpdateFields();
        _lifetime.CheckedChanged += (_, _) => UpdateFields();
        _operation.SelectedIndex = 0;

        void Add(Control control)
        {
            control.Margin = new Padding(0, 3, 0, 3);
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.Controls.Add(control, 0, layout.RowCount++);
        }

        void Field(string name, Control control)
        {
            var row = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 2, Margin = new Padding(0) };
            row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 40));
            row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 60));
            row.Controls.Add(new Label { Text = name, AutoSize = true, Anchor = AnchorStyles.Left }, 0, 0);
            row.Controls.Add(control, 1, 0);
            _fields.Add(name, row);
            Add(row);
        }
    }

    private static Control Picker(TextBox input, Action select)
    {
        var panel = new TableLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, ColumnCount = 2 };
        panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        panel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var browse = new Button { Text = "Browse", AutoSize = true };
        browse.Click += (_, _) => select();
        panel.Controls.Add(input, 0, 0);
        panel.Controls.Add(browse, 1, 0);
        return panel;
    }

    private void ChooseFolder(TextBox input)
    {
        using var dialog = new FolderBrowserDialog { SelectedPath = input.Text };
        if (dialog.ShowDialog(this) == DialogResult.OK) input.Text = dialog.SelectedPath;
    }

    private void ChooseRequest()
    {
        using var dialog = new OpenFileDialog { Filter = "Signed activation request (*.json)|*.json" };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        try
        {
            using var stream = File.OpenRead(dialog.FileName);
            if (stream.Length is <= 0 or > 65536)
                throw new InvalidDataException("Activation request size is invalid.");
            using var reader = new StreamReader(stream);
            var request = new ActivationRequestParser().Parse(reader.ReadToEnd(), DateTime.UtcNow);
            _request.Text = dialog.FileName;
            if (_operation.SelectedIndex == 0)
                _product.Text = request.ProductCode;
            _result.Text = $"Verified device request: {request.ProductCode}{Environment.NewLine}Machine: {request.MachineCode}";
        }
        catch (Exception exception)
        {
            _request.Clear();
            _result.Text = $"Request rejected: {exception.Message}";
        }
    }

    private void UpdateFields()
    {
        var action = _operation.SelectedIndex;
        _fields["Authoritative ledger directory"].Visible = action != 5;
        _fields["Trusted old public keys (optional, for rotation)"].Visible = action != 5;
        _fields["Signed activation request"].Visible = action is 0 or 7;
        _fields["Product code"].Visible = action == 0;
        _fields["Customer ID"].Visible = action is 0 or 3;
        _fields["Product ID"].Visible = action == 0;
        _fields["Validity days"].Visible = action == 1 || (action == 0 && !_lifetime.Checked);
        _fields["Lifetime entitlement"].Visible = action == 0;
        _fields["License ID"].Visible = action is 1 or 2 or 4 or 6 or 7;
    }

    private bool Confirm(string message) => MessageBox.Show(this, message, Text,
        MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes;

    private void Execute()
    {
        _export.Enabled = false;
        _lastSignedFile = null;
        _lastLedger = null;
        _result.Clear();
        try
        {
            var args = new List<string>();
            if (!string.IsNullOrWhiteSpace(_slot.Text)) args.AddRange(["--key-slot", _slot.Text.Trim()]);
            if (!string.IsNullOrWhiteSpace(_trust.Text) && _operation.SelectedIndex != 5)
                args.AddRange(["--trust-dir", _trust.Text]);

            var ledger = _ledger.Text;
            var id = _license.Text.Trim();
            if (_operation.SelectedIndex == 5)
            {
                if (!Confirm("Only initialize a genuinely new issuer or export the existing public key. Never recreate a lost issuer key under the old identity. Continue?")) return;
                using var dialog = new SaveFileDialog { Filter = "Public PEM (*.pem)|*.pem", FileName = "issuer-public.pem" };
                if (dialog.ShowDialog(this) != DialogResult.OK) return;
                args.AddRange(["init", dialog.FileName]);
            }
            else
            {
                if (!Directory.Exists(ledger)) throw new InvalidOperationException("Select the authoritative ledger directory.");
                switch (_operation.SelectedIndex)
                {
                    case 0:
                        if (!Confirm($"Issue a license for customer {_customer.Text}, product {_product.Text}, using the selected ledger?")) return;
                        args.AddRange(["issue", ledger, _request.Text, _product.Text.Trim(), _customer.Text.Trim(), _productId.Text.Trim(), _lifetime.Checked ? "lifetime" : _days.Text.Trim()]);
                        break;
                    case 1:
                        if (!Confirm($"Renew license {id} for {_days.Text} days?")) return;
                        args.AddRange(["renew", ledger, id, _days.Text.Trim()]);
                        break;
                    case 2:
                        if (!Confirm($"Revoke license {id}? The signed revocation must still reach the offline client.")) return;
                        args.AddRange(["revoke", ledger, id]);
                        break;
                    case 3:
                        args.AddRange(["list", ledger]);
                        if (!string.IsNullOrWhiteSpace(_customer.Text)) args.Add(_customer.Text.Trim());
                        break;
                    case 4:
                        args.AddRange(["history", ledger, id]);
                        break;
                    case 6:
                        if (!Confirm($"Rotate license {id} to the selected issuer? Ensure client trust has already been updated.")) return;
                        args.AddRange(["rotate", ledger, id]);
                        break;
                    case 7:
                        if (!Confirm("Confirm the original device is retired or physically failed and revocation has been delivered when possible. Authorize replacement?")) return;
                        args.AddRange(["replace", ledger, id, _request.Text, "confirm-retired"]);
                        break;
                    default:
                        throw new InvalidOperationException("Select an operation.");
                }
            }
            if (_tpm.Checked) args.Add("--tpm");

            using var output = new StringWriter();
            using var error = new StringWriter();
            var exit = Program.Run(args.ToArray(), output, error, out var signedFile);
            _result.Text = (exit == 0 ? "Completed." : "Operation failed.") + Environment.NewLine + output + error;
            if (exit == 0 && signedFile is not null)
            {
                _lastSignedFile = Path.GetFullPath(signedFile);
                _lastLedger = Path.GetFullPath(ledger);
                _export.Enabled = true;
            }
        }
        catch (Exception exception)
        {
            _result.Text = $"Operation failed: {exception.Message}";
        }
    }

    private void Export()
    {
        if (_lastSignedFile is null || _lastLedger is null) return;
        try
        {
            using var dialog = new SaveFileDialog { Filter = "Signed license (*.lic)|*.lic", FileName = Path.GetFileName(_lastSignedFile) };
            if (dialog.ShowDialog(this) != DialogResult.OK) return;
            var destination = Path.GetFullPath(dialog.FileName);
            var relative = Path.GetRelativePath(_lastLedger, destination);
            if (!Path.IsPathRooted(relative) && relative != ".." && !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal))
                throw new InvalidOperationException("Export outside the authoritative ledger; never overwrite its records.");
            File.Copy(_lastSignedFile, destination, overwrite: true);
            _result.AppendText(Environment.NewLine + $"Signed copy exported: {destination}");
        }
        catch (Exception exception)
        {
            MessageBox.Show(this, exception.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}
