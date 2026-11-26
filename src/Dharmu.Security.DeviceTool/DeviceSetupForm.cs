using System.Drawing;
using System.Security.Cryptography;
using Dharmu.Security.Core.Licensing;
using Dharmu.Security.Windows.Machine;
using Dharmu.Security.Windows.Secrets;

namespace Dharmu.Security.DeviceTool;

internal sealed class DeviceSetupForm : Form
{
    private readonly ComboBox _profile = new() { Dock = DockStyle.Top, DropDownStyle = ComboBoxStyle.DropDownList };
    private readonly TextBox _product = new() { Dock = DockStyle.Top, PlaceholderText = "Exact product code" };
    private readonly TextBox _folder = new() { Dock = DockStyle.Top, ReadOnly = true };
    private readonly TextBox _publicKey = new() { Dock = DockStyle.Top, ReadOnly = true, PlaceholderText = "Verified owner public PEM" };
    private readonly TabControl _steps = new() { Dock = DockStyle.Fill };
    private readonly Button _back = new() { Text = "Back", AutoSize = true };
    private readonly Button _next = new() { Text = "Next", AutoSize = true };
    private readonly CheckBox _tpm = new() { AutoSize = true, Text = "Use TPM (must match application configuration)" };
    private readonly TextBox _machine = new() { Dock = DockStyle.Top, ReadOnly = true };
    private readonly TextBox _secret = new() { Dock = DockStyle.Top, UseSystemPasswordChar = true, PlaceholderText = "Database connection string or secret" };
    private readonly TextBox _protected = new() { Dock = DockStyle.Top, ReadOnly = true, Multiline = true, Height = 72, ScrollBars = ScrollBars.Vertical };
    private readonly Label _status = new() { AutoSize = true, MaximumSize = new Size(500, 0), Text = "No device or license checks performed yet." };

    public DeviceSetupForm()
    {
        Text = "Dharmu Security — License Setup Wizard";
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(640, 460);
        MinimumSize = new Size(580, 440);
        AutoScaleMode = AutoScaleMode.Dpi;
        BackColor = Color.White;
        ForeColor = Color.Black;

        var footer = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 44, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(8, 2, 8, 2) };
        footer.Controls.Add(_next);
        footer.Controls.Add(_back);
        var statusPanel = new Panel { Dock = DockStyle.Bottom, Height = 62, Padding = new Padding(12) };
        statusPanel.Controls.Add(_status);
        _status.Dock = DockStyle.Fill;
        Controls.Add(_steps);
        Controls.Add(statusPanel);
        Controls.Add(footer);

        var setup = Page("1. Setup");
        Add(setup, new Label { Text = $"Computer: {Environment.MachineName}", AutoSize = true });
        Add(setup, new Label { Text = "Choose the deployed product", AutoSize = true });
        _profile.Items.AddRange(new object[] { "SR Construction", "Other product" });
        Add(setup, _profile);
        Add(setup, _product);
        Add(setup, _tpm);
        Add(setup, new Label { Text = "License directory (outside web root)", AutoSize = true });
        Add(setup, _folder);
        var browseFolder = Button("Choose custom directory", () =>
        {
            using var dialog = new FolderBrowserDialog { SelectedPath = _folder.Text };
            if (dialog.ShowDialog(this) == DialogResult.OK) _folder.Text = dialog.SelectedPath;
        });
        Add(setup, browseFolder);
        Add(setup, new Label { Text = "TPM must match the deployed application. Existing keys are retained.", AutoSize = true, MaximumSize = new Size(530, 0) });

        var request = Page("2. Device request");
        Add(request, new Label { Text = "For first activation, generate a signed request and send it to the owner. For renewal or an existing request, go directly to License.", AutoSize = true, MaximumSize = new Size(530, 0) });
        Add(request, Button("Generate signed activation request", GenerateRequest));
        Add(request, new Label { Text = "Machine code", AutoSize = true });
        Add(request, _machine);

        var license = Page("3. License");
        Add(license, new Label { Text = "Choose the independently verified owner public key matching the deployed application's compiled key. The selection is reused for this session.", AutoSize = true, MaximumSize = new Size(530, 0) });
        Add(license, _publicKey);
        Add(license, Button("Choose verified public key", () =>
        {
            var path = SelectFile("Select verified owner PUBLIC key", "Public key (*.pem)|*.pem");
            if (path is not null) _publicKey.Text = path;
        }));
        Add(license, Button("Import signed license", ImportLicense));
        Add(license, Button("Verify installed license file", VerifyLicense));
        Add(license, new Label { Text = "File verification is not application activation. Restart the application and verify protected access and IIS permissions.", AutoSize = true, MaximumSize = new Size(530, 0) });

        var secret = Page("4. Optional secret");
        Add(secret, new Label { Text = "Protect a local database secret (optional). Plaintext is never written to a file.", AutoSize = true, MaximumSize = new Size(530, 0) });
        Add(secret, _secret);
        Add(secret, Button("Protect secret", () =>
        {
            _protected.Clear();
            try
            {
                _protected.Text = new DpapiSecretProtector().Protect(_secret.Text);
                _status.Text = "Protected value ready. Save it only in the application's protected configuration.";
            }
            finally { _secret.Clear(); }
        }));
        Add(secret, _protected);

        _profile.SelectedIndexChanged += (_, _) =>
        {
            var sr = _profile.SelectedIndex == 0;
            _product.ReadOnly = sr;
            browseFolder.Visible = !sr;
            _product.Text = sr ? "SR_CONSTRUCTION" : string.Empty;
            _folder.Text = sr ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SRConstruction", "License") : string.Empty;
            _machine.Clear();
            _publicKey.Clear();
            _status.Text = "Confirm the deployed product and device provider.";
        };
        _profile.SelectedIndex = 0;
        _tpm.CheckedChanged += (_, _) =>
        {
            _machine.Clear();
            _status.Text = "Device provider changed. Verify it matches the deployed application.";
        };
        _steps.SelectedIndexChanged += (_, _) => UpdateNavigation();
        _back.Click += (_, _) => { if (_steps.SelectedIndex > 0) _steps.SelectedIndex--; };
        _next.Click += (_, _) =>
        {
            if (_steps.SelectedIndex == _steps.TabCount - 1) Close();
            else _steps.SelectedIndex++;
        };
        UpdateNavigation();
    }

    private TableLayoutPanel Page(string title)
    {
        var tab = new TabPage(title) { BackColor = Color.White };
        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, Padding = new Padding(16), ColumnCount = 1, AutoScroll = true
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        tab.Controls.Add(layout);
        _steps.TabPages.Add(tab);
        return layout;
    }

    private static void Add(TableLayoutPanel layout, Control control)
    {
        control.Margin = new Padding(0, 4, 0, 4);
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.Controls.Add(control, 0, layout.RowCount++);
    }

    private void UpdateNavigation()
    {
        _back.Enabled = _steps.SelectedIndex > 0;
        _next.Text = _steps.SelectedIndex == _steps.TabCount - 1 ? "Finish" : "Next";
    }

    private Button Button(string text, Action action)
    {
        var button = new Button { Text = text, Dock = DockStyle.Top, Height = 34, AutoSize = true };
        button.Click += (_, _) =>
        {
            try { action(); }
            catch (Exception exception)
            {
                _status.Text = "Operation failed. No successful verification is recorded.";
                MessageBox.Show(this, exception.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        };
        return button;
    }

    private string ProductCode()
    {
        var product = _product.Text.Trim();
        ArgumentException.ThrowIfNullOrWhiteSpace(product);
        if (product.Length > 50) throw new InvalidDataException("Product code must be at most 50 characters.");
        return product;
    }

    private void GenerateRequest()
    {
        var product = ProductCode();
        using var dialog = new SaveFileDialog { Filter = "Activation request (*.json)|*.json", FileName = "activation-request.json" };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        _machine.Text = Program.Provision(_tpm.Checked);
        var generator = new ActivationRequestGenerator(new WindowsMachineIdentityProvider(_tpm.Checked));
        File.WriteAllText(dialog.FileName, generator.Generate(product, DateTime.UtcNow));
        _status.Text = "Signed request saved. Send this JSON to the owner only.";
    }

    private string LicenseFolder()
    {
        if (string.IsNullOrWhiteSpace(_folder.Text))
            throw new InvalidOperationException("Select the deployed application's license directory in Setup.");
        var folder = Path.GetFullPath(_folder.Text);
        if (folder.Split(Path.DirectorySeparatorChar).Any(part => string.Equals(part, "wwwroot", StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException("License directory must be outside wwwroot.");
        if (!Directory.Exists(folder))
            throw new DirectoryNotFoundException("The configured license directory must be created and secured by the administrator before import.");
        return folder;
    }

    private string PublicKey()
    {
        if (string.IsNullOrWhiteSpace(_publicKey.Text))
            throw new InvalidOperationException("Choose the verified owner public key on the License page.");
        return ReadBounded(_publicKey.Text);
    }

    private string? SelectFile(string title, string filter)
    {
        using var dialog = new OpenFileDialog { Title = title, Filter = filter, CheckFileExists = true };
        return dialog.ShowDialog(this) == DialogResult.OK ? dialog.FileName : null;
    }

    private static string ReadBounded(string path)
    {
        using var stream = File.OpenRead(path);
        if (stream.Length is <= 0 or > 65536) throw new InvalidDataException("File must be between 1 and 65536 bytes.");
        using var reader = new StreamReader(stream, new System.Text.UTF8Encoding(false, true));
        return reader.ReadToEnd();
    }

    private LicenseValidationResult Validate(string content, string product, string pem)
    {
        using var key = ECDsa.Create();
        if (!pem.Trim().StartsWith("-----BEGIN PUBLIC KEY-----", StringComparison.Ordinal) ||
            !pem.Trim().EndsWith("-----END PUBLIC KEY-----", StringComparison.Ordinal))
            throw new InvalidDataException("Select only the verified owner public PEM, never a private key.");
        key.ImportFromPem(pem);
        if (key.KeySize != 256) throw new InvalidDataException("Expected an ECDSA P-256 public key.");
        var fingerprint = Convert.ToHexString(SHA256.HashData(key.ExportSubjectPublicKeyInfo())).ToLowerInvariant();
        var trusted = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["issuer-v1"] = pem,
            ["issuer-" + fingerprint] = pem
        };
        var machine = new WindowsMachineIdentityProvider(_tpm.Checked).GetMachineCode();
        _machine.Text = machine;
        return new EcdsaLicenseValidator().Validate(content, trusted, product, machine, DateTime.UtcNow);
    }

    private void ImportLicense()
    {
        var product = ProductCode();
        var source = SelectFile("Select signed license from owner", "License (*.lic)|*.lic");
        if (source is null) return;
        var content = ReadBounded(source);
        var pem = PublicKey();
        var result = Validate(content, product, pem);
        if (!result.IsValid && result.Status != LicenseValidationStatus.Revoked)
            throw new InvalidDataException($"License rejected: {result.Status}.");
        var folder = LicenseFolder();
        var destination = Path.Combine(folder, "license.lic");
        var warning = result.Status == LicenseValidationStatus.Revoked
            ? "This is a signed revocation. Installing it can disable the application."
            : "The file matches the selected public key, product and device. The deployed application still enforces its own pinned key and runtime state.";
        if (MessageBox.Show(this, $"{warning}\n\nInstall at {destination}?", Text,
                MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
        if (File.Exists(destination))
        {
            var current = Validate(ReadBounded(destination), product, pem);
            if (current.License is { } old && result.License is { } next &&
                old.LicenseId == next.LicenseId &&
                (old.Revision > next.Revision || (old.IsRevoked && !next.IsRevoked)))
                throw new InvalidDataException("Cannot replace the installed license with an older or unrevoked revision.");
        }
        var temporary = Path.Combine(folder, $".license-{Guid.NewGuid():N}.tmp");
        try
        {
            File.WriteAllText(temporary, content);
            if (File.Exists(destination)) File.Replace(temporary, destination, null);
            else File.Move(temporary, destination);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
        _status.Text = $"Installed file: {result.Status}. Verify the actual application after restart. Runtime state was not changed.";
    }

    private void VerifyLicense()
    {
        var product = ProductCode();
        var folder = LicenseFolder();
        var result = Validate(ReadBounded(Path.Combine(folder, "license.lic")), product, PublicKey());
        _status.Text = $"File check: {result.Status}. Application runtime and IIS permissions must be verified separately.";
    }
}
