using System.Drawing;
using System.Security.Cryptography;
using Dharmu.Security.Core.Licensing;
using Dharmu.Security.Windows.Machine;
using Dharmu.Security.Windows.Secrets;

namespace Dharmu.Security.DeviceTool;

internal sealed class DeviceSetupForm : Form
{
    private readonly TextBox _product = new() { Dock = DockStyle.Top, PlaceholderText = "Product code (e.g. SR_CONSTRUCTION)" };
    private readonly CheckBox _tpm = new() { AutoSize = true, Text = "Use TPM (must match application configuration)" };
    private readonly TextBox _machine = new() { Dock = DockStyle.Top, ReadOnly = true };
    private readonly TextBox _secret = new() { Dock = DockStyle.Top, UseSystemPasswordChar = true, PlaceholderText = "Database connection string or secret" };
    private readonly TextBox _protected = new() { Dock = DockStyle.Top, ReadOnly = true, Multiline = true, Height = 72, ScrollBars = ScrollBars.Vertical };
    private readonly Label _status = new() { AutoSize = true, MaximumSize = new Size(500, 0), Text = "No device or license checks performed yet." };

    public DeviceSetupForm()
    {
        Text = "Dharmu Security — Device Setup";
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(560, 590);
        MinimumSize = new Size(540, 600);
        AutoScaleMode = AutoScaleMode.Dpi;
        BackColor = Color.White;
        ForeColor = Color.Black;
        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, Padding = new Padding(18), ColumnCount = 1,
            AutoScroll = true, AutoSize = false
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        Controls.Add(layout);
        Add(new Label { Text = "Device & License Setup", AutoSize = true, Font = new Font(Font, FontStyle.Bold) });
        Add(new Label { Text = $"Computer: {Environment.MachineName}", AutoSize = true });
        Add(_product);
        Add(_tpm);
        Add(Button("Prepare device keys", () =>
        {
            _machine.Text = Program.Provision(_tpm.Checked);
            _status.Text = "Device identity and secret protection keys provisioned.";
        }));
        Add(_machine);
        Add(Button("Generate signed activation request", GenerateRequest));
        Add(Button("Import signed license", ImportLicense));
        Add(Button("Verify installed license file", VerifyLicense));
        Add(new Label { Text = "Protect a local database secret", AutoSize = true });
        Add(_secret);
        Add(Button("Protect secret", () =>
        {
            _protected.Clear();
            try
            {
                _protected.Text = new DpapiSecretProtector().Protect(_secret.Text);
                _status.Text = "Protected value ready. Save it only in the application's protected configuration.";
            }
            finally { _secret.Clear(); }
        }));
        Add(_protected);
        Add(_status);
        _tpm.CheckedChanged += (_, _) =>
        {
            _machine.Clear();
            _status.Text = "Device provider changed. Verify it matches the deployed application.";
        };
        _product.TextChanged += (_, _) => _status.Text = "Product changed. Verify the product code before generating or importing.";

        void Add(Control control)
        {
            control.Margin = new Padding(0, 4, 0, 4);
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.Controls.Add(control, 0, layout.RowCount++);
        }
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

    private string? SelectLicenseFolder(string product)
    {
        using var dialog = new FolderBrowserDialog
        {
            Description = "Select the configured license directory (outside wwwroot)",
            UseDescriptionForTitle = true,
            SelectedPath = product == "SR_CONSTRUCTION"
                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SRConstruction", "License")
                : string.Empty
        };
        return dialog.ShowDialog(this) == DialogResult.OK ? dialog.SelectedPath : null;
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
        var pemPath = SelectFile("Select independently verified owner PUBLIC key (same as application pin)", "Public key (*.pem)|*.pem");
        if (pemPath is null) return;
        var content = ReadBounded(source);
        var pem = ReadBounded(pemPath);
        var result = Validate(content, product, pem);
        if (!result.IsValid && result.Status != LicenseValidationStatus.Revoked)
            throw new InvalidDataException($"License rejected: {result.Status}.");
        var folder = SelectLicenseFolder(product);
        if (folder is null) return;
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
        var folder = SelectLicenseFolder(product);
        if (folder is null) return;
        var pemPath = SelectFile("Select independently verified owner PUBLIC key (same as application pin)", "Public key (*.pem)|*.pem");
        if (pemPath is null) return;
        var result = Validate(ReadBounded(Path.Combine(folder, "license.lic")), product, ReadBounded(pemPath));
        _status.Text = $"File check: {result.Status}. Application runtime and IIS permissions must be verified separately.";
    }
}
