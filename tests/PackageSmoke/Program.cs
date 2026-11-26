// CI-only executable, copied to an isolated project with NuGet package references.
// Never deploy this test app or its temporary issuer keys to a customer.
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using Dharmu.Security.AspNetCore;
using Dharmu.Security.Core.Licensing;
using Dharmu.Security.Windows.Machine;
using Dharmu.Security.Windows.Secrets;

var root = Path.Combine(Path.GetTempPath(), "DharmuPackageSmoke-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
var ledger = Path.Combine(root, "ledger");
var publicKeyPath = Path.Combine(root, "issuer.pem");
var requestPath = Path.Combine(root, "activation.json");
var licensePath = Path.Combine(root, "license.lic");
var statePath = Path.Combine(root, "runtime.state");
var keySlot = "smoke-" + Guid.NewGuid().ToString("N");
var deviceTool = Environment.GetEnvironmentVariable("DHARMU_SMOKE_DEVICE_TOOL")
    ?? throw new InvalidOperationException("Device tool path is required.");
var copyInput = Environment.GetEnvironmentVariable("DHARMU_SMOKE_COPY_INPUT");
var copyOutput = Environment.GetEnvironmentVariable("DHARMU_SMOKE_COPY_OUTPUT");
var issuerTool = Environment.GetEnvironmentVariable("DHARMU_SMOKE_LICENSE_TOOL");

try
{
    await RunToolAsync(deviceTool, "--provision");
    if (copyInput is null)
    {
        await RunToolAsync(issuerTool ?? throw new InvalidOperationException("Issuer tool path is required."),
            "--key-slot", keySlot, "init", publicKeyPath);
    }
    else
    {
        File.Copy(Path.Combine(copyInput, "issuer.pem"), publicKeyPath);
    }
    var pem = await File.ReadAllTextAsync(publicKeyPath);
    using var publicKey = ECDsa.Create();
    publicKey.ImportFromPem(pem);
    var keyId = "issuer-" + Convert.ToHexString(
        SHA256.HashData(publicKey.ExportSubjectPublicKeyInfo())).ToLowerInvariant();

    var machineCode = new WindowsMachineIdentityProvider().GetMachineCode();
    if (copyInput is not null)
    {
        var sourceMachine = await File.ReadAllTextAsync(Path.Combine(copyInput, "machine.txt"));
        if (string.Equals(sourceMachine, machineCode, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Cross-machine fixture must originate from a different device identity.");
        }

        File.Copy(Path.Combine(copyInput, "license.lic"), licensePath);
        var result = new EcdsaLicenseValidator().Validate(await File.ReadAllTextAsync(licensePath),
            new Dictionary<string, string> { [keyId] = pem }, "SMOKE", machineCode, DateTime.UtcNow);
        if (result.Status != LicenseValidationStatus.MachineMismatch)
        {
            throw new InvalidOperationException($"Expected machine mismatch, got {result.Status}.");
        }

        await using var target = await StartAsync();
        using var client = new HttpClient { BaseAddress = new Uri(target.Urls.Single()) };
        await ExpectAsync(client, "/health", HttpStatusCode.OK);
        await ExpectAsync(client, "/protected", HttpStatusCode.Forbidden);
        Console.WriteLine("CROSS_MACHINE_LICENSE PASS: distinct CNG identity, MachineMismatch and HTTP 403.");
        var cipher = await File.ReadAllTextAsync(Path.Combine(copyInput, "protected.txt"));
        try
        {
            _ = new DpapiSecretProtector().Unprotect(cipher);
            throw new InvalidOperationException("Copied DPAPI test data unexpectedly decrypted.");
        }
        catch (CryptographicException)
        {
            Console.WriteLine("CROSS_MACHINE_DPAPI PASS");
        }

        await target.StopAsync();
        return;
    }

    string original;
    await using (var app = await StartAsync())
    {
        using var client = new HttpClient { BaseAddress = new Uri(app.Urls.Single()) };
        await ExpectAsync(client, "/health", HttpStatusCode.OK);
        await ExpectAsync(client, "/protected", HttpStatusCode.Forbidden);
        using (var response = await client.GetAsync("/license/activation-request"))
        {
            response.EnsureSuccessStatusCode();
            await File.WriteAllTextAsync(requestPath, await response.Content.ReadAsStringAsync());
        }

        await RunToolAsync(issuerTool!, "--key-slot", keySlot, "issue", ledger,
            requestPath, "SMOKE", "1", "1", "30");
        var signedFile = Directory.GetFiles(ledger, "*.lic").Single();
        original = await File.ReadAllTextAsync(signedFile);
        File.Copy(signedFile, licensePath);
        await ExpectAsync(client, "/protected", HttpStatusCode.OK);
        if (!File.Exists(statePath))
        {
            throw new InvalidOperationException("Runtime state was not persisted.");
        }

        if (copyOutput is not null)
        {
            Directory.CreateDirectory(copyOutput);
            File.Copy(publicKeyPath, Path.Combine(copyOutput, "issuer.pem"));
            await File.WriteAllTextAsync(Path.Combine(copyOutput, "license.lic"), original);
            await File.WriteAllTextAsync(Path.Combine(copyOutput, "machine.txt"), machineCode);
            var protector = new DpapiSecretProtector();
            const string fixture = "CI-only non-secret fixture";
            var protectedFixture = protector.Protect(fixture);
            if (protector.Unprotect(protectedFixture) != fixture)
            {
                throw new InvalidOperationException("Source protected data round trip failed.");
            }
            await File.WriteAllTextAsync(Path.Combine(copyOutput, "protected.txt"), protectedFixture);
        }

        await RunToolAsync(issuerTool!, "--key-slot", keySlot, "revoke", ledger,
            Path.GetFileNameWithoutExtension(signedFile));
        File.Copy(signedFile, licensePath, overwrite: true);
        await ExpectAsync(client, "/protected", HttpStatusCode.Forbidden);

        await File.WriteAllTextAsync(licensePath, original);
        await ExpectAsync(client, "/protected", HttpStatusCode.Forbidden);
        await app.StopAsync();
    }

    // New host and guard must load durable DPAPI state, not trust the old file.
    await using (var app = await StartAsync())
    {
        using var client = new HttpClient { BaseAddress = new Uri(app.Urls.Single()) };
        await ExpectAsync(client, "/protected", HttpStatusCode.Forbidden);
        await ExpectAsync(client, "/health", HttpStatusCode.OK);
        await app.StopAsync();
    }

    Console.WriteLine("PACKAGE_RUNTIME_SMOKE PASS: activation, issue, valid access, revoke, stale license and restart.");

    async Task<WebApplication> StartAsync()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            ContentRootPath = root,
            EnvironmentName = "Production",
            Args = []
        });
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Services.AddDharmuSecurity(options =>
        {
            options.ProductCode = "SMOKE";
            options.TrustedPublicKeys[keyId] = pem;
            options.LicenseFilePath = licensePath;
            options.RuntimeStateFilePath = statePath;
        });
        var application = builder.Build();
        application.UseDharmuLicenseProtection();
        application.MapDharmuSecurityEndpoints();
        application.MapGet("/health", () => "ok");
        application.MapGet("/protected", () => "ok");
        try
        {
            await application.StartAsync();
            return application;
        }
        catch
        {
            await application.DisposeAsync();
            throw;
        }
    }
}
finally
{
    Directory.Delete(root, recursive: true);
}

static async Task ExpectAsync(HttpClient client, string path, HttpStatusCode expected)
{
    using var response = await client.GetAsync(path);
    if (response.StatusCode != expected)
    {
        throw new InvalidOperationException(
            $"{path}: expected {(int)expected}, got {(int)response.StatusCode}.");
    }
    Console.WriteLine($"PACKAGE_RUNTIME_SMOKE {path} {(int)expected}");
}

static async Task RunToolAsync(string assembly, params string[] arguments)
{
    var info = new ProcessStartInfo("dotnet") { UseShellExecute = false };
    info.ArgumentList.Add(assembly);
    foreach (var argument in arguments)
    {
        info.ArgumentList.Add(argument);
    }
    using var process = Process.Start(info)
        ?? throw new InvalidOperationException("Could not start test tool.");
    await process.WaitForExitAsync();
    if (process.ExitCode != 0)
    {
        throw new InvalidOperationException($"Test tool failed: {Path.GetFileName(assembly)} ({process.ExitCode}).");
    }
}
