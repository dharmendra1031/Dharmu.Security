// Disposable CI test site only; never publish this application to customers.
using System.Security.Cryptography;
using System.Security.Principal;
using Dharmu.Security.AspNetCore;

var data = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "data"));
var pem = File.ReadAllText(Path.Combine(data, "issuer.pem"));
using var key = ECDsa.Create();
key.ImportFromPem(pem);
var keyId = "issuer-" + Convert.ToHexString(
    SHA256.HashData(key.ExportSubjectPublicKeyInfo())).ToLowerInvariant();

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddDharmuSecurity(options =>
{
    options.ProductCode = "IIS_SMOKE";
    options.TrustedPublicKeys[keyId] = pem;
    options.LicenseFilePath = Path.Combine(data, "license.lic");
    options.RuntimeStateFilePath = Path.Combine(data, "state", "runtime.state");
});
var app = builder.Build();
app.UseDharmuLicenseProtection();
app.MapDharmuSecurityEndpoints();
app.MapGet("/health", () =>
{
    using var identity = WindowsIdentity.GetCurrent();
    return Results.Json(new
    {
        identity = identity.Name,
        administrator = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator),
        pid = Environment.ProcessId
    });
});
app.MapGet("/protected", () => "ok");
app.Run();
