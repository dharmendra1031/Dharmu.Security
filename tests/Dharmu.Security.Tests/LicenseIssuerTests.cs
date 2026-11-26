using System.Security.Cryptography;
using System.Text.Json;
using Dharmu.Security.Core.Licensing;
using Dharmu.Security.Core.Machine;
using Dharmu.Security.LicenseTool;
using Xunit;

namespace Dharmu.Security.Tests;

public sealed class LicenseIssuerTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
    private readonly DateTime _now = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void IssueRenewRevoke_RoundTripsThroughRuntimeValidator()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var device = new TestDevice();
        var issuer = new LicenseIssuer(_directory, key, "issuer-v1");
        var request = new ActivationRequestGenerator(device).Generate("ERP", _now);
        var path = issuer.Issue(request, "ERP", 1, 2, 30, _now);
        var validator = new EcdsaLicenseValidator();
        var trusted = new Dictionary<string, string> { ["issuer-v1"] = key.ExportSubjectPublicKeyInfoPem() };
        var first = validator.Validate(File.ReadAllText(path), trusted, "ERP", device.GetMachineCode(), _now);
        Assert.True(first.IsValid);
        var id = Assert.IsType<LicensePayload>(first.License).LicenseId;
        Assert.Equal(1L, first.License!.Revision);
        Assert.Equal(LicenseValidationStatus.MachineMismatch,
            validator.Validate(File.ReadAllText(path), trusted, "ERP", "OTHER", _now).Status);

        issuer = new LicenseIssuer(_directory, key, "issuer-v1");
        issuer.Renew(id, 30, _now.AddDays(31));
        var renewed = validator.Validate(File.ReadAllText(path), trusted, "ERP", device.GetMachineCode(), _now.AddDays(31));
        Assert.True(renewed.IsValid);
        Assert.Equal(2L, renewed.License!.Revision);
        issuer.Revoke(id, _now.AddDays(32));
        var revoked = validator.Validate(File.ReadAllText(path), trusted, "ERP", device.GetMachineCode(), _now.AddDays(32));
        Assert.Equal(LicenseValidationStatus.Revoked, revoked.Status);
        Assert.Equal(3L, revoked.License!.Revision);
        var record = File.ReadAllText(path);
        Assert.Throws<InvalidOperationException>(() => issuer.Renew(id, 30, _now.AddDays(33)));
        issuer.Revoke(id, _now.AddDays(33));
        Assert.Equal(record, File.ReadAllText(path));
    }

    [Fact]
    public void WrongProductOrTamperedRequest_IsRejected()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var device = new TestDevice();
        var issuer = new LicenseIssuer(_directory, key, "issuer-v1");
        var request = new ActivationRequestGenerator(device).Generate("ERP", _now);
        Assert.Throws<InvalidDataException>(() => issuer.Issue(request, "OTHER", 1, 2, null, _now));
        var json = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        var original = JsonSerializer.Deserialize<ActivationRequestEnvelope>(request, json)!;
        var forged = JsonSerializer.Serialize(new ActivationRequestEnvelope
        {
            Algorithm = original.Algorithm, DevicePublicKey = original.DevicePublicKey,
            Payload = Convert.ToBase64String(new byte[] { 1, 2, 3 }), Signature = original.Signature
        }, json);
        Assert.Throws<InvalidDataException>(() => issuer.Issue(forged, "ERP", 1, 2, 30, _now));
        Assert.Empty(Directory.GetFiles(_directory, "*.lic"));
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    private sealed class TestDevice : IMachineIdentityProvider, IDisposable
    {
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        public byte[] ExportPublicKey() => _key.ExportSubjectPublicKeyInfo();
        public string GetMachineCode() => Convert.ToHexString(SHA256.HashData(ExportPublicKey()));
        public byte[] Sign(byte[] data) => _key.SignData(data, HashAlgorithmName.SHA256);
        public void Dispose() => _key.Dispose();
    }
}
