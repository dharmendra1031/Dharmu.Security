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

    [Fact]
    public void DuplicateProductAndDevice_RequiresRenewalOrExplicitRevocation()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var device = new TestDevice();
        var issuer = new LicenseIssuer(_directory, key, "issuer-v1");
        var generator = new ActivationRequestGenerator(device);
        var path = issuer.Issue(generator.Generate("ERP", _now), "ERP", 1, 2, 1, _now);
        Assert.Throws<InvalidOperationException>(() =>
            issuer.Issue(generator.Generate("ERP", _now.AddDays(2)), "ERP", 3, 2, 30, _now.AddDays(2)));
        Assert.Single(Directory.GetFiles(_directory, "*.lic"));
        var otherProduct = issuer.Issue(generator.Generate("POS", _now), "POS", 1, 3, 30, _now);
        Assert.NotEqual(path, otherProduct);
        issuer.Revoke(long.Parse(Path.GetFileNameWithoutExtension(path)), _now.AddDays(2));
        var replacement = issuer.Issue(generator.Generate("ERP", _now.AddDays(2)), "ERP", 1, 2, 30, _now.AddDays(2));
        Assert.NotEqual(path, replacement);
        Assert.Equal(3, Directory.GetFiles(_directory, "*.lic").Length);
    }

    [Fact]
    public void ListAndHistory_ReturnAuthenticatedCustomerRecordsAndRevisions()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var device = new TestDevice();
        var issuer = new LicenseIssuer(_directory, key, "issuer-v1");
        var generator = new ActivationRequestGenerator(device);
        issuer.Issue(generator.Generate("ERP", _now), "ERP", 1, 2, 30, _now);
        issuer.Issue(generator.Generate("POS", _now), "POS", 2, 3, 30, _now);
        var initial = Assert.Single(issuer.List(1));
        issuer.Renew(initial.LicenseId, 30, _now.AddDays(1));
        issuer.Revoke(initial.LicenseId, _now.AddDays(2));
        issuer.Revoke(initial.LicenseId, _now.AddDays(3));
        issuer = new LicenseIssuer(_directory, key, "issuer-v1");
        Assert.Equal(2, issuer.List().Count);
        Assert.Empty(issuer.List(99));
        Assert.True(Assert.Single(issuer.List(1)).IsRevoked);
        var history = issuer.History(initial.LicenseId);
        Assert.Equal(new long[] { 1, 2, 3 }, history.Select(record => record.Revision));
        Assert.False(history[0].IsRevoked);
        Assert.True(history[2].IsRevoked);
    }

    [Fact]
    public void TamperedHistory_IsRejected()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var device = new TestDevice();
        var issuer = new LicenseIssuer(_directory, key, "issuer-v1");
        var request = new ActivationRequestGenerator(device).Generate("ERP", _now);
        issuer.Issue(request, "ERP", 1, 2, 30, _now);
        var id = Assert.Single(issuer.List()).LicenseId;
        issuer.Renew(id, 30, _now.AddDays(1));
        var archive = Assert.Single(Directory.GetFiles(Path.Combine(_directory, "history"), "*.lic", SearchOption.AllDirectories));
        File.WriteAllText(archive, File.ReadAllText(archive).Replace("ECDSA-P256-SHA256", "invalid", StringComparison.Ordinal));
        Assert.Throws<InvalidDataException>(() => issuer.History(id));
    }

    [Fact]
    public void Replacement_PreservesEntitlementAndIsIdempotent()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var oldDevice = new TestDevice();
        using var newDevice = new TestDevice();
        using var thirdDevice = new TestDevice();
        var issuer = new LicenseIssuer(_directory, key, "issuer-v1");
        var oldPath = issuer.Issue(new ActivationRequestGenerator(oldDevice).Generate("ERP", _now), "ERP", 1, 2, 30, _now);
        var original = Assert.Single(issuer.List());
        var now = _now.AddDays(2);
        var request = new ActivationRequestGenerator(newDevice).Generate("ERP", now);
        Assert.Throws<InvalidOperationException>(() => issuer.Replace(original.LicenseId, request, now));
        issuer.Revoke(original.LicenseId, now);
        var replacementPath = issuer.Replace(original.LicenseId, request, now);
        Assert.Equal(replacementPath, issuer.Replace(original.LicenseId, request, now));
        Assert.Throws<InvalidOperationException>(() => issuer.Replace(original.LicenseId,
            new ActivationRequestGenerator(thirdDevice).Generate("ERP", now), now));
        var replacement = Assert.Single(issuer.List(), item => !item.IsRevoked);
        Assert.Equal(original.LicenseId, replacement.ReplacesLicenseId);
        Assert.Equal(original.CustomerId, replacement.CustomerId);
        Assert.Equal(original.ProductId, replacement.ProductId);
        Assert.Equal(original.ExpiresAtUtc, replacement.ExpiresAtUtc);
        Assert.Equal(newDevice.GetMachineCode(), replacement.MachineCode);
        var validator = new EcdsaLicenseValidator();
        var trusted = new Dictionary<string, string> { ["issuer-v1"] = key.ExportSubjectPublicKeyInfoPem() };
        Assert.True(validator.Validate(File.ReadAllText(replacementPath), trusted, "ERP", newDevice.GetMachineCode(), now).IsValid);
        Assert.Equal(LicenseValidationStatus.MachineMismatch, validator.Validate(
            File.ReadAllText(replacementPath), trusted, "ERP", oldDevice.GetMachineCode(), now).Status);
        Assert.Equal(LicenseValidationStatus.Revoked, validator.Validate(
            File.ReadAllText(oldPath), trusted, "ERP", oldDevice.GetMachineCode(), now).Status);
        issuer.Renew(replacement.LicenseId, 30, now);
        Assert.All(issuer.History(replacement.LicenseId), item => Assert.Equal(original.LicenseId, item.ReplacesLicenseId));
    }

    [Fact]
    public void Replacement_RejectsExpiredEntitlementAndWrongProduct()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var oldDevice = new TestDevice();
        using var newDevice = new TestDevice();
        var issuer = new LicenseIssuer(_directory, key, "issuer-v1");
        issuer.Issue(new ActivationRequestGenerator(oldDevice).Generate("ERP", _now), "ERP", 1, 2, 1, _now);
        var id = Assert.Single(issuer.List()).LicenseId;
        issuer.Revoke(id, _now);
        var generator = new ActivationRequestGenerator(newDevice);
        Assert.Throws<InvalidDataException>(() => issuer.Replace(id, generator.Generate("POS", _now), _now));
        var later = _now.AddDays(2);
        Assert.Throws<InvalidOperationException>(() => issuer.Replace(id, generator.Generate("ERP", later), later));
        Assert.Single(issuer.List());
    }

    [Fact]
    public void Replacement_PreservesLifetimeAndRejectsOriginalDevice()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var oldDevice = new TestDevice();
        using var newDevice = new TestDevice();
        var issuer = new LicenseIssuer(_directory, key, "issuer-v1");
        var request = new ActivationRequestGenerator(oldDevice).Generate("ERP", _now);
        issuer.Issue(request, "ERP", 1, 2, null, _now);
        var id = Assert.Single(issuer.List()).LicenseId;
        issuer.Revoke(id, _now);
        Assert.Throws<InvalidDataException>(() => issuer.Replace(id, request, _now));
        issuer.Replace(id, new ActivationRequestGenerator(newDevice).Generate("ERP", _now), _now);
        var replacement = Assert.Single(issuer.List(), item => !item.IsRevoked);
        Assert.True(replacement.IsLifetime);
        Assert.Null(replacement.ExpiresAtUtc);
    }

    [Fact]
    public void Rotation_PreservesEntitlementHistoryAndTerminalRevocation()
    {
        using var oldKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var newKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var device = new TestDevice();
        var oldIssuer = new LicenseIssuer(_directory, oldKey, "issuer-v1");
        var request = new ActivationRequestGenerator(device).Generate("ERP", _now);
        var path = oldIssuer.Issue(request, "ERP", 1, 2, 30, _now);
        var original = Assert.Single(oldIssuer.List());
        var oldContent = File.ReadAllText(path);
        var previous = new Dictionary<string, string> { ["issuer-v1"] = oldKey.ExportSubjectPublicKeyInfoPem() };
        var newIssuer = new LicenseIssuer(_directory, newKey, "issuer-v2", previous);
        newIssuer.Rotate(original.LicenseId, _now.AddDays(1));
        var rotated = Assert.Single(newIssuer.List());
        Assert.Equal(original.LicenseId, rotated.LicenseId);
        Assert.Equal(original.ExpiresAtUtc, rotated.ExpiresAtUtc);
        Assert.Equal(original.MachineCode, rotated.MachineCode);
        Assert.Equal(2L, rotated.Revision);
        Assert.Equal(path, newIssuer.Rotate(original.LicenseId, _now.AddDays(2)));
        Assert.Equal(2, newIssuer.History(original.LicenseId).Count);
        var validator = new EcdsaLicenseValidator();
        var trusted = new Dictionary<string, string> { ["issuer-v2"] = newKey.ExportSubjectPublicKeyInfoPem() };
        Assert.True(validator.Validate(File.ReadAllText(path), trusted, "ERP", device.GetMachineCode(), _now.AddDays(1)).IsValid);
        Assert.Equal(LicenseValidationStatus.UnknownSigningKey, validator.Validate(oldContent,
            trusted, "ERP", device.GetMachineCode(), _now).Status);

        newIssuer.Revoke(original.LicenseId, _now.AddDays(2));
        var oldAgain = new LicenseIssuer(_directory, oldKey, "issuer-v1", trusted);
        oldAgain.Rotate(original.LicenseId, _now.AddDays(3));
        Assert.True(Assert.Single(oldAgain.List()).IsRevoked);
        Assert.Throws<InvalidOperationException>(() => oldAgain.Renew(original.LicenseId, 30, _now.AddDays(4)));
        Assert.Equal(4, oldAgain.History(original.LicenseId).Count);
    }

    [Fact]
    public void Rotation_RejectsUnknownPreviousKeyAndConflictingPinnedKey()
    {
        using var oldKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var newKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var device = new TestDevice();
        var oldIssuer = new LicenseIssuer(_directory, oldKey, "issuer-v1");
        oldIssuer.Issue(new ActivationRequestGenerator(device).Generate("ERP", _now), "ERP", 1, 2, 30, _now);
        var id = Assert.Single(oldIssuer.List()).LicenseId;
        var newIssuer = new LicenseIssuer(_directory, newKey, "issuer-v2");
        Assert.Throws<InvalidDataException>(() => newIssuer.Rotate(id, _now.AddDays(1)));
        Assert.Throws<InvalidDataException>(() => new LicenseIssuer(_directory, newKey, "issuer-v1",
            new Dictionary<string, string> { ["issuer-v1"] = oldKey.ExportSubjectPublicKeyInfoPem() }));
    }

    [Fact]
    public void OversizedActivationRequest_IsRejected()
    {
        Assert.Throws<InvalidDataException>(() =>
            new ActivationRequestParser().Parse(new string('A', 64 * 1024 + 1), _now));
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
