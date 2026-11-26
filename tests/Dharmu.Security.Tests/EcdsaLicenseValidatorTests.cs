using System.Security.Cryptography;
using System.Text.Json;
using Dharmu.Security.Core.Licensing;
using Xunit;

namespace Dharmu.Security.Tests;

public sealed class EcdsaLicenseValidatorTests
{
    private static readonly JsonSerializerOptions JsonOptions =
        new(JsonSerializerDefaults.Web);

    private readonly EcdsaLicenseValidator _validator = new();

    [Fact]
    public void ValidLicense_ReturnsValid()
    {
        using var signingKey = CreateKey();
        var now = DateTime.UtcNow;

        var license = CreateLicense(
            signingKey,
            productCode: "ERP",
            machineCode: "MACHINE-A",
            validFromUtc: now.AddDays(-1),
            expiresAtUtc: now.AddDays(30));

        var result = _validator.Validate(
            license,
            TrustedKeys(signingKey),
            "ERP",
            "MACHINE-A",
            now);

        Assert.True(result.IsValid);
        Assert.Equal(LicenseValidationStatus.Valid, result.Status);
    }

    [Fact]
    public void TamperedPayload_ReturnsInvalidSignature()
    {
        using var signingKey = CreateKey();
        var now = DateTime.UtcNow;

        var license = CreateLicense(
            signingKey,
            productCode: "ERP",
            machineCode: "MACHINE-A",
            validFromUtc: now.AddDays(-1),
            expiresAtUtc: now.AddDays(30));

        var envelope = JsonSerializer.Deserialize<LicenseEnvelope>(
            license,
            JsonOptions)!;

        var payload = JsonSerializer.Deserialize<LicensePayload>(
            Convert.FromBase64String(envelope.Payload),
            JsonOptions)!;

        var tamperedPayload = JsonSerializer.SerializeToUtf8Bytes(
            new LicensePayload
            {
                LicenseId = payload.LicenseId,
                CustomerId = payload.CustomerId,
                ProductId = payload.ProductId,
                ProductCode = payload.ProductCode,
                MachineCode = payload.MachineCode,
                IssuedAtUtc = payload.IssuedAtUtc,
                ValidFromUtc = payload.ValidFromUtc,
                ExpiresAtUtc = now.AddYears(10),
                IsLifetime = true
            },
            JsonOptions);

        var tampered = JsonSerializer.Serialize(
            new LicenseEnvelope
            {
                Algorithm = envelope.Algorithm,
                KeyId = envelope.KeyId,
                Payload = Convert.ToBase64String(tamperedPayload),
                Signature = envelope.Signature
            },
            JsonOptions);

        var result = _validator.Validate(
            tampered,
            TrustedKeys(signingKey),
            "ERP",
            "MACHINE-A",
            now);

        Assert.Equal(
            LicenseValidationStatus.InvalidSignature,
            result.Status);
    }

    [Fact]
    public void WrongProduct_ReturnsProductMismatch()
    {
        using var signingKey = CreateKey();
        var now = DateTime.UtcNow;

        var result = _validator.Validate(
            CreateLicense(
                signingKey,
                "ERP",
                "MACHINE-A",
                now.AddDays(-1),
                now.AddDays(30)),
            TrustedKeys(signingKey),
            "POS",
            "MACHINE-A",
            now);

        Assert.Equal(
            LicenseValidationStatus.ProductMismatch,
            result.Status);
    }

    [Fact]
    public void WrongMachine_ReturnsMachineMismatch()
    {
        using var signingKey = CreateKey();
        var now = DateTime.UtcNow;

        var result = _validator.Validate(
            CreateLicense(
                signingKey,
                "ERP",
                "MACHINE-A",
                now.AddDays(-1),
                now.AddDays(30)),
            TrustedKeys(signingKey),
            "ERP",
            "MACHINE-B",
            now);

        Assert.Equal(
            LicenseValidationStatus.MachineMismatch,
            result.Status);
    }

    [Fact]
    public void ExpiredLicense_ReturnsExpired()
    {
        using var signingKey = CreateKey();
        var now = DateTime.UtcNow;

        var result = _validator.Validate(
            CreateLicense(
                signingKey,
                "ERP",
                "MACHINE-A",
                now.AddDays(-30),
                now.AddSeconds(-1)),
            TrustedKeys(signingKey),
            "ERP",
            "MACHINE-A",
            now);

        Assert.Equal(LicenseValidationStatus.Expired, result.Status);
        Assert.NotNull(result.License);
        Assert.False(result.IsValid);
    }

    [Fact]
    public void InvalidValidityRange_ReturnsInvalidFormat()
    {
        using var key = CreateKey();
        var now = DateTime.UtcNow;
        var result = _validator.Validate(CreateLicense(key, "ERP", "MACHINE-A",
            now.AddDays(-1), now.AddDays(-2)), TrustedKeys(key), "ERP", "MACHINE-A", now);
        Assert.Equal(LicenseValidationStatus.InvalidFormat, result.Status);
        Assert.Null(result.License);
    }

    [Fact]
    public void RevokedLicense_ReturnsRevoked()
    {
        using var signingKey = CreateKey();
        var now = DateTime.UtcNow;

        var result = _validator.Validate(
            CreateLicense(
                signingKey,
                "ERP",
                "MACHINE-A",
                now.AddDays(-1),
                now.AddDays(30),
                isRevoked: true),
            TrustedKeys(signingKey),
            "ERP",
            "MACHINE-A",
            now);

        Assert.Equal(LicenseValidationStatus.Revoked, result.Status);
    }

    [Fact]
    public void UnknownKeyId_ReturnsUnknownSigningKey()
    {
        using var signingKey = CreateKey();
        using var differentKey = CreateKey();
        var now = DateTime.UtcNow;

        var result = _validator.Validate(
            CreateLicense(
                signingKey,
                "ERP",
                "MACHINE-A",
                now.AddDays(-1),
                now.AddDays(30)),
            new Dictionary<string, string>
            {
                ["secondary"] =
                    differentKey.ExportSubjectPublicKeyInfoPem()
            },
            "ERP",
            "MACHINE-A",
            now);

        Assert.Equal(
            LicenseValidationStatus.UnknownSigningKey,
            result.Status);
    }

    [Theory]
    [InlineData(1, 0, true)]
    [InlineData(2, 1, true)]
    [InlineData(2, 0, false)]
    [InlineData(1, 1, false)]
    [InlineData(3, 1, false)]
    public void SchemaAndRevision_AreValidated(int schemaVersion, long revision, bool valid)
    {
        using var key = CreateKey();
        var now = DateTime.UtcNow;
        var result = _validator.Validate(
            CreateLicense(key, "ERP", "MACHINE-A", now.AddDays(-1), now.AddDays(1),
                schemaVersion: schemaVersion, revision: revision),
            TrustedKeys(key), "ERP", "MACHINE-A", now);
        Assert.Equal(valid, result.IsValid);
    }

    [Fact]
    public void SignedExpiredRevocation_ReturnsAuthenticatedPayloadWithoutAccess()
    {
        using var key = CreateKey();
        var now = DateTime.UtcNow;
        var license = CreateLicense(key, "ERP", "MACHINE-A", now.AddDays(-30), now.AddDays(-1),
            isRevoked: true, schemaVersion: 2, revision: 3);
        var result = _validator.Validate(license, TrustedKeys(key), "ERP", "MACHINE-A", now);
        Assert.False(result.IsValid);
        Assert.Equal(3L, Assert.IsType<LicensePayload>(result.License).Revision);
        var mismatch = _validator.Validate(license, TrustedKeys(key), "ERP", "OTHER", now);
        Assert.Null(mismatch.License);
    }

    private static ECDsa CreateKey() =>
        ECDsa.Create(ECCurve.NamedCurves.nistP256);

    private static IReadOnlyDictionary<string, string> TrustedKeys(
        ECDsa signingKey) =>
        new Dictionary<string, string>
        {
            ["primary"] = signingKey.ExportSubjectPublicKeyInfoPem()
        };

    private static string CreateLicense(
        ECDsa signingKey,
        string productCode,
        string machineCode,
        DateTime validFromUtc,
        DateTime? expiresAtUtc,
        bool isRevoked = false, int schemaVersion = 1, long revision = 0)
    {
        var payload = new LicensePayload
        {
            SchemaVersion = schemaVersion,
            Revision = revision,
            LicenseId = 10,
            CustomerId = 20,
            ProductId = 30,
            ProductCode = productCode,
            MachineCode = machineCode,
            IssuedAtUtc = DateTime.UtcNow.AddMinutes(-1),
            ValidFromUtc = validFromUtc,
            ExpiresAtUtc = expiresAtUtc,
            IsLifetime = false,
            IsRevoked = isRevoked
        };

        var payloadBytes = JsonSerializer.SerializeToUtf8Bytes(
            payload,
            JsonOptions);

        var signature = signingKey.SignData(
            payloadBytes,
            HashAlgorithmName.SHA256);

        return JsonSerializer.Serialize(
            new LicenseEnvelope
            {
                Algorithm = "ECDSA-P256-SHA256",
                KeyId = "primary",
                Payload = Convert.ToBase64String(payloadBytes),
                Signature = Convert.ToBase64String(signature)
            },
            JsonOptions);
    }
}
