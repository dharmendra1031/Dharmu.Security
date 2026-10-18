using System.Security.Cryptography;
using System.Text.Json;

namespace Dharmu.Security.Core.Licensing;

public sealed class EcdsaLicenseValidator : ILicenseValidator
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public LicenseValidationResult Validate(
        string licenseContent,
        string publicKeyPem,
        string expectedProductCode,
        string currentMachineCode,
        DateTime utcNow)
    {
        try
        {
            var envelope = JsonSerializer.Deserialize<LicenseEnvelope>(licenseContent, JsonOptions);
            if (envelope is null ||
                string.IsNullOrWhiteSpace(envelope.Payload) ||
                string.IsNullOrWhiteSpace(envelope.Signature))
            {
                return LicenseValidationResult.Invalid(LicenseValidationStatus.InvalidFormat);
            }

            var payloadBytes = Convert.FromBase64String(envelope.Payload);
            var signatureBytes = Convert.FromBase64String(envelope.Signature);

            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(publicKeyPem);

            if (!ecdsa.VerifyData(payloadBytes, signatureBytes, HashAlgorithmName.SHA256))
            {
                return LicenseValidationResult.Invalid(LicenseValidationStatus.InvalidSignature);
            }

            var payload = JsonSerializer.Deserialize<LicensePayload>(payloadBytes, JsonOptions);
            if (payload is null || payload.SchemaVersion != 1)
            {
                return LicenseValidationResult.Invalid(LicenseValidationStatus.InvalidFormat);
            }

            if (!string.Equals(payload.ProductCode, expectedProductCode, StringComparison.Ordinal))
            {
                return LicenseValidationResult.Invalid(LicenseValidationStatus.ProductMismatch);
            }

            if (!string.Equals(payload.MachineCode, currentMachineCode, StringComparison.Ordinal))
            {
                return LicenseValidationResult.Invalid(LicenseValidationStatus.MachineMismatch);
            }

            if (utcNow < payload.ValidFromUtc)
            {
                return LicenseValidationResult.Invalid(LicenseValidationStatus.NotYetValid);
            }

            if (!payload.IsLifetime &&
                (!payload.ExpiresAtUtc.HasValue || utcNow >= payload.ExpiresAtUtc.Value))
            {
                return LicenseValidationResult.Invalid(LicenseValidationStatus.Expired);
            }

            return LicenseValidationResult.Valid(payload);
        }
        catch (FormatException)
        {
            return LicenseValidationResult.Invalid(LicenseValidationStatus.InvalidFormat);
        }
        catch (JsonException)
        {
            return LicenseValidationResult.Invalid(LicenseValidationStatus.InvalidFormat);
        }
        catch (CryptographicException)
        {
            return LicenseValidationResult.Invalid(LicenseValidationStatus.InvalidSignature);
        }
    }
}
