using System.Security.Cryptography;
using System.Text.Json;

namespace Dharmu.Security.Core.Licensing;

public sealed class EcdsaLicenseValidator : ILicenseValidator
{
    private const string SupportedAlgorithm = "ECDSA-P256-SHA256";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public LicenseValidationResult Validate(
        string licenseContent,
        IReadOnlyDictionary<string, string> trustedPublicKeys,
        string expectedProductCode,
        string currentMachineCode,
        DateTime utcNow)
    {
        try
        {
            var envelope = JsonSerializer.Deserialize<LicenseEnvelope>(
                licenseContent,
                JsonOptions);

            if (envelope is null ||
                !string.Equals(
                    envelope.Algorithm,
                    SupportedAlgorithm,
                    StringComparison.Ordinal) ||
                string.IsNullOrWhiteSpace(envelope.KeyId) ||
                string.IsNullOrWhiteSpace(envelope.Payload) ||
                string.IsNullOrWhiteSpace(envelope.Signature))
            {
                return LicenseValidationResult.Invalid(
                    LicenseValidationStatus.InvalidFormat);
            }

            if (!trustedPublicKeys.TryGetValue(
                    envelope.KeyId,
                    out var publicKeyPem) ||
                string.IsNullOrWhiteSpace(publicKeyPem))
            {
                return LicenseValidationResult.Invalid(
                    LicenseValidationStatus.UnknownSigningKey);
            }

            var payloadBytes = Convert.FromBase64String(envelope.Payload);
            var signatureBytes = Convert.FromBase64String(envelope.Signature);

            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(publicKeyPem);

            if (ecdsa.KeySize != 256 ||
                !ecdsa.VerifyData(
                    payloadBytes,
                    signatureBytes,
                    HashAlgorithmName.SHA256))
            {
                return LicenseValidationResult.Invalid(
                    LicenseValidationStatus.InvalidSignature);
            }

            var payload = JsonSerializer.Deserialize<LicensePayload>(
                payloadBytes,
                JsonOptions);

            if (payload is null || payload.LicenseId <= 0 ||
                !((payload.SchemaVersion == 1 && payload.Revision == 0) ||
                  (payload.SchemaVersion == 2 && payload.Revision > 0)) ||
                payload.IssuedAtUtc == default || payload.ValidFromUtc == default ||
                payload.IssuedAtUtc.Kind != DateTimeKind.Utc ||
                payload.ValidFromUtc.Kind != DateTimeKind.Utc ||
                (payload.IsLifetime
                    ? payload.ExpiresAtUtc.HasValue
                    : payload.ExpiresAtUtc is not DateTime expiry ||
                      expiry.Kind != DateTimeKind.Utc || expiry <= payload.ValidFromUtc))
            {
                return LicenseValidationResult.Invalid(
                    LicenseValidationStatus.InvalidFormat);
            }

            if (!string.Equals(
                    payload.ProductCode,
                    expectedProductCode,
                    StringComparison.Ordinal))
            {
                return LicenseValidationResult.Invalid(
                    LicenseValidationStatus.ProductMismatch);
            }

            if (!string.Equals(
                    payload.MachineCode,
                    currentMachineCode,
                    StringComparison.Ordinal))
            {
                return LicenseValidationResult.Invalid(
                    LicenseValidationStatus.MachineMismatch);
            }

            if (payload.IsRevoked)
            {
                // Only authenticated, product- and machine-matched revocations reach the runtime store.
                return new LicenseValidationResult(LicenseValidationStatus.Revoked, payload);
            }

            if (utcNow < payload.ValidFromUtc)
            {
                return LicenseValidationResult.Invalid(
                    LicenseValidationStatus.NotYetValid);
            }

            if (!payload.IsLifetime &&
                (!payload.ExpiresAtUtc.HasValue ||
                 utcNow >= payload.ExpiresAtUtc.Value))
            {
                return new LicenseValidationResult(LicenseValidationStatus.Expired, payload);
            }

            return LicenseValidationResult.Valid(payload);
        }
        catch (FormatException)
        {
            return LicenseValidationResult.Invalid(
                LicenseValidationStatus.InvalidFormat);
        }
        catch (JsonException)
        {
            return LicenseValidationResult.Invalid(
                LicenseValidationStatus.InvalidFormat);
        }
        catch (CryptographicException)
        {
            return LicenseValidationResult.Invalid(
                LicenseValidationStatus.InvalidSignature);
        }
    }
}
