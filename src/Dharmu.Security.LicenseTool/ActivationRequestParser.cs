using System.Security.Cryptography;
using System.Text.Json;
using Dharmu.Security.Core.Licensing;

namespace Dharmu.Security.LicenseTool;

public sealed class ActivationRequestParser
{
    private const string Algorithm = "ECDSA-P256-SHA256";
    private static readonly TimeSpan MaxRequestAge = TimeSpan.FromDays(30);
    private static readonly TimeSpan FutureTolerance = TimeSpan.FromMinutes(10);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public ActivationRequest Parse(string content, DateTime utcNow)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(content);

        try
        {
            var envelope = JsonSerializer.Deserialize<ActivationRequestEnvelope>(
                content,
                JsonOptions)
                ?? throw new InvalidDataException("Activation request is empty.");

            if (!string.Equals(envelope.Algorithm, Algorithm, StringComparison.Ordinal) ||
                string.IsNullOrWhiteSpace(envelope.Payload) ||
                string.IsNullOrWhiteSpace(envelope.DevicePublicKey) ||
                string.IsNullOrWhiteSpace(envelope.Signature))
            {
                throw new InvalidDataException("Activation request envelope is invalid.");
            }

            var payloadBytes = Convert.FromBase64String(envelope.Payload);
            var publicKeyBytes = Convert.FromBase64String(envelope.DevicePublicKey);
            var signatureBytes = Convert.FromBase64String(envelope.Signature);

            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out var bytesRead);

            if (bytesRead != publicKeyBytes.Length || ecdsa.KeySize != 256)
            {
                throw new InvalidDataException("Activation request device key is invalid.");
            }

            if (!ecdsa.VerifyData(payloadBytes, signatureBytes, HashAlgorithmName.SHA256))
            {
                throw new InvalidDataException(
                    "Activation request device signature is invalid.");
            }

            var request = JsonSerializer.Deserialize<ActivationRequest>(
                payloadBytes,
                JsonOptions)
                ?? throw new InvalidDataException("Activation request payload is empty.");

            ValidateRequest(request, publicKeyBytes, utcNow);
            return request;
        }
        catch (Exception exception) when (
            exception is JsonException or
            FormatException or
            CryptographicException)
        {
            throw new InvalidDataException(
                "Activation request format or signature is invalid.",
                exception);
        }
    }

    private static void ValidateRequest(
        ActivationRequest request,
        byte[] publicKeyBytes, DateTime utcNow)
    {
        if (request.SchemaVersion != 2 ||
            string.IsNullOrWhiteSpace(request.ProductCode) ||
            string.IsNullOrWhiteSpace(request.MachineCode) ||
            request.CreatedAtUtc == default || request.CreatedAtUtc.Kind != DateTimeKind.Utc)
        {
            throw new InvalidDataException("Activation request data is incomplete.");
        }

        if (request.ProductCode.Length > 50 || request.MachineCode.Length != 64)
        {
            throw new InvalidDataException("Activation request data is invalid.");
        }

        var expectedMachineCode = Convert.ToHexString(
            SHA256.HashData(publicKeyBytes));

        if (!string.Equals(
                request.MachineCode,
                expectedMachineCode,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Activation request machine identity does not match its device key.");
        }

        var now = utcNow;
        var createdAtUtc = request.CreatedAtUtc.ToUniversalTime();

        if (createdAtUtc > now.Add(FutureTolerance))
        {
            throw new InvalidDataException(
                "Activation request creation time is in the future.");
        }

        if (createdAtUtc < now.Subtract(MaxRequestAge))
        {
            throw new InvalidDataException(
                "Activation request is older than 30 days. Generate a new request.");
        }
    }
}
