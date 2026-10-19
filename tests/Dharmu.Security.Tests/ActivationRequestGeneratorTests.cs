using System.Security.Cryptography;
using System.Text.Json;
using Dharmu.Security.Core.Licensing;
using Dharmu.Security.Core.Machine;

namespace Dharmu.Security.Tests;

public sealed class ActivationRequestGeneratorTests
{
    private static readonly JsonSerializerOptions JsonOptions =
        new(JsonSerializerDefaults.Web);

    [Fact]
    public void Generate_CreatesSignedDeviceProof()
    {
        using var provider = new TestMachineIdentityProvider();
        var generator = new ActivationRequestGenerator(provider);
        var now = DateTime.UtcNow;

        var content = generator.Generate("ERP", now);

        var envelope = JsonSerializer.Deserialize<ActivationRequestEnvelope>(
            content,
            JsonOptions);

        Assert.NotNull(envelope);
        Assert.Equal("ECDSA-P256-SHA256", envelope!.Algorithm);

        var payloadBytes = Convert.FromBase64String(envelope.Payload);
        var publicKeyBytes = Convert.FromBase64String(
            envelope.DevicePublicKey);

        using var verifier = ECDsa.Create();
        verifier.ImportSubjectPublicKeyInfo(
            publicKeyBytes,
            out var bytesRead);

        Assert.Equal(publicKeyBytes.Length, bytesRead);
        Assert.True(
            verifier.VerifyData(
                payloadBytes,
                Convert.FromBase64String(envelope.Signature),
                HashAlgorithmName.SHA256));

        var request = JsonSerializer.Deserialize<ActivationRequest>(
            payloadBytes,
            JsonOptions);

        Assert.NotNull(request);
        Assert.Equal(2, request!.SchemaVersion);
        Assert.Equal("ERP", request.ProductCode);
        Assert.Equal(provider.GetMachineCode(), request.MachineCode);
        Assert.Equal(now, request.CreatedAtUtc);
    }

    private sealed class TestMachineIdentityProvider
        : IMachineIdentityProvider, IDisposable
    {
        private readonly ECDsa _key =
            ECDsa.Create(ECCurve.NamedCurves.nistP256);

        public string GetMachineCode() =>
            Convert.ToHexString(
                SHA256.HashData(ExportPublicKey()));

        public byte[] ExportPublicKey() =>
            _key.ExportSubjectPublicKeyInfo();

        public byte[] Sign(byte[] data) =>
            _key.SignData(data, HashAlgorithmName.SHA256);

        public void Dispose() => _key.Dispose();
    }
}
