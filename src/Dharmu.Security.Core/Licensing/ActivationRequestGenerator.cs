using System.Text.Json;
using Dharmu.Security.Core.Machine;

namespace Dharmu.Security.Core.Licensing;

public sealed class ActivationRequestGenerator : IActivationRequestGenerator
{
    private const string Algorithm = "ECDSA-P256-SHA256";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly IMachineIdentityProvider _machineIdentityProvider;

    public ActivationRequestGenerator(IMachineIdentityProvider machineIdentityProvider)
    {
        _machineIdentityProvider = machineIdentityProvider;
    }

    public string Generate(string productCode, DateTime utcNow)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(productCode);

        var payload = new ActivationRequest
        {
            ProductCode = productCode.Trim(),
            MachineCode = _machineIdentityProvider.GetMachineCode(),
            CreatedAtUtc = utcNow
        };

        var payloadBytes = JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions);
        var publicKey = _machineIdentityProvider.ExportPublicKey();
        var signature = _machineIdentityProvider.Sign(payloadBytes);

        var envelope = new ActivationRequestEnvelope
        {
            Algorithm = Algorithm,
            Payload = Convert.ToBase64String(payloadBytes),
            DevicePublicKey = Convert.ToBase64String(publicKey),
            Signature = Convert.ToBase64String(signature)
        };

        return JsonSerializer.Serialize(envelope, JsonOptions);
    }
}
