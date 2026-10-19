namespace Dharmu.Security.Core.Licensing;

public sealed class ActivationRequestEnvelope
{
    public string Algorithm { get; init; } = string.Empty;
    public string Payload { get; init; } = string.Empty;
    public string DevicePublicKey { get; init; } = string.Empty;
    public string Signature { get; init; } = string.Empty;
}
