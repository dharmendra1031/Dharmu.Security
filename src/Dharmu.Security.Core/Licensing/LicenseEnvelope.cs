namespace Dharmu.Security.Core.Licensing;

public sealed class LicenseEnvelope
{
    public string Payload { get; init; } = string.Empty;
    public string Signature { get; init; } = string.Empty;
}
