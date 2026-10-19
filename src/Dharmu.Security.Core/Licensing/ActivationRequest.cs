namespace Dharmu.Security.Core.Licensing;

public sealed class ActivationRequest
{
    public int SchemaVersion { get; init; } = 2;
    public string ProductCode { get; init; } = string.Empty;
    public string MachineCode { get; init; } = string.Empty;
    public DateTime CreatedAtUtc { get; init; }
}
