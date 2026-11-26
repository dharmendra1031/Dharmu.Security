namespace Dharmu.Security.Core.Licensing;

public sealed class LicensePayload
{
    public int SchemaVersion { get; init; } = 1;
    public long Revision { get; init; }
    public long LicenseId { get; init; }
    public long? ReplacesLicenseId { get; init; }
    public long CustomerId { get; init; }
    public long ProductId { get; init; }
    public string ProductCode { get; init; } = string.Empty;
    public string MachineCode { get; init; } = string.Empty;
    public DateTime IssuedAtUtc { get; init; }
    public DateTime ValidFromUtc { get; init; }
    public DateTime? ExpiresAtUtc { get; init; }
    public bool IsLifetime { get; init; }
    public bool IsRevoked { get; init; }
}
