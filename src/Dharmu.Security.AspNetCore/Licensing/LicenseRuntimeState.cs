namespace Dharmu.Security.AspNetCore.Licensing;

internal sealed class LicenseRuntimeState
{
    public long LicenseId { get; init; }
    public string ProductCode { get; init; } = string.Empty;
    public DateTime LastValidatedUtc { get; set; }
}
