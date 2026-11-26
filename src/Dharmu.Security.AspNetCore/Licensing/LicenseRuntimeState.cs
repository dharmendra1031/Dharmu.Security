namespace Dharmu.Security.AspNetCore.Licensing;

internal sealed class LicenseRuntimeState
{
    public string ProductCode { get; init; } = string.Empty;
    public DateTime LastValidatedUtc { get; set; }
    public Dictionary<long, LicenseRevisionState> Revisions { get; init; } = new();
}

internal sealed class LicenseRevisionState
{
    public long Revision { get; set; }
    public bool Revoked { get; set; }
}
