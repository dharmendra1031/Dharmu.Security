namespace Dharmu.Security.AspNetCore;

public sealed class DharmuSecurityOptions
{
    public string ProductCode { get; set; } = string.Empty;
    public string LicenseFilePath { get; set; } = "license/license.lic";
    public string PublicKeyFilePath { get; set; } = "license/public-key.pem";
    public string RuntimeStateFilePath { get; set; } = "license/runtime.state";
    public TimeSpan ClockRollbackTolerance { get; set; } = TimeSpan.FromMinutes(5);
    public TimeSpan ClockStatePersistInterval { get; set; } = TimeSpan.FromMinutes(5);

    public IList<string> ExcludedPaths { get; } = new List<string>
    {
        "/license",
        "/health"
    };
}
