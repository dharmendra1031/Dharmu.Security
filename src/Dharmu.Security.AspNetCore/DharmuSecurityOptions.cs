namespace Dharmu.Security.AspNetCore;

public sealed class DharmuSecurityOptions
{
    public string ProductCode { get; set; } = string.Empty;
    public string LicenseFilePath { get; set; } = "license/license.lic";
    public string PublicKeyFilePath { get; set; } = "license/public-key.pem";
    public IList<string> ExcludedPaths { get; } = new List<string>
    {
        "/license",
        "/health"
    };
}
