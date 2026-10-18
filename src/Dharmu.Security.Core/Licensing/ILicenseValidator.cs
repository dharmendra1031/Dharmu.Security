namespace Dharmu.Security.Core.Licensing;

public interface ILicenseValidator
{
    LicenseValidationResult Validate(
        string licenseContent,
        string publicKeyPem,
        string expectedProductCode,
        string currentMachineCode,
        DateTime utcNow);
}
