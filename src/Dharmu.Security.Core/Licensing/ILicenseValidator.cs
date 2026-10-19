namespace Dharmu.Security.Core.Licensing;

public interface ILicenseValidator
{
    LicenseValidationResult Validate(
        string licenseContent,
        IReadOnlyDictionary<string, string> trustedPublicKeys,
        string expectedProductCode,
        string currentMachineCode,
        DateTime utcNow);
}
