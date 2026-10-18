namespace Dharmu.Security.Core.Licensing;

public sealed record LicenseValidationResult(
    LicenseValidationStatus Status,
    LicensePayload? License = null)
{
    public bool IsValid => Status == LicenseValidationStatus.Valid;

    public static LicenseValidationResult Valid(LicensePayload license) =>
        new(LicenseValidationStatus.Valid, license);

    public static LicenseValidationResult Invalid(LicenseValidationStatus status) =>
        new(status);
}
