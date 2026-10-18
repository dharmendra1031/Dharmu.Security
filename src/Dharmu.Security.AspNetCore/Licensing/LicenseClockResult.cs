namespace Dharmu.Security.AspNetCore.Licensing;

public sealed record LicenseClockResult(LicenseClockStatus Status)
{
    public bool IsValid => Status == LicenseClockStatus.Valid;

    public static LicenseClockResult Valid() =>
        new(LicenseClockStatus.Valid);

    public static LicenseClockResult Invalid(LicenseClockStatus status) =>
        new(status);
}
