namespace Dharmu.Security.AspNetCore.Licensing;

public enum LicenseClockStatus
{
    Valid = 0,
    RollbackDetected = 1,
    StateInvalid = 2,
    StaleRevision = 3,
    Revoked = 4
}
