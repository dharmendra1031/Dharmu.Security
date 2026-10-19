namespace Dharmu.Security.Core.Licensing;

public enum LicenseValidationStatus
{
    Valid = 0,
    InvalidFormat = 1,
    InvalidSignature = 2,
    ProductMismatch = 3,
    MachineMismatch = 4,
    NotYetValid = 5,
    Expired = 6,
    UnknownSigningKey = 7
}
