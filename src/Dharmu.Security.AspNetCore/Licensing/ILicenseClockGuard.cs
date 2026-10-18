using Dharmu.Security.Core.Licensing;

namespace Dharmu.Security.AspNetCore.Licensing;

public interface ILicenseClockGuard
{
    Task<LicenseClockResult> CheckAsync(
        LicensePayload license,
        DateTime utcNow,
        CancellationToken cancellationToken = default);
}
