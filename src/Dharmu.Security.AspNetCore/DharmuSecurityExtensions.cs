using Dharmu.Security.AspNetCore.Licensing;
using Dharmu.Security.Core.Licensing;
using Dharmu.Security.Core.Machine;
using Dharmu.Security.Core.Secrets;
using Dharmu.Security.Windows.Machine;
using Dharmu.Security.Windows.Secrets;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Dharmu.Security.AspNetCore;

public static class DharmuSecurityExtensions
{
    public static IServiceCollection AddDharmuSecurity(
        this IServiceCollection services,
        Action<DharmuSecurityOptions> configure)
    {
        services.AddOptions<DharmuSecurityOptions>()
            .Configure(configure)
            .Validate(
                options => !string.IsNullOrWhiteSpace(options.ProductCode),
                "ProductCode is required.")
            .Validate(
                options => options.TrustedPublicKeys.Count > 0 &&
                           options.TrustedPublicKeys.All(
                               item => !string.IsNullOrWhiteSpace(item.Key) &&
                                       !string.IsNullOrWhiteSpace(item.Value)),
                "At least one trusted public signing key is required.")
            .Validate(
                options => options.ClockRollbackTolerance >= TimeSpan.Zero,
                "ClockRollbackTolerance cannot be negative.")
            .Validate(
                options => options.ClockStatePersistInterval > TimeSpan.Zero,
                "ClockStatePersistInterval must be greater than zero.")
            .ValidateOnStart();

        services.AddSingleton<ILicenseValidator, EcdsaLicenseValidator>();
        services.AddSingleton<IMachineIdentityProvider, WindowsMachineIdentityProvider>();
        services.AddSingleton<IActivationRequestGenerator, ActivationRequestGenerator>();
        services.AddSingleton<ISecretProtector, DpapiSecretProtector>();
        services.AddSingleton<ILicenseClockGuard, LicenseClockGuard>();

        return services;
    }

    public static IApplicationBuilder UseDharmuLicenseProtection(
        this IApplicationBuilder app)
    {
        _ = app.ApplicationServices.GetRequiredService<IOptions<DharmuSecurityOptions>>();
        return app.UseMiddleware<LicenseMiddleware>();
    }
}
