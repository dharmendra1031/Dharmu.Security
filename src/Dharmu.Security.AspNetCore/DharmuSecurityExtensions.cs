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
            .ValidateOnStart();

        services.AddSingleton<ILicenseValidator, EcdsaLicenseValidator>();
        services.AddSingleton<IMachineIdentityProvider, WindowsMachineIdentityProvider>();
        services.AddSingleton<IActivationRequestGenerator, ActivationRequestGenerator>();
        services.AddSingleton<ISecretProtector, DpapiSecretProtector>();

        return services;
    }

    public static IApplicationBuilder UseDharmuLicenseProtection(
        this IApplicationBuilder app)
    {
        _ = app.ApplicationServices.GetRequiredService<IOptions<DharmuSecurityOptions>>();
        return app.UseMiddleware<LicenseMiddleware>();
    }
}
