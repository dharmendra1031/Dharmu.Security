using Dharmu.Security.Core.Licensing;
using Dharmu.Security.Core.Machine;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Dharmu.Security.AspNetCore;

public sealed class LicenseMiddleware
{
    private readonly RequestDelegate _next;

    public LicenseMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(
        HttpContext context,
        ILicenseValidator validator,
        IMachineIdentityProvider machineIdentityProvider,
        IOptions<DharmuSecurityOptions> options,
        IHostEnvironment environment)
    {
        var settings = options.Value;

        if (IsExcluded(context.Request.Path, settings.ExcludedPaths))
        {
            await _next(context);
            return;
        }

        var licensePath = ResolvePath(environment.ContentRootPath, settings.LicenseFilePath);
        var publicKeyPath = ResolvePath(environment.ContentRootPath, settings.PublicKeyFilePath);

        if (!File.Exists(licensePath) || !File.Exists(publicKeyPath))
        {
            await RejectAsync(context, "License is not configured.");
            return;
        }

        var licenseContent = await File.ReadAllTextAsync(licensePath, context.RequestAborted);
        var publicKeyPem = await File.ReadAllTextAsync(publicKeyPath, context.RequestAborted);

        var result = validator.Validate(
            licenseContent,
            publicKeyPem,
            settings.ProductCode,
            machineIdentityProvider.GetMachineCode(),
            DateTime.UtcNow);

        if (!result.IsValid)
        {
            await RejectAsync(context, $"License validation failed: {result.Status}.");
            return;
        }

        await _next(context);
    }

    private static bool IsExcluded(PathString path, IEnumerable<string> excludedPaths) =>
        excludedPaths.Any(excluded =>
            path.StartsWithSegments(new PathString(excluded), StringComparison.OrdinalIgnoreCase));

    private static string ResolvePath(string contentRootPath, string path) =>
        Path.IsPathRooted(path) ? path : Path.Combine(contentRootPath, path);

    private static async Task RejectAsync(HttpContext context, string message)
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        context.Response.ContentType = "text/plain";
        await context.Response.WriteAsync(message);
    }
}
