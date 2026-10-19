using Dharmu.Security.AspNetCore.Licensing;
using Dharmu.Security.Core.Licensing;
using Dharmu.Security.Core.Machine;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Dharmu.Security.AspNetCore;

public sealed class LicenseMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<LicenseMiddleware> _logger;

    public LicenseMiddleware(
        RequestDelegate next,
        ILogger<LicenseMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(
        HttpContext context,
        ILicenseValidator validator,
        IMachineIdentityProvider machineIdentityProvider,
        ILicenseClockGuard clockGuard,
        IOptions<DharmuSecurityOptions> options,
        IHostEnvironment environment)
    {
        var settings = options.Value;

        if (IsExcluded(context.Request.Path, settings.ExcludedPaths))
        {
            await _next(context);
            return;
        }

        try
        {
            var licensePath = ResolvePath(
                environment.ContentRootPath,
                settings.LicenseFilePath);

            if (!File.Exists(licensePath))
            {
                _logger.LogWarning("License file is not configured.");
                await RejectAsync(context);
                return;
            }

            var licenseContent = await File.ReadAllTextAsync(
                licensePath,
                context.RequestAborted);

            var utcNow = DateTime.UtcNow;

            var result = validator.Validate(
                licenseContent,
                new Dictionary<string, string>(
                    settings.TrustedPublicKeys,
                    StringComparer.Ordinal),
                settings.ProductCode,
                machineIdentityProvider.GetMachineCode(),
                utcNow);

            if (!result.IsValid || result.License is null)
            {
                _logger.LogWarning(
                    "License validation failed with status {Status}.",
                    result.Status);

                await RejectAsync(context);
                return;
            }

            var clockResult = await clockGuard.CheckAsync(
                result.License,
                utcNow,
                context.RequestAborted);

            if (!clockResult.IsValid)
            {
                _logger.LogWarning(
                    "License clock validation failed with status {Status}.",
                    clockResult.Status);

                await RejectAsync(context);
                return;
            }

            await _next(context);
        }
        catch (OperationCanceledException) when (
            context.RequestAborted.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            _logger.LogError(
                exception,
                "License enforcement failed unexpectedly.");

            await RejectAsync(context);
        }
    }

    private static bool IsExcluded(
        PathString path,
        IEnumerable<string> excludedPaths) =>
        excludedPaths.Any(excluded =>
            path.StartsWithSegments(
                new PathString(excluded),
                StringComparison.OrdinalIgnoreCase));

    private static string ResolvePath(
        string contentRootPath,
        string path) =>
        Path.IsPathRooted(path)
            ? path
            : Path.Combine(contentRootPath, path);

    private static async Task RejectAsync(HttpContext context)
    {
        if (context.Response.HasStarted)
        {
            return;
        }

        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        context.Response.ContentType = "text/plain";

        await context.Response.WriteAsync(
            "License validation failed. Please contact support.");
    }
}
