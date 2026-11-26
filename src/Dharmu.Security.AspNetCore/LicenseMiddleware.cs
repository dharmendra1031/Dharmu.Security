using System.Diagnostics;
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
    private static readonly TimeSpan RevalidationInterval = TimeSpan.FromSeconds(30);
    private readonly object _validationLock = new();
    private CachedLicense? _cachedLicense;
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

            var result = ValidateLicense(
                licenseContent, validator, machineIdentityProvider, settings, utcNow);

            if (result.License is null || (!result.IsValid && result.Status is not (LicenseValidationStatus.Revoked or LicenseValidationStatus.Expired)))
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

            if (!clockResult.IsValid || !result.IsValid)
            {
                _logger.LogWarning(
                    "License enforcement rejected license status {LicenseStatus}, clock status {ClockStatus}.",
                    result.Status, clockResult.Status);

                await RejectAsync(context);
                return;
            }
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
            return;
        }

        // Application exceptions belong to the application's error pipeline.
        await _next(context);
    }

    private LicenseValidationResult ValidateLicense(
        string content,
        ILicenseValidator validator,
        IMachineIdentityProvider machineIdentityProvider,
        DharmuSecurityOptions settings,
        DateTime utcNow)
    {
        lock (_validationLock)
        {
            var cached = _cachedLicense;
            if (cached is not null &&
                ReferenceEquals(cached.Settings, settings) &&
                string.Equals(cached.Content, content, StringComparison.Ordinal) &&
                Stopwatch.GetElapsedTime(cached.ValidatedAt) < RevalidationInterval &&
                utcNow >= cached.Payload.ValidFromUtc &&
                (cached.Payload.IsLifetime ||
                 (cached.Payload.ExpiresAtUtc is DateTime expiry && utcNow < expiry)))
            {
                return LicenseValidationResult.Valid(cached.Payload);
            }

            // A changed file, failed check or expired cache must never fall back
            // to an earlier successful result.
            _cachedLicense = null;
            var result = validator.Validate(
                content, settings.TrustedPublicKeys, settings.ProductCode,
                machineIdentityProvider.GetMachineCode(), utcNow);

            if (result.IsValid && result.License is { } payload)
            {
                _cachedLicense = new CachedLicense(
                    content, settings, payload, Stopwatch.GetTimestamp());
            }

            return result;
        }
    }

    private sealed record CachedLicense(
        string Content,
        DharmuSecurityOptions Settings,
        LicensePayload Payload,
        long ValidatedAt);

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
