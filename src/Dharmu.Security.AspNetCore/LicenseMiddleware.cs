using System.Diagnostics;
using System.Text;
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
    private const int MaxLicenseFileBytes = 64 * 1024;
    private static readonly UTF8Encoding LicenseEncoding = new(false, true);
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

        if (IsExcluded(context.Request, settings.ExcludedPaths))
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
                ClearCache();
                _logger.LogWarning("License file is not configured.");
                await RejectAsync(context);
                return;
            }

            var licenseContent = await ReadLicenseAsync(licensePath, context.RequestAborted);

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
            ClearCache();
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
                string.Equals(cached.ProductCode, settings.ProductCode, StringComparison.Ordinal) &&
                cached.TrustedKeys.Count == settings.TrustedPublicKeys.Count &&
                cached.TrustedKeys.All(pair => settings.TrustedPublicKeys.TryGetValue(pair.Key, out var key) &&
                    string.Equals(pair.Value, key, StringComparison.Ordinal)) &&
                cached.RequireTpm == settings.RequireTpmDeviceIdentity &&
                ReferenceEquals(cached.Machine, machineIdentityProvider) &&
                ReferenceEquals(cached.Validator, validator) &&
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
            var productCode = settings.ProductCode;
            var trustedKeys = new Dictionary<string, string>(settings.TrustedPublicKeys, StringComparer.Ordinal);
            var requireTpm = settings.RequireTpmDeviceIdentity;
            var result = validator.Validate(
                content, trustedKeys, productCode,
                machineIdentityProvider.GetMachineCode(), utcNow);

            if (result.IsValid && result.License is { } payload)
            {
                _cachedLicense = new CachedLicense(
                    content, productCode, trustedKeys, requireTpm, machineIdentityProvider,
                    validator, payload, Stopwatch.GetTimestamp());
            }

            return result;
        }
    }

    private sealed record CachedLicense(
        string Content,
        string ProductCode,
        IReadOnlyDictionary<string, string> TrustedKeys,
        bool RequireTpm,
        IMachineIdentityProvider Machine,
        ILicenseValidator Validator,
        LicensePayload Payload,
        long ValidatedAt);

    private void ClearCache()
    {
        lock (_validationLock)
        {
            _cachedLicense = null;
        }
    }

    private static async Task<string> ReadLicenseAsync(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.Read | FileShare.Delete, 4096, useAsync: true);
        var length = stream.Length;
        if (length <= 0 || length > MaxLicenseFileBytes)
        {
            throw new InvalidDataException("License file size is invalid.");
        }

        var bytes = new byte[(int)length];
        await stream.ReadExactlyAsync(bytes, cancellationToken);
        if (stream.ReadByte() != -1)
        {
            throw new InvalidDataException("License file changed during reading.");
        }

        var content = LicenseEncoding.GetString(bytes);
        return content.Length > 0 && content[0] == '\uFEFF' ? content[1..] : content;
    }

    private static bool IsExcluded(
        HttpRequest request,
        IEnumerable<string> excludedPaths) =>
        (HttpMethods.IsGet(request.Method) || HttpMethods.IsHead(request.Method)) &&
        excludedPaths.Any(excluded =>
            string.Equals(request.Path.Value, excluded, StringComparison.OrdinalIgnoreCase));

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
