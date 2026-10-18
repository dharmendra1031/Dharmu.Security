using System.Security.Cryptography;
using System.Text.Json;
using Dharmu.Security.Core.Licensing;
using Dharmu.Security.Core.Secrets;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Dharmu.Security.AspNetCore.Licensing;

public sealed class LicenseClockGuard : ILicenseClockGuard
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly ISecretProtector _secretProtector;
    private readonly DharmuSecurityOptions _options;
    private readonly IHostEnvironment _environment;
    private readonly SemaphoreSlim _gate = new(1, 1);

    private LicenseRuntimeState? _state;
    private bool _stateLoaded;
    private DateTime _lastPersistedUtc;

    public LicenseClockGuard(
        ISecretProtector secretProtector,
        IOptions<DharmuSecurityOptions> options,
        IHostEnvironment environment)
    {
        _secretProtector = secretProtector;
        _options = options.Value;
        _environment = environment;
    }

    public async Task<LicenseClockResult> CheckAsync(
        LicensePayload license,
        DateTime utcNow,
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);

        try
        {
            if (utcNow.Add(_options.ClockRollbackTolerance) < license.IssuedAtUtc)
            {
                return LicenseClockResult.Invalid(LicenseClockStatus.RollbackDetected);
            }

            if (!_stateLoaded)
            {
                var loadResult = await LoadStateAsync(cancellationToken);
                if (!loadResult.IsValid)
                {
                    return loadResult;
                }

                _stateLoaded = true;
            }

            if (_state is null)
            {
                _state = new LicenseRuntimeState
                {
                    LicenseId = license.LicenseId,
                    ProductCode = license.ProductCode,
                    LastValidatedUtc = utcNow
                };

                await PersistStateAsync(cancellationToken);
                return LicenseClockResult.Valid();
            }

            if (!string.Equals(
                    _state.ProductCode,
                    license.ProductCode,
                    StringComparison.Ordinal))
            {
                return LicenseClockResult.Invalid(LicenseClockStatus.StateInvalid);
            }

            if (utcNow.Add(_options.ClockRollbackTolerance) < _state.LastValidatedUtc)
            {
                return LicenseClockResult.Invalid(LicenseClockStatus.RollbackDetected);
            }

            _state.LicenseId = license.LicenseId;

            if (utcNow > _state.LastValidatedUtc)
            {
                _state.LastValidatedUtc = utcNow;

                if (utcNow - _lastPersistedUtc >= _options.ClockStatePersistInterval)
                {
                    await PersistStateAsync(cancellationToken);
                }
            }

            return LicenseClockResult.Valid();
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<LicenseClockResult> LoadStateAsync(
        CancellationToken cancellationToken)
    {
        var path = ResolveStatePath();

        if (!File.Exists(path))
        {
            return LicenseClockResult.Valid();
        }

        try
        {
            var protectedState = await File.ReadAllTextAsync(path, cancellationToken);
            var json = _secretProtector.Unprotect(protectedState);

            _state = JsonSerializer.Deserialize<LicenseRuntimeState>(json, JsonOptions)
                ?? throw new InvalidDataException("License runtime state is empty.");

            if (_state.LastValidatedUtc == default ||
                string.IsNullOrWhiteSpace(_state.ProductCode))
            {
                return LicenseClockResult.Invalid(LicenseClockStatus.StateInvalid);
            }

            _lastPersistedUtc = _state.LastValidatedUtc;
            return LicenseClockResult.Valid();
        }
        catch (Exception exception) when (
            exception is FormatException or
            CryptographicException or
            JsonException or
            InvalidDataException)
        {
            return LicenseClockResult.Invalid(LicenseClockStatus.StateInvalid);
        }
    }

    private async Task PersistStateAsync(CancellationToken cancellationToken)
    {
        if (_state is null)
        {
            return;
        }

        var path = ResolveStatePath();
        var directory = Path.GetDirectoryName(path);

        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var json = JsonSerializer.Serialize(_state, JsonOptions);
        var protectedState = _secretProtector.Protect(json);
        var temporaryPath = $"{path}.tmp";

        await File.WriteAllTextAsync(
            temporaryPath,
            protectedState,
            cancellationToken);

        File.Move(temporaryPath, path, overwrite: true);
        _lastPersistedUtc = _state.LastValidatedUtc;
    }

    private string ResolveStatePath() =>
        Path.IsPathRooted(_options.RuntimeStateFilePath)
            ? _options.RuntimeStateFilePath
            : Path.Combine(_environment.ContentRootPath, _options.RuntimeStateFilePath);
}
