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
    private bool _dirty;
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
            if (!_stateLoaded)
            {
                var loadResult = await LoadStateAsync(cancellationToken);
                if (!loadResult.IsValid)
                {
                    return loadResult;
                }

                _stateLoaded = true;
            }

            if (_state is not null)
            {
                if ((_lastPersistedUtc != default && !File.Exists(ResolveStatePath())) ||
                    !string.Equals(_state.ProductCode, license.ProductCode, StringComparison.Ordinal))
                {
                    return LicenseClockResult.Invalid(LicenseClockStatus.StateInvalid);
                }

                // An unsuccessful revocation or revision write must be retried
                // before another license can be accepted.
                if (_dirty)
                {
                    await PersistStateAsync(_state, cancellationToken);
                }
            }

            // A verified revocation is recorded even if its validity has expired
            // or the local clock is incorrect. It never grants application access.
            if (!license.IsRevoked &&
                (utcNow.Add(_options.ClockRollbackTolerance) < license.IssuedAtUtc ||
                 (_state is not null &&
                  utcNow.Add(_options.ClockRollbackTolerance) < _state.LastValidatedUtc)))
            {
                return LicenseClockResult.Invalid(LicenseClockStatus.RollbackDetected);
            }

            if (_state is null)
            {
                _state = new LicenseRuntimeState
                {
                    ProductCode = license.ProductCode,
                    LastValidatedUtc = utcNow
                };
                _dirty = true;
            }

            if (!_state.Revisions.TryGetValue(license.LicenseId, out var revision))
            {
                revision = new LicenseRevisionState { Revision = license.Revision };
                _state.Revisions.Add(license.LicenseId, revision);
                _dirty = true;
            }

            if (license.IsRevoked)
            {
                if (!revision.Revoked || license.Revision > revision.Revision)
                {
                    revision.Revoked = true;
                    revision.Revision = Math.Max(revision.Revision, license.Revision);
                    _dirty = true;
                }

                if (_dirty)
                {
                    await PersistStateAsync(_state, cancellationToken);
                }

                return LicenseClockResult.Invalid(LicenseClockStatus.Revoked);
            }

            if (revision.Revoked)
            {
                return LicenseClockResult.Invalid(LicenseClockStatus.Revoked);
            }

            if (license.Revision < revision.Revision)
            {
                return LicenseClockResult.Invalid(LicenseClockStatus.StaleRevision);
            }

            if (license.Revision > revision.Revision)
            {
                revision.Revision = license.Revision;
                _dirty = true;
            }

            if (utcNow > _state.LastValidatedUtc)
            {
                _state.LastValidatedUtc = utcNow;
            }

            if (_dirty || _state.LastValidatedUtc - _lastPersistedUtc >= _options.ClockStatePersistInterval)
            {
                _dirty = true;
                await PersistStateAsync(_state, cancellationToken);
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

            var state = JsonSerializer.Deserialize<LicenseRuntimeState>(json, JsonOptions)
                ?? throw new InvalidDataException("License runtime state is empty.");

            if (state.LastValidatedUtc == default ||
                string.IsNullOrWhiteSpace(state.ProductCode) ||
                state.Revisions is null ||
                state.Revisions.Any(x => x.Key <= 0 || x.Value is null || x.Value.Revision < 0))
            {
                return LicenseClockResult.Invalid(LicenseClockStatus.StateInvalid);
            }

            _state = state;
            _lastPersistedUtc = state.LastValidatedUtc;
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

    private async Task PersistStateAsync(
        LicenseRuntimeState state,
        CancellationToken cancellationToken)
    {
        var path = ResolveStatePath();
        var directory = Path.GetDirectoryName(path);

        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var json = JsonSerializer.Serialize(state, JsonOptions);
        var protectedState = _secretProtector.Protect(json);
        var temporaryPath = $"{path}.tmp";

        await File.WriteAllTextAsync(
            temporaryPath,
            protectedState,
            cancellationToken);

        File.Move(temporaryPath, path, overwrite: true);
        _lastPersistedUtc = state.LastValidatedUtc;
        _dirty = false;
    }

    private string ResolveStatePath() =>
        Path.IsPathRooted(_options.RuntimeStateFilePath)
            ? _options.RuntimeStateFilePath
            : Path.Combine(_environment.ContentRootPath, _options.RuntimeStateFilePath);
}
