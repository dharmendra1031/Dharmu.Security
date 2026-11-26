using System.Diagnostics;
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
    private string? _persistedContent;
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
            // Serialize read/merge/write across cooperating worker processes.
            using var processLock = await AcquireProcessLockAsync(cancellationToken);
            var loadResult = await LoadStateAsync(cancellationToken);
            if (!loadResult.IsValid)
            {
                return loadResult;
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
                  (utcNow.Add(_options.ClockRollbackTolerance) < _state.LastValidatedUtc ||
                   (!license.IsLifetime && license.ExpiresAtUtc is DateTime expiredAt &&
                    _state.LastValidatedUtc >= expiredAt && utcNow < expiredAt)))))
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

            // Persist the first observed expiry immediately, even inside the normal write interval.
            var observedExpiry = !license.IsLifetime && license.ExpiresAtUtc is DateTime expiry &&
                utcNow >= expiry && _lastPersistedUtc < expiry;
            if (_dirty || observedExpiry || _state.LastValidatedUtc - _lastPersistedUtc >= _options.ClockStatePersistInterval)
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
            return _persistedContent is not null || File.Exists(path + ".initialized")
                ? LicenseClockResult.Invalid(LicenseClockStatus.StateInvalid)
                : LicenseClockResult.Valid();
        }

        try
        {
            var protectedState = await File.ReadAllTextAsync(path, cancellationToken);
            if (string.Equals(protectedState, _persistedContent, StringComparison.Ordinal))
            {
                EnsureInitializationMarker(path);
                return LicenseClockResult.Valid();
            }

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

            if (_state is not null)
            {
                if (!string.Equals(_state.ProductCode, state.ProductCode, StringComparison.Ordinal))
                {
                    return LicenseClockResult.Invalid(LicenseClockStatus.StateInvalid);
                }

                // Never overwrite a newer observation from another worker, or
                // discard a pending local observation after a failed write.
                foreach (var (id, local) in _state.Revisions)
                {
                    if (!state.Revisions.TryGetValue(id, out var stored))
                    {
                        state.Revisions.Add(id, local);
                        _dirty = true;
                    }
                    else if (local.Revision > stored.Revision || (local.Revoked && !stored.Revoked))
                    {
                        stored.Revision = Math.Max(local.Revision, stored.Revision);
                        stored.Revoked |= local.Revoked;
                        _dirty = true;
                    }
                }
            }

            EnsureInitializationMarker(path);
            _lastPersistedUtc = state.LastValidatedUtc;
            if (_state is not null && _state.LastValidatedUtc > state.LastValidatedUtc)
            {
                state.LastValidatedUtc = _state.LastValidatedUtc;
            }

            _state = state;
            _persistedContent = protectedState;
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
        var temporaryPath = $"{path}.{Guid.NewGuid():N}.tmp";

        try
        {
            await using (var stream = new FileStream(temporaryPath, FileMode.Create,
                FileAccess.Write, FileShare.None, 4096, useAsync: true))
            {
                var bytes = System.Text.Encoding.UTF8.GetBytes(protectedState);
                await stream.WriteAsync(bytes, cancellationToken);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporaryPath, path, overwrite: true);
            EnsureInitializationMarker(path);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
        _persistedContent = protectedState;
        _lastPersistedUtc = state.LastValidatedUtc;
        _dirty = false;
    }

    private async Task<FileStream> AcquireProcessLockAsync(CancellationToken cancellationToken)
    {
        var path = ResolveStatePath();
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        var started = Stopwatch.GetTimestamp();
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return new FileStream(path + ".lock", FileMode.OpenOrCreate,
                    FileAccess.ReadWrite, FileShare.None);
            }
            catch (IOException exception) when (
                (exception.HResult & 0xFFFF) is 32 or 33 &&
                Stopwatch.GetElapsedTime(started) < TimeSpan.FromSeconds(2))
            {
                await Task.Delay(20, cancellationToken);
            }
        }
    }

    // This local sidecar detects isolated state-file loss, not administrator rollback
    // of the whole directory. It is deliberately not treated as a trusted hardware anchor.
    private static void EnsureInitializationMarker(string path)
    {
        var marker = path + ".initialized";
        if (!File.Exists(marker))
        {
            using var stream = new FileStream(marker, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            stream.WriteByte(1);
            stream.Flush(flushToDisk: true);
        }
    }

    private string ResolveStatePath() =>
        Path.IsPathRooted(_options.RuntimeStateFilePath)
            ? _options.RuntimeStateFilePath
            : Path.Combine(_environment.ContentRootPath, _options.RuntimeStateFilePath);
}
