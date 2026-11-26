using Dharmu.Security.AspNetCore;
using Dharmu.Security.AspNetCore.Licensing;
using Dharmu.Security.Core.Licensing;
using Dharmu.Security.Core.Machine;
using Dharmu.Security.Core.Secrets;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Dharmu.Security.Tests;

public sealed class RuntimeProtectionTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
    private readonly DateTime _now = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    public RuntimeProtectionTests() => Directory.CreateDirectory(_directory);

    [Fact]
    public async Task DeletedRuntimeState_IsRejectedWhileRunning()
    {
        var guard = CreateGuard(new TestProtector());
        var license = CreateLicense();
        Assert.True((await guard.CheckAsync(license, _now)).IsValid);
        File.Delete(Path.Combine(_directory, "runtime.state"));
        Assert.False((await guard.CheckAsync(license, _now.AddMinutes(1))).IsValid);
    }

    [Fact]
    public async Task DeletedRuntimeState_IsRejectedAfterRestartWhenMarkerRemains()
    {
        var protector = new TestProtector();
        var license = CreateLicense();
        Assert.True((await CreateGuard(protector).CheckAsync(license, _now)).IsValid);
        File.Delete(Path.Combine(_directory, "runtime.state"));
        Assert.Equal(LicenseClockStatus.StateInvalid,
            (await CreateGuard(protector).CheckAsync(license, _now)).Status);
    }

    [Fact]
    public async Task ExpiryObservation_IsPersistedImmediatelyAndCannotRollBackWithinTolerance()
    {
        var protector = new TestProtector();
        var guard = CreateGuard(protector);
        var license = new LicensePayload
        {
            LicenseId = 1, ProductCode = "TEST", IssuedAtUtc = _now.AddDays(-1),
            ValidFromUtc = _now.AddDays(-1), ExpiresAtUtc = _now.AddMinutes(1)
        };
        Assert.True((await guard.CheckAsync(license, _now)).IsValid);
        Assert.True((await guard.CheckAsync(license, _now.AddMinutes(1))).IsValid);
        Assert.Equal(LicenseClockStatus.RollbackDetected,
            (await CreateGuard(protector).CheckAsync(license, _now.AddSeconds(30))).Status);
    }

    [Fact]
    public async Task FailedFirstWrite_MustBeRetriedBeforeAccepting()
    {
        var protector = new TestProtector { Fail = true };
        var guard = CreateGuard(protector);
        var license = CreateLicense();
        await Assert.ThrowsAsync<IOException>(() => guard.CheckAsync(license, _now));
        await Assert.ThrowsAsync<IOException>(() => guard.CheckAsync(license, _now));
        protector.Fail = false;
        Assert.True((await guard.CheckAsync(license, _now)).IsValid);
        Assert.True(File.Exists(Path.Combine(_directory, "runtime.state")));
    }

    [Fact]
    public async Task FailedPeriodicWrite_IsRetriedAtSameTimestamp()
    {
        var protector = new TestProtector();
        var guard = CreateGuard(protector);
        var license = CreateLicense();
        Assert.True((await guard.CheckAsync(license, _now)).IsValid);
        protector.Fail = true;
        await Assert.ThrowsAsync<IOException>(() => guard.CheckAsync(license, _now.AddMinutes(6)));
        await Assert.ThrowsAsync<IOException>(() => guard.CheckAsync(license, _now.AddMinutes(6)));
        protector.Fail = false;
        Assert.True((await guard.CheckAsync(license, _now.AddMinutes(6))).IsValid);
        Assert.False((await CreateGuard(protector).CheckAsync(license, _now)).IsValid);
    }

    [Fact]
    public async Task DownstreamException_IsNotConvertedToLicenseFailure()
    {
        await File.WriteAllTextAsync(Path.Combine(_directory, "license.lic"), "test");
        var options = CreateOptions();
        var middleware = new LicenseMiddleware(
            _ => throw new InvalidOperationException("application failure"),
            NullLogger<LicenseMiddleware>.Instance);
        var context = new DefaultHttpContext();
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            middleware.InvokeAsync(context, new TestValidator(CreateLicense()),
                new TestMachine(), CreateGuard(new TestProtector()), options, CreateEnvironment()));
        Assert.Equal("application failure", exception.Message);
    }

    [Fact]
    public async Task RevisionRollback_IsRejectedAfterRestart()
    {
        var protector = new TestProtector();
        var guard = CreateGuard(protector);
        Assert.True((await guard.CheckAsync(CreateLicense(), _now)).IsValid);
        Assert.True((await guard.CheckAsync(CreateLicense(2), _now)).IsValid);
        guard = CreateGuard(protector);
        Assert.Equal(LicenseClockStatus.StaleRevision, (await guard.CheckAsync(CreateLicense(1), _now)).Status);
        Assert.Equal(LicenseClockStatus.StaleRevision, (await guard.CheckAsync(CreateLicense(), _now)).Status);
        Assert.True((await guard.CheckAsync(CreateLicense(2), _now)).IsValid);
    }

    [Fact]
    public async Task Revocation_IsTerminalAfterRestartAndReplacementLicense()
    {
        var protector = new TestProtector();
        var guard = CreateGuard(protector);
        Assert.True((await guard.CheckAsync(CreateLicense(1), _now)).IsValid);
        Assert.Equal(LicenseClockStatus.Revoked, (await guard.CheckAsync(CreateLicense(2, true), _now)).Status);
        guard = CreateGuard(protector);
        Assert.True((await guard.CheckAsync(CreateLicense(1, id: 2), _now)).IsValid);
        Assert.Equal(LicenseClockStatus.Revoked, (await guard.CheckAsync(CreateLicense(3), _now)).Status);
        Assert.Equal(LicenseClockStatus.Revoked, (await guard.CheckAsync(CreateLicense(), _now)).Status);
    }

    [Fact]
    public async Task IndependentGuards_ObserveRevisionAndRevocationWithoutRestart()
    {
        var first = CreateGuard(new TestProtector());
        var second = CreateGuard(new TestProtector());
        Assert.True((await first.CheckAsync(CreateLicense(1), _now)).IsValid);
        Assert.True((await second.CheckAsync(CreateLicense(1), _now)).IsValid);
        Assert.True((await first.CheckAsync(CreateLicense(2), _now)).IsValid);
        Assert.Equal(LicenseClockStatus.StaleRevision,
            (await second.CheckAsync(CreateLicense(1), _now)).Status);
        Assert.Equal(LicenseClockStatus.Revoked,
            (await second.CheckAsync(CreateLicense(3, true), _now)).Status);
        Assert.Equal(LicenseClockStatus.Revoked,
            (await first.CheckAsync(CreateLicense(2), _now)).Status);
    }

    [Fact]
    public async Task ConcurrentGuards_DoNotLoseRevocationHistory()
    {
        var first = CreateGuard(new TestProtector());
        var second = CreateGuard(new TestProtector());
        var results = await Task.WhenAll(
            first.CheckAsync(CreateLicense(2, true, 1), _now),
            second.CheckAsync(CreateLicense(2, true, 2), _now));
        Assert.All(results, result => Assert.Equal(LicenseClockStatus.Revoked, result.Status));
        var restarted = CreateGuard(new TestProtector());
        Assert.Equal(LicenseClockStatus.Revoked,
            (await restarted.CheckAsync(CreateLicense(1, id: 1), _now)).Status);
        Assert.Equal(LicenseClockStatus.Revoked,
            (await restarted.CheckAsync(CreateLicense(1, id: 2), _now)).Status);
    }

    [Fact]
    public async Task FailedRevocationWrite_BlocksOldLicenseUntilDurable()
    {
        var protector = new TestProtector();
        var guard = CreateGuard(protector);
        Assert.True((await guard.CheckAsync(CreateLicense(1), _now)).IsValid);
        protector.Fail = true;
        await Assert.ThrowsAsync<IOException>(() => guard.CheckAsync(CreateLicense(2, true), _now));
        await Assert.ThrowsAsync<IOException>(() => guard.CheckAsync(CreateLicense(1), _now));
        protector.Fail = false;
        Assert.Equal(LicenseClockStatus.Revoked, (await guard.CheckAsync(CreateLicense(1), _now)).Status);
        Assert.Equal(LicenseClockStatus.Revoked, (await CreateGuard(protector).CheckAsync(CreateLicense(1), _now)).Status);
    }

    [Fact]
    public async Task UnchangedLicense_ReusesSignatureCheckButChangesAreVerified()
    {
        var path = Path.Combine(_directory, "license.lic");
        await File.WriteAllTextAsync(path, "original");
        var options = CreateOptions();
        var validator = new TestValidator(CreateLicense());
        var machine = new TestMachine();
        var guard = CreateGuard(new TestProtector());
        var environment = CreateEnvironment();
        var calls = 0;
        var middleware = new LicenseMiddleware(
            _ => { calls++; return Task.CompletedTask; },
            NullLogger<LicenseMiddleware>.Instance);

        for (var i = 0; i < 5; i++)
        {
            await middleware.InvokeAsync(new DefaultHttpContext(), validator, machine,
                guard, options, environment);
        }

        Assert.Equal(5, calls);
        Assert.Equal(1, validator.Calls);
        Assert.Equal(1, machine.Calls);

        // Equal-length content changes must also force validation.
        await File.WriteAllTextAsync(path, "modified");
        validator.Reject = true;
        var rejected = new DefaultHttpContext();
        await middleware.InvokeAsync(rejected, validator, machine, guard, options, environment);
        Assert.Equal(403, rejected.Response.StatusCode);
        Assert.Equal(2, validator.Calls);
        Assert.Equal(5, calls);

        File.Delete(path);
        var missing = new DefaultHttpContext();
        await middleware.InvokeAsync(missing, validator, machine, guard, options, environment);
        Assert.Equal(403, missing.Response.StatusCode);
        Assert.Equal(5, calls);
    }

    [Fact]
    public async Task CachedLicense_DoesNotBypassRuntimeStateLoss()
    {
        await File.WriteAllTextAsync(Path.Combine(_directory, "license.lic"), "original");
        var options = CreateOptions();
        var validator = new TestValidator(CreateLicense());
        var machine = new TestMachine();
        var guard = CreateGuard(new TestProtector());
        var environment = CreateEnvironment();
        var middleware = new LicenseMiddleware(_ => Task.CompletedTask,
            NullLogger<LicenseMiddleware>.Instance);
        await middleware.InvokeAsync(new DefaultHttpContext(), validator, machine, guard, options, environment);
        File.Delete(Path.Combine(_directory, "runtime.state"));
        var rejected = new DefaultHttpContext();
        await middleware.InvokeAsync(rejected, validator, machine, guard, options, environment);
        Assert.Equal(403, rejected.Response.StatusCode);
        Assert.Equal(1, validator.Calls);
    }

    [Fact]
    public async Task CachedLicense_RevalidatesWhenTrustedKeyOrProductChanges()
    {
        await File.WriteAllTextAsync(Path.Combine(_directory, "license.lic"), "original");
        var options = CreateOptions();
        options.Value.TrustedPublicKeys["issuer-v1"] = "first";
        var validator = new TestValidator(CreateLicense());
        var machine = new TestMachine();
        var guard = CreateGuard(new TestProtector());
        var environment = CreateEnvironment();
        var middleware = new LicenseMiddleware(_ => Task.CompletedTask,
            NullLogger<LicenseMiddleware>.Instance);
        await middleware.InvokeAsync(new DefaultHttpContext(), validator, machine, guard, options, environment);
        options.Value.TrustedPublicKeys["issuer-v1"] = "changed";
        await middleware.InvokeAsync(new DefaultHttpContext(), validator, machine, guard, options, environment);
        Assert.Equal(2, validator.Calls);
        options.Value.ProductCode = "OTHER";
        validator.Reject = true;
        var rejected = new DefaultHttpContext();
        await middleware.InvokeAsync(rejected, validator, machine, guard, options, environment);
        Assert.Equal(3, validator.Calls);
        Assert.Equal(403, rejected.Response.StatusCode);
    }

    [Fact]
    public async Task OversizedLicense_IsRejectedBeforeValidation()
    {
        await File.WriteAllBytesAsync(Path.Combine(_directory, "license.lic"), new byte[64 * 1024 + 1]);
        var validator = new TestValidator(CreateLicense());
        var machine = new TestMachine();
        var middleware = new LicenseMiddleware(_ => throw new InvalidOperationException("Unexpected access"),
            NullLogger<LicenseMiddleware>.Instance);
        var rejected = new DefaultHttpContext();
        await middleware.InvokeAsync(rejected, validator, machine, CreateGuard(new TestProtector()),
            CreateOptions(), CreateEnvironment());
        Assert.Equal(403, rejected.Response.StatusCode);
        Assert.Equal(0, validator.Calls);
        Assert.Equal(0, machine.Calls);
    }

    [Theory]
    [InlineData("GET", "/license/activation-request", true)]
    [InlineData("GET", "/health", true)]
    [InlineData("HEAD", "/health", true)]
    [InlineData("POST", "/health", false)]
    [InlineData("GET", "/license/admin", false)]
    [InlineData("GET", "/health/details", false)]
    public async Task Exclusions_AllowOnlyExactReadOnlyRoutes(string method, string path, bool allowed)
    {
        var calls = 0;
        var middleware = new LicenseMiddleware(_ => { calls++; return Task.CompletedTask; },
            NullLogger<LicenseMiddleware>.Instance);
        var context = new DefaultHttpContext();
        context.Request.Method = method;
        context.Request.Path = path;
        await middleware.InvokeAsync(context, new TestValidator(CreateLicense()), new TestMachine(),
            CreateGuard(new TestProtector()), CreateOptions(), CreateEnvironment());
        Assert.Equal(allowed ? 1 : 0, calls);
        Assert.Equal(allowed ? 200 : 403, context.Response.StatusCode);
    }

    private LicenseClockGuard CreateGuard(TestProtector protector) =>
        new(protector, CreateOptions(), CreateEnvironment());

    private IOptions<DharmuSecurityOptions> CreateOptions() => Options.Create(new DharmuSecurityOptions
    {
        ProductCode = "TEST",
        RuntimeStateFilePath = "runtime.state",
        LicenseFilePath = "license.lic"
    });

    private IHostEnvironment CreateEnvironment() => new TestEnvironment { ContentRootPath = _directory };

    private LicensePayload CreateLicense(long revision = 0, bool revoked = false, long id = 1) => new()
    {
        SchemaVersion = revision == 0 ? 1 : 2, Revision = revision,
        LicenseId = id, ProductCode = "TEST", IssuedAtUtc = _now.AddDays(-1),
        ValidFromUtc = _now.AddDays(-1), IsLifetime = true, IsRevoked = revoked
    };

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private sealed class TestProtector : ISecretProtector
    {
        public bool Fail { get; set; }
        public string Protect(string value) => Fail ? throw new IOException("test write failure") : value;
        public string Unprotect(string protectedValue) => protectedValue;
    }

    private sealed class TestEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Testing";
        public string ApplicationName { get; set; } = "Test";
        public string ContentRootPath { get; set; } = "";
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    private sealed class TestMachine : IMachineIdentityProvider
    {
        public int Calls { get; private set; }
        public string GetMachineCode()
        {
            Calls++;
            return "TEST";
        }
        public byte[] ExportPublicKey() => throw new NotSupportedException();
        public byte[] Sign(byte[] data) => throw new NotSupportedException();
    }

    private sealed class TestValidator(LicensePayload license) : ILicenseValidator
    {
        public int Calls { get; private set; }
        public bool Reject { get; set; }
        public LicenseValidationResult Validate(string licenseContent,
            IReadOnlyDictionary<string, string> trustedPublicKeys, string expectedProductCode,
            string currentMachineCode, DateTime utcNow)
        {
            Calls++;
            return Reject
                ? LicenseValidationResult.Invalid(LicenseValidationStatus.InvalidSignature)
                : LicenseValidationResult.Valid(license);
        }
    }
}
