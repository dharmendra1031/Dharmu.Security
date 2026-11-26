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

    private LicenseClockGuard CreateGuard(TestProtector protector) =>
        new(protector, CreateOptions(), CreateEnvironment());

    private IOptions<DharmuSecurityOptions> CreateOptions() => Options.Create(new DharmuSecurityOptions
    {
        ProductCode = "TEST",
        RuntimeStateFilePath = "runtime.state",
        LicenseFilePath = "license.lic"
    });

    private IHostEnvironment CreateEnvironment() => new TestEnvironment { ContentRootPath = _directory };

    private LicensePayload CreateLicense() => new()
    {
        LicenseId = 1, ProductCode = "TEST", IssuedAtUtc = _now.AddDays(-1),
        ValidFromUtc = _now.AddDays(-1), IsLifetime = true
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
        public string GetMachineCode() => "TEST";
        public byte[] ExportPublicKey() => throw new NotSupportedException();
        public byte[] Sign(byte[] data) => throw new NotSupportedException();
    }

    private sealed class TestValidator(LicensePayload license) : ILicenseValidator
    {
        public LicenseValidationResult Validate(string licenseContent,
            IReadOnlyDictionary<string, string> trustedPublicKeys, string expectedProductCode,
            string currentMachineCode, DateTime utcNow) => LicenseValidationResult.Valid(license);
    }
}
