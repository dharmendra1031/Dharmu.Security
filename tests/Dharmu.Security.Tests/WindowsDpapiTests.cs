using System.Security.Cryptography;
using Dharmu.Security.Windows.Secrets;
using Xunit;

namespace Dharmu.Security.Tests;

public sealed class WindowsDpapiTests
{
    [Fact]
    public void LocalMachineProtection_RoundTripsAcrossInstances()
    {
        const string original = "Server=localhost;Database=TestOnly;Integrated Security=true;";
        var protectedValue = new DpapiSecretProtector().Protect(original);
        Assert.NotEqual(original, protectedValue);
        Assert.Equal(original, new DpapiSecretProtector().Unprotect(protectedValue));
    }

    [Fact]
    public void LegacyDpapiBlob_IsNotAcceptedAsDeviceBoundData()
    {
        var legacy = Convert.ToBase64String(ProtectedData.Protect(
            System.Text.Encoding.UTF8.GetBytes("legacy-test"), null, DataProtectionScope.LocalMachine));
        Assert.ThrowsAny<CryptographicException>(() => new DpapiSecretProtector().Unprotect(legacy));
    }

    [Fact]
    public void LocalMachineProtection_RejectsTamperedWrappedEntropy()
    {
        var protector = new DpapiSecretProtector();
        var bytes = Convert.FromBase64String(protector.Protect("test-only"));
        bytes[4] ^= 0x80;
        Assert.ThrowsAny<CryptographicException>(() => protector.Unprotect(Convert.ToBase64String(bytes)));
    }

    [Fact]
    public void LocalMachineProtection_RejectsTamperedCiphertext()
    {
        var protector = new DpapiSecretProtector();
        var bytes = Convert.FromBase64String(protector.Protect("test-only"));
        bytes[^1] ^= 0x80;
        Assert.ThrowsAny<CryptographicException>(() => protector.Unprotect(Convert.ToBase64String(bytes)));
    }
}
