using System.Security.Cryptography;
using Dharmu.Security.Core.Machine;

namespace Dharmu.Security.Windows.Machine;

public sealed class WindowsMachineIdentityProvider : IMachineIdentityProvider
{
    public const string DeviceKeyName = "DharmuSecurityDeviceIdentity";

    public string GetMachineCode()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Windows machine identity is only available on Windows.");
        }

        using var key = OpenDeviceKey();
        using var ecdsa = new ECDsaCng(key);

        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();
        return Convert.ToHexString(SHA256.HashData(publicKey));
    }

    private static CngKey OpenDeviceKey()
    {
        var providers = new[]
        {
            CngProvider.MicrosoftPlatformCryptoProvider,
            CngProvider.MicrosoftSoftwareKeyStorageProvider
        };

        foreach (var provider in providers)
        {
            try
            {
                if (CngKey.Exists(
                        DeviceKeyName,
                        provider,
                        CngKeyOpenOptions.MachineKey))
                {
                    return CngKey.Open(
                        DeviceKeyName,
                        provider,
                        CngKeyOpenOptions.MachineKey);
                }
            }
            catch (CryptographicException)
            {
                // Try the next Windows key-storage provider.
            }
        }

        throw new InvalidOperationException(
            "Dharmu.Security device identity is not provisioned on this machine.");
    }
}
