using System.Security.Cryptography;
using Dharmu.Security.Core.Machine;

namespace Dharmu.Security.Windows.Machine;

public sealed class WindowsMachineIdentityProvider : IMachineIdentityProvider
{
    public const string DeviceKeyName = "DharmuSecurityDeviceIdentity";

    public string GetMachineCode()
    {
        var publicKey = ExportPublicKey();
        return Convert.ToHexString(SHA256.HashData(publicKey));
    }

    public byte[] ExportPublicKey()
    {
        EnsureWindows();

        using var key = OpenDeviceKey();
        using var ecdsa = new ECDsaCng(key);

        return ecdsa.ExportSubjectPublicKeyInfo();
    }

    public byte[] Sign(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        EnsureWindows();

        using var key = OpenDeviceKey();
        using var ecdsa = new ECDsaCng(key);

        return ecdsa.SignData(data, HashAlgorithmName.SHA256);
    }

    private static void EnsureWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Windows machine identity is only available on Windows.");
        }
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
