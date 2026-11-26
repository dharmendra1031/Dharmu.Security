using System.Security.Cryptography;
using Dharmu.Security.Core.Machine;

namespace Dharmu.Security.Windows.Machine;

public sealed class WindowsMachineIdentityProvider : IMachineIdentityProvider
{
    public const string DeviceKeyName = "DharmuSecurityDeviceIdentity";
    private readonly CngProvider _provider;

    public WindowsMachineIdentityProvider() : this(false) { }

    public WindowsMachineIdentityProvider(bool requireTpm)
    {
        _provider = requireTpm
            ? CngProvider.MicrosoftPlatformCryptoProvider
            : CngProvider.MicrosoftSoftwareKeyStorageProvider;
    }

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

    private CngKey OpenDeviceKey()
    {
        if (!CngKey.Exists(DeviceKeyName, _provider, CngKeyOpenOptions.MachineKey))
        {
            throw new InvalidOperationException(
                $"Dharmu.Security device identity is not provisioned for {_provider.Provider}.");
        }

        return CngKey.Open(DeviceKeyName, _provider, CngKeyOpenOptions.MachineKey);
    }
}
