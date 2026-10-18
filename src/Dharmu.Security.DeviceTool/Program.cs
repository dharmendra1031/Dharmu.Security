using System.Security.Cryptography;
using Dharmu.Security.Windows.Machine;

if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine("Device provisioning is supported only on Windows.");
    return 1;
}

var useTpm = args.Any(
    value => string.Equals(value, "--tpm", StringComparison.OrdinalIgnoreCase));

var provider = useTpm
    ? CngProvider.MicrosoftPlatformCryptoProvider
    : CngProvider.MicrosoftSoftwareKeyStorageProvider;

if (CngKey.Exists(
        WindowsMachineIdentityProvider.DeviceKeyName,
        provider,
        CngKeyOpenOptions.MachineKey))
{
    Console.WriteLine("Dharmu.Security device identity already exists.");
    return 0;
}

var creationParameters = new CngKeyCreationParameters
{
    Provider = provider,
    KeyCreationOptions = CngKeyCreationOptions.MachineKey,
    ExportPolicy = CngExportPolicies.None,
    KeyUsage = CngKeyUsages.Signing
};

using var key = CngKey.Create(
    CngAlgorithm.ECDsaP256,
    WindowsMachineIdentityProvider.DeviceKeyName,
    creationParameters);

using var ecdsa = new ECDsaCng(key);
var publicKey = ecdsa.ExportSubjectPublicKeyInfo();
var machineCode = Convert.ToHexString(SHA256.HashData(publicKey));

Console.WriteLine("Dharmu.Security device identity created.");
Console.WriteLine($"Provider: {provider.Provider}");
Console.WriteLine($"Machine code: {machineCode}");
Console.WriteLine("Private device key is non-exportable.");

return 0;
