using System.Security.Cryptography;
using Dharmu.Security.Windows.Machine;
using Dharmu.Security.Windows.Secrets;

namespace Dharmu.Security.DeviceTool;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            ApplicationConfiguration.Initialize();
            Application.Run(new DeviceSetupForm());
            return 0;
        }

        if (args is ["--configure-iis", var pool, var licenseDirectory, var stateDirectory])
        {
            try
            {
                IisPermissions.Configure(pool, licenseDirectory, stateDirectory);
                return 0;
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine(exception.Message);
                return 1;
            }
        }

        if (args is not ["--provision"] and not ["--tpm"] and not ["--provision", "--tpm"])
        {
            Console.Error.WriteLine("Use --provision [--tpm] or --configure-iis <pool> <license-dir> <state-dir> for unattended setup.");
            return 1;
        }

        try
        {
            var code = Provision(args.Contains("--tpm"));
            Console.WriteLine($"Dharmu.Security device and secret protection keys provisioned. Machine code: {code}");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(exception.Message);
            return 1;
        }
    }

    internal static string Provision(bool useTpm)
    {
        var provider = useTpm
            ? CngProvider.MicrosoftPlatformCryptoProvider
            : CngProvider.MicrosoftSoftwareKeyStorageProvider;

        if (!CngKey.Exists(WindowsMachineIdentityProvider.DeviceKeyName, provider,
                CngKeyOpenOptions.MachineKey))
        {
            using var created = CngKey.Create(CngAlgorithm.ECDsaP256,
                WindowsMachineIdentityProvider.DeviceKeyName, new CngKeyCreationParameters
                {
                    Provider = provider,
                    KeyCreationOptions = CngKeyCreationOptions.MachineKey,
                    ExportPolicy = CngExportPolicies.None,
                    KeyUsage = CngKeyUsages.Signing
                });
        }

        DpapiSecretProtector.Provision();
        return new WindowsMachineIdentityProvider(useTpm).GetMachineCode();
    }
}
