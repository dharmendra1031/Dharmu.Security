using System.Security.Cryptography;
using System.Text;
using Dharmu.Security.Core.Machine;
using Microsoft.Win32;

namespace Dharmu.Security.Windows.Machine;

public sealed class WindowsMachineIdentityProvider : IMachineIdentityProvider
{
    private const string RegistryPath = @"SOFTWARE\Microsoft\Cryptography";
    private const string RegistryValue = "MachineGuid";

    public string GetMachineCode()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Windows machine identity is only available on Windows.");
        }

        using var key = Registry.LocalMachine.OpenSubKey(RegistryPath, writable: false);
        var machineGuid = key?.GetValue(RegistryValue)?.ToString();

        if (string.IsNullOrWhiteSpace(machineGuid))
        {
            throw new InvalidOperationException("Windows machine identity is unavailable.");
        }

        var source = Encoding.UTF8.GetBytes($"dharmu-security:v1|{machineGuid.Trim()}");
        return Convert.ToHexString(SHA256.HashData(source));
    }
}
