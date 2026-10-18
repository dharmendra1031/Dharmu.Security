using System.Security.Cryptography;
using System.Text;
using Dharmu.Security.Core.Secrets;

namespace Dharmu.Security.Windows.Secrets;

public sealed class DpapiSecretProtector : ISecretProtector
{
    public string Protect(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);

        var clearBytes = Encoding.UTF8.GetBytes(value);
        var protectedBytes = ProtectedData.Protect(
            clearBytes,
            optionalEntropy: null,
            DataProtectionScope.LocalMachine);

        return Convert.ToBase64String(protectedBytes);
    }

    public string Unprotect(string protectedValue)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(protectedValue);

        var protectedBytes = Convert.FromBase64String(protectedValue);
        var clearBytes = ProtectedData.Unprotect(
            protectedBytes,
            optionalEntropy: null,
            DataProtectionScope.LocalMachine);

        return Encoding.UTF8.GetString(clearBytes);
    }
}
