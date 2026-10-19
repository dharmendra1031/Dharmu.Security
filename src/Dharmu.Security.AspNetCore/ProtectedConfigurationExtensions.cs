using Dharmu.Security.Windows.Secrets;
using Microsoft.Extensions.Configuration;

namespace Dharmu.Security.AspNetCore;

public static class ProtectedConfigurationExtensions
{
    public static string GetDharmuProtectedConnectionString(
        this IConfiguration configuration,
        string name)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        var protectedValue = configuration[$"ProtectedConnectionStrings:{name}"];

        if (string.IsNullOrWhiteSpace(protectedValue))
        {
            throw new InvalidOperationException(
                $"ProtectedConnectionStrings:{name} is not configured.");
        }

        return new DpapiSecretProtector().Unprotect(protectedValue);
    }
}
