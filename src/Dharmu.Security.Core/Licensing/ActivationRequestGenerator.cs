using System.Text.Json;
using Dharmu.Security.Core.Machine;

namespace Dharmu.Security.Core.Licensing;

public sealed class ActivationRequestGenerator : IActivationRequestGenerator
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly IMachineIdentityProvider _machineIdentityProvider;

    public ActivationRequestGenerator(IMachineIdentityProvider machineIdentityProvider)
    {
        _machineIdentityProvider = machineIdentityProvider;
    }

    public string Generate(string productCode, DateTime utcNow)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(productCode);

        var request = new ActivationRequest
        {
            ProductCode = productCode.Trim(),
            MachineCode = _machineIdentityProvider.GetMachineCode(),
            CreatedAtUtc = utcNow
        };

        return JsonSerializer.Serialize(request, JsonOptions);
    }
}
