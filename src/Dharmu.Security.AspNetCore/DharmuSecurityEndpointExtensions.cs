using System.Text;
using Dharmu.Security.Core.Licensing;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;

namespace Dharmu.Security.AspNetCore;

public static class DharmuSecurityEndpointExtensions
{
    public static IEndpointRouteBuilder MapDharmuSecurityEndpoints(
        this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet(
            "/license/activation-request",
            (
                IActivationRequestGenerator generator,
                IOptions<DharmuSecurityOptions> options) =>
            {
                var productCode = options.Value.ProductCode;
                var content = generator.Generate(productCode, DateTime.UtcNow);
                var fileName = $"{SanitizeFileName(productCode)}-activation-request.json";

                return Results.File(
                    Encoding.UTF8.GetBytes(content),
                    "application/json",
                    fileName);
            });

        return endpoints;
    }

    private static string SanitizeFileName(string value)
    {
        var invalidCharacters = Path.GetInvalidFileNameChars();
        return new string(value
            .Where(character => !invalidCharacters.Contains(character))
            .ToArray());
    }
}
