# Dharmu.Security

Offline software licensing and Windows security components for .NET 10.

## Packages

| Package | Target | Purpose |
| --- | --- | --- |
| Dharmu.Security.Core | net10.0 | License contracts, signed activation requests and ECDSA validation |
| Dharmu.Security.Windows | net10.0-windows | CNG device identity and device-key-bound DPAPI protection |
| Dharmu.Security.AspNetCore | net10.0-windows | ASP.NET Core license enforcement and activation endpoint |

For an ASP.NET Core application on Windows, install the integration package.
Its Core and Windows dependencies are restored automatically.

```sh
dotnet add package Dharmu.Security.AspNetCore --version 0.2.0
```

## Integration

Use a Windows-targeted .NET 10 web project. Obtain the authorized client
provisioning tool, a signed license, and the trusted issuer public key from
the software provider. Provision the Windows machine keys before starting
the application. The owner-only signing tool and private issuer keys are not
distributed in these runtime packages.

```csharp
using Dharmu.Security.AspNetCore;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddDharmuSecurity(options =>
{
    options.ProductCode = "YOUR_PRODUCT";
    options.TrustedPublicKeys["YOUR_ISSUER_KEY_ID"] =
        "REPLACE_WITH_TRUSTED_ISSUER_PUBLIC_KEY_PEM";
    options.LicenseFilePath = "license/license.lic";
    options.RuntimeStateFilePath = "license/runtime.state";
});

var app = builder.Build();
app.UseDharmuLicenseProtection();
app.MapDharmuSecurityEndpoints();
app.MapGet("/health", () => "OK");
app.MapGet("/protected", () => "Licensed");
app.Run();
```

Replace the example key and product values before deployment. Pin trusted
public keys into the application, not editable customer configuration.
Keep license and runtime state outside public web directories. Configure
least-privilege Windows key and directory permissions for the service identity.

## Security and operational limits

- Signed offline activation and license validation; no mandatory license server.
- Explicit Windows CNG provisioning with optional TPM-backed signing identity.
- Device-key-bound DPAPI protection uses a separate software CNG decryption key.
- Revocation requires delivery of the updated signed license to an offline client.
- The middleware returns HTTP 403 for denied protected requests; it is not
  a substitute for authentication, authorization, backups, or data recovery.
- Privileged administrators and full machine clones are outside the guarantee.
  No offline library guarantees complete piracy prevention.
- Legacy DPAPI-only runtime state must be migrated on the original machine,
  preserving its security records. Never delete state as an upgrade workaround.
- Physical hardware, recovery policy and application-specific acceptance must
  be validated before production use.

## Licensing and support

Proprietary software. See the included LICENSE.txt. Public package availability
does not grant unrestricted commercial or redistribution rights.
Contact the package owner through NuGet.org for licensing and support.
