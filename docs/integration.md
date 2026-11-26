# ASP.NET Core integration

The trusted license verification key must be compiled into the application.
Do not load the trust key from an editable file beside the published application.

Example:

```csharp
using Dharmu.Security.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDharmuSecurity(options =>
{
    options.ProductCode = "ERP";

    options.TrustedPublicKeys["primary"] = """
-----BEGIN PUBLIC KEY-----
PASTE_THE_LICENSE_MANAGER_PUBLIC_KEY_HERE
-----END PUBLIC KEY-----
""";
});

var connectionString =
    builder.Configuration.GetDharmuProtectedConnectionString("DefaultConnection");

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(connectionString));

var app = builder.Build();

app.UseDharmuLicenseProtection();
app.MapDharmuSecurityEndpoints();

app.Run();
```

The public verification key is not secret. Pinning it into the compiled
application prevents the simple attack where a copied publish folder replaces
both the license file and the public-key file with attacker-controlled values.

The `KeyId` inside each signed license selects one of the pinned trusted keys.
This enables controlled signing-key rotation by shipping a new application build
that temporarily trusts both the old and new public keys.

## Client provisioning

Before generating an activation request, provision the machine identity once:

`Dharmu.Security.DeviceTool.exe`

Use `--tpm` on supported Windows hardware when TPM-backed identity is required,
and set `options.RequireTpmDeviceIdentity = true` in the application. Without
this option the runtime uses software CNG only. Do not change the selected
provider for an already licensed device; existing TPM installations must
explicitly configure the option on upgrade. A TPM-backed key is not remote
hardware attestation.

Then open:

`/license/activation-request`

The generated JSON contains a signed device proof. The private device key never
leaves the machine.

## Protected connection string

Run on the target Windows server:

`Dharmu.Security.SecretTool.exe`

Store the returned value under:

`ProtectedConnectionStrings:DefaultConnection`

Do not keep the plaintext production connection string in appsettings files.

## Runtime performance

The middleware compares the exact license content on every protected request.
For an unchanged valid license, expensive signature and device-key checks are
reused for at most 30 seconds (monotonic elapsed time). License validity dates,
clock rollback and revocation history remain checked per request. A changed
license is verified immediately; a missing or invalid file is rejected. Keep
trusted options fixed for the process lifetime and restart after changing them.
No Redis, database or additional Windows service is needed for this cache.
