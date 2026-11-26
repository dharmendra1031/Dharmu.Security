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

    options.TrustedPublicKeys["issuer-v1"] = """
-----BEGIN PUBLIC KEY-----
PASTE_THE_STANDALONE_ISSUER_PUBLIC_KEY_HERE
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
license is verified immediately; a missing, oversized (over 64 KiB), or
invalid file is rejected. Trusted key and product changes invalidate cached
signature results. Configure options before startup and restart after changing
them; the device provider is selected once by dependency injection.

Only exact GET/HEAD paths in ExcludedPaths bypass license enforcement.
Defaults are /license/activation-request and /health. Do not add business
operations to those paths or treat license protection as user authorization.
No Redis, database or additional Windows service is needed for this cache.

## Performance baseline

The Windows CI test RuntimePerformanceBaseline_RealSignatureAndDpapi reports
SECURITY_BENCH lines for cold validation, 200 sequential requests and 200
requests at concurrency 8. It uses the actual middleware, signed P-256 license,
DPAPI, runtime state files and locking, with an in-memory HTTP context and a
fixed test machine code (not a provisioned TPM/CNG key). Timing is diagnostic,
not a fixed CI threshold. It does not measure IIS, network, SQL Server, POS
operations, multiple worker processes or physical device provisioning.
Measure those on the customer deployment before deciding on further caching.

The isolated package consumption CI also starts a real loopback Kestrel host
using the newly built NuGet packages, actual Windows software CNG device identity,
DPAPI and standalone issuer CLI. It verifies the complete activation and revocation
path including a new host instance. The smoke public key is read from a temporary
test file only; production applications must pin their public keys in code.

## Device-bound protected data format

Run DeviceTool on the target Windows machine before using SecretTool, protected
connection strings or runtime state. DeviceTool also provisions an independent
non-exportable software CNG RSA-2048 decryption key, even if the signing identity
uses TPM. New protected data uses DPAPI with random entropy wrapped using RSA
OAEP-SHA256. This does not make the software decryption key TPM-backed. Preserve
the machine keys; restrict their ACLs and do not copy them to another machine.
Runtime does not create keys or fall back to legacy DPAPI-only data. Existing
pre-release DPAPI-only values/state need an explicit original-machine migration
before upgrade; do not delete state to bypass migration. Local tests using the
real protector require DeviceTool provisioning first, on an isolated test host.
