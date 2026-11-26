using System.Globalization;
using System.Security.Cryptography;
using Dharmu.Security.LicenseTool;
using Dharmu.Security.Core.Licensing;

if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine("License issuance requires Windows CNG.");
    return 1;
}

// A separate owner-only key. Never use the client device identity for signing.
const string keyName = "DharmuSecurityIssuer";
const string keyId = "issuer-v1";
var useTpm = args.Length > 0 && args[^1] == "--tpm";
if (useTpm)
{
    args = args[..^1];
}

var provider = useTpm
    ? CngProvider.MicrosoftPlatformCryptoProvider
    : CngProvider.MicrosoftSoftwareKeyStorageProvider;

try
{
    if (args is ["init", var publicKeyPath])
    {
        var path = Path.GetFullPath(publicKeyPath);
        using var key = CngKey.Exists(keyName, provider, CngKeyOpenOptions.MachineKey)
            ? CngKey.Open(keyName, provider, CngKeyOpenOptions.MachineKey)
            : CngKey.Create(CngAlgorithm.ECDsaP256, keyName, new CngKeyCreationParameters
            {
                Provider = provider,
                KeyCreationOptions = CngKeyCreationOptions.MachineKey,
                ExportPolicy = CngExportPolicies.None,
                KeyUsage = CngKeyUsages.Signing
            });
        using var signer = new ECDsaCng(key);
        using var output = new StreamWriter(new FileStream(path, FileMode.CreateNew));
        output.Write(signer.ExportSubjectPublicKeyInfoPem());
        Console.WriteLine($"Public key exported. Key ID: {keyId}");
        return 0;
    }

    if (args is not ["issue", _, _, _, _, _, _] &&
        args is not ["renew", _, _, _] &&
        args is not ["revoke", _, _] &&
        args is not ["list", _] &&
        args is not ["list", _, _] &&
        args is not ["history", _, _])
    {
        Console.Error.WriteLine("""
            Owner-only commands (optional --tpm at end):
              init <public-key.pem>
              issue <ledger-dir> <activation.json> <product-code> <customer-id> <product-id> <days|lifetime>
              renew <ledger-dir> <license-id> <days>
              revoke <ledger-dir> <license-id>
              list <ledger-dir> [customer-id]
              history <ledger-dir> <license-id>
            """);
        return 1;
    }

    using var signingKey = CngKey.Open(keyName, provider, CngKeyOpenOptions.MachineKey);
    using var ecdsa = new ECDsaCng(signingKey);
    var issuer = new LicenseIssuer(args[1], ecdsa, keyId);
    var now = DateTime.UtcNow;
    if (args[0] == "list" || args[0] == "history")
    {
        var records = args[0] == "history"
            ? issuer.History(ParseId(args[2]))
            : issuer.List(args.Length == 3 ? ParseId(args[2]) : null);
        foreach (var record in records)
        {
            PrintRecord(record, now);
        }

        Console.WriteLine($"Records: {records.Count}");
        return 0;
    }

    var file = args[0] switch
    {
        "issue" => issuer.Issue(ReadActivationRequest(args[2]), args[3], ParseId(args[4]), ParseId(args[5]),
            args[6] == "lifetime" ? null : ParseDays(args[6]), now),
        "renew" => issuer.Renew(ParseId(args[2]), ParseDays(args[3]), now),
        "revoke" => issuer.Revoke(ParseId(args[2]), now),
        _ => throw new InvalidOperationException("Unknown command.")
    };
    Console.WriteLine($"Signed license: {file}");
    return 0;
}
catch (Exception exception) when (exception is IOException or InvalidDataException or UnauthorizedAccessException
    or CryptographicException or FormatException or InvalidOperationException
    or ArgumentException or System.Text.Json.JsonException or OverflowException)
{
    Console.Error.WriteLine(exception.Message);
    return 1;
}

static void PrintRecord(LicensePayload record, DateTime now)
{
    var status = record.IsRevoked ? "Revoked"
        : now < record.ValidFromUtc ? "Not yet valid"
        : record.IsLifetime ? "Lifetime"
        : now >= record.ExpiresAtUtc ? "Expired" : "Active";
    Console.WriteLine(FormattableString.Invariant(
        $"License: {record.LicenseId} | Revision: {record.Revision} | Customer: {record.CustomerId} | Product: {record.ProductCode} | Status: {status}"));
    Console.WriteLine(FormattableString.Invariant(
        $"  Machine: {record.MachineCode} | Issued UTC: {record.IssuedAtUtc:O} | Expires UTC: {record.ExpiresAtUtc:O}"));
}

static long ParseId(string value) => long.Parse(value, NumberStyles.None, CultureInfo.InvariantCulture);
static int ParseDays(string value) => int.Parse(value, NumberStyles.None, CultureInfo.InvariantCulture);

static string ReadActivationRequest(string path)
{
    using var stream = File.OpenRead(path);
    if (stream.Length > 64 * 1024)
    {
        throw new InvalidDataException("Activation request exceeds 64 KiB.");
    }

    using var reader = new StreamReader(stream);
    return reader.ReadToEnd();
}
