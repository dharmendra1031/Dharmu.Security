using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using Dharmu.Security.Core.Licensing;

namespace Dharmu.Security.LicenseTool;

// Owner-side only. One signed license file per ID is the authoritative local ledger.
public sealed class LicenseIssuer
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly string _directory;
    private readonly ECDsa _key;
    private readonly string _keyId;

    public LicenseIssuer(string directory, ECDsa key, string keyId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        if (key.KeySize != 256)
        {
            throw new ArgumentException("A P-256 signing key is required.", nameof(key));
        }

        _directory = Path.GetFullPath(directory);
        _key = key;
        _keyId = keyId;
        Directory.CreateDirectory(_directory);
    }

    public string Issue(string requestContent, string productCode, long customerId,
        long productId, int? days, DateTime utcNow)
    {
        ValidateDays(days);
        if (customerId <= 0 || productId <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(customerId), "Positive customer and product IDs are required.");
        }

        var request = new ActivationRequestParser().Parse(requestContent, utcNow);
        if (!string.Equals(request.ProductCode, productCode, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Activation request product does not match the selected product.");
        }

        using var gate = LockLedger();
        long id;
        do
        {
            id = BinaryPrimitives.ReadInt64LittleEndian(RandomNumberGenerator.GetBytes(8)) & long.MaxValue;
        }
        while (id == 0 || File.Exists(LicensePath(id)));

        return Save(new LicensePayload
        {
            SchemaVersion = 2,
            LicenseId = id,
            Revision = 1,
            CustomerId = customerId,
            ProductId = productId,
            ProductCode = request.ProductCode,
            MachineCode = request.MachineCode,
            IssuedAtUtc = utcNow,
            ValidFromUtc = utcNow,
            ExpiresAtUtc = days is int duration ? utcNow.AddDays(duration) : null,
            IsLifetime = days is null
        }, overwrite: false);
    }

    public string Renew(long id, int days, DateTime utcNow)
    {
        ValidateDays(days);
        using var gate = LockLedger();
        var current = Read(id);
        if (current.IsRevoked || current.IsLifetime)
        {
            throw new InvalidOperationException("Revoked or lifetime licenses cannot be renewed.");
        }

        var expiry = current.ExpiresAtUtc
            ?? throw new InvalidDataException("Finite license has no expiry.");
        return Save(Next(current, utcNow, (expiry > utcNow ? expiry : utcNow).AddDays(days), false), true);
    }

    public string Revoke(long id, DateTime utcNow)
    {
        using var gate = LockLedger();
        var current = Read(id);
        return current.IsRevoked
            ? LicensePath(id)
            : Save(Next(current, utcNow, current.ExpiresAtUtc, true), true);
    }

    private static LicensePayload Next(LicensePayload current, DateTime utcNow,
        DateTime? expiresAtUtc, bool revoked) => new()
    {
        SchemaVersion = 2,
        LicenseId = current.LicenseId,
        Revision = checked(current.Revision + 1),
        CustomerId = current.CustomerId,
        ProductId = current.ProductId,
        ProductCode = current.ProductCode,
        MachineCode = current.MachineCode,
        IssuedAtUtc = utcNow,
        ValidFromUtc = current.ValidFromUtc,
        ExpiresAtUtc = expiresAtUtc,
        IsLifetime = current.IsLifetime,
        IsRevoked = revoked
    };

    private LicensePayload Read(long id)
    {
        if (id <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(id));
        }

        var content = File.ReadAllText(LicensePath(id));
        var envelope = JsonSerializer.Deserialize<LicenseEnvelope>(content, Json)
            ?? throw new InvalidDataException("Invalid ledger envelope.");
        var payload = JsonSerializer.Deserialize<LicensePayload>(Convert.FromBase64String(envelope.Payload), Json)
            ?? throw new InvalidDataException("Invalid ledger payload.");

        // Authenticate the stored record before using any fields for renewal.
        // Validate at the signed start date so expired licenses can be renewed.
        var result = new EcdsaLicenseValidator().Validate(content,
            new Dictionary<string, string> { [_keyId] = _key.ExportSubjectPublicKeyInfoPem() },
            payload.ProductCode, payload.MachineCode, payload.ValidFromUtc);
        if (result.License is not { } verified || verified.LicenseId != id ||
            verified.SchemaVersion != 2 || (!result.IsValid && result.Status != LicenseValidationStatus.Revoked))
        {
            throw new InvalidDataException("Ledger record authentication failed.");
        }

        return verified;
    }

    private string Save(LicensePayload payload, bool overwrite)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(payload, Json);
        var content = JsonSerializer.Serialize(new LicenseEnvelope
        {
            Algorithm = "ECDSA-P256-SHA256",
            KeyId = _keyId,
            Payload = Convert.ToBase64String(bytes),
            Signature = Convert.ToBase64String(_key.SignData(bytes, HashAlgorithmName.SHA256))
        }, Json);

        var path = LicensePath(payload.LicenseId);
        var temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            using (var writer = new StreamWriter(stream))
            {
                writer.Write(content);
                writer.Flush();
                stream.Flush(flushToDisk: true);
            }

            File.Move(temp, path, overwrite);
            return path;
        }
        finally
        {
            if (File.Exists(temp))
            {
                File.Delete(temp);
            }
        }
    }

    private FileStream LockLedger() =>
        new(Path.Combine(_directory, ".issuer.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);

    private string LicensePath(long id) => Path.Combine(_directory, $"{id}.lic");

    private static void ValidateDays(int? days)
    {
        if (days is < 1 or > 3650)
        {
            throw new ArgumentOutOfRangeException(nameof(days), "Validity must be between 1 and 3650 days, or lifetime.");
        }
    }
}
