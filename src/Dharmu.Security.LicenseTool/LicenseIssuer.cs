using System.Buffers.Binary;
using System.Globalization;
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
    private readonly Dictionary<string, string> _trustedKeys;

    public LicenseIssuer(string directory, ECDsa key, string keyId,
        IReadOnlyDictionary<string, string>? previousPublicKeys = null)
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
        _trustedKeys = previousPublicKeys is null
            ? new Dictionary<string, string>(StringComparer.Ordinal)
            : new Dictionary<string, string>(previousPublicKeys, StringComparer.Ordinal);
        if (_trustedKeys.TryGetValue(keyId, out var pinned))
        {
            using var existing = ECDsa.Create();
            existing.ImportFromPem(pinned);
            if (!existing.ExportSubjectPublicKeyInfo().SequenceEqual(key.ExportSubjectPublicKeyInfo()))
            {
                throw new InvalidDataException("Signing key does not match the pinned public key for this ID.");
            }
        }
        _trustedKeys[keyId] = key.ExportSubjectPublicKeyInfoPem();
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
        EnsureDeviceAvailable(ReadAll(), request.ProductCode, request.MachineCode);

        return Save(new LicensePayload
        {
            SchemaVersion = 2,
            LicenseId = NewLicenseId(),
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

    // The operator must first revoke the old ID and verify retirement of the old device.
    // Replacement is a separate atomic operation; retrying cannot issue another ID.
    public string Replace(long revokedId, string requestContent, DateTime utcNow)
    {
        var request = new ActivationRequestParser().Parse(requestContent, utcNow);
        using var gate = LockLedger();
        var current = Read(revokedId);
        if (!current.IsRevoked)
        {
            throw new InvalidOperationException("Revoke the old license before authorizing replacement.");
        }

        if (!string.Equals(current.ProductCode, request.ProductCode, StringComparison.Ordinal) ||
            string.Equals(current.MachineCode, request.MachineCode, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Replacement requires the same product and a different device.");
        }

        var records = ReadAll().ToArray();
        var replacements = records.Where(item => item.ReplacesLicenseId == revokedId).ToArray();
        if (replacements.Length != 0)
        {
            if (replacements.Length == 1 && !replacements[0].IsRevoked &&
                string.Equals(replacements[0].MachineCode, request.MachineCode, StringComparison.Ordinal))
            {
                return LicensePath(replacements[0].LicenseId);
            }

            throw new InvalidOperationException("This license already has a replacement. Use its latest license ID.");
        }

        if (utcNow < current.IssuedAtUtc ||
            (!current.IsLifetime && current.ExpiresAtUtc <= utcNow))
        {
            throw new InvalidOperationException("The original entitlement has expired or the issuer clock is incorrect.");
        }

        EnsureDeviceAvailable(records, current.ProductCode, request.MachineCode);
        return Save(new LicensePayload
        {
            SchemaVersion = 2,
            LicenseId = NewLicenseId(),
            ReplacesLicenseId = current.LicenseId,
            Revision = 1,
            CustomerId = current.CustomerId,
            ProductId = current.ProductId,
            ProductCode = current.ProductCode,
            MachineCode = request.MachineCode,
            IssuedAtUtc = utcNow,
            ValidFromUtc = utcNow,
            ExpiresAtUtc = current.ExpiresAtUtc,
            IsLifetime = current.IsLifetime
        }, overwrite: false);
    }

    private static void EnsureDeviceAvailable(IEnumerable<LicensePayload> records, string productCode, string machineCode)
    {
        foreach (var existing in records)
        {
            if (!existing.IsRevoked &&
                string.Equals(existing.ProductCode, productCode, StringComparison.Ordinal) &&
                string.Equals(existing.MachineCode, machineCode, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"License {existing.LicenseId} already exists for this product and device. Renew the existing license or explicitly revoke it before replacement.");
            }
        }
    }

    private long NewLicenseId()
    {
        long id;
        do
        {
            id = BinaryPrimitives.ReadInt64LittleEndian(RandomNumberGenerator.GetBytes(8)) & long.MaxValue;
        }
        while (id == 0 || File.Exists(LicensePath(id)));
        return id;
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
        return SaveRevision(current, Next(current, utcNow, (expiry > utcNow ? expiry : utcNow).AddDays(days), false));
    }

    public string Revoke(long id, DateTime utcNow)
    {
        using var gate = LockLedger();
        var current = Read(id);
        return current.IsRevoked
            ? LicensePath(id)
            : SaveRevision(current, Next(current, utcNow, current.ExpiresAtUtc, true));
    }

    public string Rotate(long id, DateTime utcNow)
    {
        using var gate = LockLedger();
        var current = Read(id);
        if (utcNow < current.IssuedAtUtc || utcNow.Kind != DateTimeKind.Utc)
        {
            throw new InvalidOperationException("Issuer clock is invalid.");
        }

        var envelope = JsonSerializer.Deserialize<LicenseEnvelope>(File.ReadAllText(LicensePath(id)), Json)
            ?? throw new InvalidDataException("Invalid ledger envelope.");
        return string.Equals(envelope.KeyId, _keyId, StringComparison.Ordinal)
            ? LicensePath(id)
            : SaveRevision(current, Next(current, utcNow, current.ExpiresAtUtc, current.IsRevoked));
    }

    public IReadOnlyList<LicensePayload> List(long? customerId = null)
    {
        if (customerId is <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(customerId));
        }

        using var gate = LockLedger();
        return ReadAll().Where(item => customerId is null || item.CustomerId == customerId)
            .OrderBy(item => item.CustomerId).ThenBy(item => item.ProductCode, StringComparer.Ordinal)
            .ThenBy(item => item.LicenseId).ToArray();
    }

    public IReadOnlyList<LicensePayload> History(long id)
    {
        using var gate = LockLedger();
        var current = Read(id);
        var records = new List<LicensePayload>();
        var historyDirectory = HistoryDirectory(id);
        if (Directory.Exists(historyDirectory))
        {
            foreach (var path in Directory.EnumerateFiles(historyDirectory, "*.lic"))
            {
                var revision = ParseLedgerId(path);
                var record = Authenticate(File.ReadAllText(path), id);
                if (record.Revision != revision || revision > current.Revision ||
                    record.CustomerId != current.CustomerId || record.ProductId != current.ProductId ||
                    record.ReplacesLicenseId != current.ReplacesLicenseId ||
                    !string.Equals(record.ProductCode, current.ProductCode, StringComparison.Ordinal) ||
                    !string.Equals(record.MachineCode, current.MachineCode, StringComparison.Ordinal))
                {
                    throw new InvalidDataException("Historical ledger record does not match the current license.");
                }

                if (revision == current.Revision)
                {
                    // A failed replacement may leave an archived copy of the current record.
                    if (!string.Equals(File.ReadAllText(path), File.ReadAllText(LicensePath(id)), StringComparison.Ordinal))
                    {
                        throw new InvalidDataException("Conflicting ledger revision.");
                    }
                    continue;
                }

                records.Add(record);
            }
        }

        records.Add(current);
        return records.OrderBy(record => record.Revision).ToArray();
    }

    private IEnumerable<LicensePayload> ReadAll()
    {
        foreach (var path in Directory.EnumerateFiles(_directory, "*.lic"))
        {
            yield return Read(ParseLedgerId(path));
        }
    }

    private static long ParseLedgerId(string path)
    {
        if (!long.TryParse(Path.GetFileNameWithoutExtension(path), NumberStyles.None,
                CultureInfo.InvariantCulture, out var id) || id <= 0 ||
            !string.Equals(Path.GetFileName(path), id.ToString(CultureInfo.InvariantCulture) + ".lic",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Unexpected license ledger filename.");
        }

        return id;
    }

    private string SaveRevision(LicensePayload current, LicensePayload next)
    {
        var directory = HistoryDirectory(current.LicenseId);
        Directory.CreateDirectory(directory);
        var archive = Path.Combine(directory, current.Revision.ToString(CultureInfo.InvariantCulture) + ".lic");
        var content = File.ReadAllText(LicensePath(current.LicenseId));
        if (File.Exists(archive))
        {
            if (!string.Equals(File.ReadAllText(archive), content, StringComparison.Ordinal))
            {
                throw new InvalidDataException("Conflicting historical revision.");
            }
        }
        else
        {
            WriteAtomically(archive, content, overwrite: false);
        }

        return Save(next, overwrite: true);
    }

    private string HistoryDirectory(long id) =>
        Path.Combine(_directory, "history", id.ToString(CultureInfo.InvariantCulture));

    private static LicensePayload Next(LicensePayload current, DateTime utcNow,
        DateTime? expiresAtUtc, bool revoked) => new()
    {
        SchemaVersion = 2,
        LicenseId = current.LicenseId,
        ReplacesLicenseId = current.ReplacesLicenseId,
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

        return Authenticate(File.ReadAllText(LicensePath(id)), id);
    }

    private LicensePayload Authenticate(string content, long id)
    {
        var envelope = JsonSerializer.Deserialize<LicenseEnvelope>(content, Json)
            ?? throw new InvalidDataException("Invalid ledger envelope.");
        var payload = JsonSerializer.Deserialize<LicensePayload>(Convert.FromBase64String(envelope.Payload), Json)
            ?? throw new InvalidDataException("Invalid ledger payload.");

        // Authenticate the stored record before using any fields for renewal.
        // Validate at the signed start date so expired licenses can be renewed.
        var result = new EcdsaLicenseValidator().Validate(content,
            _trustedKeys,
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
        WriteAtomically(path, content, overwrite);
        return path;
    }

    private static void WriteAtomically(string path, string content, bool overwrite)
    {
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

    private string LicensePath(long id) => Path.Combine(_directory, id.ToString(CultureInfo.InvariantCulture) + ".lic");

    private static void ValidateDays(int? days)
    {
        if (days is < 1 or > 3650)
        {
            throw new ArgumentOutOfRangeException(nameof(days), "Validity must be between 1 and 3650 days, or lifetime.");
        }
    }
}
