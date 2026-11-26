using System.Security.Cryptography;
using System.Text;
using Dharmu.Security.Core.Secrets;

namespace Dharmu.Security.Windows.Secrets;

// DPAPI protects the payload; an independently provisioned, non-exportable
// machine RSA key protects the random DPAPI entropy. No legacy fallback.
public sealed class DpapiSecretProtector : ISecretProtector
{
    private const string KeyName = "DharmuSecuritySecretProtection";
    private const int KeyBits = 2048;
    private const int WrappedLength = KeyBits / 8;
    private const int EntropyLength = 32;
    private static ReadOnlySpan<byte> Header => "DHS2"u8;
    private static readonly CngProvider Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider;

    // Explicit provisioning only. Runtime must never create a replacement key
    // automatically when the existing key is missing.
    public static void Provision()
    {
        if (!CngKey.Exists(KeyName, Provider, CngKeyOpenOptions.MachineKey))
        {
            var parameters = new CngKeyCreationParameters
            {
                Provider = Provider,
                KeyCreationOptions = CngKeyCreationOptions.MachineKey,
                ExportPolicy = CngExportPolicies.None,
                KeyUsage = CngKeyUsages.Decryption
            };
            parameters.Parameters.Add(new CngProperty("Length",
                BitConverter.GetBytes(KeyBits), CngPropertyOptions.None));
            using var created = CngKey.Create(CngAlgorithm.Rsa, KeyName, parameters);
        }

        using var key = OpenKey();
        using var rsa = new RSACng(key);
        if (rsa.KeySize != KeyBits)
        {
            throw new CryptographicException("Unexpected secret protection key size.");
        }
    }

    public string Protect(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        using var key = OpenKey();
        using var rsa = new RSACng(key);
        var entropy = RandomNumberGenerator.GetBytes(EntropyLength);
        var clearBytes = Encoding.UTF8.GetBytes(value);
        try
        {
            var wrapped = rsa.Encrypt(entropy, RSAEncryptionPadding.OaepSHA256);
            var protectedBytes = ProtectedData.Protect(clearBytes, entropy, DataProtectionScope.LocalMachine);
            if (wrapped.Length != WrappedLength)
            {
                throw new CryptographicException("Unexpected secret protection key size.");
            }

            var envelope = new byte[Header.Length + wrapped.Length + protectedBytes.Length];
            Header.CopyTo(envelope);
            wrapped.CopyTo(envelope, Header.Length);
            protectedBytes.CopyTo(envelope, Header.Length + wrapped.Length);
            return Convert.ToBase64String(envelope);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(entropy);
            CryptographicOperations.ZeroMemory(clearBytes);
        }
    }

    public string Unprotect(string protectedValue)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(protectedValue);
        var envelope = Convert.FromBase64String(protectedValue);
        if (envelope.Length <= Header.Length + WrappedLength ||
            !envelope.AsSpan(0, Header.Length).SequenceEqual(Header))
        {
            throw new CryptographicException("Unsupported protected data format. Original-machine migration is required for legacy DPAPI data.");
        }

        using var key = OpenKey();
        using var rsa = new RSACng(key);
        var entropy = rsa.Decrypt(envelope.AsSpan(Header.Length, WrappedLength).ToArray(),
            RSAEncryptionPadding.OaepSHA256);
        try
        {
            if (entropy.Length != EntropyLength)
            {
                throw new CryptographicException("Invalid protected data entropy.");
            }

            var clearBytes = ProtectedData.Unprotect(envelope.AsSpan(Header.Length + WrappedLength).ToArray(),
                entropy, DataProtectionScope.LocalMachine);
            try
            {
                return Encoding.UTF8.GetString(clearBytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(clearBytes);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(entropy);
        }
    }

    private static CngKey OpenKey()
    {
        var key = CngKey.Open(KeyName, Provider, CngKeyOpenOptions.MachineKey);
        if (key.AlgorithmGroup != CngAlgorithmGroup.Rsa ||
            key.ExportPolicy != CngExportPolicies.None ||
            key.KeySize != KeyBits)
        {
            key.Dispose();
            throw new CryptographicException("Invalid secret protection key.");
        }
        return key;
    }
}
