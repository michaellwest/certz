using System.Text.RegularExpressions;
using certz.Models;

namespace certz.Services;

/// <summary>
/// Service that verifies a certificate (or CSR) and a private key reference the same
/// public key by comparing their SubjectPublicKeyInfo bytes.
/// </summary>
internal static class VerifyKeypairService
{
    public static VerifyKeypairResult VerifyCertAndKey(
        FileInfo certFile,
        FileInfo keyFile,
        string? password)
    {
        if (!certFile.Exists)
            throw new FileNotFoundException($"Certificate file not found: {certFile.FullName}");
        if (!keyFile.Exists)
            throw new FileNotFoundException($"Key file not found: {keyFile.FullName}");

        using var cert = LoadCertificateFromFile(certFile.FullName, password);
        var certSpki = cert.PublicKey.ExportSubjectPublicKeyInfo();

        var keySpki = LoadKeyAndExportSpki(keyFile.FullName, password);

        var (algorithm, keySize) = DescribePublicKey(cert.PublicKey);

        return BuildResult(
            certSpki: certSpki,
            keySpki: keySpki,
            certSource: certFile.Name,
            keySource: keyFile.Name,
            subject: cert.SubjectName.Format(false),
            algorithm: algorithm,
            keySize: keySize);
    }

    public static VerifyKeypairResult VerifyPfxSelfCheck(FileInfo pfxFile, string? password)
    {
        if (!pfxFile.Exists)
            throw new FileNotFoundException($"PFX file not found: {pfxFile.FullName}");
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("--password is required for --pfx self-check.");

        var cert = X509CertificateLoader.LoadPkcs12FromFile(
            pfxFile.FullName,
            password,
            X509KeyStorageFlags.Exportable);

        try
        {
            if (!cert.HasPrivateKey)
                throw new ArgumentException("PFX file does not contain a private key. Self-check requires both halves.");

            var certSpki = cert.PublicKey.ExportSubjectPublicKeyInfo();
            var keySpki = ExportPrivateKeyPublicSpki(cert)
                ?? throw new CertificateException("Unable to extract private key SPKI (only RSA and ECDSA are supported).");

            var (algorithm, keySize) = DescribePublicKey(cert.PublicKey);

            return BuildResult(
                certSpki: certSpki,
                keySpki: keySpki,
                certSource: pfxFile.Name,
                keySource: pfxFile.Name,
                subject: cert.SubjectName.Format(false),
                algorithm: algorithm,
                keySize: keySize);
        }
        finally
        {
            cert.Dispose();
        }
    }

    public static VerifyKeypairResult VerifyCsrAndKey(FileInfo csrFile, FileInfo keyFile, string? password)
    {
        if (!csrFile.Exists)
            throw new FileNotFoundException($"CSR file not found: {csrFile.FullName}");
        if (!keyFile.Exists)
            throw new FileNotFoundException($"Key file not found: {keyFile.FullName}");

        var csrText = File.ReadAllText(csrFile.FullName);
        CertificateRequest csr;
        try
        {
            csr = CertificateRequest.LoadSigningRequestPem(
                csrText,
                HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.Default);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            throw new ArgumentException($"Unable to parse CSR file '{csrFile.Name}': {ex.Message}");
        }

        var certSpki = csr.PublicKey.ExportSubjectPublicKeyInfo();
        var keySpki = LoadKeyAndExportSpki(keyFile.FullName, password);

        var (algorithm, keySize) = DescribePublicKey(csr.PublicKey);

        return BuildResult(
            certSpki: certSpki,
            keySpki: keySpki,
            certSource: csrFile.Name,
            keySource: keyFile.Name,
            subject: csr.SubjectName.Format(false),
            algorithm: algorithm,
            keySize: keySize);
    }

    private static VerifyKeypairResult BuildResult(
        byte[] certSpki,
        byte[] keySpki,
        string certSource,
        string keySource,
        string subject,
        string algorithm,
        int? keySize)
    {
        var match = certSpki.AsSpan().SequenceEqual(keySpki);

        return new VerifyKeypairResult
        {
            Match = match,
            CertSource = certSource,
            KeySource = keySource,
            Subject = subject,
            Algorithm = algorithm,
            KeySize = keySize,
            CertPublicKeyHash = HashSpki(certSpki),
            KeyPublicKeyHash = HashSpki(keySpki)
        };
    }

    private static byte[] LoadKeyAndExportSpki(string path, string? password)
    {
        var keyText = File.ReadAllText(path);

        // Try RSA first
        try
        {
            using var rsa = RSA.Create();
            if (!string.IsNullOrEmpty(password))
                rsa.ImportFromEncryptedPem(keyText, password);
            else
                rsa.ImportFromPem(keyText);
            return rsa.ExportSubjectPublicKeyInfo();
        }
        catch
        {
            // fall through
        }

        // Try ECDSA
        try
        {
            using var ecdsa = ECDsa.Create();
            if (!string.IsNullOrEmpty(password))
                ecdsa.ImportFromEncryptedPem(keyText, password);
            else
                ecdsa.ImportFromPem(keyText);
            return ecdsa.ExportSubjectPublicKeyInfo();
        }
        catch
        {
            // fall through
        }

        throw new CertificateException(
            $"Unable to import private key from '{Path.GetFileName(path)}'. " +
            "Supported algorithms: RSA, ECDSA. " +
            "If the key is password-protected, supply --password.");
    }

    private static byte[]? ExportPrivateKeyPublicSpki(X509Certificate2 cert)
    {
        var rsa = cert.GetRSAPrivateKey();
        if (rsa != null)
        {
            using (rsa)
                return rsa.ExportSubjectPublicKeyInfo();
        }

        var ecdsa = cert.GetECDsaPrivateKey();
        if (ecdsa != null)
        {
            using (ecdsa)
                return ecdsa.ExportSubjectPublicKeyInfo();
        }

        return null;
    }

    private static (string Algorithm, int? KeySize) DescribePublicKey(PublicKey publicKey)
    {
        var rsa = publicKey.GetRSAPublicKey();
        if (rsa != null)
        {
            using (rsa)
                return ("RSA", rsa.KeySize);
        }

        var ecdsa = publicKey.GetECDsaPublicKey();
        if (ecdsa != null)
        {
            using (ecdsa)
                return ($"ECDSA {DescribeCurve(ecdsa.KeySize)}", ecdsa.KeySize);
        }

        return (publicKey.Oid.FriendlyName ?? publicKey.Oid.Value ?? "unknown", null);
    }

    private static string DescribeCurve(int keySize) => keySize switch
    {
        256 => "P-256",
        384 => "P-384",
        521 => "P-521",
        _ => $"{keySize}-bit"
    };

    private static string HashSpki(byte[] spki)
    {
        var hash = SHA256.HashData(spki);
        return "sha256:" + Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static X509Certificate2 LoadCertificateFromFile(string path, string? password)
    {
        var extension = Path.GetExtension(path).ToLowerInvariant();

        return extension switch
        {
            ".pfx" or ".p12" => X509CertificateLoader.LoadPkcs12(
                File.ReadAllBytes(path),
                password,
                X509KeyStorageFlags.Exportable),
            ".pem" => LoadPemCertificate(path),
            ".crt" or ".cer" => LoadCrtCertificate(path),
            ".der" => X509CertificateLoader.LoadCertificate(File.ReadAllBytes(path)),
            ".key" => throw new ArgumentException(
                $"'{Path.GetFileName(path)}' looks like a private key, not a certificate. " +
                "Pass the certificate to --cert and the key to --key."),
            _ => AutoDetectAndLoad(path, password)
        };
    }

    private static X509Certificate2 LoadPemCertificate(string path)
    {
        var pemContent = File.ReadAllText(path);
        var match = Regex.Match(
            pemContent,
            @"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----",
            RegexOptions.Singleline);

        if (!match.Success)
            throw new ArgumentException($"No certificate found in '{Path.GetFileName(path)}'.");

        return X509Certificate2.CreateFromPem(match.Value);
    }

    private static X509Certificate2 LoadCrtCertificate(string path)
    {
        var data = File.ReadAllBytes(path);
        var text = System.Text.Encoding.UTF8.GetString(data);
        if (text.Contains("-----BEGIN CERTIFICATE-----"))
            return LoadPemCertificate(path);
        return X509CertificateLoader.LoadCertificate(data);
    }

    private static X509Certificate2 AutoDetectAndLoad(string path, string? password)
    {
        var data = File.ReadAllBytes(path);
        var text = System.Text.Encoding.UTF8.GetString(data);

        if (text.Contains("-----BEGIN"))
            return LoadPemCertificate(path);

        try
        {
            return X509CertificateLoader.LoadPkcs12(data, password, X509KeyStorageFlags.Exportable);
        }
        catch { }

        try
        {
            return X509CertificateLoader.LoadCertificate(data);
        }
        catch
        {
            throw new ArgumentException($"Unable to determine certificate format for: {path}");
        }
    }
}
