using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using certz.Models;

namespace certz.Services;

/// <summary>
/// Service for computing certificate fingerprints from files, URLs, or the certificate store.
/// </summary>
internal static class FingerprintService
{
    /// <summary>
    /// Computes the fingerprint of a certificate loaded from a file.
    /// </summary>
    public static FingerprintResult FingerprintFile(string path, string algorithm, string? password, string separator)
    {
        var cert = LoadCertificateFromFile(path, password);
        try
        {
            var fingerprint = ComputeFingerprint(cert, algorithm, separator);
            return new FingerprintResult
            {
                Algorithm = algorithm.ToUpperInvariant(),
                Fingerprint = fingerprint,
                Source = path,
                Subject = cert.Subject
            };
        }
        finally
        {
            cert.Dispose();
        }
    }

    /// <summary>
    /// Computes the fingerprint of the server certificate at the given HTTPS URL.
    /// </summary>
    public static async Task<FingerprintResult> FingerprintUrlAsync(string url, string algorithm, string separator)
    {
        X509Certificate2? certificate = null;

        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, cert, _, _) =>
            {
                if (cert != null)
                {
                    certificate = X509CertificateLoader.LoadCertificate(cert.GetRawCertData());
                }
                return true;
            }
        };

        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };

        try
        {
            await client.GetAsync(url);
        }
        catch (HttpRequestException) { }
        catch (TaskCanceledException) { }

        if (certificate == null)
        {
            throw new InvalidOperationException($"Could not retrieve certificate from {url}");
        }

        try
        {
            var fingerprint = ComputeFingerprint(certificate, algorithm, separator);
            return new FingerprintResult
            {
                Algorithm = algorithm.ToUpperInvariant(),
                Fingerprint = fingerprint,
                Source = url,
                Subject = certificate.Subject
            };
        }
        finally
        {
            certificate.Dispose();
        }
    }

    /// <summary>
    /// Formats a raw hash byte array as a hex string joined by the given separator.
    /// </summary>
    private static string FormatFingerprint(byte[] hash, string separator)
    {
        return string.Join(separator, hash.Select(b => b.ToString("X2")));
    }

    private static string ComputeFingerprint(X509Certificate2 cert, string algorithm, string separator)
    {
        var hashAlgorithm = algorithm.ToUpperInvariant() switch
        {
            "SHA256" or "SHA-256" => HashAlgorithmName.SHA256,
            "SHA384" or "SHA-384" => HashAlgorithmName.SHA384,
            "SHA512" or "SHA-512" => HashAlgorithmName.SHA512,
            _ => throw new ArgumentException($"Unsupported algorithm '{algorithm}'. Supported: sha256, sha384, sha512.")
        };

        var hash = cert.GetCertHash(hashAlgorithm);
        return FormatFingerprint(hash, separator);
    }

    private static X509Certificate2 LoadCertificateFromFile(string path, string? password)
    {
        var extension = Path.GetExtension(path).ToLowerInvariant();

        return extension switch
        {
            ".pfx" or ".p12" => X509CertificateLoader.LoadPkcs12(File.ReadAllBytes(path), password, X509KeyStorageFlags.Exportable),
            ".pem" => LoadPemCertificate(path),
            ".crt" or ".cer" => LoadCrtCertificate(path),
            ".der" => X509CertificateLoader.LoadCertificate(File.ReadAllBytes(path)),
            ".key" => throw new InvalidOperationException("Cannot fingerprint a private key file. Provide a certificate file instead."),
            _ => AutoDetectAndLoad(path, password)
        };
    }

    private static X509Certificate2 LoadPemCertificate(string path)
    {
        var pemContent = File.ReadAllText(path);
        var match = Regex.Match(pemContent, @"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", RegexOptions.Singleline);
        if (!match.Success)
        {
            throw new InvalidOperationException("No certificate found in PEM file.");
        }

        if (pemContent.Contains("-----BEGIN PRIVATE KEY-----") ||
            pemContent.Contains("-----BEGIN RSA PRIVATE KEY-----") ||
            pemContent.Contains("-----BEGIN EC PRIVATE KEY-----"))
        {
            return X509Certificate2.CreateFromPem(match.Value, pemContent);
        }

        return X509Certificate2.CreateFromPem(match.Value);
    }

    private static X509Certificate2 LoadCrtCertificate(string path)
    {
        var data = File.ReadAllBytes(path);
        var text = Encoding.UTF8.GetString(data);
        if (text.Contains("-----BEGIN CERTIFICATE-----"))
        {
            return LoadPemCertificate(path);
        }
        return X509CertificateLoader.LoadCertificate(data);
    }

    private static X509Certificate2 AutoDetectAndLoad(string path, string? password)
    {
        var data = File.ReadAllBytes(path);
        var text = Encoding.UTF8.GetString(data);

        if (text.Contains("-----BEGIN"))
        {
            return LoadPemCertificate(path);
        }

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
            throw new InvalidOperationException($"Unable to determine certificate format for: {path}");
        }
    }
}
