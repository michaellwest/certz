using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using certz.Models;

namespace certz.Services;

/// <summary>
/// Service for monitoring certificates for expiration.
/// </summary>
internal static class MonitorService
{
    /// <summary>
    /// Monitors certificates from the specified sources.
    /// </summary>
    /// <param name="options">The monitoring options.</param>
    /// <returns>The monitoring result.</returns>
    public static async Task<MonitorResult> MonitorAsync(MonitorOptions options)
    {
        var certificates = new List<MonitoredCertificate>();
        var errors = new List<MonitorError>();
        var now = DateTime.Now;

        // Process each source
        foreach (var source in options.Sources)
        {
            await ProcessSourceAsync(source, options, certificates, errors, now);
        }

        // Scan certificate store if specified
        if (!string.IsNullOrEmpty(options.StoreName))
        {
            ScanCertificateStore(options, certificates, now);
        }

        return new MonitorResult
        {
            TotalScanned = certificates.Count,
            ExpiredCount = certificates.Count(c => c.Status == "Expired"),
            ExpiringCount = certificates.Count(c => c.Status == "Expiring"),
            ValidCount = certificates.Count(c => c.Status == "Valid"),
            WarnThreshold = options.WarnDays,
            Certificates = certificates,
            Errors = errors
        };
    }

    private static async Task ProcessSourceAsync(
        string source,
        MonitorOptions options,
        List<MonitoredCertificate> certificates,
        List<MonitorError> errors,
        DateTime now)
    {
        try
        {
            if (IsUrl(source))
            {
                await FetchCertificateFromUrlAsync(source, certificates, errors, now, options.WarnDays);
            }
            else if (Directory.Exists(source))
            {
                ScanDirectory(source, options.Recursive, options.Password, certificates, errors, now, options.WarnDays);
            }
            else if (File.Exists(source))
            {
                LoadCertificateFromFile(source, options.Password, certificates, errors, now, options.WarnDays);
            }
            else
            {
                errors.Add(new MonitorError { Source = source, Message = "Source not found" });
            }
        }
        catch (Exception ex)
        {
            errors.Add(new MonitorError { Source = source, Message = ex.Message });
        }
    }

    private static bool IsUrl(string source)
    {
        return source.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
               source.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
    }

    private static async Task FetchCertificateFromUrlAsync(
        string url,
        List<MonitoredCertificate> certificates,
        List<MonitorError> errors,
        DateTime now,
        int warnDays)
    {
        try
        {
            var uri = new Uri(url);
            X509Certificate2? certificate = null;

            var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (message, cert, certChain, sslErrors) =>
                {
                    if (cert != null)
                    {
                        certificate = X509CertificateLoader.LoadCertificate(cert.GetRawCertData());
                    }
                    return true;
                }
            };

            using var client = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(30)
            };

            try
            {
                await client.GetAsync(uri);
            }
            catch (HttpRequestException)
            {
                // Connection errors are expected for some sites, but we still got the cert
            }
            catch (TaskCanceledException)
            {
                // Timeout - may still have captured the certificate
            }

            if (certificate != null)
            {
                certificates.Add(CreateMonitoredCertificate(certificate, url, now, warnDays));
                certificate.Dispose();
            }
            else
            {
                errors.Add(new MonitorError { Source = url, Message = "Could not retrieve certificate" });
            }
        }
        catch (Exception ex)
        {
            errors.Add(new MonitorError { Source = url, Message = ex.Message });
        }
    }

    private static void ScanDirectory(
        string directory,
        bool recursive,
        string? password,
        List<MonitoredCertificate> certificates,
        List<MonitorError> errors,
        DateTime now,
        int warnDays)
    {
        var files = GetCertificateFiles(directory, recursive);
        foreach (var file in files)
        {
            LoadCertificateFromFile(file, password, certificates, errors, now, warnDays);
        }
    }

    private static void LoadCertificateFromFile(
        string filePath,
        string? password,
        List<MonitoredCertificate> certificates,
        List<MonitorError> errors,
        DateTime now,
        int warnDays)
    {
        try
        {
            var extension = Path.GetExtension(filePath).ToLowerInvariant();
            X509Certificate2? cert = null;

            switch (extension)
            {
                case ".pfx":
                case ".p12":
                    cert = LoadPfx(filePath, password);
                    break;
                case ".pem":
                    cert = LoadPem(filePath);
                    break;
                case ".crt":
                case ".cer":
                    cert = LoadCertFile(filePath);
                    break;
                case ".der":
                    cert = LoadDer(filePath);
                    break;
                default:
                    cert = AutoDetectAndLoad(filePath, password);
                    break;
            }

            if (cert != null)
            {
                certificates.Add(CreateMonitoredCertificate(cert, filePath, now, warnDays));
                cert.Dispose();
            }
        }
        catch (Exception ex)
        {
            errors.Add(new MonitorError { Source = filePath, Message = ex.Message });
        }
    }

    private static X509Certificate2 LoadPfx(string path, string? password)
    {
        var pfxData = File.ReadAllBytes(path);
        return X509CertificateLoader.LoadPkcs12(pfxData, password, X509KeyStorageFlags.Exportable);
    }

    private static X509Certificate2 LoadPem(string path)
    {
        var pemContent = File.ReadAllText(path);
        var certMatches = Regex.Matches(pemContent, @"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", RegexOptions.Singleline);

        if (certMatches.Count == 0)
        {
            throw new InvalidOperationException("No certificates found in PEM file.");
        }

        // Check if there's a private key
        if (pemContent.Contains("-----BEGIN PRIVATE KEY-----") ||
            pemContent.Contains("-----BEGIN RSA PRIVATE KEY-----") ||
            pemContent.Contains("-----BEGIN EC PRIVATE KEY-----"))
        {
            return X509Certificate2.CreateFromPem(certMatches[0].Value, pemContent);
        }

        return X509Certificate2.CreateFromPem(certMatches[0].Value);
    }

    private static X509Certificate2 LoadCertFile(string path)
    {
        var data = File.ReadAllBytes(path);
        var text = Encoding.UTF8.GetString(data);

        if (text.Contains("-----BEGIN CERTIFICATE-----"))
        {
            return LoadPem(path);
        }

        return X509CertificateLoader.LoadCertificate(data);
    }

    private static X509Certificate2 LoadDer(string path)
    {
        var data = File.ReadAllBytes(path);
        return X509CertificateLoader.LoadCertificate(data);
    }

    private static X509Certificate2 AutoDetectAndLoad(string path, string? password)
    {
        var data = File.ReadAllBytes(path);
        var text = Encoding.UTF8.GetString(data);

        // Check for PEM
        if (text.Contains("-----BEGIN"))
        {
            return LoadPem(path);
        }

        // Try PFX
        try
        {
            return LoadPfx(path, password);
        }
        catch
        {
            // Not a PFX
        }

        // Try DER
        return X509CertificateLoader.LoadCertificate(data);
    }

    private static void ScanCertificateStore(
        MonitorOptions options,
        List<MonitoredCertificate> certificates,
        DateTime now)
    {
        var location = StoreListHandler.ParseStoreLocation(options.StoreLocation);
        var name = StoreListHandler.ParseStoreName(options.StoreName);
        var storeSource = $"store:{location}\\{name}";

        using var store = new X509Store(name, location);
        store.Open(OpenFlags.ReadOnly);

        foreach (var cert in store.Certificates)
        {
            certificates.Add(CreateMonitoredCertificate(cert, storeSource, now, options.WarnDays));
        }
    }

    private static MonitoredCertificate CreateMonitoredCertificate(
        X509Certificate2 cert,
        string source,
        DateTime now,
        int warnDays)
    {
        var daysRemaining = (cert.NotAfter - now).Days;
        var status = DetermineStatus(cert, now, daysRemaining, warnDays);

        return new MonitoredCertificate
        {
            Source = source,
            Subject = cert.Subject,
            Thumbprint = cert.Thumbprint,
            NotAfter = cert.NotAfter,
            DaysRemaining = daysRemaining,
            Status = status,
            IsWarning = status == "Expiring" || status == "Expired"
        };
    }

    private static string DetermineStatus(X509Certificate2 cert, DateTime now, int daysRemaining, int warnDays)
    {
        if (cert.NotAfter < now)
        {
            return "Expired";
        }

        if (cert.NotBefore > now)
        {
            return "NotYetValid";
        }

        if (daysRemaining <= warnDays)
        {
            return "Expiring";
        }

        return "Valid";
    }

    private static string[] GetCertificateFiles(string directory, bool recursive)
    {
        var searchOption = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
        var extensions = new[] { "*.pfx", "*.p12", "*.pem", "*.crt", "*.cer" };

        return extensions
            .SelectMany(ext => Directory.GetFiles(directory, ext, searchOption))
            .ToArray();
    }
}
