using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using certz.Models;

namespace certz.Services;

/// <summary>
/// Service for managing certificates in trust stores.
/// </summary>
internal static class TrustHandler
{
    /// <summary>
    /// Adds a certificate to the specified trust store.
    /// </summary>
    public static TrustOperationResult AddToStore(string filePath, string? password, string storeName, string storeLocation)
    {
        var location = StoreListHandler.ParseStoreLocation(storeLocation);
        var name = StoreListHandler.ParseStoreName(storeName);

        // Check admin requirement for LocalMachine
        if (location == StoreLocation.LocalMachine && !IsRunningAsAdmin())
        {
            throw new InvalidOperationException(
                "Administrator privileges required to modify LocalMachine certificate store. " +
                "Run the command as Administrator, or use '--location CurrentUser' for user-level trust.");
        }

        var cert = LoadCertificateFromFile(filePath, password);

        try
        {
            using var store = new X509Store(name, location);
            store.Open(OpenFlags.ReadWrite);
            store.Add(cert);

            return new TrustOperationResult
            {
                Success = true,
                Operation = TrustOperationType.Add,
                StoreName = name.ToString(),
                StoreLocation = location.ToString(),
                Certificates =
                [
                    new TrustCertificateInfo
                    {
                        Subject = cert.Subject,
                        Thumbprint = cert.Thumbprint,
                        NotAfter = cert.NotAfter
                    }
                ]
            };
        }
        finally
        {
            cert.Dispose();
        }
    }

    /// <summary>
    /// Finds certificates matching the specified criteria.
    /// </summary>
    public static List<X509Certificate2> FindMatchingCertificates(string? thumbprint, string? subject, string storeName, string storeLocation)
    {
        var location = StoreListHandler.ParseStoreLocation(storeLocation);
        var name = StoreListHandler.ParseStoreName(storeName);

        using var store = new X509Store(name, location);
        store.Open(OpenFlags.ReadOnly);

        var matching = new List<X509Certificate2>();

        if (!string.IsNullOrEmpty(thumbprint))
        {
            // Find by thumbprint
            var normalizedThumbprint = thumbprint.Replace(" ", "").ToUpperInvariant();
            var found = store.Certificates.Find(X509FindType.FindByThumbprint, normalizedThumbprint, false);
            foreach (var cert in found)
            {
                // Clone the cert to avoid disposal issues when store closes
                matching.Add(X509CertificateLoader.LoadCertificate(cert.RawData));
            }
        }
        else if (!string.IsNullOrEmpty(subject))
        {
            // Find by subject pattern (supports wildcards)
            var pattern = WildcardToRegex(subject);
            var regex = new Regex(pattern, RegexOptions.IgnoreCase);

            foreach (var cert in store.Certificates)
            {
                if (regex.IsMatch(cert.Subject))
                {
                    // Clone the cert to avoid disposal issues when store closes
                    matching.Add(X509CertificateLoader.LoadCertificate(cert.RawData));
                }
            }
        }

        return matching;
    }

    /// <summary>
    /// Removes certificates from the store.
    /// </summary>
    public static TrustOperationResult RemoveFromStore(List<X509Certificate2> certificates, string storeName, string storeLocation)
    {
        var location = StoreListHandler.ParseStoreLocation(storeLocation);
        var name = StoreListHandler.ParseStoreName(storeName);

        // Check admin requirement for LocalMachine
        if (location == StoreLocation.LocalMachine && !IsRunningAsAdmin())
        {
            throw new InvalidOperationException(
                "Administrator privileges required to modify LocalMachine certificate store. " +
                "Run the command as Administrator, or use '--location CurrentUser' for user-level trust.");
        }

        using var store = new X509Store(name, location);
        store.Open(OpenFlags.ReadWrite);

        var removedCerts = new List<TrustCertificateInfo>();

        foreach (var cert in certificates)
        {
            try
            {
                // Find the actual certificate in the store by thumbprint
                var found = store.Certificates.Find(X509FindType.FindByThumbprint, cert.Thumbprint, false);
                if (found.Count > 0)
                {
                    store.Remove(found[0]);
                    removedCerts.Add(new TrustCertificateInfo
                    {
                        Subject = cert.Subject,
                        Thumbprint = cert.Thumbprint,
                        NotAfter = cert.NotAfter
                    });
                }
            }
            finally
            {
                cert.Dispose();
            }
        }

        return new TrustOperationResult
        {
            Success = true,
            Operation = TrustOperationType.Remove,
            StoreName = name.ToString(),
            StoreLocation = location.ToString(),
            Certificates = removedCerts
        };
    }

    /// <summary>
    /// Checks if the current process is running with administrator privileges.
    /// </summary>
    internal static bool IsRunningAsAdmin()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>
    /// Loads a certificate from a file.
    /// </summary>
    private static X509Certificate2 LoadCertificateFromFile(string path, string? password)
    {
        var extension = Path.GetExtension(path).ToLowerInvariant();

        return extension switch
        {
            ".pfx" or ".p12" => LoadPfx(path, password),
            ".pem" => LoadPem(path),
            ".crt" or ".cer" => LoadCertFile(path),
            ".der" => LoadDer(path),
            _ => AutoDetectAndLoad(path, password)
        };
    }

    private static X509Certificate2 LoadPfx(string path, string? password)
    {
        var pfxData = File.ReadAllBytes(path);
        return X509CertificateLoader.LoadPkcs12(pfxData, password, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
    }

    private static X509Certificate2 LoadPem(string path)
    {
        var pemContent = File.ReadAllText(path);

        // Find the first certificate block
        var certMatch = Regex.Match(pemContent, @"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", RegexOptions.Singleline);

        if (!certMatch.Success)
        {
            throw new InvalidOperationException("No certificate found in PEM file.");
        }

        // Check if there's a private key
        if (pemContent.Contains("-----BEGIN PRIVATE KEY-----") ||
            pemContent.Contains("-----BEGIN RSA PRIVATE KEY-----") ||
            pemContent.Contains("-----BEGIN EC PRIVATE KEY-----"))
        {
            return X509Certificate2.CreateFromPem(certMatch.Value, pemContent);
        }

        return X509Certificate2.CreateFromPem(certMatch.Value);
    }

    private static X509Certificate2 LoadCertFile(string path)
    {
        var data = File.ReadAllBytes(path);

        // Try PEM first
        var text = Encoding.UTF8.GetString(data);
        if (text.Contains("-----BEGIN CERTIFICATE-----"))
        {
            return LoadPem(path);
        }

        // Otherwise treat as DER
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

        // Try to detect file type
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
        try
        {
            return X509CertificateLoader.LoadCertificate(data);
        }
        catch
        {
            throw new InvalidOperationException($"Unable to determine certificate format for: {path}");
        }
    }

    /// <summary>
    /// Converts a wildcard pattern to a regex pattern.
    /// </summary>
    private static string WildcardToRegex(string pattern)
    {
        return "^" + Regex.Escape(pattern)
            .Replace("\\*", ".*")
            .Replace("\\?", ".") + "$";
    }
}
