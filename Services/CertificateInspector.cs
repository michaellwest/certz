using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using certz.Models;
using certz.Services.Validation;

namespace certz.Services;

/// <summary>
/// Service for inspecting certificates from various sources.
/// </summary>
internal static class CertificateInspector
{
    /// <summary>
    /// Inspects a certificate from a file.
    /// </summary>
    public static CertificateInspectResult InspectFile(InspectOptions options)
    {
        var (cert, additionalCerts) = LoadCertificateFromFile(options.Source, options.Password);

        try
        {
            var result = BuildInspectResult(cert, additionalCerts, InspectSource.File, options.Source, options);

            // Handle save operations
            HandleSaveOperations(cert, options);

            return result;
        }
        finally
        {
            cert.Dispose();
            foreach (var c in additionalCerts)
            {
                c.Dispose();
            }
        }
    }

    /// <summary>
    /// Inspects a certificate from an HTTPS URL.
    /// </summary>
    public static async Task<CertificateInspectResult> InspectUrlAsync(InspectOptions options)
    {
        var uri = new Uri(options.Source);
        X509Certificate2? certificate = null;
        X509Certificate2Collection chain = new();

        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (message, cert, certChain, errors) =>
            {
                if (cert != null)
                {
                    // Clone the certificate using its raw data to avoid disposal issues
                    certificate = X509CertificateLoader.LoadCertificate(cert.GetRawCertData());

                    // Capture chain certificates if requested
                    // We need to clone them as well since the chain will be disposed after callback
                    if (options.ShowChain && certChain != null)
                    {
                        foreach (var element in certChain.ChainElements)
                        {
                            if (element.Certificate.Thumbprint != cert.GetCertHashString())
                            {
                                // Clone the certificate to avoid disposal issues
                                var clonedCert = X509CertificateLoader.LoadCertificate(element.Certificate.RawData);
                                chain.Add(clonedCert);
                            }
                        }
                    }
                }
                return true; // Accept all certs for inspection purposes
            }
        };

        using var client = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(30)
        };

        try
        {
            await client.GetAsync(options.Source);
        }
        catch (HttpRequestException)
        {
            // Connection errors are expected for some sites, but we still got the cert
        }
        catch (TaskCanceledException)
        {
            // Timeout - may still have captured the certificate
        }

        if (certificate == null)
        {
            throw new InvalidOperationException($"Could not retrieve certificate from {options.Source}");
        }

        try
        {
            var result = BuildInspectResult(certificate, chain, InspectSource.Url, options.Source, options);

            // Handle save operations (no private key from URL)
            if (!string.IsNullOrEmpty(options.SavePath))
            {
                SaveCertificate(certificate, options.SavePath, options.SaveFormat);
            }

            return result;
        }
        finally
        {
            certificate.Dispose();
            foreach (var c in chain)
            {
                c.Dispose();
            }
        }
    }

    /// <summary>
    /// Inspects a certificate from the certificate store by thumbprint.
    /// </summary>
    public static CertificateInspectResult InspectFromStore(InspectOptions options)
    {
        var location = options.StoreLocation?.ToLowerInvariant() switch
        {
            "localmachine" => StoreLocation.LocalMachine,
            _ => StoreLocation.CurrentUser
        };

        var name = options.StoreName?.ToLowerInvariant() switch
        {
            "root" => StoreName.Root,
            "ca" => StoreName.CertificateAuthority,
            "my" or null => StoreName.My,
            _ => StoreName.My
        };

        using var store = new X509Store(name, location);
        store.Open(OpenFlags.ReadOnly);

        var thumbprint = options.Source.Replace(" ", "").ToUpperInvariant();
        var cert = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false)
            .OfType<X509Certificate2>()
            .FirstOrDefault();

        if (cert == null)
        {
            throw new InvalidOperationException($"Certificate with thumbprint {thumbprint} not found in {location}\\{name}");
        }

        var sourcePath = $"{location}\\{name}\\{thumbprint}";
        var result = BuildInspectResult(cert, new X509Certificate2Collection(), InspectSource.Store, sourcePath, options);

        // Handle save operations
        HandleSaveOperations(cert, options);

        return result;
    }

    private static (X509Certificate2 Certificate, X509Certificate2Collection AdditionalCerts) LoadCertificateFromFile(string path, string? password)
    {
        var extension = Path.GetExtension(path).ToLowerInvariant();

        return extension switch
        {
            ".pfx" or ".p12" => LoadPfx(path, password),
            ".pem" => LoadPem(path),
            ".crt" or ".cer" => LoadCertFile(path),
            ".der" => LoadDer(path),
            ".key" => throw new InvalidOperationException("Cannot inspect a private key file. Provide a certificate file instead."),
            _ => AutoDetectAndLoad(path, password)
        };
    }

    private static (X509Certificate2, X509Certificate2Collection) LoadPfx(string path, string? password)
    {
        var pfxData = File.ReadAllBytes(path);

        // Use X509CertificateLoader (non-obsolete API for .NET 9+)
        var cert = X509CertificateLoader.LoadPkcs12(pfxData, password, X509KeyStorageFlags.Exportable);

        // Try to extract additional certificates from the PFX
        var additionalCerts = new X509Certificate2Collection();
        try
        {
            var tempCollection = X509CertificateLoader.LoadPkcs12Collection(pfxData, password, X509KeyStorageFlags.Exportable);
            foreach (var c in tempCollection)
            {
                if (c.Thumbprint != cert.Thumbprint)
                {
                    additionalCerts.Add(c);
                }
            }
        }
        catch
        {
            // Ignore errors extracting additional certs
        }

        return (cert, additionalCerts);
    }

    private static (X509Certificate2, X509Certificate2Collection) LoadPem(string path)
    {
        var pemContent = File.ReadAllText(path);
        var additionalCerts = new X509Certificate2Collection();

        // Find all certificate blocks
        var certMatches = Regex.Matches(pemContent, @"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", RegexOptions.Singleline);

        if (certMatches.Count == 0)
        {
            throw new InvalidOperationException("No certificates found in PEM file.");
        }

        // First certificate is the main one
        X509Certificate2 mainCert;

        // Check if there's a private key
        if (pemContent.Contains("-----BEGIN PRIVATE KEY-----") ||
            pemContent.Contains("-----BEGIN RSA PRIVATE KEY-----") ||
            pemContent.Contains("-----BEGIN EC PRIVATE KEY-----"))
        {
            mainCert = X509Certificate2.CreateFromPem(certMatches[0].Value, pemContent);
        }
        else
        {
            mainCert = X509Certificate2.CreateFromPem(certMatches[0].Value);
        }

        // Additional certificates
        for (int i = 1; i < certMatches.Count; i++)
        {
            additionalCerts.Add(X509Certificate2.CreateFromPem(certMatches[i].Value));
        }

        return (mainCert, additionalCerts);
    }

    private static (X509Certificate2, X509Certificate2Collection) LoadCertFile(string path)
    {
        var data = File.ReadAllBytes(path);

        // Try PEM first
        var text = Encoding.UTF8.GetString(data);
        if (text.Contains("-----BEGIN CERTIFICATE-----"))
        {
            return LoadPem(path);
        }

        // Otherwise treat as DER - use X509CertificateLoader
        return (X509CertificateLoader.LoadCertificate(data), new X509Certificate2Collection());
    }

    private static (X509Certificate2, X509Certificate2Collection) LoadDer(string path)
    {
        var data = File.ReadAllBytes(path);
        return (X509CertificateLoader.LoadCertificate(data), new X509Certificate2Collection());
    }

    private static (X509Certificate2, X509Certificate2Collection) AutoDetectAndLoad(string path, string? password)
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

        // Try DER - use X509CertificateLoader
        try
        {
            return (X509CertificateLoader.LoadCertificate(data), new X509Certificate2Collection());
        }
        catch
        {
            throw new InvalidOperationException($"Unable to determine certificate format for: {path}");
        }
    }

    private static CertificateInspectResult BuildInspectResult(
        X509Certificate2 cert,
        X509Certificate2Collection additionalCerts,
        InspectSource source,
        string sourcePath,
        InspectOptions options)
    {
        var warnings = new List<string>();
        var now = DateTime.Now;
        var daysRemaining = (cert.NotAfter - now).Days;

        // Check expiration warnings
        if (cert.NotAfter < now)
        {
            warnings.Add($"Certificate has EXPIRED on {cert.NotAfter:yyyy-MM-dd}");
        }
        else if (cert.NotBefore > now)
        {
            warnings.Add($"Certificate is not yet valid (valid from {cert.NotBefore:yyyy-MM-dd})");
        }
        else if (options.WarnDays.HasValue && daysRemaining <= options.WarnDays.Value)
        {
            warnings.Add($"Certificate expires in {daysRemaining} days (on {cert.NotAfter:yyyy-MM-dd})");
        }

        // Get basic constraints
        var basicConstraints = cert.Extensions["2.5.29.19"] as X509BasicConstraintsExtension;
        var isCa = basicConstraints?.CertificateAuthority ?? false;
        var pathLength = basicConstraints?.HasPathLengthConstraint == true ? basicConstraints.PathLengthConstraint : (int?)null;

        // Get SANs
        var sans = GetSubjectAlternativeNames(cert);

        // Get key usages
        var keyUsages = GetKeyUsages(cert);
        var enhancedKeyUsages = GetEnhancedKeyUsages(cert);

        // Get key info
        var (keyAlgorithm, keySize) = GetKeyInfo(cert);

        // Build chain if requested
        List<ChainElementInfo>? chainInfo = null;
        bool chainIsValid = true;

        if (options.ShowChain)
        {
            var validator = new ChainValidator();
            var chainResult = validator.ValidateChain(cert, additionalCerts, options.CheckCrl);
            chainIsValid = chainResult.IsValid;

            chainInfo = chainResult.ChainElements.Select(e => new ChainElementInfo
            {
                Subject = e.Certificate.Subject,
                Issuer = e.Certificate.Issuer,
                Thumbprint = e.Certificate.Thumbprint,
                SerialNumber = e.Certificate.SerialNumber,
                NotBefore = e.Certificate.NotBefore,
                NotAfter = e.Certificate.NotAfter,
                IsCa = (e.Certificate.Extensions["2.5.29.19"] as X509BasicConstraintsExtension)?.CertificateAuthority ?? false,
                IsSelfSigned = e.Certificate.Subject == e.Certificate.Issuer,
                ValidationErrors = e.Status
                    .Where(s => s.Status != X509ChainStatusFlags.NoError)
                    .Select(s => s.StatusInformation)
                    .ToList()
            }).ToList();

            if (!chainIsValid)
            {
                warnings.Add("Certificate chain validation failed");
            }
        }

        return new CertificateInspectResult
        {
            Subject = cert.Subject,
            Issuer = cert.Issuer,
            Thumbprint = cert.Thumbprint,
            SerialNumber = cert.SerialNumber,
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
            DaysRemaining = daysRemaining,
            KeyAlgorithm = keyAlgorithm,
            KeySize = keySize,
            SignatureAlgorithm = cert.SignatureAlgorithm.FriendlyName ?? "Unknown",
            SubjectAlternativeNames = sans,
            KeyUsages = keyUsages,
            EnhancedKeyUsages = enhancedKeyUsages,
            IsCa = isCa,
            PathLengthConstraint = pathLength,
            HasPrivateKey = cert.HasPrivateKey,
            Source = source,
            SourcePath = sourcePath,
            Chain = chainInfo,
            ChainIsValid = chainIsValid,
            Warnings = warnings
        };
    }

    private static List<string> GetSubjectAlternativeNames(X509Certificate2 cert)
    {
        var sans = new List<string>();
        var sanExtension = cert.Extensions["2.5.29.17"];

        if (sanExtension != null)
        {
            var asnData = new AsnEncodedData(sanExtension.Oid!, sanExtension.RawData);
            var formatted = asnData.Format(true);

            // Parse the formatted string to extract SANs
            foreach (var line in formatted.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var trimmed = line.Trim();
                if (trimmed.StartsWith("DNS Name=", StringComparison.OrdinalIgnoreCase))
                {
                    sans.Add(trimmed.Substring("DNS Name=".Length));
                }
                else if (trimmed.StartsWith("IP Address=", StringComparison.OrdinalIgnoreCase))
                {
                    sans.Add(trimmed.Substring("IP Address=".Length));
                }
                else if (trimmed.StartsWith("URL=", StringComparison.OrdinalIgnoreCase))
                {
                    sans.Add(trimmed.Substring("URL=".Length));
                }
                else if (!string.IsNullOrWhiteSpace(trimmed) && !trimmed.Contains("="))
                {
                    sans.Add(trimmed);
                }
            }
        }

        return sans;
    }

    private static List<string> GetKeyUsages(X509Certificate2 cert)
    {
        var usages = new List<string>();
        var keyUsageExtension = cert.Extensions["2.5.29.15"] as X509KeyUsageExtension;

        if (keyUsageExtension != null)
        {
            var ku = keyUsageExtension.KeyUsages;

            if (ku.HasFlag(X509KeyUsageFlags.DigitalSignature)) usages.Add("Digital Signature");
            if (ku.HasFlag(X509KeyUsageFlags.NonRepudiation)) usages.Add("Non-Repudiation");
            if (ku.HasFlag(X509KeyUsageFlags.KeyEncipherment)) usages.Add("Key Encipherment");
            if (ku.HasFlag(X509KeyUsageFlags.DataEncipherment)) usages.Add("Data Encipherment");
            if (ku.HasFlag(X509KeyUsageFlags.KeyAgreement)) usages.Add("Key Agreement");
            if (ku.HasFlag(X509KeyUsageFlags.KeyCertSign)) usages.Add("Certificate Signing");
            if (ku.HasFlag(X509KeyUsageFlags.CrlSign)) usages.Add("CRL Signing");
            if (ku.HasFlag(X509KeyUsageFlags.EncipherOnly)) usages.Add("Encipher Only");
            if (ku.HasFlag(X509KeyUsageFlags.DecipherOnly)) usages.Add("Decipher Only");
        }

        return usages;
    }

    private static List<string> GetEnhancedKeyUsages(X509Certificate2 cert)
    {
        var usages = new List<string>();
        var ekuExtension = cert.Extensions["2.5.29.37"] as X509EnhancedKeyUsageExtension;

        if (ekuExtension != null)
        {
            foreach (var oid in ekuExtension.EnhancedKeyUsages)
            {
                usages.Add(oid.FriendlyName ?? oid.Value ?? "Unknown");
            }
        }

        return usages;
    }

    private static (string Algorithm, int KeySize) GetKeyInfo(X509Certificate2 cert)
    {
        var publicKey = cert.PublicKey;
        var algorithm = publicKey.Oid.FriendlyName ?? "Unknown";
        var keySize = 0;

        try
        {
            using var rsa = cert.GetRSAPublicKey();
            if (rsa != null)
            {
                return ("RSA", rsa.KeySize);
            }
        }
        catch { }

        try
        {
            using var ecdsa = cert.GetECDsaPublicKey();
            if (ecdsa != null)
            {
                return ($"ECDSA {ecdsa.KeySize switch { 256 => "P-256", 384 => "P-384", 521 => "P-521", _ => $"({ecdsa.KeySize}-bit)" }}", ecdsa.KeySize);
            }
        }
        catch { }

        return (algorithm, keySize);
    }

    private static void HandleSaveOperations(X509Certificate2 cert, InspectOptions options)
    {
        if (!string.IsNullOrEmpty(options.SavePath))
        {
            SaveCertificate(cert, options.SavePath, options.SaveFormat);
        }

        if (!string.IsNullOrEmpty(options.SaveKeyPath))
        {
            SavePrivateKey(cert, options.SaveKeyPath, options.SaveFormat);
        }
    }

    private static void SaveCertificate(X509Certificate2 certificate, string outputPath, string format)
    {
        var isPem = format.Equals("pem", StringComparison.OrdinalIgnoreCase);

        if (isPem)
        {
            var pem = certificate.ExportCertificatePem();
            File.WriteAllText(outputPath, pem);
        }
        else
        {
            var der = certificate.RawData;
            File.WriteAllBytes(outputPath, der);
        }
    }

    private static void SavePrivateKey(X509Certificate2 certificate, string outputPath, string format)
    {
        if (!certificate.HasPrivateKey)
        {
            throw new InvalidOperationException("Certificate does not have a private key. Cannot save key.");
        }

        var isPem = format.Equals("pem", StringComparison.OrdinalIgnoreCase);

        // Try RSA first
        using var rsa = certificate.GetRSAPrivateKey();
        if (rsa != null)
        {
            if (isPem)
            {
                var pem = rsa.ExportRSAPrivateKeyPem();
                File.WriteAllText(outputPath, pem);
            }
            else
            {
                var der = rsa.ExportRSAPrivateKey();
                File.WriteAllBytes(outputPath, der);
            }
            return;
        }

        // Try ECDSA
        using var ecdsa = certificate.GetECDsaPrivateKey();
        if (ecdsa != null)
        {
            if (isPem)
            {
                var pem = ecdsa.ExportECPrivateKeyPem();
                File.WriteAllText(outputPath, pem);
            }
            else
            {
                var der = ecdsa.ExportECPrivateKey();
                File.WriteAllBytes(outputPath, der);
            }
            return;
        }

        throw new InvalidOperationException("Unsupported private key type. Only RSA and ECDSA keys are supported.");
    }
}
