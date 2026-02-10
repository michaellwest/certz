using certz.Models;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace certz.Services;

/// <summary>
/// Service for renewing certificates.
/// </summary>
internal static class RenewService
{
    /// <summary>
    /// Renews a certificate by creating a new one with the same parameters.
    /// </summary>
    internal static async Task<RenewResult> RenewCertificate(RenewOptions options)
    {
        // 1. Load source certificate
        X509Certificate2 sourceCert;
        try
        {
            sourceCert = LoadSourceCertificate(options);
        }
        catch (Exception ex)
        {
            return new RenewResult
            {
                Success = false,
                ErrorMessage = $"Failed to load source certificate: {ex.Message}",
                OriginalSubject = options.Source,
                OriginalThumbprint = "",
                OriginalNotAfter = DateTime.MinValue
            };
        }

        // 2. Extract parameters from existing cert
        var detectedParams = ExtractCertificateParameters(sourceCert);

        // 3. Determine if CA-signed
        var isSelfSigned = sourceCert.Subject == sourceCert.Issuer;
        if (!isSelfSigned && options.IssuerCert == null)
        {
            return new RenewResult
            {
                Success = false,
                ErrorMessage = "Certificate was signed by a CA. Provide --issuer-cert to renew.",
                OriginalSubject = sourceCert.Subject,
                OriginalThumbprint = sourceCert.Thumbprint,
                OriginalNotAfter = sourceCert.NotAfter,
                SANs = detectedParams.SANs,
                KeyType = detectedParams.KeyType
            };
        }

        // 4. Calculate new validity (cap at 398 days per CA/B Forum requirements)
        var originalDays = (sourceCert.NotAfter - sourceCert.NotBefore).Days;
        var newDays = options.Days ?? Math.Min(originalDays, 398);
        newDays = Math.Min(newDays, 398); // Enforce cap

        // 5. Handle password
        bool passwordWasGenerated = false;
        var outputPassword = options.OutputPassword;
        if (string.IsNullOrEmpty(outputPassword))
        {
            outputPassword = CertificateUtilities.GenerateSecurePassword();
            passwordWasGenerated = true;
        }

        // 6. Determine output file
        var outputFile = options.OutputFile?.FullName
            ?? GetDefaultOutputPath(options.Source);

        // 7. Load issuer certificate if provided
        X509Certificate2? issuerCert = null;
        if (options.IssuerCert != null)
        {
            try
            {
                issuerCert = LoadIssuerCertificate(options);
            }
            catch (Exception ex)
            {
                return new RenewResult
                {
                    Success = false,
                    ErrorMessage = $"Failed to load issuer certificate: {ex.Message}",
                    OriginalSubject = sourceCert.Subject,
                    OriginalThumbprint = sourceCert.Thumbprint,
                    OriginalNotAfter = sourceCert.NotAfter
                };
            }
        }

        // 8. Generate or preserve key, create new certificate
        X509Certificate2 renewedCert;
        try
        {
            if (options.KeepKey && sourceCert.HasPrivateKey)
            {
                renewedCert = RenewWithExistingKey(sourceCert, detectedParams, newDays, issuerCert);
            }
            else
            {
                renewedCert = RenewWithNewKey(sourceCert, detectedParams, newDays, issuerCert);
            }
        }
        catch (Exception ex)
        {
            return new RenewResult
            {
                Success = false,
                ErrorMessage = $"Failed to create renewed certificate: {ex.Message}",
                OriginalSubject = sourceCert.Subject,
                OriginalThumbprint = sourceCert.Thumbprint,
                OriginalNotAfter = sourceCert.NotAfter
            };
        }

        // 9. Save to output file
        await CertificateUtilities.WriteCertificateToFile(
            renewedCert,
            outputFile,
            outputPassword,
            CertificateFileType.Pfx,
            displayPassword: false,
            passwordFile: null,
            pfxEncryption: "modern",
            quiet: true);

        return new RenewResult
        {
            Success = true,
            OriginalSubject = sourceCert.Subject,
            OriginalThumbprint = sourceCert.Thumbprint,
            OriginalNotAfter = sourceCert.NotAfter,
            NewSubject = renewedCert.Subject,
            NewThumbprint = renewedCert.Thumbprint,
            NewNotBefore = renewedCert.NotBefore,
            NewNotAfter = renewedCert.NotAfter,
            OutputFile = outputFile,
            Password = passwordWasGenerated ? outputPassword : null,
            PasswordWasGenerated = passwordWasGenerated,
            SANs = detectedParams.SANs,
            KeyType = detectedParams.KeyType,
            KeyWasPreserved = options.KeepKey && sourceCert.HasPrivateKey,
            WasResigned = !isSelfSigned
        };
    }

    private static X509Certificate2 LoadSourceCertificate(RenewOptions options)
    {
        // Check if source is a file
        if (File.Exists(options.Source))
        {
            var ext = Path.GetExtension(options.Source).ToLowerInvariant();
            if (ext is ".pfx" or ".p12")
            {
                var password = options.Password ?? Environment.GetEnvironmentVariable("CERTZ_PASSWORD");
                return X509CertificateLoader.LoadPkcs12FromFile(
                    options.Source,
                    password,
                    X509KeyStorageFlags.Exportable);
            }
            else
            {
                // Load as PEM or DER
                var certData = File.ReadAllBytes(options.Source);
                return X509CertificateLoader.LoadCertificate(certData);
            }
        }

        // Try as thumbprint in store
        var storeName = options.StoreName ?? "My";
        var storeLocation = options.StoreLocation == "LocalMachine"
            ? StoreLocation.LocalMachine
            : StoreLocation.CurrentUser;

        using var store = new X509Store(storeName, storeLocation);
        store.Open(OpenFlags.ReadOnly);

        // Try exact thumbprint match first
        var found = store.Certificates.Find(X509FindType.FindByThumbprint, options.Source, false);
        if (found.Count == 0)
        {
            // Try partial thumbprint match
            var searchThumb = options.Source.ToUpperInvariant().Replace(" ", "");
            foreach (var cert in store.Certificates)
            {
                if (cert.Thumbprint.StartsWith(searchThumb, StringComparison.OrdinalIgnoreCase))
                {
                    return cert;
                }
            }
            throw new FileNotFoundException($"Certificate not found: {options.Source}");
        }
        return found[0];
    }

    private static X509Certificate2 LoadIssuerCertificate(RenewOptions options)
    {
        if (options.IssuerCert == null)
        {
            throw new ArgumentException("Issuer certificate is required");
        }

        var ext = Path.GetExtension(options.IssuerCert.FullName).ToLowerInvariant();

        if (ext is ".pfx" or ".p12")
        {
            // PFX format - contains both certificate and private key
            var password = options.IssuerPassword ?? Environment.GetEnvironmentVariable("CERTZ_ISSUER_PASSWORD");
            return X509CertificateLoader.LoadPkcs12FromFile(
                options.IssuerCert.FullName,
                password,
                X509KeyStorageFlags.Exportable);
        }
        else if (ext is ".pem" or ".crt" or ".cer")
        {
            // PEM format - need to load cert and key separately
            var certPem = File.ReadAllText(options.IssuerCert.FullName);
            var cert = X509Certificate2.CreateFromPem(certPem);

            if (options.IssuerKey != null)
            {
                var keyPem = File.ReadAllText(options.IssuerKey.FullName);

                // Try ECDSA first, then RSA
                try
                {
                    var ecdsa = ECDsa.Create();
                    ecdsa.ImportFromPem(keyPem);
                    return cert.CopyWithPrivateKey(ecdsa);
                }
                catch
                {
                    var rsa = RSA.Create();
                    rsa.ImportFromPem(keyPem);
                    return cert.CopyWithPrivateKey(rsa);
                }
            }

            return cert;
        }
        else
        {
            // Try as DER-encoded certificate
            var certData = File.ReadAllBytes(options.IssuerCert.FullName);
            return X509CertificateLoader.LoadCertificate(certData);
        }
    }

    private static CertificateParameters ExtractCertificateParameters(X509Certificate2 cert)
    {
        var sans = new List<string>();
        var sanExt = cert.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
        if (sanExt != null)
        {
            foreach (var dns in sanExt.EnumerateDnsNames()) sans.Add(dns);
            foreach (var ip in sanExt.EnumerateIPAddresses()) sans.Add(ip.ToString());
        }

        string keyType;
        int keySize;
        if (cert.GetECDsaPublicKey() is ECDsa ecdsa)
        {
            keySize = ecdsa.KeySize;
            keyType = keySize switch
            {
                256 => "ECDSA-P256",
                384 => "ECDSA-P384",
                521 => "ECDSA-P521",
                _ => $"ECDSA-P{keySize}"
            };
        }
        else if (cert.GetRSAPublicKey() is RSA rsa)
        {
            keySize = rsa.KeySize;
            keyType = "RSA";
        }
        else
        {
            keyType = "Unknown";
            keySize = 0;
        }

        var isCa = cert.Extensions.OfType<X509BasicConstraintsExtension>()
            .FirstOrDefault()?.CertificateAuthority ?? false;

        // Extract hash algorithm from signature
        var hashAlgorithm = cert.SignatureAlgorithm.FriendlyName ?? "SHA256";
        if (hashAlgorithm.Contains("SHA256", StringComparison.OrdinalIgnoreCase))
            hashAlgorithm = "SHA256";
        else if (hashAlgorithm.Contains("SHA384", StringComparison.OrdinalIgnoreCase))
            hashAlgorithm = "SHA384";
        else if (hashAlgorithm.Contains("SHA512", StringComparison.OrdinalIgnoreCase))
            hashAlgorithm = "SHA512";
        else
            hashAlgorithm = "SHA256"; // Default

        return new CertificateParameters
        {
            Subject = cert.Subject,
            SANs = sans.ToArray(),
            KeyType = keyType,
            KeySize = keySize,
            IsCA = isCa,
            HashAlgorithm = hashAlgorithm
        };
    }

    private static string GetDefaultOutputPath(string source)
    {
        if (File.Exists(source))
        {
            var dir = Path.GetDirectoryName(source) ?? ".";
            var name = Path.GetFileNameWithoutExtension(source);
            return Path.Combine(dir, $"{name}-renewed.pfx");
        }
        // Thumbprint-based source
        var thumbPart = source.Length >= 8 ? source[..8] : source;
        return $"renewed-{thumbPart}.pfx";
    }

    /// <summary>
    /// Renews a certificate by reusing the existing private key.
    /// </summary>
    private static X509Certificate2 RenewWithExistingKey(
        X509Certificate2 source,
        CertificateParameters detectedParams,
        int days,
        X509Certificate2? issuerCert)
    {
        var notBefore = DateTimeOffset.UtcNow;
        var notAfter = notBefore.AddDays(days);

        // Get DNS names for the certificate (use SANs, or extract CN if no SANs)
        var dnsNames = detectedParams.SANs.Length > 0
            ? detectedParams.SANs
            : ExtractCNFromSubject(detectedParams.Subject);

        // Build certificate request with existing key
        CertificateRequest request;
        X509SubjectKeyIdentifierExtension subjectKeyIdentifier;

        var subject = new X500DistinguishedName(detectedParams.Subject);

        if (detectedParams.KeyType == "RSA")
        {
            var rsaKey = source.GetRSAPrivateKey()
                ?? throw new CertificateException("Cannot extract RSA private key from source certificate");

            var hashName = GetHashAlgorithmName(detectedParams.HashAlgorithm);
            request = new CertificateRequest(subject, rsaKey, hashName, RSASignaturePadding.Pkcs1);
            subjectKeyIdentifier = new X509SubjectKeyIdentifierExtension(request.PublicKey, false);
        }
        else if (detectedParams.KeyType.StartsWith("ECDSA"))
        {
            var ecdsaKey = source.GetECDsaPrivateKey()
                ?? throw new CertificateException("Cannot extract ECDSA private key from source certificate");

            var hashName = GetHashAlgorithmName(detectedParams.HashAlgorithm);
            request = new CertificateRequest(subject, ecdsaKey, hashName);
            subjectKeyIdentifier = new X509SubjectKeyIdentifierExtension(request.PublicKey, false);
        }
        else
        {
            throw new CertificateException($"Unsupported key type: {detectedParams.KeyType}");
        }

        // Add extensions
        AddCertificateExtensions(request, subjectKeyIdentifier, dnsNames, detectedParams.IsCA, issuerCert);

        // Create the certificate
        if (issuerCert != null)
        {
            return SignWithIssuer(request, issuerCert, notBefore, notAfter, source);
        }
        else
        {
            var result = request.CreateSelfSigned(notBefore, notAfter);
            if (OperatingSystem.IsWindows())
            {
                result.FriendlyName = "certz";
            }
            return result;
        }
    }

    /// <summary>
    /// Renews a certificate by generating a new key with the same algorithm.
    /// </summary>
    private static X509Certificate2 RenewWithNewKey(
        X509Certificate2 source,
        CertificateParameters detectedParams,
        int days,
        X509Certificate2? issuerCert)
    {
        var notBefore = DateTimeOffset.UtcNow;
        var notAfter = notBefore.AddDays(days);

        // Get DNS names for the certificate
        var dnsNames = detectedParams.SANs.Length > 0
            ? detectedParams.SANs
            : ExtractCNFromSubject(detectedParams.Subject);

        if (issuerCert != null)
        {
            // CA-signed renewal - use GenerateSignedCertificate
            return CertificateGeneration.GenerateSignedCertificate(
                dnsNames: dnsNames,
                notBefore: notBefore,
                notAfter: notAfter,
                keySize: detectedParams.KeySize,
                hashAlgorithm: detectedParams.HashAlgorithm,
                keyType: detectedParams.KeyType,
                rsaPadding: "pkcs1",
                isCA: detectedParams.IsCA,
                issuerCertificate: issuerCert);
        }
        else
        {
            // Self-signed renewal - use GenerateCertificate
            return CertificateGeneration.GenerateCertificate(
                dnsNames: dnsNames,
                notBefore: notBefore,
                notAfter: notAfter,
                keySize: detectedParams.KeySize,
                hashAlgorithm: detectedParams.HashAlgorithm,
                keyType: detectedParams.KeyType,
                rsaPadding: "pkcs1",
                isCA: detectedParams.IsCA);
        }
    }

    private static string[] ExtractCNFromSubject(string subject)
    {
        if (subject.Contains("CN="))
        {
            var cnStart = subject.IndexOf("CN=") + 3;
            var cnEnd = subject.IndexOf(',', cnStart);
            var cn = cnEnd > 0 ? subject.Substring(cnStart, cnEnd - cnStart) : subject.Substring(cnStart);
            return new[] { cn };
        }
        return new[] { "localhost" };
    }

    private static HashAlgorithmName GetHashAlgorithmName(string hashAlgorithm)
    {
        return hashAlgorithm.ToUpperInvariant() switch
        {
            "SHA256" => HashAlgorithmName.SHA256,
            "SHA384" => HashAlgorithmName.SHA384,
            "SHA512" => HashAlgorithmName.SHA512,
            _ => HashAlgorithmName.SHA256
        };
    }

    private static void AddCertificateExtensions(
        CertificateRequest request,
        X509SubjectKeyIdentifierExtension subjectKeyIdentifier,
        string[] dnsNames,
        bool isCA,
        X509Certificate2? issuerCert)
    {
        // Basic Constraints
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(isCA, false, 0, true));

        // Key Usage
        if (isCA)
        {
            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature,
                critical: true));
        }
        else
        {
            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature,
                critical: true));

            // Enhanced Key Usage for end-entity certificates
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.1", "Server Authentication") },
                critical: false));
        }

        // Subject Key Identifier
        request.CertificateExtensions.Add(subjectKeyIdentifier);

        // Authority Key Identifier
        if (issuerCert != null)
        {
            var issuerSubjectKeyId = issuerCert.Extensions
                .OfType<X509SubjectKeyIdentifierExtension>()
                .FirstOrDefault();

            if (issuerSubjectKeyId != null)
            {
                request.CertificateExtensions.Add(
                    X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(issuerSubjectKeyId));
            }
            else
            {
                request.CertificateExtensions.Add(
                    X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuerCert, true, true));
            }
        }
        else
        {
            // Self-signed: AKI = SKI
            request.CertificateExtensions.Add(
                X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(subjectKeyIdentifier));
        }

        // Subject Alternative Names
        var sanBuilder = new SubjectAlternativeNameBuilder();
        foreach (var name in dnsNames)
        {
            if (System.Net.IPAddress.TryParse(name, out var ip))
            {
                sanBuilder.AddIpAddress(ip);
            }
            else
            {
                sanBuilder.AddDnsName(name);
            }
        }
        request.CertificateExtensions.Add(sanBuilder.Build(false));
    }

    private static X509Certificate2 SignWithIssuer(
        CertificateRequest request,
        X509Certificate2 issuerCert,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        X509Certificate2 sourceCert)
    {
        // Generate serial number
        byte[] serialNumber = new byte[16];
        RandomNumberGenerator.Fill(serialNumber);
        serialNumber[0] &= 0x7F; // Ensure positive

        // Sign with issuer's private key
        X509Certificate2 signedCert;
        var issuerRsa = issuerCert.GetRSAPrivateKey();
        var issuerEcdsa = issuerCert.GetECDsaPrivateKey();

        if (issuerRsa != null)
        {
            var generator = X509SignatureGenerator.CreateForRSA(issuerRsa, RSASignaturePadding.Pkcs1);
            signedCert = request.Create(
                issuerCert.SubjectName,
                generator,
                notBefore,
                notAfter,
                serialNumber);
        }
        else if (issuerEcdsa != null)
        {
            var generator = X509SignatureGenerator.CreateForECDsa(issuerEcdsa);
            signedCert = request.Create(
                issuerCert.SubjectName,
                generator,
                notBefore,
                notAfter,
                serialNumber);
        }
        else
        {
            throw new CertificateException("Issuer certificate must have RSA or ECDSA private key.");
        }

        // Attach the private key from the source certificate
        var rsaKey = sourceCert.GetRSAPrivateKey();
        if (rsaKey != null)
        {
            var certWithKey = signedCert.CopyWithPrivateKey(rsaKey);
            if (OperatingSystem.IsWindows())
            {
                certWithKey.FriendlyName = "certz";
            }
            return certWithKey;
        }

        var ecdsaKey = sourceCert.GetECDsaPrivateKey();
        if (ecdsaKey != null)
        {
            var certWithKey = signedCert.CopyWithPrivateKey(ecdsaKey);
            if (OperatingSystem.IsWindows())
            {
                certWithKey.FriendlyName = "certz";
            }
            return certWithKey;
        }

        throw new CertificateException("Source certificate must have RSA or ECDSA private key.");
    }

    private record CertificateParameters
    {
        public required string Subject { get; init; }
        public required string[] SANs { get; init; }
        public required string KeyType { get; init; }
        public required int KeySize { get; init; }
        public required bool IsCA { get; init; }
        public required string HashAlgorithm { get; init; }
    }
}
