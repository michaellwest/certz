using certz.Models;

namespace certz.Services;

/// <summary>
/// Service for creating certificates (development/server certificates and CAs).
/// </summary>
internal static class CreateService
{
    /// <summary>
    /// Creates a development/server certificate.
    /// </summary>
    /// <param name="options">The certificate creation options.</param>
    /// <returns>The creation result.</returns>
    internal static async Task<CertificateCreationResult> CreateDevCertificate(DevCertificateOptions options)
    {
        // Build SANs list: domain first, then additional SANs
        var sans = new List<string> { options.Domain };
        sans.AddRange(options.AdditionalSANs);

        // Handle password
        bool passwordWasGenerated = false;
        var password = options.Password;
        if (string.IsNullOrEmpty(password))
        {
            password = CertificateUtilities.GenerateSecurePassword();
            passwordWasGenerated = true;
        }

        var validFrom = DateTime.Today;
        var validTo = DateTime.Today.AddDays(options.Days).AddSeconds(-1);

        X509Certificate2 certificate;

        // Check if we have an issuer to sign with
        if (options.IssuerCert != null)
        {
            certificate = await GenerateSignedCertificate(
                sans.ToArray(),
                validFrom,
                validTo,
                options.KeySize,
                options.HashAlgorithm,
                options.KeyType,
                options.RsaPadding,
                isCA: false,
                pathLength: -1,
                crlUrl: null,
                ocspUrl: null,
                caIssuersUrl: null,
                options.SubjectO,
                options.SubjectOU,
                options.SubjectC,
                options.SubjectST,
                options.SubjectL,
                options.IssuerCert,
                options.IssuerKey,
                options.IssuerPassword);
        }
        else
        {
            certificate = CertificateGeneration.GenerateCertificate(
                sans.ToArray(),
                validFrom,
                validTo,
                options.KeySize,
                options.HashAlgorithm,
                options.KeyType,
                options.RsaPadding,
                isCA: false,
                pathLength: -1,
                crlUrl: null,
                ocspUrl: null,
                caIssuersUrl: null,
                options.SubjectO,
                options.SubjectOU,
                options.SubjectC,
                options.SubjectST,
                options.SubjectL);
        }

        // Handle pipe mode - stream to stdout and return
        if (options.Pipe)
        {
            await PipeOutputService.WritePipeOutput(
                certificate,
                options.PipeFormat ?? "pem",
                options.PipePassword);

            return new CertificateCreationResult
            {
                Subject = certificate.Subject,
                Thumbprint = certificate.Thumbprint,
                NotBefore = certificate.NotBefore,
                NotAfter = certificate.NotAfter,
                KeyType = options.KeyType,
                SANs = sans.ToArray(),
                OutputFiles = Array.Empty<string>(),
                Password = null,
                PasswordWasGenerated = false,
                WasTrusted = false,
                IsCA = false,
                PathLength = -1,
                IsEphemeral = false,
                WasPiped = true
            };
        }

        // Handle ephemeral mode - skip all file writing
        if (options.Ephemeral)
        {
            return new CertificateCreationResult
            {
                Subject = certificate.Subject,
                Thumbprint = certificate.Thumbprint,
                NotBefore = certificate.NotBefore,
                NotAfter = certificate.NotAfter,
                KeyType = options.KeyType,
                SANs = sans.ToArray(),
                OutputFiles = Array.Empty<string>(),
                Password = null,
                PasswordWasGenerated = false,
                WasTrusted = false,
                IsCA = false,
                PathLength = -1,
                IsEphemeral = true,
                WasPiped = false
            };
        }

        var outputFiles = new List<string>();

        // Save certificate files
        if (options.PfxFile != null)
        {
            await CertificateUtilities.WriteCertificateToFile(
                certificate,
                options.PfxFile.FullName,
                password,
                CertificateFileType.Pfx,
                displayPassword: false,
                passwordFile: options.PasswordFile,
                pfxEncryption: options.PfxEncryption,
                quiet: true);
            outputFiles.Add(options.PfxFile.FullName);
        }

        if (options.CertFile != null)
        {
            await CertificateUtilities.WriteCertificateToFile(
                certificate,
                options.CertFile.FullName,
                password,
                CertificateFileType.PemCer,
                quiet: true);
            outputFiles.Add(options.CertFile.FullName);
        }

        if (options.KeyFile != null)
        {
            await CertificateUtilities.WriteCertificateToFile(
                certificate,
                options.KeyFile.FullName,
                password,
                CertificateFileType.PemKey,
                quiet: true);
            outputFiles.Add(options.KeyFile.FullName);
        }

        // Write password to file if generated and file specified
        if (passwordWasGenerated && options.PasswordFile != null)
        {
            options.PasswordFile.Directory?.Create();
            await File.WriteAllTextAsync(options.PasswordFile.FullName, password);
        }

        // Install to trust store if requested
        bool wasTrusted = false;
        if (options.Trust && options.PfxFile != null)
        {
            await CertificateUtilities.InstallCertificate(
                options.PfxFile,
                password,
                StoreName.Root,
                options.TrustLocation,
                exportable: true,
                quiet: true);
            wasTrusted = true;
        }

        return new CertificateCreationResult
        {
            Subject = certificate.Subject,
            Thumbprint = certificate.Thumbprint,
            NotBefore = certificate.NotBefore,
            NotAfter = certificate.NotAfter,
            KeyType = options.KeyType,
            SANs = sans.ToArray(),
            OutputFiles = outputFiles.ToArray(),
            Password = passwordWasGenerated ? password : null,
            PasswordWasGenerated = passwordWasGenerated,
            WasTrusted = wasTrusted,
            IsCA = false,
            PathLength = -1,
            IsEphemeral = false,
            WasPiped = false
        };
    }

    /// <summary>
    /// Creates a Certificate Authority (CA) certificate.
    /// </summary>
    /// <param name="options">The CA certificate creation options.</param>
    /// <returns>The creation result.</returns>
    internal static async Task<CertificateCreationResult> CreateCACertificate(CACertificateOptions options)
    {
        // CA uses name as the subject
        var sans = new[] { options.Name };

        // Handle password
        bool passwordWasGenerated = false;
        var password = options.Password;
        if (string.IsNullOrEmpty(password))
        {
            password = CertificateUtilities.GenerateSecurePassword();
            passwordWasGenerated = true;
        }

        var validFrom = DateTime.Today;
        var validTo = DateTime.Today.AddDays(options.Days).AddSeconds(-1);

        var certificate = CertificateGeneration.GenerateCertificate(
            sans,
            validFrom,
            validTo,
            options.KeySize,
            options.HashAlgorithm,
            options.KeyType,
            options.RsaPadding,
            isCA: true,
            pathLength: options.PathLength,
            crlUrl: options.CrlUrl,
            ocspUrl: options.OcspUrl,
            caIssuersUrl: options.CAIssuersUrl,
            options.SubjectO,
            options.SubjectOU,
            options.SubjectC,
            options.SubjectST,
            options.SubjectL);

        // Handle pipe mode - stream to stdout and return
        if (options.Pipe)
        {
            await PipeOutputService.WritePipeOutput(
                certificate,
                options.PipeFormat ?? "pem",
                options.PipePassword);

            return new CertificateCreationResult
            {
                Subject = certificate.Subject,
                Thumbprint = certificate.Thumbprint,
                NotBefore = certificate.NotBefore,
                NotAfter = certificate.NotAfter,
                KeyType = options.KeyType,
                SANs = sans,
                OutputFiles = Array.Empty<string>(),
                Password = null,
                PasswordWasGenerated = false,
                WasTrusted = false,
                IsCA = true,
                PathLength = options.PathLength,
                IsEphemeral = false,
                WasPiped = true
            };
        }

        // Handle ephemeral mode - skip all file writing
        if (options.Ephemeral)
        {
            return new CertificateCreationResult
            {
                Subject = certificate.Subject,
                Thumbprint = certificate.Thumbprint,
                NotBefore = certificate.NotBefore,
                NotAfter = certificate.NotAfter,
                KeyType = options.KeyType,
                SANs = sans,
                OutputFiles = Array.Empty<string>(),
                Password = null,
                PasswordWasGenerated = false,
                WasTrusted = false,
                IsCA = true,
                PathLength = options.PathLength,
                IsEphemeral = true,
                WasPiped = false
            };
        }

        var outputFiles = new List<string>();

        // Save certificate files
        if (options.PfxFile != null)
        {
            await CertificateUtilities.WriteCertificateToFile(
                certificate,
                options.PfxFile.FullName,
                password,
                CertificateFileType.Pfx,
                displayPassword: false,
                passwordFile: options.PasswordFile,
                pfxEncryption: options.PfxEncryption,
                quiet: true);
            outputFiles.Add(options.PfxFile.FullName);
        }

        if (options.CertFile != null)
        {
            await CertificateUtilities.WriteCertificateToFile(
                certificate,
                options.CertFile.FullName,
                password,
                CertificateFileType.PemCer,
                quiet: true);
            outputFiles.Add(options.CertFile.FullName);
        }

        if (options.KeyFile != null)
        {
            await CertificateUtilities.WriteCertificateToFile(
                certificate,
                options.KeyFile.FullName,
                password,
                CertificateFileType.PemKey,
                quiet: true);
            outputFiles.Add(options.KeyFile.FullName);
        }

        // Write password to file if generated and file specified
        if (passwordWasGenerated && options.PasswordFile != null)
        {
            options.PasswordFile.Directory?.Create();
            await File.WriteAllTextAsync(options.PasswordFile.FullName, password);
        }

        // Install to trust store if requested
        bool wasTrusted = false;
        if (options.Trust && options.PfxFile != null)
        {
            await CertificateUtilities.InstallCertificate(
                options.PfxFile,
                password,
                StoreName.Root,
                options.TrustLocation,
                exportable: true,
                quiet: true);
            wasTrusted = true;
        }

        return new CertificateCreationResult
        {
            Subject = certificate.Subject,
            Thumbprint = certificate.Thumbprint,
            NotBefore = certificate.NotBefore,
            NotAfter = certificate.NotAfter,
            KeyType = options.KeyType,
            SANs = sans,
            OutputFiles = outputFiles.ToArray(),
            Password = passwordWasGenerated ? password : null,
            PasswordWasGenerated = passwordWasGenerated,
            WasTrusted = wasTrusted,
            IsCA = true,
            PathLength = options.PathLength,
            IsEphemeral = false,
            WasPiped = false
        };
    }

    private static async Task<X509Certificate2> GenerateSignedCertificate(
        string[] dnsNames,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        int keySize,
        string hashAlgorithm,
        string keyType,
        string rsaPadding,
        bool isCA,
        int pathLength,
        string? crlUrl,
        string? ocspUrl,
        string? caIssuersUrl,
        string? subjectO,
        string? subjectOU,
        string? subjectC,
        string? subjectST,
        string? subjectL,
        FileInfo issuerCertFile,
        FileInfo? issuerKeyFile,
        string? issuerPassword)
    {
        // Load issuer certificate
        X509Certificate2 issuerCert;

        if (issuerCertFile.Extension.Equals(".pfx", StringComparison.OrdinalIgnoreCase) ||
            issuerCertFile.Extension.Equals(".p12", StringComparison.OrdinalIgnoreCase))
        {
            // PFX format - contains both cert and key
            if (string.IsNullOrEmpty(issuerPassword))
            {
                throw new CertificateException("Password is required for PFX issuer certificate.");
            }
            issuerCert = X509CertificateLoader.LoadPkcs12FromFile(
                issuerCertFile.FullName,
                issuerPassword,
                X509KeyStorageFlags.Exportable);
        }
        else
        {
            // PEM format - need separate key file
            if (issuerKeyFile == null)
            {
                throw new CertificateException("Issuer key file is required for PEM format issuer certificate.");
            }

            var certPem = await File.ReadAllTextAsync(issuerCertFile.FullName);
            var keyPem = await File.ReadAllTextAsync(issuerKeyFile.FullName);
            issuerCert = X509Certificate2.CreateFromPem(certPem, keyPem);
        }

        if (!issuerCert.HasPrivateKey)
        {
            throw new CertificateException("Issuer certificate must have a private key for signing.");
        }

        // Generate the certificate with the issuer
        return CertificateGeneration.GenerateSignedCertificate(
            dnsNames,
            notBefore,
            notAfter,
            keySize,
            hashAlgorithm,
            keyType,
            rsaPadding,
            isCA,
            pathLength,
            crlUrl,
            ocspUrl,
            caIssuersUrl,
            subjectO,
            subjectOU,
            subjectC,
            subjectST,
            subjectL,
            issuerCert);
    }
}
