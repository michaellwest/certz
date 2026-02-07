using certz.Models;

namespace certz.Services;

internal static class CertificateOperationsV2
{
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
            PathLength = -1
        };
    }

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
            PathLength = options.PathLength
        };
    }

    /// <summary>
    /// Converts a PEM certificate and private key to PFX format.
    /// </summary>
    /// <param name="options">The conversion options.</param>
    /// <returns>The conversion result.</returns>
    internal static async Task<ConversionResult> ConvertToPfx(ConvertToPfxOptions options)
    {
        if (!options.CertFile.Exists)
        {
            throw new FileNotFoundException($"Certificate file not found: {options.CertFile.FullName}");
        }

        if (!options.KeyFile.Exists)
        {
            throw new FileNotFoundException($"Key file not found: {options.KeyFile.FullName}");
        }

        // Handle password
        bool passwordWasGenerated = false;
        var password = options.Password;
        if (string.IsNullOrEmpty(password))
        {
            password = CertificateUtilities.GenerateSecurePassword();
            passwordWasGenerated = true;
        }

        // Load the certificate
        var certificateText = await File.ReadAllTextAsync(options.CertFile.FullName);
        var certificate = X509Certificate2.CreateFromPem(certificateText);

        // Load the private key - try RSA first, then ECDSA
        var privateKeyText = await File.ReadAllTextAsync(options.KeyFile.FullName);
        X509Certificate2 certificateWithKey;

        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(privateKeyText);
            certificateWithKey = certificate.CopyWithPrivateKey(rsa);
        }
        catch
        {
            // Try ECDSA
            try
            {
                using var ecdsa = ECDsa.Create();
                ecdsa.ImportFromPem(privateKeyText);
                certificateWithKey = certificate.CopyWithPrivateKey(ecdsa);
            }
            catch
            {
                throw new CertificateException("Unable to import private key. Only RSA and ECDSA keys are supported.");
            }
        }

        // Export as PFX
        options.OutputFile.Directory?.Create();
        byte[] pfxData;
        if (options.PfxEncryption.ToUpperInvariant() == "MODERN")
        {
            // Modern encryption: AES-256-CBC with SHA-256 and high iteration count
            var pbeParams = new PbeParameters(
                PbeEncryptionAlgorithm.Aes256Cbc,
                HashAlgorithmName.SHA256,
                iterationCount: 100000);
            pfxData = certificateWithKey.ExportPkcs12(pbeParams, password);
        }
        else
        {
            // Legacy encryption: 3DES for compatibility with older systems
            pfxData = certificateWithKey.Export(X509ContentType.Pfx, password);
        }
        await File.WriteAllBytesAsync(options.OutputFile.FullName, pfxData);

        // Write password to file if generated and file specified
        if (passwordWasGenerated && options.PasswordFile != null)
        {
            options.PasswordFile.Directory?.Create();
            await File.WriteAllTextAsync(options.PasswordFile.FullName, password);
        }

        return new ConversionResult
        {
            Success = true,
            OutputFile = options.OutputFile.FullName,
            InputCertificate = options.CertFile.FullName,
            InputKey = options.KeyFile.FullName,
            GeneratedPassword = passwordWasGenerated ? password : null,
            PasswordWasGenerated = passwordWasGenerated,
            Subject = certificate.SubjectName.Format(false)
        };
    }

    /// <summary>
    /// Converts a PFX file to PEM format.
    /// </summary>
    /// <param name="options">The conversion options.</param>
    /// <returns>The conversion result.</returns>
    internal static async Task<ConversionResult> ConvertFromPfx(ConvertFromPfxOptions options)
    {
        if (!options.PfxFile.Exists)
        {
            throw new FileNotFoundException($"PFX file not found: {options.PfxFile.FullName}");
        }

        if (options.OutputCert == null && options.OutputKey == null)
        {
            throw new ArgumentException("Please specify at least one output: --out-cert or --out-key");
        }

        if (string.IsNullOrEmpty(options.Password))
        {
            throw new ArgumentException("Password is required to load PFX file. Use --password to specify the password.");
        }

        // Load PFX file
        var certificate = X509CertificateLoader.LoadPkcs12FromFile(
            options.PfxFile.FullName,
            options.Password,
            X509KeyStorageFlags.Exportable
        );

        var additionalOutputFiles = new List<string>();

        // Export certificate to PEM
        if (options.OutputCert != null)
        {
            options.OutputCert.Directory?.Create();
            var certificatePem = PemEncoding.Write("CERTIFICATE", certificate.RawData);
            await File.WriteAllTextAsync(options.OutputCert.FullName, new string(certificatePem));
            additionalOutputFiles.Add(options.OutputCert.FullName);
        }

        // Export private key to PEM (if present)
        if (options.OutputKey != null)
        {
            if (!certificate.HasPrivateKey)
            {
                throw new CertificateException("PFX file does not contain a private key");
            }

            string privateKeyPem;
            var rsaKey = certificate.GetRSAPrivateKey();
            if (rsaKey != null)
            {
                privateKeyPem = rsaKey.ExportPkcs8PrivateKeyPem();
            }
            else
            {
                var ecdsaKey = certificate.GetECDsaPrivateKey();
                if (ecdsaKey != null)
                {
                    privateKeyPem = ecdsaKey.ExportPkcs8PrivateKeyPem();
                }
                else
                {
                    throw new CertificateException("Unable to extract private key (unsupported key type - only RSA and ECDSA are supported)");
                }
            }

            options.OutputKey.Directory?.Create();
            await File.WriteAllTextAsync(options.OutputKey.FullName, privateKeyPem);
        }

        // Determine primary output file
        var primaryOutput = options.OutputCert?.FullName ?? options.OutputKey?.FullName ?? "";

        // Build additional outputs list (excluding primary)
        var additionalOutputs = additionalOutputFiles.Where(f => f != primaryOutput).ToArray();

        certificate.Dispose();

        return new ConversionResult
        {
            Success = true,
            OutputFile = primaryOutput,
            InputPfx = options.PfxFile.FullName,
            AdditionalOutputFiles = additionalOutputs,
            Subject = certificate.SubjectName.Format(false)
        };
    }

    /// <summary>
    /// Exports a certificate from a remote URL.
    /// </summary>
    /// <param name="options">The export options.</param>
    /// <returns>The export result.</returns>
    internal static async Task<ExportResult> ExportFromUrl(ExportFromUrlOptions options)
    {
        // Connect to remote host and retrieve certificate
        RemoteCertificateValidationCallback certCallback = (_, _, _, _) => true;
        using var client = new TcpClient(options.Url.Host, 443);
        using var sslStream = new SslStream(client.GetStream(), true, certCallback);
        await sslStream.AuthenticateAsClientAsync(options.Url.Host);
        var serverCertificate = sslStream.RemoteCertificate;
        var certificate = new X509Certificate2(serverCertificate);

        // Handle password for PFX
        bool passwordWasGenerated = false;
        string? password = options.Password;
        if (options.PfxFile != null && string.IsNullOrEmpty(password))
        {
            password = CertificateUtilities.GenerateSecurePassword();
            passwordWasGenerated = true;
        }

        var outputFiles = new List<string>();

        // Save certificate files
        if (options.PfxFile != null)
        {
            await CertificateUtilities.WriteCertificateToFile(
                certificate,
                options.PfxFile.FullName,
                password!,
                CertificateFileType.Pfx,
                displayPassword: false,
                passwordFile: options.PasswordFile,
                quiet: true);
            outputFiles.Add(options.PfxFile.FullName);
        }

        if (options.CertFile != null)
        {
            await CertificateUtilities.WriteCertificateToFile(
                certificate,
                options.CertFile.FullName,
                password ?? string.Empty,
                CertificateFileType.PemCer,
                quiet: true);
            outputFiles.Add(options.CertFile.FullName);
        }

        if (options.KeyFile != null)
        {
            await CertificateUtilities.WriteCertificateToFile(
                certificate,
                options.KeyFile.FullName,
                password ?? string.Empty,
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

        return new ExportResult
        {
            Success = true,
            Subject = certificate.SubjectName.Format(false),
            Issuer = certificate.IssuerName.Format(false),
            Thumbprint = certificate.Thumbprint,
            NotAfter = certificate.NotAfter,
            Source = $"URL: {options.Url}",
            OutputFiles = outputFiles.ToArray(),
            GeneratedPassword = passwordWasGenerated ? password : null,
            PasswordWasGenerated = passwordWasGenerated
        };
    }

    /// <summary>
    /// Exports a certificate from a certificate store.
    /// </summary>
    /// <param name="options">The export options.</param>
    /// <returns>The export result.</returns>
    internal static async Task<ExportResult> ExportFromStore(ExportFromStoreOptions options)
    {
        // Handle password for PFX
        bool passwordWasGenerated = false;
        string? password = options.Password;
        if (options.PfxFile != null && string.IsNullOrEmpty(password))
        {
            password = CertificateUtilities.GenerateSecurePassword();
            passwordWasGenerated = true;
        }

        // Open store and find certificate
        using var store = new X509Store(options.StoreName, options.StoreLocation, OpenFlags.ReadOnly);
        var certificate = store.Certificates
            .FirstOrDefault(c => c.Thumbprint.Equals(options.Thumbprint, StringComparison.InvariantCultureIgnoreCase));

        if (certificate == null)
        {
            throw new CertificateException($"Certificate with thumbprint {options.Thumbprint} not found in {options.StoreLocation}\\{options.StoreName}");
        }

        var outputFiles = new List<string>();

        // Save certificate files
        if (options.PfxFile != null)
        {
            await CertificateUtilities.WriteCertificateToFile(
                certificate,
                options.PfxFile.FullName,
                password!,
                CertificateFileType.Pfx,
                displayPassword: false,
                passwordFile: options.PasswordFile,
                quiet: true);
            outputFiles.Add(options.PfxFile.FullName);
        }

        if (options.CertFile != null)
        {
            await CertificateUtilities.WriteCertificateToFile(
                certificate,
                options.CertFile.FullName,
                password ?? string.Empty,
                CertificateFileType.PemCer,
                quiet: true);
            outputFiles.Add(options.CertFile.FullName);
        }

        if (options.KeyFile != null)
        {
            await CertificateUtilities.WriteCertificateToFile(
                certificate,
                options.KeyFile.FullName,
                password ?? string.Empty,
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

        store.Close();

        return new ExportResult
        {
            Success = true,
            Subject = certificate.SubjectName.Format(false),
            Issuer = certificate.IssuerName.Format(false),
            Thumbprint = certificate.Thumbprint,
            NotAfter = certificate.NotAfter,
            Source = $"Store: {options.StoreLocation}\\{options.StoreName}",
            OutputFiles = outputFiles.ToArray(),
            GeneratedPassword = passwordWasGenerated ? password : null,
            PasswordWasGenerated = passwordWasGenerated
        };
    }

    /// <summary>
    /// Lists certificates from a certificate store.
    /// </summary>
    /// <param name="options">Options for listing certificates.</param>
    /// <returns>Result containing the list of certificates.</returns>
    internal static StoreListResult ListCertificates(ListCertificatesOptions options)
    {
        var storeListOptions = new StoreListOptions
        {
            StoreName = options.StoreName.ToString(),
            StoreLocation = options.StoreLocation.ToString(),
            ShowExpired = false,
            ExpiringDays = null
        };

        return StoreListHandler.ListCertificates(storeListOptions);
    }

    /// <summary>
    /// Removes a certificate from a certificate store.
    /// </summary>
    /// <param name="options">Options for removing the certificate.</param>
    /// <returns>Result containing information about removed certificates.</returns>
    internal static TrustOperationResult RemoveCertificate(RemoveCertificateOptions options)
    {
        var subject = options.Subject;
        var thumbprint = options.Thumbprint;

        // Normalize subject to include CN= prefix if needed
        if (!string.IsNullOrEmpty(subject) && !subject.StartsWith("CN="))
        {
            subject = $"CN={subject}";
        }

        // Build predicate for matching certificates
        bool predicate(X509Certificate2 c) =>
            (!string.IsNullOrEmpty(thumbprint) && c.Thumbprint.Equals(thumbprint, StringComparison.InvariantCultureIgnoreCase)) ||
            (!string.IsNullOrEmpty(subject) && c.Subject.Equals(subject, StringComparison.InvariantCultureIgnoreCase));

        var removedCertificates = new List<TrustCertificateInfo>();

        using var store = new X509Store(options.StoreName, options.StoreLocation, OpenFlags.ReadWrite);
        foreach (var certificate in store.Certificates.Where(predicate))
        {
            removedCertificates.Add(new TrustCertificateInfo
            {
                Subject = certificate.Subject,
                Thumbprint = certificate.Thumbprint,
                NotAfter = certificate.NotAfter
            });
            store.Remove(certificate);
        }
        store.Close();

        return new TrustOperationResult
        {
            Success = true,
            Operation = TrustOperationType.Remove,
            StoreName = options.StoreName.ToString(),
            StoreLocation = options.StoreLocation.ToString(),
            Certificates = removedCertificates
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
