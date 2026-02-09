using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using certz.Models;

namespace certz.Services;

/// <summary>
/// Service for converting certificates between formats (PEM, PFX/PKCS#12).
/// </summary>
internal static class ConvertService
{
    /// <summary>
    /// Converts a PEM certificate and private key to PFX format.
    /// </summary>
    /// <param name="options">The conversion options.</param>
    /// <returns>The conversion result.</returns>
    /// <exception cref="FileNotFoundException">Thrown when the certificate or key file is not found.</exception>
    /// <exception cref="CertificateException">Thrown when the private key cannot be imported.</exception>
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

        // Handle password - check password file first if provided
        bool passwordWasGenerated = false;
        var password = options.Password;
        if (string.IsNullOrEmpty(password) && options.PasswordFile != null && options.PasswordFile.Exists)
        {
            password = (await File.ReadAllTextAsync(options.PasswordFile.FullName)).Trim();
        }
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
    /// <exception cref="FileNotFoundException">Thrown when the PFX file is not found.</exception>
    /// <exception cref="ArgumentException">Thrown when no output file is specified or password is missing.</exception>
    /// <exception cref="CertificateException">Thrown when the private key cannot be extracted.</exception>
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

        var subject = certificate.SubjectName.Format(false);
        certificate.Dispose();

        return new ConversionResult
        {
            Success = true,
            OutputFile = primaryOutput,
            InputPfx = options.PfxFile.FullName,
            AdditionalOutputFiles = additionalOutputs,
            Subject = subject
        };
    }

    /// <summary>
    /// Converts a certificate to DER format.
    /// </summary>
    internal static async Task<ConversionResult> ConvertToDer(ConvertOptions options)
    {
        // Load certificate based on input format
        var certificate = await LoadCertificate(options);

        // Determine output path
        var outputPath = options.OutputFile?.FullName
            ?? FormatDetectionService.GenerateOutputPath(options.InputFile, FormatType.Der);

        // Create output directory if needed
        var outputDir = Path.GetDirectoryName(outputPath);
        if (!string.IsNullOrEmpty(outputDir))
        {
            Directory.CreateDirectory(outputDir);
        }

        // Export certificate as DER (binary)
        await File.WriteAllBytesAsync(outputPath, certificate.RawData);

        var subject = certificate.SubjectName.Format(false);
        certificate.Dispose();

        return new ConversionResult
        {
            Success = true,
            OutputFile = outputPath,
            InputPfx = options.InputFormat == FormatType.Pfx ? options.InputFile.FullName : null,
            InputCertificate = options.InputFormat == FormatType.Pem ? options.InputFile.FullName : null,
            Subject = subject,
            OutputFormat = "DER"
        };
    }

    /// <summary>
    /// Converts a certificate to PEM format.
    /// </summary>
    internal static async Task<ConversionResult> ConvertToPem(ConvertOptions options)
    {
        // Load certificate based on input format
        var certificate = await LoadCertificate(options);

        // Determine output path
        var outputPath = options.OutputFile?.FullName
            ?? FormatDetectionService.GenerateOutputPath(options.InputFile, FormatType.Pem);

        // Create output directory if needed
        var outputDir = Path.GetDirectoryName(outputPath);
        if (!string.IsNullOrEmpty(outputDir))
        {
            Directory.CreateDirectory(outputDir);
        }

        var sb = new StringBuilder();

        // Export certificate as PEM
        var certPem = PemEncoding.Write("CERTIFICATE", certificate.RawData);
        sb.AppendLine(new string(certPem));

        // Export private key if present and requested
        var additionalFiles = new List<string>();
        if (options.IncludeKey && certificate.HasPrivateKey)
        {
            var keyPem = ExportPrivateKeyPem(certificate);
            if (keyPem != null)
            {
                // Write key to separate file
                var keyPath = Path.Combine(
                    Path.GetDirectoryName(outputPath) ?? ".",
                    Path.GetFileNameWithoutExtension(outputPath) + ".key");

                await File.WriteAllTextAsync(keyPath, keyPem);
                additionalFiles.Add(keyPath);
            }
        }

        await File.WriteAllTextAsync(outputPath, sb.ToString());

        var subject = certificate.SubjectName.Format(false);
        certificate.Dispose();

        return new ConversionResult
        {
            Success = true,
            OutputFile = outputPath,
            InputPfx = options.InputFormat == FormatType.Pfx ? options.InputFile.FullName : null,
            AdditionalOutputFiles = additionalFiles.ToArray(),
            Subject = subject,
            OutputFormat = "PEM"
        };
    }

    /// <summary>
    /// Converts a certificate to PFX format using the simplified interface.
    /// </summary>
    internal static async Task<ConversionResult> ConvertToPfxSimple(ConvertOptions options)
    {
        // Load certificate based on input format
        var certificate = await LoadCertificate(options);

        // If certificate doesn't have key, try to load from key file
        if (!certificate.HasPrivateKey)
        {
            var keyFile = options.KeyFile ?? FormatDetectionService.FindKeyFile(options.InputFile);
            if (keyFile == null || !keyFile.Exists)
            {
                throw new ArgumentException(
                    "Private key required for PFX output. Use --key to specify the key file.");
            }

            certificate = await AttachPrivateKey(certificate, keyFile);
        }

        // Handle password
        bool passwordWasGenerated = false;
        var password = options.Password;

        if (string.IsNullOrEmpty(password) && options.PasswordFile?.Exists == true)
        {
            password = (await File.ReadAllTextAsync(options.PasswordFile.FullName)).Trim();
        }

        if (string.IsNullOrEmpty(password))
        {
            password = CertificateUtilities.GenerateSecurePassword();
            passwordWasGenerated = true;
        }

        // Determine output path
        var outputPath = options.OutputFile?.FullName
            ?? FormatDetectionService.GenerateOutputPath(options.InputFile, FormatType.Pfx);

        // Create output directory if needed
        var outputDir = Path.GetDirectoryName(outputPath);
        if (!string.IsNullOrEmpty(outputDir))
        {
            Directory.CreateDirectory(outputDir);
        }

        // Export as PFX
        byte[] pfxData;
        if (options.PfxEncryption.Equals("modern", StringComparison.OrdinalIgnoreCase))
        {
            var pbeParams = new PbeParameters(
                PbeEncryptionAlgorithm.Aes256Cbc,
                HashAlgorithmName.SHA256,
                iterationCount: 100000);
            pfxData = certificate.ExportPkcs12(pbeParams, password);
        }
        else
        {
            pfxData = certificate.Export(X509ContentType.Pfx, password);
        }

        await File.WriteAllBytesAsync(outputPath, pfxData);

        // Write password to file if generated
        if (passwordWasGenerated && options.PasswordFile != null)
        {
            options.PasswordFile.Directory?.Create();
            await File.WriteAllTextAsync(options.PasswordFile.FullName, password);
        }

        var subject = certificate.SubjectName.Format(false);
        certificate.Dispose();

        return new ConversionResult
        {
            Success = true,
            OutputFile = outputPath,
            InputCertificate = options.InputFile.FullName,
            InputKey = options.KeyFile?.FullName,
            GeneratedPassword = passwordWasGenerated ? password : null,
            PasswordWasGenerated = passwordWasGenerated,
            Subject = subject,
            OutputFormat = "PFX"
        };
    }

    /// <summary>
    /// Loads a certificate from a file based on detected format.
    /// </summary>
    private static async Task<X509Certificate2> LoadCertificate(ConvertOptions options)
    {
        var format = options.InputFormat != FormatType.Unknown
            ? options.InputFormat
            : await FormatDetectionService.DetectFormat(options.InputFile);

        return format switch
        {
            FormatType.Pfx => LoadPfxCertificate(options),
            FormatType.Der => LoadDerCertificate(options.InputFile),
            FormatType.Pem => await LoadPemCertificate(options.InputFile),
            _ => throw new ArgumentException($"Unable to detect format of {options.InputFile.Name}")
        };
    }

    private static X509Certificate2 LoadPfxCertificate(ConvertOptions options)
    {
        if (string.IsNullOrEmpty(options.Password))
        {
            throw new ArgumentException("Password required for PFX input. Use --password to specify.");
        }

        return X509CertificateLoader.LoadPkcs12FromFile(
            options.InputFile.FullName,
            options.Password,
            X509KeyStorageFlags.Exportable);
    }

    private static X509Certificate2 LoadDerCertificate(FileInfo file)
    {
        return X509CertificateLoader.LoadCertificateFromFile(file.FullName);
    }

    private static async Task<X509Certificate2> LoadPemCertificate(FileInfo file)
    {
        var text = await File.ReadAllTextAsync(file.FullName);
        return X509Certificate2.CreateFromPem(text);
    }

    /// <summary>
    /// Attaches a private key from a file to a certificate.
    /// </summary>
    private static async Task<X509Certificate2> AttachPrivateKey(X509Certificate2 cert, FileInfo keyFile)
    {
        var keyText = await File.ReadAllTextAsync(keyFile.FullName);

        // Try RSA first
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(keyText);
            return cert.CopyWithPrivateKey(rsa);
        }
        catch
        {
            // Try ECDSA
            try
            {
                using var ecdsa = ECDsa.Create();
                ecdsa.ImportFromPem(keyText);
                return cert.CopyWithPrivateKey(ecdsa);
            }
            catch
            {
                throw new CertificateException(
                    "Unable to import private key. Only RSA and ECDSA keys are supported.");
            }
        }
    }

    /// <summary>
    /// Exports a certificate's private key as PEM.
    /// </summary>
    private static string? ExportPrivateKeyPem(X509Certificate2 certificate)
    {
        var rsaKey = certificate.GetRSAPrivateKey();
        if (rsaKey != null)
        {
            return rsaKey.ExportPkcs8PrivateKeyPem();
        }

        var ecdsaKey = certificate.GetECDsaPrivateKey();
        if (ecdsaKey != null)
        {
            return ecdsaKey.ExportPkcs8PrivateKeyPem();
        }

        return null;
    }
}
