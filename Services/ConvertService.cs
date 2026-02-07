using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
}
