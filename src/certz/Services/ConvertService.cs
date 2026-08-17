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
    /// Re-encrypts a PFX file with a new password using modern AES-256-CBC encryption.
    /// </summary>
    internal static async Task<ConversionResult> RepasswordPfx(
        FileInfo inputFile,
        string oldPassword,
        string? newPassword,
        FileInfo? passwordFile,
        FileInfo? outputFile)
    {
        // Load every certificate so re-encryption preserves any chain in the source
        var certificates = X509CertificateLoader.LoadPkcs12CollectionFromFile(
            inputFile.FullName,
            oldPassword,
            X509KeyStorageFlags.Exportable);

        try
        {
            if (certificates.Count == 0)
            {
                throw new ArgumentException($"No certificates found in {inputFile.Name}");
            }

            // Inside the try so a throw here still disposes what was loaded
            certificates = OrderLeafFirst(certificates);

            var certificate = certificates[0];

            // Determine new password
            bool passwordWasGenerated = false;
            if (string.IsNullOrEmpty(newPassword) && passwordFile?.Exists == true)
            {
                newPassword = (await File.ReadAllTextAsync(passwordFile.FullName)).Trim();
            }
            if (string.IsNullOrEmpty(newPassword))
            {
                newPassword = CertificateUtilities.GenerateSecurePassword();
                passwordWasGenerated = true;
            }

            // Determine output path (default: overwrite in-place)
            var outputPath = outputFile?.FullName ?? inputFile.FullName;

            // Create output directory if needed
            var outputDir = Path.GetDirectoryName(outputPath);
            if (!string.IsNullOrEmpty(outputDir))
            {
                Directory.CreateDirectory(outputDir);
            }

            // Always use modern AES-256-CBC encryption
            var pfxData = ExportCollectionAsPfx(certificates, newPassword, "modern");

            await File.WriteAllBytesAsync(outputPath, pfxData);

            // Write password to file if generated
            if (passwordWasGenerated && passwordFile != null)
            {
                passwordFile.Directory?.Create();
                await File.WriteAllTextAsync(passwordFile.FullName, newPassword);
            }

            return new ConversionResult
            {
                Success = true,
                OutputFile = outputPath,
                InputPfx = inputFile.FullName,
                GeneratedPassword = passwordWasGenerated ? newPassword : null,
                PasswordWasGenerated = passwordWasGenerated,
                Subject = certificate.SubjectName.Format(false),
                OutputFormat = "PFX",
                CertificateCount = certificates.Count
            };
        }
        finally
        {
            DisposeAll(certificates);
        }
    }

    /// <summary>
    /// Converts a certificate to DER format.
    /// </summary>
    internal static async Task<ConversionResult> ConvertToDer(ConvertOptions options)
    {
        // Load every certificate so chain loss can be reported rather than hidden
        var certificates = await LoadCertificateChain(options);

        try
        {
            var certificate = certificates[0];

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

            // DER encodes a single certificate, so a chain cannot survive. Say so instead
            // of truncating silently.
            var warnings = new List<string>();
            if (certificates.Count > 1)
            {
                warnings.Add(
                    $"DER holds a single certificate - {certificates.Count - 1} chain certificate(s) " +
                    "were not written. Use --to pem or --to pfx to keep the chain.");
            }

            return new ConversionResult
            {
                Success = true,
                OutputFile = outputPath,
                InputPfx = options.InputFormat == FormatType.Pfx ? options.InputFile.FullName : null,
                InputCertificate = options.InputFormat == FormatType.Pem ? options.InputFile.FullName : null,
                Subject = certificate.SubjectName.Format(false),
                OutputFormat = "DER",
                CertificateCount = 1,
                Warnings = warnings.ToArray()
            };
        }
        finally
        {
            // Loaded Exportable, so on Windows the private key is materialized into the
            // key store and Dispose is what removes it - an error path must not skip this.
            DisposeAll(certificates);
        }
    }

    /// <summary>
    /// Converts a certificate to PEM format.
    /// </summary>
    internal static async Task<ConversionResult> ConvertToPem(ConvertOptions options)
    {
        // Load every certificate - a PEM bundle can carry the whole chain
        var certificates = await LoadCertificateChain(options);

        try
        {
            var certificate = certificates[0];

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

            // Export each certificate as PEM, leaf first
            foreach (var cert in certificates)
            {
                var certPem = PemEncoding.Write("CERTIFICATE", cert.RawData);
                sb.AppendLine(new string(certPem));
            }

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

            return new ConversionResult
            {
                Success = true,
                OutputFile = outputPath,
                InputPfx = options.InputFormat == FormatType.Pfx ? options.InputFile.FullName : null,
                AdditionalOutputFiles = additionalFiles.ToArray(),
                Subject = certificate.SubjectName.Format(false),
                OutputFormat = "PEM",
                CertificateCount = certificates.Count
            };
        }
        finally
        {
            DisposeAll(certificates);
        }
    }

    /// <summary>
    /// Converts a certificate to PFX format using the simplified interface.
    /// </summary>
    internal static async Task<ConversionResult> ConvertToPfxSimple(ConvertOptions options)
    {
        // Load every certificate - PKCS#12 can carry the whole chain
        var certificates = await LoadCertificateChain(options);

        try
        {
            var certificate = certificates[0];

            // If certificate doesn't have key, try to load from key file
            if (!certificate.HasPrivateKey)
            {
                var keyFile = options.KeyFile ?? FormatDetectionService.FindKeyFile(options.InputFile);
                if (keyFile == null || !keyFile.Exists)
                {
                    throw new ArgumentException(
                        "Private key required for PFX output. Use --key to specify the key file.");
                }

                // AttachPrivateKey returns a new instance, so the keyless leaf must be
                // swapped out of the collection or the exported PFX loses the key.
                var keyless = certificate;
                certificate = await AttachPrivateKey(certificate, keyFile);
                certificates[0] = certificate;
                keyless.Dispose();
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

            // Export the whole collection so intermediates travel with the leaf
            var pfxData = ExportCollectionAsPfx(certificates, password, options.PfxEncryption);

            await File.WriteAllBytesAsync(outputPath, pfxData);

            // Write password to file if generated
            if (passwordWasGenerated && options.PasswordFile != null)
            {
                options.PasswordFile.Directory?.Create();
                await File.WriteAllTextAsync(options.PasswordFile.FullName, password);
            }

            return new ConversionResult
            {
                Success = true,
                OutputFile = outputPath,
                InputCertificate = options.InputFile.FullName,
                InputKey = options.KeyFile?.FullName,
                GeneratedPassword = passwordWasGenerated ? password : null,
                PasswordWasGenerated = passwordWasGenerated,
                Subject = certificate.SubjectName.Format(false),
                OutputFormat = "PFX",
                CertificateCount = certificates.Count
            };
        }
        finally
        {
            DisposeAll(certificates);
        }
    }

    /// <summary>
    /// Exports a certificate collection as PKCS#12, honoring the encryption preference.
    /// </summary>
    private static byte[] ExportCollectionAsPfx(
        X509Certificate2Collection certificates,
        string password,
        string pfxEncryption)
    {
        // Only the end-entity certificate's private key belongs in the output. Chain
        // certificates travel as public certificates, which is what a server or a
        // vendor needs. Carrying a CA's private key into an artifact built for
        // distribution would hand over the ability to issue - and because the source
        // bag is loaded Exportable, every key in it would otherwise be serialized.
        var exportable = new X509Certificate2Collection { certificates[0] };
        var strippedCopies = new List<X509Certificate2>();

        for (var index = 1; index < certificates.Count; index++)
        {
            var chainCert = certificates[index];

            if (chainCert.HasPrivateKey)
            {
                // Reloading from RawData yields the same certificate without its key
                var publicOnly = X509CertificateLoader.LoadCertificate(chainCert.RawData);
                strippedCopies.Add(publicOnly);
                exportable.Add(publicOnly);
            }
            else
            {
                exportable.Add(chainCert);
            }
        }

        try
        {
            if (pfxEncryption.Equals("modern", StringComparison.OrdinalIgnoreCase))
            {
                // Modern encryption: AES-256-CBC with SHA-256 and high iteration count
                var pbeParams = new PbeParameters(
                    PbeEncryptionAlgorithm.Aes256Cbc,
                    HashAlgorithmName.SHA256,
                    iterationCount: 100000);
                return exportable.ExportPkcs12(pbeParams, password);
            }

            // Legacy encryption: 3DES for compatibility with older systems
            return exportable.Export(X509ContentType.Pfx, password)
                ?? throw new CertificateException("Failed to export certificates as PFX.");
        }
        finally
        {
            foreach (var copy in strippedCopies)
            {
                copy.Dispose();
            }
        }
    }

    /// <summary>
    /// Disposes every certificate in a collection.
    /// </summary>
    private static void DisposeAll(X509Certificate2Collection certificates)
    {
        foreach (var certificate in certificates)
        {
            certificate.Dispose();
        }
    }

    /// <summary>
    /// Loads every certificate from a file, ordered leaf first.
    /// </summary>
    /// <remarks>
    /// Conversion must be lossless: a PFX or PEM bundle carrying a chain has to survive
    /// the round trip. Loading only the end-entity certificate silently discarded the
    /// chain, which is what issue #74 fixed.
    /// </remarks>
    private static async Task<X509Certificate2Collection> LoadCertificateChain(ConvertOptions options)
    {
        var format = options.InputFormat != FormatType.Unknown
            ? options.InputFormat
            : await FormatDetectionService.DetectFormat(options.InputFile);

        var loaded = format switch
        {
            FormatType.Pfx => LoadPfxCertificates(options),
            FormatType.Der => LoadDerCertificate(options.InputFile),
            FormatType.Pem => LoadPemCertificates(options.InputFile),
            _ => throw new ArgumentException($"Unable to detect format of {options.InputFile.Name}")
        };

        return OrderLeafFirst(loaded);
    }

    private static X509Certificate2Collection LoadPfxCertificates(ConvertOptions options)
    {
        if (string.IsNullOrEmpty(options.Password))
        {
            throw new ArgumentException("Password required for PFX input. Use --password to specify.");
        }

        var collection = X509CertificateLoader.LoadPkcs12CollectionFromFile(
            options.InputFile.FullName,
            options.Password,
            X509KeyStorageFlags.Exportable);

        // A PKCS#12 holding only a key bag loads to an empty collection; without this
        // the caller indexes [0] and the user sees a raw framework exception.
        if (collection.Count == 0)
        {
            throw new ArgumentException($"No certificates found in {options.InputFile.Name}");
        }

        return collection;
    }

    private static X509Certificate2Collection LoadDerCertificate(FileInfo file)
    {
        // DER holds exactly one certificate by construction.
        return [X509CertificateLoader.LoadCertificateFromFile(file.FullName)];
    }

    private static X509Certificate2Collection LoadPemCertificates(FileInfo file)
    {
        var collection = new X509Certificate2Collection();
        collection.ImportFromPemFile(file.FullName);

        if (collection.Count == 0)
        {
            throw new ArgumentException($"No certificates found in {file.Name}");
        }

        return collection;
    }

    /// <summary>
    /// Orders certificates end-entity first, following issuer links toward the root.
    /// </summary>
    /// <remarks>
    /// Input order is not trustworthy - a PKCS#12 bag has no defined ordering, and a
    /// hand-assembled PEM bundle may be in any sequence. Certificates that are not part
    /// of the leaf's chain are appended rather than dropped, since discarding input is
    /// the very behavior this method exists to prevent.
    /// </remarks>
    private static X509Certificate2Collection OrderLeafFirst(X509Certificate2Collection certificates)
    {
        if (certificates.Count <= 1)
        {
            return certificates;
        }

        var remaining = certificates.OfType<X509Certificate2>().ToList();

        // The leaf issues nothing else in the set. Prefer one holding a private key,
        // which disambiguates cross-signed sets where two certificates share a subject.
        var leaf = remaining
            .Where(c => !remaining.Any(other =>
                !ReferenceEquals(other, c) && other.Issuer == c.Subject))
            .OrderByDescending(c => c.HasPrivateKey)
            .FirstOrDefault()
            ?? remaining.OrderByDescending(c => c.HasPrivateKey).First();

        var ordered = new X509Certificate2Collection();
        var current = leaf;

        while (current != null)
        {
            ordered.Add(current);

            // Reference equality, not List.Remove: X509Certificate2 compares by issuer
            // and serial number, so Remove would delete the first value-equal instance -
            // which for a bundle holding the same certificate twice is the wrong one.
            remaining.RemoveAll(c => ReferenceEquals(c, current));

            // Self-signed means we have reached the root - stop before looping on it.
            if (current.Subject == current.Issuer)
            {
                break;
            }

            var issuer = current.Issuer;
            current = remaining.FirstOrDefault(c => c.Subject == issuer);
        }

        // Anything not on the leaf's path still belongs in the output.
        foreach (var orphan in remaining)
        {
            ordered.Add(orphan);
        }

        return ordered;
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
        // GetRSAPrivateKey/GetECDsaPrivateKey hand back owned key objects
        using var rsaKey = certificate.GetRSAPrivateKey();
        if (rsaKey != null)
        {
            return rsaKey.ExportPkcs8PrivateKeyPem();
        }

        using var ecdsaKey = certificate.GetECDsaPrivateKey();
        if (ecdsaKey != null)
        {
            return ecdsaKey.ExportPkcs8PrivateKeyPem();
        }

        return null;
    }
}
