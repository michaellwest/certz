using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace certz.Services;

/// <summary>
/// Shared utility methods for certificate operations.
/// </summary>
internal static class CertificateUtilities
{
    /// <summary>
    /// Generates a cryptographically secure random password.
    /// </summary>
    /// <returns>A 64-character hexadecimal string (256 bits of entropy).</returns>
    internal static string GenerateSecurePassword()
    {
        // 32 bytes = 256 bits = 64 hex characters
        byte[] data = RandomNumberGenerator.GetBytes(32);
        return Convert.ToHexString(data);
    }

    /// <summary>
    /// Displays a password warning to the console or writes it to a file.
    /// </summary>
    /// <param name="password">The password to display.</param>
    /// <param name="purpose">Description of what the password is for.</param>
    /// <param name="passwordFile">Optional file to write the password to.</param>
    internal static void DisplayPasswordWarning(string password, string purpose, FileInfo? passwordFile = null)
    {
        if (passwordFile != null)
        {
            passwordFile.Directory?.Create();
            File.WriteAllText(passwordFile.FullName, password.TrimEnd());
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"Password for {purpose} written to: {passwordFile.FullName}");
            Console.ResetColor();
            Console.WriteLine();
            return;
        }

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("=".PadRight(80, '='));
        Console.WriteLine("IMPORTANT: Certificate Password");
        Console.WriteLine("=".PadRight(80, '='));
        Console.ResetColor();
        Console.WriteLine();
        Console.WriteLine($"Password for {purpose}:");
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"  {password}");
        Console.ResetColor();
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("WARNING: Store this password securely!");
        Console.WriteLine("This is your only chance to see it. Without this password,");
        Console.WriteLine("you will NOT be able to use the certificate.");
        Console.WriteLine("=".PadRight(80, '='));
        Console.ResetColor();
        Console.WriteLine();
    }

    /// <summary>
    /// Gets the appropriate X509 key storage flags based on storage location and options.
    /// </summary>
    /// <param name="storeLocation">Target store location (LocalMachine or CurrentUser).</param>
    /// <param name="persist">Whether to persist the key.</param>
    /// <param name="exportable">Whether the key should be exportable.</param>
    /// <param name="ephemeral">Whether to use ephemeral key storage.</param>
    /// <returns>Configured X509KeyStorageFlags.</returns>
    internal static X509KeyStorageFlags GetKeyStorageFlags(
        StoreLocation? storeLocation = null,
        bool persist = false,
        bool exportable = true,
        bool ephemeral = false)
    {
        if (ephemeral)
        {
            return X509KeyStorageFlags.EphemeralKeySet;
        }

        var flags = (X509KeyStorageFlags)0;

        if (exportable)
            flags |= X509KeyStorageFlags.Exportable;

        if (persist)
            flags |= X509KeyStorageFlags.PersistKeySet;

        // Use MachineKeySet for LocalMachine, UserKeySet for CurrentUser
        // This ensures keys are stored with the correct provider context
        if (storeLocation == StoreLocation.LocalMachine)
            flags |= X509KeyStorageFlags.MachineKeySet;
        else if (storeLocation == StoreLocation.CurrentUser)
            flags |= X509KeyStorageFlags.UserKeySet;

        return flags;
    }

    /// <summary>
    /// Installs a certificate to the specified Windows certificate store.
    /// </summary>
    /// <param name="file">The PFX file to install.</param>
    /// <param name="password">The password for the PFX file.</param>
    /// <param name="storeName">The certificate store name (e.g., Root, My).</param>
    /// <param name="storeLocation">The store location (LocalMachine or CurrentUser).</param>
    /// <param name="exportable">Whether the private key should be exportable.</param>
    /// <param name="quiet">Whether to suppress console output.</param>
    internal static async Task InstallCertificate(FileInfo file, string password, StoreName storeName, StoreLocation storeLocation, bool exportable = true, bool quiet = false)
    {
        if (!file.Exists)
        {
            throw new FileNotFoundException($"Certificate file not found: {file.FullName}");
        }

        var flags = GetKeyStorageFlags(storeLocation, persist: true, exportable: exportable);
        using var store = new X509Store(storeName, storeLocation, OpenFlags.ReadWrite);
        using var certificate = X509CertificateLoader.LoadPkcs12FromFile(file.FullName, password, flags);
        if (!quiet)
        {
            Console.WriteLine("Installed certificate '{0}' in 'Cert:\\{1}\\{2}'.", file.Name, storeLocation, storeName);
        }
        store.Add(certificate);
        store.Close();

        await Task.Delay(10);
    }

    /// <summary>
    /// Writes a certificate to a file in the specified format.
    /// </summary>
    /// <param name="certificate">The certificate to write.</param>
    /// <param name="path">The output file path.</param>
    /// <param name="password">The password for PFX files.</param>
    /// <param name="certificateFileType">The output file format.</param>
    /// <param name="displayPassword">Whether to display the password to the console.</param>
    /// <param name="passwordFile">Optional file to write the password to.</param>
    /// <param name="pfxEncryption">The PFX encryption mode ("modern" or "legacy").</param>
    /// <param name="quiet">Whether to suppress console output.</param>
    internal static async Task WriteCertificateToFile(X509Certificate2 certificate, string path, string password, CertificateFileType certificateFileType, bool displayPassword = false, FileInfo? passwordFile = null, string pfxEncryption = "modern", bool quiet = false)
    {
        // Ensure output directory exists
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        if (certificateFileType == CertificateFileType.Pfx)
        {
            byte[] certData;

            if (pfxEncryption.ToUpperInvariant() == "MODERN")
            {
                // Modern encryption: AES-256-CBC with SHA-256 and high iteration count
                // Recommended for Windows Server 2019+, Windows 11
                var pbeParams = new PbeParameters(
                    PbeEncryptionAlgorithm.Aes256Cbc,
                    HashAlgorithmName.SHA256,
                    iterationCount: 100000);

                certData = certificate.ExportPkcs12(pbeParams, password);
            }
            else
            {
                // Legacy encryption: 3DES for compatibility with older systems
                certData = certificate.Export(X509ContentType.Pfx, password);
            }

            await File.WriteAllBytesAsync(path, certData);

            if (!quiet)
            {
                Console.WriteLine(" - certificate '{0}'", Path.GetFileName(path));
            }

            if (displayPassword)
            {
                DisplayPasswordWarning(password, Path.GetFileName(path), passwordFile);
            }
        }
        else if (certificateFileType == CertificateFileType.PemCer)
        {
            var certificatePem = PemEncoding.Write("CERTIFICATE", certificate.RawData);
            await File.WriteAllTextAsync(path, new string(certificatePem));
            if (!quiet)
            {
                Console.WriteLine(" - certificate '{0}'", Path.GetFileName(path));
            }
        }
        else if (certificateFileType == CertificateFileType.PemKey)
        {
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
            await File.WriteAllTextAsync(path, privateKeyPem);
            if (!quiet)
            {
                Console.WriteLine(" - certificate private key '{0}'", Path.GetFileName(path));
            }
        }
    }
}
