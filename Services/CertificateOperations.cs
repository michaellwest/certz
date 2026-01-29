namespace certz.Services;

internal static class CertificateOperations
{
    private static string GenerateSecurePassword()
    {
        // 32 bytes = 256 bits = 64 hex characters
        byte[] data = RandomNumberGenerator.GetBytes(32);
        return Convert.ToHexString(data);
    }

    private static void DisplayPasswordWarning(string password, string purpose, FileInfo? passwordFile = null)
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

    private static X509KeyStorageFlags GetKeyStorageFlags(
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

    internal static async Task InstallCertificate(FileInfo file, string password, StoreName storeName, StoreLocation storeLocation, bool exportable = true)
    {
        if (!file.Exists)
        {
            throw new FileNotFoundException($"Certificate file not found: {file.FullName}");
        }

        var flags = GetKeyStorageFlags(storeLocation, persist: true, exportable: exportable);
        using var store = new X509Store(storeName, storeLocation, OpenFlags.ReadWrite);
        using var certificate = X509CertificateLoader.LoadPkcs12FromFile(file.FullName, password, flags);
        Console.WriteLine("Installed certificate '{0}' in 'Cert:\\{1}\\{2}'.", file.Name, storeLocation, storeName);
        store.Add(certificate);
        store.Close();

        await Task.Delay(10);
    }

    internal static async Task WriteCertificateToFile(X509Certificate2 certificate, string path, string password, CertificateFileType certificateFileType, bool displayPassword = false, FileInfo? passwordFile = null, string pfxEncryption = "modern")
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

            Console.WriteLine(" - certificate '{0}'", Path.GetFileName(path));

            if (displayPassword)
            {
                DisplayPasswordWarning(password, Path.GetFileName(path), passwordFile);
            }
        }
        else if (certificateFileType == CertificateFileType.PemCer)
        {
            var certificatePem = PemEncoding.Write("CERTIFICATE", certificate.RawData);
            await File.WriteAllTextAsync(path, new string(certificatePem));
            Console.WriteLine(" - certificate '{0}'", Path.GetFileName(path));
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
            Console.WriteLine(" - certificate private key '{0}'", Path.GetFileName(path));
        }
    }

    internal static async Task CreateCertificate(
        FileInfo pfx, string? password, FileInfo cert, FileInfo key, string[] dnsNames, int days,
        int keySize = 2048, string hashAlgorithm = "auto", string keyType = "RSA", string rsaPadding = "pkcs1",
        bool isCA = false, int pathLength = -1, string? crlUrl = null, string? ocspUrl = null, string? caIssuersUrl = null,
        string? subjectO = null, string? subjectOU = null, string? subjectC = null, string? subjectST = null, string? subjectL = null,
        FileInfo? passwordFile = null, string pfxEncryption = "modern")
    {
        // Set default for PFX if no files are specified
        if (pfx == null && cert == null && key == null)
        {
            pfx = new FileInfo("devcert.pfx");
        }

        // Validate: if cert or key is specified, both must be specified
        if ((cert != null && key == null) || (cert == null && key != null))
        {
            throw new ArgumentException("Both the cert and key parameters should be provided.");
        }

        bool passwordWasGenerated = false;
        if (string.IsNullOrEmpty(password))
        {
            password = GenerateSecurePassword();
            passwordWasGenerated = true;
        }

        var validFrom = DateTime.Today;
        var validTo = DateTime.Today.AddDays(days).AddSeconds(-1);

        // Weekend adjustment removed to prevent exceeding CA/B Forum validity limits
        // Certificates should expire on the exact day specified by the user
        var certificate = CertificateGeneration.GenerateCertificate(
            dnsNames, validFrom, validTo, keySize, hashAlgorithm, keyType, rsaPadding,
            isCA, pathLength, crlUrl, ocspUrl, caIssuersUrl,
            subjectO, subjectOU, subjectC, subjectST, subjectL);
        if (certificate == null)
        {
            throw new CertificateException("There was a problem creating the certificate.");
        }

        Console.WriteLine("Generated a new certificate valid from {0} to {1}.", certificate.GetEffectiveDateString(), certificate.GetExpirationDateString());
        Console.WriteLine("");
        Console.WriteLine("Subject Alternative Names:");
        foreach (var dnsName in dnsNames)
        {
            Console.WriteLine(" - {0}", dnsName);
        }

        Console.WriteLine("");
        Console.WriteLine("Saved the following certificate files:");
        if (pfx != null)
        {
            await WriteCertificateToFile(certificate, pfx.FullName, password, CertificateFileType.Pfx, passwordWasGenerated, passwordFile, pfxEncryption);
        }

        if (cert != null)
        {
            await WriteCertificateToFile(certificate, cert.FullName, password, CertificateFileType.PemCer);

            if (key != null)
            {
                await WriteCertificateToFile(certificate, key.FullName, password, CertificateFileType.PemKey);
            }
        }
    }

    internal static async Task ListCertificates(StoreName storeName, StoreLocation storeLocation)
    {
        using var store = new X509Store(storeName, storeLocation, OpenFlags.ReadOnly | OpenFlags.IncludeArchived);
        foreach (var certificate in store.Certificates.OrderBy(c => c.SubjectName.Format(false)))
        {
            CertificateDisplay.WriteRow(certificate);
        }
        store.Close();

        await Task.Delay(10);
    }

    internal static async Task RemoveCertificate(string subject, string thumbprint, StoreName storeName, StoreLocation storeLocation)
    {
        if (!string.IsNullOrEmpty(subject) && !subject.StartsWith("CN="))
        {
            subject = $"CN={subject}";
        }
        bool predicate(X509Certificate2 c) =>
            (!string.IsNullOrEmpty(thumbprint) && c.Thumbprint.Equals(thumbprint, StringComparison.InvariantCultureIgnoreCase)) ||
            (!string.IsNullOrEmpty(subject) && c.Subject.Equals(subject, StringComparison.InvariantCultureIgnoreCase));

        using var store = new X509Store(storeName, storeLocation, OpenFlags.ReadWrite);
        foreach (var certificate in store.Certificates.Where(predicate))
        {
            CertificateDisplay.WriteRow(certificate);
            store.Remove(certificate);
        }
        store.Close();

        await Task.Delay(10);
    }

    internal static async Task ExportCertificate(FileInfo pfx, string password, FileInfo cert, FileInfo key, Uri uri, FileInfo? passwordFile = null)
    {
        RemoteCertificateValidationCallback certCallback = (_, _, _, _) => true;
        using var client = new TcpClient(uri.Host, 443);
        using var sslStream = new SslStream(client.GetStream(), true, certCallback);
        await sslStream.AuthenticateAsClientAsync(uri.Host);
        var serverCertificate = sslStream.RemoteCertificate;
        var certificate = new X509Certificate2(serverCertificate);

        bool passwordWasGenerated = false;
        if (string.IsNullOrEmpty(password))
        {
            password = GenerateSecurePassword();
            passwordWasGenerated = true;
        }

        CertificateDisplay.WriteRow(certificate);
        if (pfx != null)
        {
            await WriteCertificateToFile(certificate, pfx.FullName, password, CertificateFileType.Pfx, passwordWasGenerated, passwordFile);
        }
        if (cert != null)
        {
            await WriteCertificateToFile(certificate, cert.FullName, password, CertificateFileType.PemCer);
        }
        if (key != null)
        {
            await WriteCertificateToFile(certificate, key.FullName, password, CertificateFileType.PemKey);
        }
    }

    internal static async Task ExportCertificate(FileInfo pfx, string password, FileInfo cert, FileInfo key, string thumbprint, StoreName storeName, StoreLocation storeLocation, FileInfo? passwordFile = null)
    {
        bool passwordWasGenerated = false;
        if (string.IsNullOrEmpty(password) && pfx != null)
        {
            password = GenerateSecurePassword();
            passwordWasGenerated = true;
        }

        using var store = new X509Store(storeName, storeLocation, OpenFlags.ReadOnly);
        foreach (var certificate in store.Certificates.Where(c => c.Thumbprint.Equals(thumbprint, StringComparison.InvariantCultureIgnoreCase)))
        {
            CertificateDisplay.WriteRow(certificate);
            if (pfx != null)
            {
                await WriteCertificateToFile(certificate, pfx.FullName, password, CertificateFileType.Pfx, passwordWasGenerated, passwordFile);
            }
            if (cert != null)
            {
                await WriteCertificateToFile(certificate, cert.FullName, password, CertificateFileType.PemCer);
            }
            if (key != null)
            {
                await WriteCertificateToFile(certificate, key.FullName, password, CertificateFileType.PemKey);
            }
        }
        store.Close();

        await Task.Delay(10);
    }

    internal static async Task ConvertToPfx(FileInfo certFile, FileInfo keyFile, FileInfo pfxFile, string password, FileInfo? passwordFile = null, string pfxEncryption = "modern")
    {
        if (!certFile.Exists)
        {
            throw new FileNotFoundException($"Certificate file not found: {certFile.FullName}");
        }

        if (!keyFile.Exists)
        {
            throw new FileNotFoundException($"Key file not found: {keyFile.FullName}");
        }

        bool passwordWasGenerated = false;
        if (string.IsNullOrEmpty(password))
        {
            password = GenerateSecurePassword();
            passwordWasGenerated = true;
        }

        // Load the certificate
        var certificateText = await File.ReadAllTextAsync(certFile.FullName);
        var certificate = X509Certificate2.CreateFromPem(certificateText);

        // Load the private key - try RSA first, then ECDSA
        var privateKeyText = await File.ReadAllTextAsync(keyFile.FullName);
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
        pfxFile.Directory?.Create();
        byte[] pfxData;
        if (pfxEncryption.ToUpperInvariant() == "MODERN")
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
        await File.WriteAllBytesAsync(pfxFile.FullName, pfxData);

        Console.WriteLine("Successfully converted certificate and key to PFX format:");
        Console.WriteLine(" - Input certificate: '{0}'", certFile.Name);
        Console.WriteLine(" - Input key: '{0}'", keyFile.Name);
        Console.WriteLine(" - Output PFX: '{0}'", pfxFile.Name);
        Console.WriteLine();
        Console.WriteLine("Conversion completed successfully!");

        if (passwordWasGenerated)
        {
            DisplayPasswordWarning(password, pfxFile.Name, passwordFile);
        }
    }

    internal static async Task ConvertFromPfx(FileInfo pfxFile, string password, FileInfo? outputCert, FileInfo? outputKey)
    {
        if (!pfxFile.Exists)
        {
            throw new FileNotFoundException($"PFX file not found: {pfxFile.FullName}");
        }

        if (outputCert == null && outputKey == null)
        {
            throw new ArgumentException("Please specify at least one output: --out-cert or --out-key");
        }

        if (string.IsNullOrEmpty(password))
        {
            throw new ArgumentException("Password is required to load PFX file. Use --password to specify the password.");
        }

        // Load PFX file
        var certificate = X509CertificateLoader.LoadPkcs12FromFile(
            pfxFile.FullName,
            password,
            X509KeyStorageFlags.Exportable
        );

        Console.WriteLine("Successfully loaded PFX file:");
        Console.WriteLine(" - Input PFX: '{0}'", pfxFile.Name);
        Console.WriteLine(" - Subject: '{0}'", certificate.SubjectName.Format(false));
        Console.WriteLine();

        // Export certificate to PEM
        if (outputCert != null)
        {
            outputCert.Directory?.Create();
            var certificatePem = PemEncoding.Write("CERTIFICATE", certificate.RawData);
            await File.WriteAllTextAsync(outputCert.FullName, new string(certificatePem));
            Console.WriteLine("Exported certificate:");
            Console.WriteLine(" - Output certificate: '{0}'", outputCert.Name);
        }

        // Export private key to PEM (if present)
        if (outputKey != null)
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

            outputKey.Directory?.Create();
            await File.WriteAllTextAsync(outputKey.FullName, privateKeyPem);
            Console.WriteLine(" - Output private key: '{0}'", outputKey.Name);
        }

        Console.WriteLine();
        Console.WriteLine("Conversion completed successfully!");

        certificate.Dispose();
    }

    internal static async Task ShowCertificateInfo(FileInfo file, string password)
    {
        if (!file.Exists)
        {
            throw new FileNotFoundException($"Certificate file not found: {file.FullName}");
        }

        X509Certificate2? certificate = null;

        if (file.Extension.Equals(".pfx", StringComparison.OrdinalIgnoreCase) ||
            file.Extension.Equals(".p12", StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password is required to load PFX file. Use --password to specify the password.");
            }
            certificate = X509CertificateLoader.LoadPkcs12FromFile(
                file.FullName,
                password,
                X509KeyStorageFlags.Exportable
            );
        }
        else
        {
            var certificateText = await File.ReadAllTextAsync(file.FullName);
            certificate = X509Certificate2.CreateFromPem(certificateText);
        }

        CertificateDisplay.DisplayCertificateDetails(certificate);
        certificate.Dispose();
        await Task.Delay(10);
    }

    internal static async Task ShowCertificateInfo(string thumbprint, StoreName storeName, StoreLocation storeLocation)
    {
        using var store = new X509Store(storeName, storeLocation, OpenFlags.ReadOnly);
        var certificate = store.Certificates
            .FirstOrDefault(c => c.Thumbprint.Equals(thumbprint, StringComparison.InvariantCultureIgnoreCase));

        if (certificate == null)
        {
            throw new CertificateException($"Certificate with thumbprint {thumbprint} not found in {storeLocation}\\{storeName}");
        }

        CertificateDisplay.DisplayCertificateDetails(certificate);
        store.Close();
        await Task.Delay(10);
    }

    internal static async Task ShowCertificateInfo(Uri uri)
    {
        RemoteCertificateValidationCallback certCallback = (_, _, _, _) => true;
        using var client = new TcpClient(uri.Host, 443);
        using var sslStream = new SslStream(client.GetStream(), true, certCallback);
        await sslStream.AuthenticateAsClientAsync(uri.Host);
        var serverCertificate = sslStream.RemoteCertificate;
        var certificate = new X509Certificate2(serverCertificate);

        CertificateDisplay.DisplayCertificateDetails(certificate);
    }

    internal static async Task VerifyCertificate(FileInfo file, string password, bool checkRevocation, int warningDays)
    {
        if (!file.Exists)
        {
            throw new FileNotFoundException($"Certificate file not found: {file.FullName}");
        }

        X509Certificate2? certificate = null;

        if (file.Extension.Equals(".pfx", StringComparison.OrdinalIgnoreCase) ||
            file.Extension.Equals(".p12", StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password is required to load PFX file. Use --password to specify the password.");
            }
            certificate = X509CertificateLoader.LoadPkcs12FromFile(
                file.FullName,
                password,
                X509KeyStorageFlags.Exportable
            );
        }
        else
        {
            var certificateText = await File.ReadAllTextAsync(file.FullName);
            certificate = X509Certificate2.CreateFromPem(certificateText);
        }

        CertificateDisplay.DisplayValidationReport(certificate, checkRevocation, warningDays);
        certificate.Dispose();
        await Task.Delay(10);
    }

    internal static async Task VerifyCertificate(string thumbprint, StoreName storeName, StoreLocation storeLocation, bool checkRevocation, int warningDays)
    {
        using var store = new X509Store(storeName, storeLocation, OpenFlags.ReadOnly);
        var certificate = store.Certificates
            .FirstOrDefault(c => c.Thumbprint.Equals(thumbprint, StringComparison.InvariantCultureIgnoreCase));

        if (certificate == null)
        {
            throw new CertificateException($"Certificate with thumbprint {thumbprint} not found in {storeLocation}\\{storeName}");
        }

        CertificateDisplay.DisplayValidationReport(certificate, checkRevocation, warningDays);
        store.Close();
        await Task.Delay(10);
    }
}
