namespace certz.Services;

internal static class CertificateOperations
{
    internal static async Task InstallCertificate(FileInfo file, string password, StoreName storeName, StoreLocation storeLocation)
    {
        using var store = new X509Store(storeName, storeLocation, OpenFlags.ReadWrite);
        using var certificate = X509CertificateLoader.LoadPkcs12FromFile(file.FullName, password, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
        Console.WriteLine("Installed certificate '{0}' in 'Cert:\\{1}\\{2}'.", file.Name, storeLocation, storeName);
        store.Add(certificate);
        store.Close();

        await Task.Delay(10);
    }

    internal static async Task WriteCertificateToFile(X509Certificate2 certificate, string path, string password, CertificateFileType certificateFileType)
    {
        //TODO: File extension validation
        if (certificateFileType == CertificateFileType.Pfx)
        {
            var certData = certificate.Export(X509ContentType.Pfx, password);

            await File.WriteAllBytesAsync(path, certData);

            var directory = Path.GetDirectoryName(path);
            var fileName = Path.GetFileName(path);
            var passwordFile = Path.Combine(directory, $"{fileName}.password.txt");
            await File.WriteAllTextAsync(passwordFile, password);

            Console.WriteLine(" - certificate '{0}' and password '{1}'", Path.GetFileName(path), Path.GetFileName(passwordFile));
        }
        else if (certificateFileType == CertificateFileType.PemCer)
        {
            var certificatePem = PemEncoding.Write("CERTIFICATE", certificate.RawData);
            await File.WriteAllTextAsync(path, new string(certificatePem));
            Console.WriteLine(" - certificate '{0}'", Path.GetFileName(path));
        }
        else if (certificateFileType == CertificateFileType.PemKey)
        {
            var privateKeyPem = certificate.GetRSAPrivateKey().ExportPkcs8PrivateKeyPem();
            await File.WriteAllTextAsync(path, privateKeyPem);
            Console.WriteLine(" - certificate private key '{0}'", Path.GetFileName(path));
        }
    }

    internal static async Task CreateCertificate(FileInfo pfx, string password, FileInfo cert, FileInfo key, string[] dnsNames, int days)
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

        if (string.IsNullOrEmpty(password))
        {
            password = "changeit";
        }

        var validFrom = DateTime.Today;
        var validTo = DateTime.Today.AddDays(days).AddSeconds(-1);
        if (validTo.DayOfWeek == DayOfWeek.Saturday)
        {
            validTo = validTo.AddDays(2);
        }
        else if (validTo.DayOfWeek == DayOfWeek.Sunday)
        {
            validTo = validTo.AddDays(1);
        }
        var certificate = CertificateGeneration.GenerateCertificate(dnsNames, validFrom, validTo);
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
            await WriteCertificateToFile(certificate, pfx.FullName, password, CertificateFileType.Pfx);
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

    internal static async Task ExportCertificate(FileInfo pfx, string password, FileInfo cert, FileInfo key, Uri uri)
    {
        RemoteCertificateValidationCallback certCallback = (_, _, _, _) => true;
        using var client = new TcpClient(uri.Host, 443);
        using var sslStream = new SslStream(client.GetStream(), true, certCallback);
        await sslStream.AuthenticateAsClientAsync(uri.Host);
        var serverCertificate = sslStream.RemoteCertificate;
        var certificate = new X509Certificate2(serverCertificate);

        if (string.IsNullOrEmpty(password))
        {
            password = "changeit";
        }

        CertificateDisplay.WriteRow(certificate);
        if (pfx != null)
        {
            await WriteCertificateToFile(certificate, pfx.FullName, password, CertificateFileType.Pfx);
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

    internal static async Task ExportCertificate(FileInfo pfx, string password, FileInfo cert, FileInfo key, string thumbprint, StoreName storeName, StoreLocation storeLocation)
    {
        using var store = new X509Store(storeName, storeLocation, OpenFlags.ReadOnly);
        foreach (var certificate in store.Certificates.Where(c => c.Thumbprint.Equals(thumbprint, StringComparison.InvariantCultureIgnoreCase)))
        {
            CertificateDisplay.WriteRow(certificate);
            if (pfx != null)
            {
                await WriteCertificateToFile(certificate, pfx.FullName, password, CertificateFileType.Pfx);
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

    internal static async Task ConvertToPfx(FileInfo certFile, FileInfo keyFile, FileInfo pfxFile, string password)
    {
        if (!certFile.Exists)
        {
            throw new FileNotFoundException($"Certificate file not found: {certFile.FullName}");
        }

        if (!keyFile.Exists)
        {
            throw new FileNotFoundException($"Key file not found: {keyFile.FullName}");
        }

        if (string.IsNullOrEmpty(password))
        {
            password = "changeit";
        }

        // Load the certificate
        var certificateText = await File.ReadAllTextAsync(certFile.FullName);
        var certificate = X509Certificate2.CreateFromPem(certificateText);

        // Load the private key
        var privateKeyText = await File.ReadAllTextAsync(keyFile.FullName);
        using var rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyText);

        // Combine certificate with private key
        var certificateWithKey = certificate.CopyWithPrivateKey(rsa);

        // Export as PFX
        var pfxData = certificateWithKey.Export(X509ContentType.Pfx, password);
        await File.WriteAllBytesAsync(pfxFile.FullName, pfxData);

        var directory = Path.GetDirectoryName(pfxFile.FullName);
        var fileName = Path.GetFileName(pfxFile.FullName);
        var passwordFile = Path.Combine(directory, $"{fileName}.password.txt");
        await File.WriteAllTextAsync(passwordFile, password);

        Console.WriteLine("Successfully converted certificate and key to PFX format:");
        Console.WriteLine(" - Input certificate: '{0}'", certFile.Name);
        Console.WriteLine(" - Input key: '{0}'", keyFile.Name);
        Console.WriteLine(" - Output PFX: '{0}'", pfxFile.Name);
        Console.WriteLine(" - Password file: '{0}'", Path.GetFileName(passwordFile));
        Console.WriteLine();
        Console.WriteLine("Conversion completed successfully!");
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
            password = "changeit";
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

            var privateKey = certificate.GetRSAPrivateKey();
            if (privateKey == null)
            {
                throw new CertificateException("Unable to extract private key (unsupported key type - only RSA is supported)");
            }

            var privateKeyPem = privateKey.ExportPkcs8PrivateKeyPem();
            await File.WriteAllTextAsync(outputKey.FullName, privateKeyPem);
            Console.WriteLine(" - Output private key: '{0}'", outputKey.Name);
        }

        Console.WriteLine();
        Console.WriteLine("Conversion completed successfully!");

        certificate.Dispose();
    }

    internal static async Task ShowCertificateInfo(FileInfo file, string password)
    {
        X509Certificate2? certificate = null;

        if (file.Extension.Equals(".pfx", StringComparison.OrdinalIgnoreCase) ||
            file.Extension.Equals(".p12", StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrEmpty(password))
            {
                password = "changeit";
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
        X509Certificate2? certificate = null;

        if (file.Extension.Equals(".pfx", StringComparison.OrdinalIgnoreCase) ||
            file.Extension.Equals(".p12", StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrEmpty(password))
            {
                password = "changeit";
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
