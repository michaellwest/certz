using certz.Exceptions;
using System.CommandLine;
using System.Linq.Expressions;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

class Program
{
    private const int RSAMinimumKeySizeInBits = 2048;
    private const string ServerAuthenticationEnhancedKeyUsageOid = "1.3.6.1.5.5.7.3.1";
    private const string ServerAuthenticationEnhancedKeyUsageOidFriendlyName = "Server Authentication";

    internal enum CertificateFileType
    {
        Pfx,
        PemCer,
        PemKey
    }

    static async Task<int> Main(string[] args)
    {
        var rootCommand = new RootCommand("Certz: A Simple Certificate Utility");
        rootCommand.Subcommands.Add(GetListCommand());
        rootCommand.Subcommands.Add(GetInstallCommand());
        rootCommand.Subcommands.Add(GetCreateCommand());
        rootCommand.Subcommands.Add(GetRemoveCommand());
        rootCommand.Subcommands.Add(GetExportCommand());
        rootCommand.Subcommands.Add(GetConvertCommand());

        return await rootCommand.Parse(args).InvokeAsync();
    }

    internal static Option<FileInfo?> GetFileOption(bool isRequired, string[] aliases)
    {
        var allAliases = aliases ?? new[] { "--file", "--f" };
        var fileOption = new Option<FileInfo?>(allAliases[0], allAliases.Skip(1).ToArray())
        {
            Description = "Specifies the certificate.",
            Required = isRequired
        };

        return fileOption;
    }

    internal static Option<Uri?> GetUrlOption(bool isRequired, string[] aliases)
    {
        var allAliases = aliases ?? new[] { "--url", "--u" };
        var fileOption = new Option<Uri?>(allAliases[0], allAliases.Skip(1).ToArray())
        {
            Description = "Specifies the certificate.",
            Required = isRequired
        };

        return fileOption;
    }

    internal static Option<string> GetPasswordOption()
    {
        var passwordOption = new Option<string>("--password", "--pass", "--p")
        {
            Description = "Password for the certificate."
        };

        return passwordOption;
    }

    internal static Option<int> GetDaysOption(bool isRequired)
    {
        var daysOption = new Option<int>("--days")
        {
            Description = "Lifetime for the certificate.",
            DefaultValueFactory = _ => 365,
            Required = isRequired
        };

        return daysOption;
    }

    internal static Option<StoreName> GetStoreNameOption()
    {
        var storeNameOption = new Option<StoreName>("--storename", "--sn")
        {
            Description = "Specifies the store name.",
            DefaultValueFactory = _ => StoreName.My
        };
        return storeNameOption;
    }

    internal static Option<StoreLocation> GetStoreLocationOption()
    {
        var storeLocationOption = new Option<StoreLocation>("--storelocation", "--sl")
        {
            Description = "Specifies the store location.",
            DefaultValueFactory = _ => StoreLocation.LocalMachine
        };
        return storeLocationOption;
    }

    internal static Option<string> GetThumbprintOption()
    {
        var thumbprintOption = new Option<string>("--thumbprint", "--thumb")
        {
            Description = "The unique thumbprint for the certificate."
        };
        return thumbprintOption;
    }

    internal static Command GetListCommand()
    {
        var storeNameOption = GetStoreNameOption();
        var storeLocationOption = GetStoreLocationOption();

        var listCommand = new Command("list", "Lists all certificates.");
        listCommand.Options.Add(storeNameOption);
        listCommand.Options.Add(storeLocationOption);

        listCommand.SetAction(async (parseResult) =>
        {
            var storename = parseResult.GetValue(storeNameOption);
            var storelocation = parseResult.GetValue(storeLocationOption);
            await ListCertificates(storename, storelocation);
        });

        return listCommand;
    }

    internal static Command GetInstallCommand()
    {
        var fileOption = GetFileOption(true, new[] { "--file", "--f", "--pkcs12", "--cert", "--c" });
        var passwordOption = GetPasswordOption();
        var storeNameOption = GetStoreNameOption();
        var storeLocationOption = GetStoreLocationOption();

        var installCommand = new Command("install", "Installs a certificate.");
        installCommand.Options.Add(fileOption);
        installCommand.Options.Add(passwordOption);
        installCommand.Options.Add(storeNameOption);
        installCommand.Options.Add(storeLocationOption);

        installCommand.SetAction(async (parseResult) =>
        {
            var file = parseResult.GetValue(fileOption);
            var password = parseResult.GetValue(passwordOption);
            var storename = parseResult.GetValue(storeNameOption);
            var storelocation = parseResult.GetValue(storeLocationOption);
            await InstallCertificate(file!, password, storename, storelocation);
        });

        return installCommand;
    }

    internal static Command GetCreateCommand()
    {
        var pfxOption = GetFileOption(false, new[] { "--file", "--f", "--pkcs12" });
        var certOption = GetFileOption(false, new[] { "--cert", "--c" });
        var keyOption = GetFileOption(false, new[] { "--key", "--k" });
        var passwordOption = GetPasswordOption();
        var dnsOption = new Option<string[]>("--dns", "--san")
        {
            Description = "SAN for the certificate.",
            DefaultValueFactory = _ => new[] { "*.dev.local", "*.localhost", "*.test" },
            AllowMultipleArgumentsPerToken = true
        };
        var daysOption = GetDaysOption(false);

        var createCommand = new Command("create", "Creates a certificate.");
        createCommand.Options.Add(pfxOption);
        createCommand.Options.Add(passwordOption);
        createCommand.Options.Add(certOption);
        createCommand.Options.Add(keyOption);
        createCommand.Options.Add(dnsOption);
        createCommand.Options.Add(daysOption);

        createCommand.SetAction(async (parseResult) =>
        {
            var pfx = parseResult.GetValue(pfxOption);
            var password = parseResult.GetValue(passwordOption);
            var cert = parseResult.GetValue(certOption);
            var key = parseResult.GetValue(keyOption);
            var dnsNames = parseResult.GetValue(dnsOption);
            var days = parseResult.GetValue(daysOption);
            await CreateCertificate(pfx!, password, cert!, key!, dnsNames, days);
        });

        return createCommand;
    }

    internal static Command GetRemoveCommand()
    {
        var subjectOption = new Option<string>("--subject")
        {
            Description = "The subject for the certificate. Multiple certificates may match."
        };
        var thumbprintOption = GetThumbprintOption();
        var storeNameOption = GetStoreNameOption();
        var storeLocationOption = GetStoreLocationOption();

        var removeCommand = new Command("remove", "Removes the specified certificate.");
        removeCommand.Options.Add(subjectOption);
        removeCommand.Options.Add(thumbprintOption);
        removeCommand.Options.Add(storeNameOption);
        removeCommand.Options.Add(storeLocationOption);

        removeCommand.SetAction(async (parseResult) =>
        {
            var subject = parseResult.GetValue(subjectOption);
            var thumbprint = parseResult.GetValue(thumbprintOption);
            var storename = parseResult.GetValue(storeNameOption);
            var storelocation = parseResult.GetValue(storeLocationOption);
            await RemoveCertificate(subject, thumbprint, storename, storelocation);
        });

        return removeCommand;
    }

    internal static Command GetExportCommand()
    {
        var pfxOption = GetFileOption(false, new[] { "--file", "--f", "--pkcs12" });
        var certOption = GetFileOption(false, new[] { "--cert", "--c" });
        var keyOption = GetFileOption(false, new[] { "--key", "--k" });
        var urlOption = GetUrlOption(false, new[] { "--url", "--u" });
        var passwordOption = GetPasswordOption();
        var thumbprintOption = GetThumbprintOption();
        var storeNameOption = GetStoreNameOption();
        var storeLocationOption = GetStoreLocationOption();

        var exportCommand = new Command("export", "Exports the specified certificate.");
        exportCommand.Options.Add(pfxOption);
        exportCommand.Options.Add(passwordOption);
        exportCommand.Options.Add(certOption);
        exportCommand.Options.Add(keyOption);
        exportCommand.Options.Add(urlOption);
        exportCommand.Options.Add(thumbprintOption);
        exportCommand.Options.Add(storeNameOption);
        exportCommand.Options.Add(storeLocationOption);

        exportCommand.SetAction(async (parseResult) =>
        {
            var file = parseResult.GetValue(pfxOption);
            var password = parseResult.GetValue(passwordOption);
            var cert = parseResult.GetValue(certOption);
            var key = parseResult.GetValue(keyOption);
            var uri = parseResult.GetValue(urlOption);
            var thumbprint = parseResult.GetValue(thumbprintOption);
            var storename = parseResult.GetValue(storeNameOption);
            var storelocation = parseResult.GetValue(storeLocationOption);

            if (uri != null)
            {
                await ExportCertificate(file!, password, cert!, key!, uri!);
            }
            else
            {
                await ExportCertificate(file!, password, cert!, key!, thumbprint, storename, storelocation);
            }
        });

        return exportCommand;
    }

    internal static Command GetConvertCommand()
    {
        var certOption = GetFileOption(true, new[] { "--cert", "--c" });
        var keyOption = GetFileOption(true, new[] { "--key", "--k" });
        var pfxOption = GetFileOption(true, new[] { "--file", "--f", "--pfx" });
        var passwordOption = GetPasswordOption();

        var convertCommand = new Command("convert", "Converts a CER/CRT and KEY file to a PFX file.");
        convertCommand.Options.Add(certOption);
        convertCommand.Options.Add(keyOption);
        convertCommand.Options.Add(pfxOption);
        convertCommand.Options.Add(passwordOption);

        convertCommand.SetAction(async (parseResult) =>
        {
            var cert = parseResult.GetValue(certOption);
            var key = parseResult.GetValue(keyOption);
            var pfx = parseResult.GetValue(pfxOption);
            var password = parseResult.GetValue(passwordOption);
            await ConvertToPfx(cert!, key!, pfx!, password);
        });

        return convertCommand;
    }

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
        var certificate = GenerateCertificate(dnsNames, validFrom, validTo);
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
            WriteRow(certificate);
        }
        store.Close();

        await Task.Delay(10);
    }

    internal static async Task RemoveCertificate(string subject, string thumbprint, StoreName storeName, StoreLocation storeLocation)
    {
        if(!string.IsNullOrEmpty(subject) && !subject.StartsWith("CN="))
        {
            subject = $"CN={subject}";
        }
        bool predicate(X509Certificate2 c) =>
            (!string.IsNullOrEmpty(thumbprint) && c.Thumbprint.Equals(thumbprint, StringComparison.InvariantCultureIgnoreCase)) ||
            (!string.IsNullOrEmpty(subject) && c.Subject.Equals(subject, StringComparison.InvariantCultureIgnoreCase));
        
        using var store = new X509Store(storeName, storeLocation, OpenFlags.ReadWrite);
        foreach (var certificate in store.Certificates.Where(predicate))
        {
            WriteRow(certificate);
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

        WriteRow(certificate);
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
            WriteRow(certificate);
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
    }

    private static void WriteRow(X509Certificate2 certificate)
    {
        var subject = certificate.SubjectName.Format(false);
        Console.WriteLine($"{certificate.Thumbprint}\t{subject}");
    }

    internal static X509Certificate2 GenerateCertificate(string[] dnsNames, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        var subject = new X500DistinguishedName($"CN={dnsNames[0]}");
        var extensions = new List<X509Extension>();
        var sanBuilder = new SubjectAlternativeNameBuilder();
        foreach (var dnsName in dnsNames)
        {
            if (IPAddress.TryParse(dnsName, out var ipAddress))
            {
                sanBuilder.AddIpAddress(ipAddress);
            }
            else
            {
                sanBuilder.AddDnsName(dnsName);
            }
        }
        var keyUsage = new X509KeyUsageExtension(X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature, critical: true);
        var enhancedKeyUsage = new X509EnhancedKeyUsageExtension(
            new OidCollection()
            {
                new Oid(ServerAuthenticationEnhancedKeyUsageOid, ServerAuthenticationEnhancedKeyUsageOidFriendlyName)
            }, critical: true);
        var basicConstraints = new X509BasicConstraintsExtension(false, false, 0, true);

        extensions.Add(basicConstraints);
        extensions.Add(keyUsage);
        extensions.Add(enhancedKeyUsage);
        extensions.Add(sanBuilder.Build(true));

        using var key = CreateKeyMaterial(RSAMinimumKeySizeInBits);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        foreach (var extension in extensions)
        {
            request.CertificateExtensions.Add(extension);
        }
        var result = request.CreateSelfSigned(notBefore, notAfter);
        if (OperatingSystem.IsWindows())
        {
            result.FriendlyName = "certz";
        }
        return result;

        static RSA CreateKeyMaterial(int minimumKeySize)
        {
            var rsa = RSA.Create(minimumKeySize);
            if (rsa.KeySize < minimumKeySize)
            {
                throw new InvalidOperationException($"Failed to create a key with a size of {minimumKeySize} bits");
            }

            return rsa;
        }
    }
}