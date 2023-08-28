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
        rootCommand.AddCommand(GetListCommand());
        rootCommand.AddCommand(GetInstallCommand());
        rootCommand.AddCommand(GetCreateCommand());
        rootCommand.AddCommand(GetRemoveCommand());
        rootCommand.AddCommand(GetExportCommand());

        return await rootCommand.InvokeAsync(args);
    }

    internal static Option<FileInfo?> GetFileOption(bool isRequired, string[] aliases)
    {
        var fileOption = new Option<FileInfo?>(
            aliases: aliases ?? new[] { "--file", "--f" },
            description: "Specifies the certificate.")
        { IsRequired = isRequired };

        return fileOption;
    }

    internal static Option<Uri?> GetUrlOption(bool isRequired, string[] aliases)
    {
        var fileOption = new Option<Uri?>(
            aliases: aliases ?? new[] { "--url", "--u" },
            description: "Specifies the certificate.")
        { IsRequired = isRequired };

        return fileOption;
    }

    internal static Option<string> GetPasswordOption()
    {
        var passwordOption = new Option<string>(
            aliases: new[] { "--password", "--pass", "--p" },
            description: "Password for the certificate."
            );

        return passwordOption;
    }

    internal static Option<int> GetDaysOption(bool isRequired)
    {
        var daysOption = new Option<int>(
            aliases: new[] { "--days" },
            description: "Lifetime for the certificate.",
            getDefaultValue: () => 365
            )
        { IsRequired = isRequired };

        return daysOption;
    }

    internal static Option<StoreName> GetStoreNameOption()
    {
        var storeNameOption = new Option<StoreName>(new[] { "--storename", "--sn" },
            () => StoreName.My, "Specifies the store name.");
        return storeNameOption;
    }

    internal static Option<StoreLocation> GetStoreLocationOption()
    {
        var storeLocationOption = new Option<StoreLocation>(new[] { "--storelocation", "--sl" },
            () => StoreLocation.LocalMachine, "Specifies the store location.");
        return storeLocationOption;
    }

    internal static Option<string> GetThumbprintOption()
    {
        var thumbprintOption = new Option<string>(new[] { "--thumbprint", "--thumb" },
            "The unique thumbprint for the certificate.");
        return thumbprintOption;
    }

    internal static Command GetListCommand()
    {
        var storeNameOption = GetStoreNameOption();
        var storeLocationOption = GetStoreLocationOption();

        var listCommand = new Command("list", "Lists all certificates.")
        {
            storeNameOption,
            storeLocationOption
        };

        listCommand.SetHandler(async (storename, storelocation) =>
        {
            await ListCertificates(storename, storelocation);
        }, storeNameOption, storeLocationOption);

        return listCommand;
    }

    internal static Command GetInstallCommand()
    {
        var fileOption = GetFileOption(true, new[] { "--file", "--f", "--pkcs12", "--cert", "--c" });

        var passwordOption = GetPasswordOption();
        var storeNameOption = GetStoreNameOption();
        var storeLocationOption = GetStoreLocationOption();

        var installCommand = new Command("install", "Installs a certificate.")
        {
            fileOption,
            passwordOption,
            storeNameOption,
            storeLocationOption
        };

        installCommand.SetHandler(async (file, password, storename, storelocation) =>
        {
            await InstallCertificate(file!, password, storename, storelocation);
        }, fileOption, passwordOption, storeNameOption, storeLocationOption);

        return installCommand;
    }

    internal static Command GetCreateCommand()
    {
        var pfxOption = GetFileOption(false, new[] { "--file", "--f", "--pkcs12" });
        var certOption = GetFileOption(false, new[] { "--cert", "--c" });
        var keyOption = GetFileOption(false, new[] { "--key", "--k" });
        var passwordOption = GetPasswordOption();
        var dnsOption = new Option<string[]>(new[] { "--dns", "--san" },
            () => new[] { "*.dev.local", "*.localhost", "*.test" }, "SAN for the certificate.")
        { AllowMultipleArgumentsPerToken = true };
        var daysOption = GetDaysOption(false);

        var createCommand = new Command("create", "Creates a certificate.")
        {
            pfxOption,
            passwordOption,
            certOption,
            keyOption,
            dnsOption,
            daysOption
        };

        createCommand.SetHandler(async (pfx, password, cert, key, dnsNames, days) =>
        {
            await CreateCertificate(pfx!, password, cert!, key!, dnsNames, days);
        }, pfxOption, passwordOption, certOption, keyOption, dnsOption, daysOption);

        return createCommand;
    }

    internal static Command GetRemoveCommand()
    {
        var subjectOption = new Option<string>(new[] { "--subject" },
            "The subject for the certificate. Multiple certificates may match.");
        var thumbprintOption = GetThumbprintOption();
        var storeNameOption = GetStoreNameOption();
        var storeLocationOption = GetStoreLocationOption();

        var removeCommand = new Command("remove", "Removes the specified certificate.")
        {
            subjectOption,
            thumbprintOption,
            storeNameOption,
            storeLocationOption
        };

        removeCommand.SetHandler(async (subject, thumbprint, storename, storelocation) =>
        {
            await RemoveCertificate(subject, thumbprint, storename, storelocation);
        }, subjectOption, thumbprintOption, storeNameOption, storeLocationOption);

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

        var exportCommand = new Command("export", "Exports the specified certificate.")
        {
            pfxOption,
            passwordOption,
            certOption,
            keyOption,
            urlOption,
            thumbprintOption,
            storeNameOption,
            storeLocationOption
        };

        exportCommand.SetHandler(async (file, password, cert, key, uri, thumbprint, storename, storelocation) =>
        {
            if (uri != null)
            {
                await ExportCertificate(file!, password, cert!, key!, uri!);
            }
            else
            {
                await ExportCertificate(file!, password, cert!, key!, thumbprint, storename, storelocation);
            }
        }, pfxOption, passwordOption, certOption, keyOption, urlOption, thumbprintOption, storeNameOption, storeLocationOption);

        return exportCommand;
    }

    internal static async Task InstallCertificate(FileInfo file, string password, StoreName storeName, StoreLocation storeLocation)
    {
        using var store = new X509Store(storeName, storeLocation, OpenFlags.ReadWrite);
        using var certificate = new X509Certificate2(file.FullName, password, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
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

            var name = Path.GetFileNameWithoutExtension(path);
            var directory = Path.GetDirectoryName(path);
            var passwordFile = Path.Combine(directory, $"{name}.password.txt");
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
        if (pfx == null && cert == null)
        {
            pfx = new FileInfo("devcert.pfx");
            cert = new FileInfo("devcert.cer");
            key = new FileInfo("devcert.key");
        }

        if (cert == null | key == null)
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