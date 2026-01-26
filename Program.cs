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
        rootCommand.Subcommands.Add(GetInfoCommand());
        rootCommand.Subcommands.Add(GetVerifyCommand());

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

    internal static Option<string?> GetUrlOption(bool isRequired, string[] aliases)
    {
        var allAliases = aliases ?? new[] { "--url", "--u" };
        var urlOption = new Option<string?>(allAliases[0], allAliases.Skip(1).ToArray())
        {
            Description = "Specifies the remote URL to retrieve the certificate from.",
            Required = isRequired
        };

        return urlOption;
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

    internal static Option<FileInfo?> GetOutputCertOption()
    {
        var outputCertOption = new Option<FileInfo?>("--out-cert", "--oc")
        {
            Description = "Specifies the output certificate file (PEM format).",
            Required = false
        };
        return outputCertOption;
    }

    internal static Option<FileInfo?> GetOutputKeyOption()
    {
        var outputKeyOption = new Option<FileInfo?>("--out-key", "--ok")
        {
            Description = "Specifies the output private key file (PEM format).",
            Required = false
        };
        return outputKeyOption;
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
            var urlString = parseResult.GetValue(urlOption);
            var thumbprint = parseResult.GetValue(thumbprintOption);
            var storename = parseResult.GetValue(storeNameOption);
            var storelocation = parseResult.GetValue(storeLocationOption);

            if (urlString != null)
            {
                if (!Uri.TryCreate(urlString, UriKind.Absolute, out var uri))
                {
                    throw new ArgumentException($"Invalid URL format: {urlString}");
                }
                await ExportCertificate(file!, password, cert!, key!, uri);
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
        var certOption = GetFileOption(false, new[] { "--cert", "--c" });
        var keyOption = GetFileOption(false, new[] { "--key", "--k" });
        var pfxOption = GetFileOption(false, new[] { "--file", "--f", "--pfx" });
        var passwordOption = GetPasswordOption();
        var outputCertOption = GetOutputCertOption();
        var outputKeyOption = GetOutputKeyOption();

        var convertCommand = new Command("convert", "Converts between PFX and PEM certificate formats.");
        convertCommand.Options.Add(certOption);
        convertCommand.Options.Add(keyOption);
        convertCommand.Options.Add(pfxOption);
        convertCommand.Options.Add(passwordOption);
        convertCommand.Options.Add(outputCertOption);
        convertCommand.Options.Add(outputKeyOption);

        convertCommand.SetAction(async (parseResult) =>
        {
            var cert = parseResult.GetValue(certOption);
            var key = parseResult.GetValue(keyOption);
            var pfx = parseResult.GetValue(pfxOption);
            var password = parseResult.GetValue(passwordOption);
            var outCert = parseResult.GetValue(outputCertOption);
            var outKey = parseResult.GetValue(outputKeyOption);

            // Determine conversion direction
            if (cert != null && key != null && pfx != null)
            {
                // PEM to PFX (original functionality)
                await ConvertToPfx(cert, key, pfx, password);
            }
            else if (pfx != null && (outCert != null || outKey != null))
            {
                // PFX to PEM (new functionality)
                await ConvertFromPfx(pfx, password, outCert, outKey);
            }
            else
            {
                throw new ArgumentException(
                    "Please specify conversion parameters:\n" +
                    "  PEM to PFX: --cert <file> --key <file> --pfx <output>\n" +
                    "  PFX to PEM: --pfx <file> --out-cert <output> --out-key <output>");
            }
        });

        return convertCommand;
    }

    internal static Command GetInfoCommand()
    {
        var fileOption = GetFileOption(false, new[] { "--file", "--f", "--cert", "--c" });
        var thumbprintOption = GetThumbprintOption();
        var urlOption = GetUrlOption(false, new[] { "--url", "--u" });
        var passwordOption = GetPasswordOption();
        var storeNameOption = GetStoreNameOption();
        var storeLocationOption = GetStoreLocationOption();

        var infoCommand = new Command("info", "Displays detailed information about a certificate.");
        infoCommand.Options.Add(fileOption);
        infoCommand.Options.Add(thumbprintOption);
        infoCommand.Options.Add(urlOption);
        infoCommand.Options.Add(passwordOption);
        infoCommand.Options.Add(storeNameOption);
        infoCommand.Options.Add(storeLocationOption);

        infoCommand.SetAction(async (parseResult) =>
        {
            var file = parseResult.GetValue(fileOption);
            var thumbprint = parseResult.GetValue(thumbprintOption);
            var urlString = parseResult.GetValue(urlOption);
            var password = parseResult.GetValue(passwordOption);
            var storename = parseResult.GetValue(storeNameOption);
            var storelocation = parseResult.GetValue(storeLocationOption);

            if (urlString != null)
            {
                if (!Uri.TryCreate(urlString, UriKind.Absolute, out var uri))
                {
                    throw new ArgumentException($"Invalid URL format: {urlString}");
                }
                await ShowCertificateInfo(uri);
            }
            else if (!string.IsNullOrEmpty(thumbprint))
            {
                await ShowCertificateInfo(thumbprint, storename, storelocation);
            }
            else if (file != null)
            {
                await ShowCertificateInfo(file, password);
            }
            else
            {
                throw new ArgumentException("Please specify a certificate source: --file, --thumbprint, or --url");
            }
        });

        return infoCommand;
    }

    internal static Command GetVerifyCommand()
    {
        var fileOption = GetFileOption(false, new[] { "--file", "--f", "--cert", "--c" });
        var thumbprintOption = GetThumbprintOption();
        var passwordOption = GetPasswordOption();
        var storeNameOption = GetStoreNameOption();
        var storeLocationOption = GetStoreLocationOption();
        var checkRevocationOption = new Option<bool>("--check-revocation", "--crl")
        {
            Description = "Check certificate revocation status (requires network access).",
            DefaultValueFactory = _ => false
        };
        var warningDaysOption = new Option<int>("--warning-days", "--warn")
        {
            Description = "Number of days before expiration to show warning.",
            DefaultValueFactory = _ => 30
        };

        var verifyCommand = new Command("verify", "Validates a certificate and checks its trust chain.");
        verifyCommand.Options.Add(fileOption);
        verifyCommand.Options.Add(thumbprintOption);
        verifyCommand.Options.Add(passwordOption);
        verifyCommand.Options.Add(storeNameOption);
        verifyCommand.Options.Add(storeLocationOption);
        verifyCommand.Options.Add(checkRevocationOption);
        verifyCommand.Options.Add(warningDaysOption);

        verifyCommand.SetAction(async (parseResult) =>
        {
            var file = parseResult.GetValue(fileOption);
            var thumbprint = parseResult.GetValue(thumbprintOption);
            var password = parseResult.GetValue(passwordOption);
            var storename = parseResult.GetValue(storeNameOption);
            var storelocation = parseResult.GetValue(storeLocationOption);
            var checkRevocation = parseResult.GetValue(checkRevocationOption);
            var warningDays = parseResult.GetValue(warningDaysOption);

            if (!string.IsNullOrEmpty(thumbprint))
            {
                await VerifyCertificate(thumbprint, storename, storelocation, checkRevocation, warningDays);
            }
            else if (file != null)
            {
                await VerifyCertificate(file, password, checkRevocation, warningDays);
            }
            else
            {
                throw new ArgumentException("Please specify a certificate source: --file or --thumbprint");
            }
        });

        return verifyCommand;
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

        DisplayCertificateDetails(certificate);
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

        DisplayCertificateDetails(certificate);
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

        DisplayCertificateDetails(certificate);
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

        PerformCertificateValidation(certificate, checkRevocation, warningDays);
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

        PerformCertificateValidation(certificate, checkRevocation, warningDays);
        store.Close();
        await Task.Delay(10);
    }

    private static void PerformCertificateValidation(X509Certificate2 certificate, bool checkRevocation, int warningDays)
    {
        Console.WriteLine("Certificate Validation Report");
        Console.WriteLine("============================");
        Console.WriteLine();
        Console.WriteLine("Certificate: {0}", certificate.SubjectName.Format(false));
        Console.WriteLine("Thumbprint:  {0}", certificate.Thumbprint);
        Console.WriteLine();

        var allChecksPassed = true;

        // 1. Expiration Check
        Console.WriteLine("[1] Checking Expiration Status...");
        var now = DateTime.Now;
        if (certificate.NotAfter < now)
        {
            Console.WriteLine("    [FAIL] Certificate has EXPIRED on {0}", certificate.NotAfter.ToString("yyyy-MM-dd"));
            Console.WriteLine("           Expired {0} days ago", (now - certificate.NotAfter).Days);
            allChecksPassed = false;
        }
        else if (certificate.NotBefore > now)
        {
            Console.WriteLine("    [FAIL] Certificate is NOT YET VALID (starts {0})", certificate.NotBefore.ToString("yyyy-MM-dd"));
            allChecksPassed = false;
        }
        else
        {
            var daysRemaining = (certificate.NotAfter - now).Days;
            if (daysRemaining <= warningDays)
            {
                Console.WriteLine("    [WARN] Certificate expires SOON on {0} ({1} days remaining)",
                    certificate.NotAfter.ToString("yyyy-MM-dd"), daysRemaining);
                Console.WriteLine("           Warning threshold: {0} days", warningDays);
            }
            else
            {
                Console.WriteLine("    [PASS] Certificate is valid");
                Console.WriteLine("           Valid until {0} ({1} days remaining)",
                    certificate.NotAfter.ToString("yyyy-MM-dd"), daysRemaining);
            }
        }
        Console.WriteLine();

        // 2. Chain Validation
        Console.WriteLine("[2] Checking Certificate Chain...");
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = checkRevocation
            ? X509RevocationMode.Online
            : X509RevocationMode.NoCheck;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

        var chainIsValid = chain.Build(certificate);

        if (chainIsValid)
        {
            Console.WriteLine("    [PASS] Chain is valid");
            Console.WriteLine("           Chain length: {0} certificate(s)", chain.ChainElements.Count);

            for (int i = 0; i < chain.ChainElements.Count; i++)
            {
                var element = chain.ChainElements[i];
                var indent = new string(' ', 11 + (i * 2));
                Console.WriteLine("{0}{1}. {2}", indent, i + 1, element.Certificate.Subject);
            }
        }
        else
        {
            Console.WriteLine("    [FAIL] Chain validation failed");
            allChecksPassed = false;

            foreach (var status in chain.ChainStatus)
            {
                Console.WriteLine("           - {0}: {1}", status.Status, status.StatusInformation);
            }
        }
        Console.WriteLine();

        // 3. Trust Validation
        Console.WriteLine("[3] Checking Trust Status...");
        if (chainIsValid && chain.ChainElements.Count > 0)
        {
            var rootCert = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;
            using var rootStore = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            rootStore.Open(OpenFlags.ReadOnly);

            var trustedRoot = rootStore.Certificates
                .Cast<X509Certificate2>()
                .Any(c => c.Thumbprint.Equals(rootCert.Thumbprint, StringComparison.OrdinalIgnoreCase));

            rootStore.Close();

            if (trustedRoot)
            {
                Console.WriteLine("    [PASS] Certificate chains to a trusted root");
            }
            else
            {
                Console.WriteLine("    [WARN] Root certificate is not in trusted store");
                Console.WriteLine("           Root: {0}", rootCert.Subject);
            }
        }
        else
        {
            Console.WriteLine("    [FAIL] Cannot verify trust (chain validation failed)");
            allChecksPassed = false;
        }
        Console.WriteLine();

        // 4. Revocation Check (if requested)
        if (checkRevocation)
        {
            Console.WriteLine("[4] Checking Revocation Status...");
            var revocationStatus = chain.ChainStatus
                .FirstOrDefault(s => s.Status == X509ChainStatusFlags.Revoked);

            if (revocationStatus.Status == X509ChainStatusFlags.Revoked)
            {
                Console.WriteLine("    [FAIL] Certificate has been REVOKED");
                Console.WriteLine("           {0}", revocationStatus.StatusInformation);
                allChecksPassed = false;
            }
            else
            {
                var offlineRevocation = chain.ChainStatus
                    .FirstOrDefault(s => s.Status == X509ChainStatusFlags.OfflineRevocation);

                if (offlineRevocation.Status == X509ChainStatusFlags.OfflineRevocation)
                {
                    Console.WriteLine("    [WARN] Revocation status could not be checked (offline)");
                }
                else
                {
                    Console.WriteLine("    [PASS] Certificate has not been revoked");
                }
            }
            Console.WriteLine();
        }

        // Summary
        Console.WriteLine("Summary");
        Console.WriteLine("-------");
        if (allChecksPassed)
        {
            Console.WriteLine("[PASS] Certificate validation SUCCESSFUL");
            Console.WriteLine("        The certificate passed all validation checks.");
        }
        else
        {
            Console.WriteLine("[FAIL] Certificate validation FAILED");
            Console.WriteLine("        See details above for specific failures.");
        }
    }

    private static void DisplayCertificateDetails(X509Certificate2 certificate)
    {
        Console.WriteLine("Certificate Information");
        Console.WriteLine("======================");
        Console.WriteLine();

        // Basic Information
        Console.WriteLine("Subject:              {0}", certificate.SubjectName.Format(false));
        Console.WriteLine("Issuer:               {0}", certificate.IssuerName.Format(false));
        Console.WriteLine("Thumbprint:           {0}", certificate.Thumbprint);
        Console.WriteLine("Serial Number:        {0}", certificate.SerialNumber);
        Console.WriteLine();

        // Validity Period
        Console.WriteLine("Validity Period");
        Console.WriteLine("---------------");
        Console.WriteLine("Not Before:           {0}", certificate.NotBefore.ToString("yyyy-MM-dd HH:mm:ss"));
        Console.WriteLine("Not After:            {0}", certificate.NotAfter.ToString("yyyy-MM-dd HH:mm:ss"));
        var daysRemaining = (certificate.NotAfter - DateTime.Now).Days;
        Console.WriteLine("Days Remaining:       {0}", daysRemaining > 0 ? daysRemaining : "EXPIRED");
        Console.WriteLine();

        // Public Key Information
        Console.WriteLine("Public Key");
        Console.WriteLine("----------");
        Console.WriteLine("Algorithm:            {0}", certificate.PublicKey.Oid.FriendlyName);

        // Get key size - handle different key types
        try
        {
            var rsa = certificate.GetRSAPublicKey();
            if (rsa != null)
            {
                Console.WriteLine("Key Size:             {0} bits", rsa.KeySize);
            }
            else
            {
                var ecdsa = certificate.GetECDsaPublicKey();
                if (ecdsa != null)
                {
                    Console.WriteLine("Key Size:             {0} bits", ecdsa.KeySize);
                }
                else
                {
                    Console.WriteLine("Key Size:             (Unable to determine)");
                }
            }
        }
        catch
        {
            Console.WriteLine("Key Size:             (Unable to determine)");
        }

        Console.WriteLine("Signature Algorithm:  {0}", certificate.SignatureAlgorithm.FriendlyName);
        Console.WriteLine();

        // Subject Alternative Names
        var sanExtension = certificate.Extensions
            .OfType<X509Extension>()
            .FirstOrDefault(e => e.Oid?.Value == "2.5.29.17");

        if (sanExtension != null)
        {
            Console.WriteLine("Subject Alternative Names");
            Console.WriteLine("------------------------");
            var asnData = new AsnEncodedData(sanExtension.Oid!, sanExtension.RawData);
            var sanString = asnData.Format(false);
            Console.WriteLine(sanString);
            Console.WriteLine();
        }

        // Enhanced Key Usage
        var ekuExtension = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
        if (ekuExtension != null)
        {
            Console.WriteLine("Enhanced Key Usage");
            Console.WriteLine("------------------");
            foreach (var oid in ekuExtension.EnhancedKeyUsages)
            {
                Console.WriteLine(" - {0} ({1})", oid.FriendlyName, oid.Value);
            }
            Console.WriteLine();
        }

        // Key Usage
        var keyUsageExtension = certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        if (keyUsageExtension != null)
        {
            Console.WriteLine("Key Usage");
            Console.WriteLine("---------");
            Console.WriteLine(keyUsageExtension.KeyUsages.ToString());
            Console.WriteLine();
        }

        // Basic Constraints
        var basicConstraints = certificate.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
        if (basicConstraints != null)
        {
            Console.WriteLine("Basic Constraints");
            Console.WriteLine("----------------");
            Console.WriteLine("Certificate Authority: {0}", basicConstraints.CertificateAuthority ? "Yes" : "No");
            Console.WriteLine("Path Length Constraint: {0}", basicConstraints.HasPathLengthConstraint
                ? basicConstraints.PathLengthConstraint.ToString()
                : "None");
            Console.WriteLine();
        }

        // Private Key Status
        Console.WriteLine("Private Key:          {0}", certificate.HasPrivateKey ? "Present" : "Not Present");
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