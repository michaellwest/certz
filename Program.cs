using System.CommandLine;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

class Program
{
    private const int RSAMinimumKeySizeInBits = 2048;
    private const string ServerAuthenticationEnhancedKeyUsageOid = "1.3.6.1.5.5.7.3.1";
    private const string ServerAuthenticationEnhancedKeyUsageOidFriendlyName = "Server Authentication";

    static async Task<int> Main(string[] args)
    {
        var rootCommand = new RootCommand("Certz: A Simple Certificate Utility");
        rootCommand.AddCommand(GetListCommand());
        rootCommand.AddCommand(GetInstallCommand());
        rootCommand.AddCommand(GetCreateCommand());

        return await rootCommand.InvokeAsync(args);
    }

    internal static Command GetListCommand()
    {
        var storeNameOption = new Option<StoreName>(new[] { "--storename", "--sn" }, () => StoreName.My, "Specifies the store name.");
        var storeLocationOption = new Option<StoreLocation>(new[] { "--storelocation", "--sl" }, () => StoreLocation.LocalMachine, "Specifies the store location.");

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
        var fileOption = new Option<FileInfo?>(
            aliases: new[] { "--file", "--f" },
            description: "Specifies the certificate to install.",
            parseArgument: result =>
            {
                var filePath = result.Tokens.Single().Value;
                if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                {
                    result.ErrorMessage = string.Format("The specified file '{0}' does not exist.", filePath);
                    return null;
                }
                else
                {
                    return new FileInfo(filePath);
                }
            })
        { IsRequired = true };

        var passwordOption = new Option<string>(
            aliases: new[] { "--password", "--pass", "--p" },
            description: "Password for the certificate."
            );

        var storeNameOption = new Option<StoreName>(new[] { "--storename", "--sn" }, () => StoreName.My, "Specifies the store name.");
        var storeLocationOption = new Option<StoreLocation>(new[] { "--storelocation", "--sl" }, () => StoreLocation.LocalMachine, "Specifies the store location.");

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
        var fileOption = new Option<FileInfo?>(
            aliases: new[] { "--file", "--f" },
            description: "Specifies the certificate to create.",
            parseArgument: result =>
            {
                var filePath = result.Tokens.Single().Value;
                if (string.IsNullOrEmpty(filePath))
                {
                    result.ErrorMessage = string.Format("The specified file path '{0}' is invalid.", filePath);
                    return null;
                }
                else
                {
                    return new FileInfo(filePath);
                }
            })
        { IsRequired = true };

        var passwordOption = new Option<string>(
            aliases: new[] { "--password", "--pass", "--p" },
            description: "Password for the certificate."
            )
        { IsRequired = true };

        var dnsOption = new Option<string[]>(new[] { "--dns" }, () => new[] { "*.dev.local" }, "DNS name for the certificate.");

        var createCommand = new Command("create", "Creates a certificate.")
        {
            fileOption,
            passwordOption,
            dnsOption
        };

        createCommand.SetHandler(async (file, password, dnsNames) =>
        {
            await CreateCertificate(file!, password, dnsNames);
        }, fileOption, passwordOption, dnsOption);

        return createCommand;
    }

    internal static async Task InstallCertificate(FileInfo file, string password, StoreName storeName, StoreLocation storeLocation)
    {
        using var store = new X509Store(storeName, storeLocation);
        using var certificate = new X509Certificate2(file.FullName, password, X509KeyStorageFlags.Exportable);

        store.Open(OpenFlags.ReadWrite);
        store.Add(certificate);
        store.Close();

        await Task.Delay(10);
    }

    internal static async Task CreateCertificate(FileInfo file, string password, string[] dnsNames)
    {
        var certificate = CreateCertificate(dnsNames, DateTime.Today, DateTime.Today.AddYears(5));
        var certData = certificate.Export(X509ContentType.Pfx, password);
        await File.WriteAllBytesAsync(file.FullName, certData);

        var name = Path.GetFileNameWithoutExtension(file.FullName);
        var passwordFile = Path.Combine(file.DirectoryName, $"{name}.password.txt");
        await File.WriteAllTextAsync(passwordFile, password);

        var key = certificate.GetRSAPrivateKey();
        var certificatePem = PemEncoding.Write("CERTIFICATE", certificate.RawData);
        var privateKeyPem = key.ExportPkcs8PrivateKeyPem();

        var certificateFile = Path.Combine(file.DirectoryName, $"{name}-cert.pem");
        await File.WriteAllTextAsync(certificateFile, new string(certificatePem));
        var privatePemFile = Path.Combine(file.DirectoryName, $"{name}-key.pem");
        await File.WriteAllTextAsync(privatePemFile, privateKeyPem);

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

    private static void WriteRow(X509Certificate2 certificate)
    {
        var subject = certificate.SubjectName.Format(false);
        Console.WriteLine($"{certificate.Thumbprint}\t{subject}");
    }

    internal static X509Certificate2 CreateCertificate(string[] dnsNames, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        var subject = new X500DistinguishedName($"CN={dnsNames[0]}");
        var extensions = new List<X509Extension>();
        var sanBuilder = new SubjectAlternativeNameBuilder();
        foreach (var dnsName in dnsNames)
        {
            sanBuilder.AddDnsName(dnsName);
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