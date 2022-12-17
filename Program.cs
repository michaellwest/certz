using System.CommandLine;
using System.Security.Cryptography.X509Certificates;

class Program
{
    static async Task<int> Main(string[] args)
    {
        var rootCommand = new RootCommand("Certz: A Simple Certificate Utility");
        rootCommand.AddCommand(GetListCommand());
        rootCommand.AddCommand(GetInstallCommand());

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
            name: "--file",
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

        var storeNameOption = new Option<StoreName>(new[] { "--storename", "--sn" }, () => StoreName.My, "Specifies the store name.");
        var storeLocationOption = new Option<StoreLocation>(new[] { "--storelocation", "--sl" }, () => StoreLocation.LocalMachine, "Specifies the store location.");

        var installCommand = new Command("install", "Installs a certificate.")
        {
            fileOption,
            storeNameOption,
            storeLocationOption
        };

        installCommand.SetHandler(async (file, storename, storelocation) =>
        {
            await InstallCertificate(file!, storename, storelocation);
        }, fileOption, storeNameOption, storeLocationOption);

        return installCommand;
    }

    internal static async Task InstallCertificate(FileInfo file, StoreName storeName, StoreLocation storeLocation)
    {
        using var store = new X509Store(storeName, storeLocation);
        using var certificate = new X509Certificate2(file.FullName);

        store.Open(OpenFlags.ReadWrite);
        store.Add(certificate);
        store.Close();

        await Task.Delay(10);
    }

    internal static async Task ListCertificates(StoreName storeName, StoreLocation storeLocation)
    {
        using var store = new X509Store(storeName, storeLocation, OpenFlags.ReadOnly | OpenFlags.IncludeArchived);
        foreach (var certificate in store.Certificates.OrderBy(c => c.SubjectName.Format(false) ))
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
}