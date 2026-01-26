using certz.Options;
using certz.Services;

namespace certz.Commands;

internal static class InstallCommand
{
    internal static void AddInstallCommand(this RootCommand rootCommand)
    {
        var command = BuildInstallCommand();
        rootCommand.Add(command);
    }

    private static Command BuildInstallCommand()
    {
        var fileOption = OptionBuilders.CreateFileOption(true, new[] { "--file", "--f", "--pkcs12", "--cert", "--c" });
        var passwordOption = OptionBuilders.CreatePasswordOption();
        var storeNameOption = OptionBuilders.CreateStoreNameOption();
        var storeLocationOption = OptionBuilders.CreateStoreLocationOption();

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
            await CertificateOperations.InstallCertificate(file!, password, storename, storelocation);
        });

        return installCommand;
    }
}
