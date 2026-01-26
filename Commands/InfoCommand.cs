using certz.Options;
using certz.Services;

namespace certz.Commands;

internal static class InfoCommand
{
    internal static void AddInfoCommand(this RootCommand rootCommand)
    {
        var command = BuildInfoCommand();
        rootCommand.Add(command);
    }

    private static Command BuildInfoCommand()
    {
        var fileOption = OptionBuilders.CreateFileOption(false, new[] { "--file", "--f", "--cert", "--c" });
        var thumbprintOption = OptionBuilders.CreateThumbprintOption();
        var urlOption = OptionBuilders.CreateUrlOption(false, new[] { "--url", "--u" });
        var passwordOption = OptionBuilders.CreatePasswordOption();
        var storeNameOption = OptionBuilders.CreateStoreNameOption();
        var storeLocationOption = OptionBuilders.CreateStoreLocationOption();

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
                await CertificateOperations.ShowCertificateInfo(uri);
            }
            else if (!string.IsNullOrEmpty(thumbprint))
            {
                await CertificateOperations.ShowCertificateInfo(thumbprint, storename, storelocation);
            }
            else if (file != null)
            {
                await CertificateOperations.ShowCertificateInfo(file, password);
            }
            else
            {
                throw new ArgumentException("Please specify a certificate source: --file, --thumbprint, or --url");
            }
        });

        return infoCommand;
    }
}
