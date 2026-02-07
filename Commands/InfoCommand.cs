using certz.Formatters;
using certz.Models;
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
        var fileOption = OptionBuilders.CreateFileOption(false, ["--file", "--f", "--cert", "--c"]);
        var thumbprintOption = OptionBuilders.CreateThumbprintOption();
        var urlOption = OptionBuilders.CreateUrlOption(false, ["--url", "--u"]);
        var passwordOption = OptionBuilders.CreatePasswordOption();
        var storeNameOption = OptionBuilders.CreateStoreNameOption();
        var storeLocationOption = OptionBuilders.CreateStoreLocationOption();
        var formatOption = OptionBuilders.CreateFormatOption();

        var infoCommand = new Command("info", "Displays detailed information about a certificate.");
        infoCommand.Options.Add(fileOption);
        infoCommand.Options.Add(thumbprintOption);
        infoCommand.Options.Add(urlOption);
        infoCommand.Options.Add(passwordOption);
        infoCommand.Options.Add(storeNameOption);
        infoCommand.Options.Add(storeLocationOption);
        infoCommand.Options.Add(formatOption);

        infoCommand.SetAction(async (parseResult) =>
        {
            var file = parseResult.GetValue(fileOption);
            var thumbprint = parseResult.GetValue(thumbprintOption);
            var urlString = parseResult.GetValue(urlOption);
            var password = parseResult.GetValue(passwordOption);
            var storename = parseResult.GetValue(storeNameOption);
            var storelocation = parseResult.GetValue(storeLocationOption);
            var format = parseResult.GetValue(formatOption) ?? "text";
            var formatter = FormatterFactory.Create(format);

            if (urlString != null)
            {
                if (!Uri.TryCreate(urlString, UriKind.Absolute, out var uri))
                {
                    formatter.WriteError($"Invalid URL format: {urlString}");
                    return;
                }
                var options = new ShowCertificateInfoFromUrlOptions
                {
                    Url = uri
                };
                var result = await InspectService.InspectUrl(options);
                formatter.WriteCertificateInspected(result);
            }
            else if (!string.IsNullOrEmpty(thumbprint))
            {
                var options = new ShowCertificateInfoFromStoreOptions
                {
                    Thumbprint = thumbprint,
                    StoreName = storename,
                    StoreLocation = storelocation
                };
                var result = InspectService.InspectStore(options);
                formatter.WriteCertificateInspected(result);
            }
            else if (file != null)
            {
                var options = new ShowCertificateInfoFromFileOptions
                {
                    File = file,
                    Password = password
                };
                var result = InspectService.InspectFile(options);
                formatter.WriteCertificateInspected(result);
            }
            else
            {
                formatter.WriteError("Please specify a certificate source: --file, --thumbprint, or --url");
            }
        });

        return infoCommand;
    }
}
