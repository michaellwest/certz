using certz.Formatters;
using certz.Models;
using certz.Options;
using certz.Services;

namespace certz.Commands;

internal static class ExportCommand
{
    internal static void AddExportCommand(this RootCommand rootCommand)
    {
        var command = BuildExportCommand();
        rootCommand.Add(command);
    }

    private static Command BuildExportCommand()
    {
        var pfxOption = OptionBuilders.CreateFileOption(false, new[] { "--file", "--f", "--pkcs12" });
        var certOption = OptionBuilders.CreateFileOption(false, new[] { "--cert", "--c" });
        var keyOption = OptionBuilders.CreateFileOption(false, new[] { "--key", "--k" });
        var urlOption = OptionBuilders.CreateUrlOption(false, new[] { "--url", "--u" });
        var passwordOption = OptionBuilders.CreatePasswordOption();
        var passwordFileOption = OptionBuilders.CreatePasswordFileOption();
        var thumbprintOption = OptionBuilders.CreateThumbprintOption();
        var storeNameOption = OptionBuilders.CreateStoreNameOption();
        var storeLocationOption = OptionBuilders.CreateStoreLocationOption();
        var formatOption = OptionBuilders.CreateFormatOption();

        var exportCommand = new Command("export", "Exports the specified certificate.");
        exportCommand.Options.Add(pfxOption);
        exportCommand.Options.Add(passwordOption);
        exportCommand.Options.Add(passwordFileOption);
        exportCommand.Options.Add(certOption);
        exportCommand.Options.Add(keyOption);
        exportCommand.Options.Add(urlOption);
        exportCommand.Options.Add(thumbprintOption);
        exportCommand.Options.Add(storeNameOption);
        exportCommand.Options.Add(storeLocationOption);
        exportCommand.Options.Add(formatOption);

        exportCommand.SetAction(async (parseResult) =>
        {
            var file = parseResult.GetValue(pfxOption);
            var password = parseResult.GetValue(passwordOption);
            var passwordFile = parseResult.GetValue(passwordFileOption);
            var cert = parseResult.GetValue(certOption);
            var key = parseResult.GetValue(keyOption);
            var urlString = parseResult.GetValue(urlOption);
            var thumbprint = parseResult.GetValue(thumbprintOption);
            var storename = parseResult.GetValue(storeNameOption);
            var storelocation = parseResult.GetValue(storeLocationOption);
            var format = parseResult.GetValue(formatOption) ?? "text";
            var formatter = FormatterFactory.Create(format);

            if (urlString != null)
            {
                // Export from URL (using modern V2 API)
                if (!Uri.TryCreate(urlString, UriKind.Absolute, out var uri))
                {
                    formatter.WriteError($"Invalid URL format: {urlString}");
                    return;
                }

                var options = new ExportFromUrlOptions
                {
                    Url = uri,
                    PfxFile = file,
                    CertFile = cert,
                    KeyFile = key,
                    Password = password,
                    PasswordFile = passwordFile
                };
                var result = await CertificateOperationsV2.ExportFromUrl(options);
                formatter.WriteExportResult(result);
            }
            else
            {
                // Export from store (using modern V2 API)
                if (string.IsNullOrEmpty(thumbprint))
                {
                    formatter.WriteError("Thumbprint is required for store export. Use --thumbprint to specify it.");
                    return;
                }

                var options = new ExportFromStoreOptions
                {
                    Thumbprint = thumbprint,
                    StoreName = storename,
                    StoreLocation = storelocation,
                    PfxFile = file,
                    CertFile = cert,
                    KeyFile = key,
                    Password = password,
                    PasswordFile = passwordFile
                };
                var result = await CertificateOperationsV2.ExportFromStore(options);
                formatter.WriteExportResult(result);
            }
        });

        return exportCommand;
    }
}
