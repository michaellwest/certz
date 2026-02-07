using certz.Formatters;
using certz.Models;
using certz.Options;
using certz.Services;

namespace certz.Commands;

internal static class ListCommand
{
    internal static void AddListCommand(this RootCommand rootCommand)
    {
        var command = BuildListCommand();
        rootCommand.Add(command);
    }

    private static Command BuildListCommand()
    {
        var storeNameOption = OptionBuilders.CreateStoreNameOption();
        var storeLocationOption = OptionBuilders.CreateStoreLocationOption();
        var formatOption = OptionBuilders.CreateFormatOption();

        var listCommand = new Command("list", "Lists all certificates.");
        listCommand.Options.Add(storeNameOption);
        listCommand.Options.Add(storeLocationOption);
        listCommand.Options.Add(formatOption);

        listCommand.SetAction((parseResult) =>
        {
            var storename = parseResult.GetValue(storeNameOption);
            var storelocation = parseResult.GetValue(storeLocationOption);
            var format = parseResult.GetValue(formatOption) ?? "text";
            var formatter = FormatterFactory.Create(format);

            var options = new ListCertificatesOptions
            {
                StoreName = storename,
                StoreLocation = storelocation
            };
            var result = CertificateOperationsV2.ListCertificates(options);
            formatter.WriteStoreList(result);
        });

        return listCommand;
    }
}
