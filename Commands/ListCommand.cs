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

        var listCommand = new Command("list", "Lists all certificates.");
        listCommand.Options.Add(storeNameOption);
        listCommand.Options.Add(storeLocationOption);

        listCommand.SetAction(async (parseResult) =>
        {
            var storename = parseResult.GetValue(storeNameOption);
            var storelocation = parseResult.GetValue(storeLocationOption);
            await CertificateOperations.ListCertificates(storename, storelocation);
        });

        return listCommand;
    }
}
