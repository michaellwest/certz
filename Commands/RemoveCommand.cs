using certz.Options;
using certz.Services;

namespace certz.Commands;

internal static class RemoveCommand
{
    internal static void AddRemoveCommand(this RootCommand rootCommand)
    {
        var command = BuildRemoveCommand();
        rootCommand.Add(command);
    }

    private static Command BuildRemoveCommand()
    {
        var subjectOption = new Option<string>("--subject")
        {
            Description = "The subject for the certificate. Multiple certificates may match."
        };
        var thumbprintOption = OptionBuilders.CreateThumbprintOption();
        var storeNameOption = OptionBuilders.CreateStoreNameOption();
        var storeLocationOption = OptionBuilders.CreateStoreLocationOption();

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
            await CertificateOperations.RemoveCertificate(subject, thumbprint, storename, storelocation);
        });

        return removeCommand;
    }
}
