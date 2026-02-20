using certz.Commands.Create;

namespace certz.Commands;

internal static class CreateCommand
{
    internal static void AddCreateCommand(this RootCommand rootCommand)
    {
        var createCommand = new Command("create", "Certificate creation commands");

        // Add subcommands
        createCommand.Subcommands.Add(CreateDevCommand.BuildCreateDevCommand());
        createCommand.Subcommands.Add(CreateCaCommand.BuildCreateCaCommand());

        rootCommand.Add(createCommand);
    }
}
