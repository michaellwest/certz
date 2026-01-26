using certz.Commands;

var rootCommand = new RootCommand("Certz: A Simple Certificate Utility");

rootCommand.AddListCommand();
rootCommand.AddInstallCommand();
rootCommand.AddCreateCommand();
rootCommand.AddRemoveCommand();
rootCommand.AddExportCommand();
rootCommand.AddConvertCommand();
rootCommand.AddInfoCommand();
rootCommand.AddVerifyCommand();

return await rootCommand.Parse(args).InvokeAsync();
