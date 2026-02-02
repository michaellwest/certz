using certz.Commands;
using certz.Commands.Inspect;
using certz.Commands.Store;
using certz.Commands.Trust;
using certz.Options;

var rootCommand = new RootCommand("Certz: A Simple Certificate Utility");

// Add global --format option
var formatOption = OptionBuilders.CreateFormatOption();
rootCommand.Options.Add(formatOption);

rootCommand.AddListCommand();
rootCommand.AddInstallCommand();
rootCommand.AddCreateCommand();
rootCommand.AddRemoveCommand();
rootCommand.AddExportCommand();
rootCommand.AddConvertCommand();
rootCommand.AddInfoCommand();
rootCommand.AddVerifyCommand();
rootCommand.AddInspectCommand();
rootCommand.AddStoreCommand();
rootCommand.AddTrustCommand();

try
{
    var configuration = new InvocationConfiguration()
    {
        EnableDefaultExceptionHandler = false
    };

    return await rootCommand.Parse(args).InvokeAsync(configuration);
}
catch (Exception exception)
{
    var originalColor = Console.ForegroundColor;
    Console.ForegroundColor = ConsoleColor.Red;

    var message = exception switch
    {
        FileNotFoundException fnf => $"File not found: {fnf.FileName ?? fnf.Message}",
        CryptographicException => "Cryptographic error: Invalid password or corrupted certificate file.",
        CertificateException ce => $"Certificate error: {ce.Message}",
        ArgumentException ae => $"Invalid argument: {ae.Message}",
        SocketException se => $"Network error: {se.Message}",
        _ => $"Error: {exception.Message}"
    };

    Console.Error.WriteLine(message);
    Console.ForegroundColor = originalColor;
    return 1;
}
