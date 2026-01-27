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
