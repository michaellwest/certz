using certz.Commands;
using certz.Commands.Examples;
using certz.Commands.Inspect;
using certz.Commands.Lint;
using certz.Commands.Monitor;
using certz.Commands.Renew;
using certz.Commands.Store;
using certz.Commands.Trust;
using certz.Formatters;
using certz.Options;
using certz.Services;

var rootCommand = new RootCommand("Certz: A Simple Certificate Utility");

// Add global --format option
var formatOption = OptionBuilders.CreateFormatOption();
rootCommand.Options.Add(formatOption);

// Add global --guided option
var rootGuidedOption = OptionBuilders.CreateGuidedOption();
rootCommand.Options.Add(rootGuidedOption);

// Root action: handles `certz --guided` (fires only when no subcommand is matched)
rootCommand.SetAction(async (parseResult) =>
{
    var guided = parseResult.GetValue(rootGuidedOption);

    if (!guided)
    {
        // No subcommand and no --guided: print brief guidance
        Console.WriteLine("certz - A standards-compliant certificate utility");
        Console.WriteLine();
        Console.WriteLine("  certz --help     Show command reference");
        Console.WriteLine("  certz --guided   Launch interactive wizard");
        return;
    }

    var format = parseResult.GetValue(formatOption) ?? "text";
    var formatter = FormatterFactory.Create(format);

    try
    {
        await CertificateWizard.RunGlobalWizard(formatter);
    }
    catch (OperationCanceledException)
    {
        // User pressed Ctrl+C or cancelled — exit cleanly
    }
});

// Register all commands
rootCommand.AddCreateCommand();
rootCommand.AddConvertCommand();
rootCommand.AddInspectCommand();
rootCommand.AddLintCommand();
rootCommand.AddMonitorCommand();
rootCommand.AddRenewCommand();
rootCommand.AddStoreCommand();
rootCommand.AddTrustCommand();
rootCommand.AddExamplesCommand();

try
{
    var configuration = new InvocationConfiguration()
    {
        EnableDefaultExceptionHandler = false
    };

    return await rootCommand.Parse(args).InvokeAsync(configuration);
}
catch (LintFailedException)
{
    // Lint results were already displayed, just return exit code 1
    return 1;
}
catch (Exception exception)
{
    var originalColor = Console.ForegroundColor;
    Console.ForegroundColor = ConsoleColor.Red;

    var message = exception switch
    {
        FileNotFoundException fnf => $"File not found: {fnf.FileName ?? fnf.Message}",
        CryptographicException ce when ce.Message.Contains("access", StringComparison.OrdinalIgnoreCase)
            => $"Error: {ce.Message} Run as administrator for LocalMachine store operations.",
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
