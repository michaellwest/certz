using certz.Commands;
using certz.Commands.Diff;
using certz.Commands.Examples;
using certz.Commands.Fingerprint;
using certz.Commands.Inspect;
using certz.Commands.Lint;
using certz.Commands.Monitor;
using certz.Commands.Renew;
using certz.Commands.Store;
using certz.Commands.Trust;
using certz.Formatters;
using certz.Options;
using certz.Services;
using System.CommandLine.Completions;

var rootCommand = new RootCommand("Certz: A Simple Certificate Utility");

// Register the [suggest] directive for shell tab completion
rootCommand.Directives.Add(new SuggestDirective());

// Add global --format option
var formatOption = OptionBuilders.CreateFormatOption();
rootCommand.Options.Add(formatOption);

// Add global --guided option
var rootGuidedOption = OptionBuilders.CreateGuidedOption();
rootCommand.Options.Add(rootGuidedOption);

// Add global --verbose option
var rootVerboseOption = OptionBuilders.CreateVerboseOption();
rootCommand.Options.Add(rootVerboseOption);

// Root action: handles `certz --guided` (fires only when no subcommand is matched)
rootCommand.SetAction(async (parseResult) =>
{
    var guided = parseResult.GetValue(rootGuidedOption);

    if (!guided)
    {
        // No subcommand and no --guided: show banner then standard --help output
        Console.WriteLine("  ___ ___ ___ _____ ___");
        Console.WriteLine(@" / __| __| _ \_   _|_  )");
        Console.WriteLine(@"| (__| _||   / | |  / /");
        Console.WriteLine(@" \___|___|_|_\ |_| /___| ");
        Console.WriteLine();
        await rootCommand.Parse(["--help"]).InvokeAsync();
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
        // User pressed Ctrl+C or cancelled
        Console.Error.WriteLine("Operation cancelled.");
    }
});

// Register all commands
rootCommand.AddCreateCommand();
rootCommand.AddConvertCommand();
rootCommand.AddDiffCommand();
rootCommand.AddFingerprintCommand();
rootCommand.AddInspectCommand();
rootCommand.AddLintCommand();
rootCommand.AddMonitorCommand();
rootCommand.AddRenewCommand();
rootCommand.AddStoreCommand();
rootCommand.AddTrustCommand();
rootCommand.AddExamplesCommand();
rootCommand.AddCompletionCommand();

try
{
    var configuration = new InvocationConfiguration()
    {
        EnableDefaultExceptionHandler = false
    };

    // Detect --verbose from raw args before parsing so it is active for all subcommands.
    // Strip it from args so individual subcommands do not reject it as unrecognized.
    VerboseLogger.Enabled = args.Any(a => a is "--verbose" or "-v");
    if (VerboseLogger.Enabled)
        args = args.Where(a => a is not "--verbose" and not "-v").ToArray();

    var parseResult = rootCommand.Parse(args);

    // Typo correction: suggest the nearest known option name for unrecognized options
    foreach (var token in parseResult.UnmatchedTokens)
    {
        if (!token.StartsWith("-"))
            continue;

        var suggestion = CollectOptionNames(rootCommand)
            .Where(o => o != token)
            .Select(o => (name: o, dist: LevenshteinDistance(token, o)))
            .Where(x => x.dist is >= 1 and <= 3)
            .OrderBy(x => x.dist)
            .Select(x => x.name)
            .FirstOrDefault();

        if (suggestion is not null)
            Console.Error.WriteLine($"  Did you mean '{suggestion}'?");
    }

    return await parseResult.InvokeAsync(configuration);
}
catch (LintFailedException)
{
    // Lint results were already displayed, just return exit code 1
    return 1;
}
catch (DiffHasDifferencesException)
{
    // Diff results were already displayed, return exit code 1 to signal differences found
    return 1;
}
catch (Exception exception)
{
    // Emit full exception details to stderr when --verbose is enabled
    VerboseLogger.LogException(exception);

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

// Collect all option aliases recursively across the full command tree
static IEnumerable<string> CollectOptionNames(Command cmd)
{
    foreach (var opt in cmd.Options)
        foreach (var alias in opt.Aliases)
            yield return alias;
    foreach (var sub in cmd.Subcommands)
        foreach (var name in CollectOptionNames(sub))
            yield return name;
}

// Levenshtein edit distance for typo correction (used by "Did you mean?" suggestion)
static int LevenshteinDistance(string a, string b)
{
    int[,] d = new int[a.Length + 1, b.Length + 1];
    for (int i = 0; i <= a.Length; i++) d[i, 0] = i;
    for (int j = 0; j <= b.Length; j++) d[0, j] = j;
    for (int i = 1; i <= a.Length; i++)
        for (int j = 1; j <= b.Length; j++)
            d[i, j] = Math.Min(
                Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1),
                d[i - 1, j - 1] + (a[i - 1] == b[j - 1] ? 0 : 1));
    return d[a.Length, b.Length];
}
