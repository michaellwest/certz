using System.CommandLine.Help;
using System.CommandLine.Invocation;
using certz.Examples;

namespace certz.Help;

/// <summary>
/// Adds a "Quick examples" section (and, where applicable, an "Exit codes" section)
/// to every command's --help output. After the standard help sections, three short
/// example commands are shown along with a pointer to `certz examples [command]`.
/// </summary>
internal static class HelpCustomizer
{
    // Exit codes shown only in the specific command's own help, not in parent command lists.
    private static readonly Dictionary<string, string[]> ExitCodes = new(StringComparer.OrdinalIgnoreCase)
    {
        ["lint"] =
        [
            "0  All checks passed",
            "1  One or more lint violations found",
        ],
        ["monitor"] =
        [
            "0  All certificates are healthy",
            "1  Error (file not found, network failure) or --fail-on-warning triggered",
            "2  One or more certificates have expired",
        ],
        ["renew"] =
        [
            "0  Certificate renewed successfully",
            "1  Renewal failed (read error, write error, invalid input)",
            "2  Issuer certificate required but not found (CA-signed cert)",
        ],
    };

    internal static void Configure(Command rootCommand)
    {
        ConfigureCommand(rootCommand);
    }

    private static void ConfigureCommand(Command command)
    {
        var helpOption = command.Options.OfType<HelpOption>().FirstOrDefault();
        if (helpOption?.Action is HelpAction originalAction)
        {
            helpOption.Action = new QuickExamplesHelpAction(originalAction, ExitCodes);
        }

        foreach (var sub in command.Subcommands)
            ConfigureCommand(sub);
    }
}

/// <summary>
/// Wraps the built-in HelpAction and appends a quick-examples footer and,
/// for commands that have exit codes defined, an exit codes section.
/// </summary>
internal sealed class QuickExamplesHelpAction : SynchronousCommandLineAction
{
    private const int MaxQuickExamples = 3;
    private readonly HelpAction _inner;
    private readonly IReadOnlyDictionary<string, string[]> _exitCodes;

    internal QuickExamplesHelpAction(HelpAction inner, IReadOnlyDictionary<string, string[]> exitCodes)
    {
        _inner = inner;
        _exitCodes = exitCodes;
    }

    public override bool Terminating => _inner.Terminating;
    public override bool ClearsParseErrors => _inner.ClearsParseErrors;

    public override int Invoke(ParseResult parseResult)
    {
        var result = _inner.Invoke(parseResult);

        var command = parseResult.CommandResult.Command;
        var commandPath = GetCommandPath(command);
        var output = parseResult.InvocationConfiguration.Output ?? Console.Out;

        WriteQuickExamples(commandPath, output);
        WriteExitCodes(commandPath, output);

        return result;
    }

    private void WriteQuickExamples(string commandPath, TextWriter output)
    {
        var examplesMap = ExamplesRegistry.GetExamples(commandPath);
        if (!examplesMap.Any()) return;

        var quickExamples = examplesMap.Values.First().Take(MaxQuickExamples).ToArray();
        if (quickExamples.Length == 0) return;

        output.WriteLine();
        output.WriteLine("Quick examples:");
        foreach (var ex in quickExamples)
            output.WriteLine($"  {ex.Command}");
        output.WriteLine();

        var hint = string.IsNullOrEmpty(commandPath)
            ? "  Run 'certz examples' to see all examples."
            : $"  Run 'certz examples {commandPath}' to see more examples.";
        output.WriteLine(hint);
    }

    private void WriteExitCodes(string commandPath, TextWriter output)
    {
        if (!_exitCodes.TryGetValue(commandPath, out var codes)) return;

        output.WriteLine();
        output.WriteLine("Exit codes:");
        foreach (var code in codes)
            output.WriteLine($"  {code}");
    }

    private static string GetCommandPath(Command command)
    {
        if (command is RootCommand) return "";

        var parts = new List<string> { command.Name };
        var parent = command.Parents.OfType<Command>().FirstOrDefault();

        while (parent is not null and not RootCommand)
        {
            parts.Insert(0, parent.Name);
            parent = parent.Parents.OfType<Command>().FirstOrDefault();
        }

        return string.Join(" ", parts);
    }
}
