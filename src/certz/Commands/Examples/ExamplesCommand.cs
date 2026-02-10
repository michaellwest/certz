using certz.Examples;
using certz.Formatters;
using certz.Options;

namespace certz.Commands.Examples;

internal static class ExamplesCommand
{
    internal static void AddExamplesCommand(this RootCommand rootCommand)
    {
        var command = BuildExamplesCommand();
        rootCommand.Add(command);
    }

    private static Command BuildExamplesCommand()
    {
        // Optional command path argument (e.g., "create dev", "trust add")
        var commandArgument = new Argument<string[]>("command")
        {
            Description = "Command path to show examples for (e.g., 'create dev', 'trust add')",
            Arity = ArgumentArity.ZeroOrMore
        };

        var formatOption = OptionBuilders.CreateFormatOption();

        var command = new Command("examples", "Show usage examples for certz commands")
        {
            commandArgument,
            formatOption
        };

        command.SetAction((parseResult) =>
        {
            var commandParts = parseResult.GetValue(commandArgument) ?? Array.Empty<string>();
            var format = parseResult.GetValue(formatOption) ?? "text";
            var formatter = FormatterFactory.Create(format);

            // Join command parts to form command path
            var commandPath = string.Join(" ", commandParts).Trim();

            if (string.IsNullOrEmpty(commandPath))
            {
                // Show all examples
                var allExamples = ExamplesRegistry.GetAllExamples();
                formatter.WriteAllExamples(allExamples);
            }
            else
            {
                // Show examples for specific command
                var examples = ExamplesRegistry.GetExamples(commandPath);

                if (examples.Length == 0)
                {
                    // Try to find closest match or suggest available commands
                    var available = ExamplesRegistry.GetAllCommandPaths()
                        .Where(p => p.StartsWith(commandPath, StringComparison.OrdinalIgnoreCase)
                                 || commandPath.StartsWith(p, StringComparison.OrdinalIgnoreCase))
                        .ToArray();

                    if (available.Length > 0)
                    {
                        formatter.WriteWarning($"No examples found for '{commandPath}'. Did you mean:");
                        foreach (var cmd in available)
                        {
                            Console.WriteLine($"  certz examples {cmd}");
                        }
                    }
                    else
                    {
                        formatter.WriteWarning($"No examples found for '{commandPath}'.");
                        Console.WriteLine();
                        Console.WriteLine("Available commands with examples:");
                        foreach (var cmd in ExamplesRegistry.GetAllCommandPaths())
                        {
                            Console.WriteLine($"  certz examples {cmd}");
                        }
                    }
                    return;
                }

                formatter.WriteExamples(commandPath, examples);
            }
        });

        return command;
    }
}
