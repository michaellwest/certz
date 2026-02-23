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
                // No args → show command index (summary table)
                var allExamples = ExamplesRegistry.GetAllExamples();
                formatter.WriteExamplesIndex(allExamples);
            }
            else
            {
                var examples = ExamplesRegistry.GetExamples(commandPath);

                if (!examples.Any())
                {
                    formatter.WriteWarning($"No examples found for '{commandPath}'.");
                    Console.WriteLine();
                    Console.WriteLine("Available commands with examples:");
                    foreach (var cmd in ExamplesRegistry.GetAllCommandPaths())
                    {
                        Console.WriteLine($"  certz examples {cmd}");
                    }
                    return;
                }

                if (examples.Count == 1)
                {
                    // Exact match → clean single-group view
                    var (path, exampleList) = examples.First();
                    formatter.WriteExamples(path, exampleList);
                }
                else
                {
                    // Prefix match (e.g. "create" -> "create dev" + "create ca") → multi-group view
                    formatter.WriteAllExamples(examples);
                }
            }
        });

        return command;
    }
}
