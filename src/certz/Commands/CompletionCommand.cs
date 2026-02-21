namespace certz.Commands;

internal static class CompletionCommand
{
    internal static void AddCompletionCommand(this RootCommand rootCommand)
    {
        var shellArgument = new Argument<string>("shell")
        {
            Description = "Shell type: powershell",
            DefaultValueFactory = _ => "powershell",
            Arity = ArgumentArity.ZeroOrOne
        };
        shellArgument.CompletionSources.Add(new[] { "powershell" });

        var explainOption = new Option<bool>("--explain")
        {
            Description = "Show installation instructions instead of the completion script."
        };

        var completionCommand = new Command(
            "completion",
            "Output a shell completion script. Pipe to your profile to activate.")
        {
            shellArgument,
            explainOption
        };

        completionCommand.SetAction((parseResult) =>
        {
            var shell = parseResult.GetValue(shellArgument) ?? "powershell";
            var explain = parseResult.GetValue(explainOption);

            switch (shell.ToLowerInvariant())
            {
                case "powershell":
                    Console.Write(explain ? PowerShellInstructions : PowerShellScript);
                    break;
                default:
                    throw new ArgumentException(
                        $"Unknown shell '{shell}'. Supported shells: powershell");
            }
        });

        rootCommand.Add(completionCommand);
    }

    private const string PowerShellScript =
        """
        Register-ArgumentCompleter -Native -CommandName @('certz', 'certz.exe') -ScriptBlock {
            param($wordToComplete, $commandAst, $cursorPosition)
            & certz '[suggest]' --position $cursorPosition "$commandAst" 2>$null |
                Where-Object { $_ } |
                ForEach-Object {
                    [System.Management.Automation.CompletionResult]::new(
                        $_, $_, 'ParameterValue', $_)
                }
        }

        """;

    private const string PowerShellInstructions =
        """
        To activate certz tab completion in PowerShell:

          1. Append the completion script to your PowerShell profile:
               certz completion powershell >> $PROFILE

          2. Reload your profile:
               . $PROFILE

          3. Test it:
               certz create dev --key-type <TAB>
               certz create dev --eku <TAB>
               certz --format <TAB>

        """;
}
