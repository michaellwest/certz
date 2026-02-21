using System.Diagnostics;

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

        var installOption = new Option<bool>("--install")
        {
            Description = "Write the completion script directly to your shell profile (skips stdout)."
        };

        var completionCommand = new Command(
            "completion",
            "Output a shell completion script. Pipe to your profile to activate.")
        {
            shellArgument,
            explainOption,
            installOption
        };

        completionCommand.SetAction((parseResult) =>
        {
            var shell = parseResult.GetValue(shellArgument) ?? "powershell";
            var explain = parseResult.GetValue(explainOption);
            var install = parseResult.GetValue(installOption);

            var exePath = Process.GetCurrentProcess().MainModule?.FileName
                ?? Environment.GetCommandLineArgs()[0];

            switch (shell.ToLowerInvariant())
            {
                case "powershell":
                    if (explain)
                    {
                        Console.Write(BuildPowerShellInstructions(exePath));
                    }
                    else if (install)
                    {
                        InstallPowerShellCompletion(exePath);
                    }
                    else
                    {
                        Console.Write(BuildPowerShellScript(exePath));
                    }
                    break;
                default:
                    throw new ArgumentException(
                        $"Unknown shell '{shell}'. Supported shells: powershell");
            }
        });

        rootCommand.Add(completionCommand);
    }

    private static string BuildPowerShellScript(string exePath) =>
        $$"""
        Set-Alias -Name certz -Value "{{exePath}}" -Scope Global -Option AllScope -Force
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

    private static void InstallPowerShellCompletion(string exePath)
    {
        // Ask PowerShell for the current user's profile path
        var psi = new ProcessStartInfo("pwsh")
        {
            Arguments = "-NoProfile -Command \"$PROFILE\"",
            RedirectStandardOutput = true,
            UseShellExecute = false
        };

        string profilePath;
        try
        {
            using var proc = Process.Start(psi)
                ?? throw new InvalidOperationException("Failed to start pwsh.");
            profilePath = proc.StandardOutput.ReadToEnd().Trim();
            proc.WaitForExit();
        }
        catch
        {
            // Fall back to the well-known default when pwsh is not on PATH
            profilePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                "PowerShell",
                "Microsoft.PowerShell_profile.ps1");
        }

        if (string.IsNullOrWhiteSpace(profilePath))
            throw new InvalidOperationException("Could not determine PowerShell profile path.");

        var dir = Path.GetDirectoryName(profilePath);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);

        var script = BuildPowerShellScript(exePath);

        // Avoid duplicate registration if the user runs --install more than once
        var existing = File.Exists(profilePath) ? File.ReadAllText(profilePath) : string.Empty;
        if (existing.Contains("Register-ArgumentCompleter -Native -CommandName @('certz'"))
        {
            Console.WriteLine($"certz completion is already present in: {profilePath}");
            Console.WriteLine("Run `. $PROFILE` in PowerShell to reload.");
            return;
        }

        File.AppendAllText(profilePath, Environment.NewLine + script);
        Console.WriteLine($"Appended certz completion to: {profilePath}");
        Console.WriteLine("Run `. $PROFILE` in PowerShell to activate.");
    }

    private static string BuildPowerShellInstructions(string exePath) =>
        $$"""
        To activate certz tab completion in PowerShell:

          Option A -- auto-install (recommended):
               {{exePath}} completion powershell --install
               . $PROFILE

          Option B -- manual:
               {{exePath}} completion powershell >> $PROFILE
               . $PROFILE

          Test it:
               certz create dev --key-type <TAB>
               certz create dev --eku <TAB>
               certz --format <TAB>

        The generated script includes a Set-Alias that maps 'certz' to the
        full path of this executable, so completion works even when certz is
        not on your PATH.

        """;
}
