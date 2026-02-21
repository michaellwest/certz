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
        const string marker = "Register-ArgumentCompleter -Native -CommandName @('certz'";
        var script = BuildPowerShellScript(exePath);
        var profiles = CollectPowerShellProfiles();

        Console.WriteLine("certz completion --install");
        Console.WriteLine();

        bool anyInstalled = false;
        foreach (var profile in profiles)
        {
            var dir = Path.GetDirectoryName(profile);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);

            var existing = File.Exists(profile) ? File.ReadAllText(profile) : string.Empty;
            if (existing.Contains(marker))
            {
                Console.WriteLine($"  [=] {profile}");
                Console.WriteLine($"      (already installed -- skipped)");
            }
            else
            {
                File.AppendAllText(profile, Environment.NewLine + script);
                Console.WriteLine($"  [+] {profile}");
                Console.WriteLine($"      (installed)");
                anyInstalled = true;
            }
        }

        Console.WriteLine();
        if (anyInstalled)
            Console.WriteLine("Run `. $PROFILE` in each open PowerShell session to activate.");
        else
            Console.WriteLine("No changes made -- certz completion was already present in all profiles.");
    }

    private static List<string> CollectPowerShellProfiles()
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var profiles = new List<string>();

        // Query each shell for its $PROFILE path (handles custom profile locations)
        foreach (var shell in new[] { "pwsh", "powershell" })
        {
            var path = QueryProfilePath(shell);
            if (path is not null && seen.Add(path))
                profiles.Add(path);
        }

        // Fall back to well-known locations when neither shell is on PATH
        if (profiles.Count == 0)
        {
            var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            foreach (var subdir in new[] { "PowerShell", "WindowsPowerShell" })
            {
                var path = Path.Combine(docs, subdir, "Microsoft.PowerShell_profile.ps1");
                if (seen.Add(path))
                    profiles.Add(path);
            }
        }

        return profiles;
    }

    private static string? QueryProfilePath(string shell)
    {
        try
        {
            var psi = new ProcessStartInfo(shell)
            {
                Arguments = "-NoProfile -Command \"$PROFILE\"",
                RedirectStandardOutput = true,
                UseShellExecute = false
            };
            using var proc = Process.Start(psi);
            if (proc is null) return null;
            var path = proc.StandardOutput.ReadToEnd().Trim();
            proc.WaitForExit();
            return string.IsNullOrWhiteSpace(path) ? null : path;
        }
        catch
        {
            return null;
        }
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
