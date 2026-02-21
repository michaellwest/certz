using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;

namespace certz.Commands;

internal static class CompletionCommand
{
    // Delimiters that wrap the certz block in the profile so --install can find and
    // replace it on future runs (handles path changes, line-ending fixes, upgrades).
    private const string BlockBegin = "# BEGIN certz completion";
    private const string BlockEnd   = "# END certz completion";

    // Marker present in old-format installations (no delimiters).
    private const string OldMarker = "Register-ArgumentCompleter -Native -CommandName @('certz'";

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
            var shell   = parseResult.GetValue(shellArgument) ?? "powershell";
            var explain = parseResult.GetValue(explainOption);
            var install = parseResult.GetValue(installOption);

            var exePath = Process.GetCurrentProcess().MainModule?.FileName
                ?? Environment.GetCommandLineArgs()[0];

            switch (shell.ToLowerInvariant())
            {
                case "powershell":
                    if (explain)
                        Console.Write(BuildPowerShellInstructions(exePath));
                    else if (install)
                        InstallPowerShellCompletion(exePath);
                    else
                        Console.Write(BuildPowerShellScript(exePath));
                    break;
                default:
                    throw new ArgumentException(
                        $"Unknown shell '{shell}'. Supported shells: powershell");
            }
        });

        rootCommand.Add(completionCommand);
    }

    // ---------------------------------------------------------------------------
    // Script generation
    // ---------------------------------------------------------------------------

    private static string BuildPowerShellScript(string exePath)
    {
        var inner = $$"""
        Set-Alias -Name certz -Value "{{exePath}}" -Scope Global -Option AllScope -Force
        Register-ArgumentCompleter -Native -CommandName @('certz', 'certz.exe') -ScriptBlock {
            param($wordToComplete, $commandAst, $cursorPosition)
            & certz "[suggest:$cursorPosition]" "$commandAst" 2>$null |
                Where-Object { $_ } |
                ForEach-Object {
                    [System.Management.Automation.CompletionResult]::new(
                        $_, $_, 'ParameterValue', $_)
                }
        }
        """;

        // Wrap with delimiters so --install can locate and replace the block.
        // ReplaceLineEndings("\n") normalizes to LF regardless of source-file
        // line endings, so \r never appears in what we write to the profile.
        return $"{BlockBegin}\n{inner.ReplaceLineEndings("\n").TrimEnd()}\n{BlockEnd}\n";
    }

    // ---------------------------------------------------------------------------
    // --install: write (or update) both PS7 and PS5 profiles
    // ---------------------------------------------------------------------------

    private static void InstallPowerShellCompletion(string exePath)
    {
        var script   = BuildPowerShellScript(exePath);
        var profiles = CollectPowerShellProfiles();

        Console.WriteLine("certz completion --install");
        Console.WriteLine();

        bool anyChanged = false;
        foreach (var profile in profiles)
        {
            var dir = Path.GetDirectoryName(profile);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);

            // Read with BOM detection so we handle files created by PowerShell 5's >>
            var existing = File.Exists(profile) ? File.ReadAllText(profile) : string.Empty;

            string updated;
            string status;

            if (existing.Contains(BlockBegin))
            {
                // New format: replace the delimited block in-place
                updated = ReplaceDelimitedBlock(existing, script);
                status  = updated == existing ? "already up to date" : "updated";
            }
            else if (existing.Contains(OldMarker))
            {
                // Old format (no delimiters): replace via regex
                updated = ReplaceOldBlock(existing, script);
                status  = updated != existing ? "updated from old format" : "old format -- could not replace";
            }
            else
            {
                // Fresh install: append with an LF separator
                var sep = existing.Length > 0 ? "\n" : string.Empty;
                updated = existing + sep + script;
                status  = "installed";
            }

            if (updated != existing)
            {
                // Always write UTF-8 without BOM to keep profiles clean
                File.WriteAllText(profile, updated, new UTF8Encoding(false));
                anyChanged = true;
            }

            var icon = status.StartsWith("already") ? "=" : status.StartsWith("old format --") ? "!" : status == "updated" || status == "updated from old format" ? "~" : "+";
            Console.WriteLine($"  [{icon}] {profile}");
            Console.WriteLine($"      ({status})");
        }

        Console.WriteLine();
        Console.WriteLine(anyChanged
            ? "Run `. $PROFILE` in each open PowerShell session to activate."
            : "No changes made -- all profiles are already up to date.");
    }

    // Replace the delimited certz block with newBlock; preserves surrounding content.
    private static string ReplaceDelimitedBlock(string content, string newBlock)
    {
        var beginIdx = content.IndexOf(BlockBegin, StringComparison.Ordinal);
        var endIdx   = content.IndexOf(BlockEnd,   StringComparison.Ordinal);
        if (beginIdx < 0 || endIdx < 0) return content;

        endIdx += BlockEnd.Length;
        // Consume the newline after the end marker
        if (endIdx < content.Length && content[endIdx] == '\n') endIdx++;
        else if (endIdx + 1 < content.Length && content[endIdx] == '\r' && content[endIdx + 1] == '\n') endIdx += 2;

        return content[..beginIdx] + newBlock + content[endIdx..];
    }

    // Replace the old-format certz block (no delimiters) using a regex.
    // Matches: optional Set-Alias certz line, then Register-ArgumentCompleter
    // block through the top-level closing } at column 0.
    private static string ReplaceOldBlock(string content, string newBlock)
    {
        // \n} matches a newline immediately followed by } at the start of a line.
        // The lazy .*? stops at the first such occurrence (the outer closing brace).
        const string pat = @"(?:Set-Alias\s+-Name\s+certz\b[^\n]*\n)?Register-ArgumentCompleter\s+-Native\s+-CommandName\s+@\('certz'[^\n]*\n(?:[^\n]*\n)*?\}\n*";
        var m = Regex.Match(content, pat, RegexOptions.Singleline);
        return m.Success ? content[..m.Index] + newBlock + content[(m.Index + m.Length)..] : content;
    }

    // ---------------------------------------------------------------------------
    // Profile discovery
    // ---------------------------------------------------------------------------

    private static List<string> CollectPowerShellProfiles()
    {
        var seen     = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var profiles = new List<string>();

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
                Arguments           = "-NoProfile -Command \"$PROFILE\"",
                RedirectStandardOutput = true,
                UseShellExecute     = false
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

    // ---------------------------------------------------------------------------
    // --explain
    // ---------------------------------------------------------------------------

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

        Running --install again is safe: it replaces an existing certz block
        in-place (fixing line endings or path changes) rather than appending.

        The generated script includes a Set-Alias that maps 'certz' to the
        full path of this executable, so completion works even when certz is
        not on your PATH.

        """;
}
