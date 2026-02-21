# Phase 13: Shell Tab Completion

## Overview

Add tab completion support for certz in PowerShell (Windows-first; Bash/Zsh in a follow-up
issue). Completion covers subcommands, option names, and option values for all parameters
with a fixed or predictable value set.

Delivery: a new `certz completion <shell>` command outputs a ready-to-use registration
script that the user pipes into their shell profile. Internally, completion values are
registered via `CompletionDelegate` on each option in `OptionBuilders.cs`, so the
System.CommandLine `[complete]` directive serves them dynamically.

A typo-correction pass ("Did you mean?") is included in the same issue: when System.CommandLine
reports an unrecognized option at parse time, a Levenshtein-distance check against all known
option names prints a suggestion to stderr.

---

## Design Decisions

### System.CommandLine [complete] directive

System.CommandLine 2.x includes a built-in `[complete]` directive:

```
certz [complete] --position <cursorPos> "<entire command line>"
```

The shell calls this and receives one completion item per line on stdout. No custom
completion engine is needed. Only two things are required:

1. Register `CompletionDelegate` (or `CompletionSource.List`) on each option that
   has predictable values.
2. Emit a shell-specific registration script via `certz completion powershell`.

Subcommand name completion (`certz <TAB>` -> create inspect lint ...) is handled
automatically by System.CommandLine without any extra code.

### CompletionDelegate placement

All completion additions go in `OptionBuilders.cs`, adjacent to each option factory.
This keeps completion logic co-located with validation logic for each option and avoids
a separate service class.

Pattern for fixed-value options:

```csharp
option.CompletionSources.Add(CompletionSource.List("value1", "value2", "value3"));
```

Pattern for context-aware options:

```csharp
keySizeOption.CompletionSources.Add(ctx =>
{
    // Only suggest key sizes when --key-type RSA has already been typed
    var keyType = ctx.ParseResult?.CommandResult.Children
        .OfType<OptionResult>()
        .FirstOrDefault(r => r.Option.Name == "key-type")
        ?.GetValueOrDefault<string>()
        ?.ToUpperInvariant();

    return keyType == "RSA"
        ? CompletionSource.List("2048", "3072", "4096").GetCompletions(ctx)
        : Enumerable.Empty<CompletionItem>();
});
```

### File path options

`Option<FileInfo?>` receives an empty `CompletionDelegate`, signaling the shell to fall
back to its native file completion. The PowerShell registration script post-filters results
to common certificate extensions: `.pem`, `.pfx`, `.crt`, `.cer`, `.key`, `.p12`.

### No completion for free-form options

The following options accept values that cannot be predicted:

- `--san` (hostnames / IP addresses)
- `--thumbprint` (live store query -- too slow, may require elevation)
- `--cn`, `--name`, `--url`, `--password`
- `--crl-url`, `--ocsp-url`, `--ca-issuers-url`
- `--subject-o`, `--subject-ou`, `--subject-st`, `--subject-l`

### Typo correction

Before calling `InvokeAsync`, inspect `ParseResult.Errors` for unrecognized-token errors.
A `LevenshteinDistance(string a, string b)` helper (implemented as a static function in
`Program.cs`) searches all registered option names with a max edit distance of 3 and
prints `  Did you mean '--option-name'?` to stderr when a close match is found.

---

## Implementation Steps

### Step 1 -- Add CompletionDelegate to OptionBuilders.cs

**Fixed-value options (always suggest):**

| Option | Completion values |
|--------|------------------|
| `--key-type` / `--kt` | RSA, ECDSA-P256, ECDSA-P384, ECDSA-P521 |
| `--hash-algorithm` / `--hash` | auto, SHA256, SHA384, SHA512 |
| `--pfx-encryption` / `--pe` | modern, legacy |
| `--format` / `--fmt` | text, json |
| `--pipe-format` | pem, pfx, cert, key |
| `--storename` / `--sn` | My, Root, CA, TrustedPeople, TrustedPublisher, AuthRoot, AddressBook, Disallowed |
| `--storelocation` / `--sl` | LocalMachine, CurrentUser |
| `--trust-location` / `--tl` | LocalMachine, CurrentUser |
| `--eku` | ServerAuth, ClientAuth, CodeSigning, EmailProtection, TimeStamping, OCSPSigning |
| `--days` | 30, 90, 180, 365, 398 |
| `--subject-c` / `--c` | Full ISO 3166-1 alpha-2 list (AD, AE, AF, AG, ... ZW) |

**Context-aware options (inspect ParseResult before suggesting):**

| Option | Condition | Values |
|--------|-----------|--------|
| `--key-size` / `--ks` | `--key-type RSA` already typed | 2048, 3072, 4096 |
| `--rsa-padding` / `--rp` | `--key-type RSA` already typed | pkcs1, pss |

**File options (empty delegate -- shell falls back to native file completion):**

`--file`, `--out-cert`, `--out-key`, `--issuer-cert`, `--issuer-key`,
`--password-file`, `--password-map`

### Step 2 -- Create src/certz/Commands/CompletionCommand.cs

```csharp
namespace certz.Commands;

internal static class CompletionCommandExtensions
{
    internal static void AddCompletionCommand(this RootCommand rootCommand)
    {
        var shellArgument = new Argument<string>("shell", "Shell type: powershell")
        {
            DefaultValueFactory = _ => "powershell"
        };
        shellArgument.CompletionSources.Add(CompletionSource.List("powershell"));

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

    private const string PowerShellScript = """
        Register-ArgumentCompleter -Native -CommandName certz -ScriptBlock {
            param($wordToComplete, $commandAst, $cursorPosition)
            $completions = & certz '[complete]' --position $cursorPosition "$commandAst" 2>$null
            $certExts = @('.pem', '.pfx', '.crt', '.cer', '.key', '.p12')
            $completions | Where-Object { $_ } | ForEach-Object {
                $isFile = $certExts | Where-Object { $_ -like "*$_" }
                if ($isFile -or -not ($_ -match '^\S+\.\S+$')) {
                    [System.Management.Automation.CompletionResult]::new(
                        $_, $_, 'ParameterValue', $_)
                }
            }
        }
        """;

    private const string PowerShellInstructions = """
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
```

### Step 3 -- Register command in Program.cs

Add after the other `AddXxxCommand()` calls:

```csharp
rootCommand.AddCompletionCommand();
```

### Step 4 -- Add typo correction in Program.cs

Replace the current `rootCommand.Parse(args).InvokeAsync(configuration)` call with:

```csharp
var parseResult = rootCommand.Parse(args);

// Typo correction: suggest nearest known option name on unrecognized-token errors
foreach (var error in parseResult.Errors)
{
    if (error.Token?.Type == TokenType.Option)
    {
        var badOption = error.Token.Value;
        var allOptions = CollectOptionNames(rootCommand);
        var suggestion = allOptions
            .Where(o => o != badOption)
            .Select(o => (name: o, dist: LevenshteinDistance(badOption, o)))
            .Where(x => x.dist <= 3)
            .OrderBy(x => x.dist)
            .Select(x => x.name)
            .FirstOrDefault();

        if (suggestion is not null)
            Console.Error.WriteLine($"  Did you mean '{suggestion}'?");
    }
}

return await parseResult.InvokeAsync(configuration);
```

Add helpers in the top-level file (or a `CompletionHelpers.cs`):

```csharp
static IEnumerable<string> CollectOptionNames(Command cmd)
{
    foreach (var opt in cmd.Options)
        foreach (var alias in opt.Aliases)
            yield return alias;
    foreach (var sub in cmd.Subcommands)
        foreach (var name in CollectOptionNames(sub))
            yield return name;
}

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
```

### Step 5 -- Create docs/guides/completion.md

User-facing install guide with shell-by-shell instructions and troubleshooting notes.

### Step 6 -- Update README.md

Add a "Shell Completion" section under the Installation heading with one-liner install
commands for each supported shell.

### Step 7 -- Create test/test-completion.ps1

End-to-end tests (see Tests section below).

---

## Tests

Each test calls certz exactly once (single-call principle from `test/isolation-plan.md`).

```powershell
# test/test-completion.ps1

Describe "certz completion command" {
    It "outputs a non-empty PowerShell registration script" {
        $result = & certz completion powershell
        $result | Should -Match 'Register-ArgumentCompleter'
        $result | Should -Match 'certz'
    }

    It "--explain outputs installation instructions, not the script" {
        $result = & certz completion powershell --explain
        $result | Should -Match 'PROFILE'
        $result | Should -Not -Match 'Register-ArgumentCompleter'
    }

    It "unknown shell throws with exit code 1" {
        & certz completion fish
        $LASTEXITCODE | Should -Be 1
    }
}

Describe "certz [complete] value completions" {
    It "--key-type returns all four key types" {
        $result = & certz '[complete]' --position 30 "certz create dev --key-type "
        $result | Should -Contain "RSA"
        $result | Should -Contain "ECDSA-P256"
        $result | Should -Contain "ECDSA-P384"
        $result | Should -Contain "ECDSA-P521"
    }

    It "--eku returns known OID labels" {
        $result = & certz '[complete]' --position 28 "certz create dev --eku "
        $result | Should -Contain "ServerAuth"
        $result | Should -Contain "ClientAuth"
        $result | Should -Contain "CodeSigning"
        $result | Should -Contain "EmailProtection"
    }

    It "--days returns common preset values" {
        $result = & certz '[complete]' --position 27 "certz create dev --days "
        $result | Should -Contain "30"
        $result | Should -Contain "90"
        $result | Should -Contain "398"
    }

    It "--format returns text and json" {
        $result = & certz '[complete]' --position 16 "certz --format "
        $result | Should -Contain "text"
        $result | Should -Contain "json"
    }

    It "--pipe-format returns all pipe format values" {
        $result = & certz '[complete]' --position 37 "certz create dev --pipe --pipe-format "
        $result | Should -Contain "pem"
        $result | Should -Contain "pfx"
        $result | Should -Contain "cert"
        $result | Should -Contain "key"
    }

    It "--storename returns .NET StoreName enum values" {
        $result = & certz '[complete]' --position 37 "certz store list --storename "
        $result | Should -Contain "My"
        $result | Should -Contain "Root"
        $result | Should -Contain "CA"
    }

    It "--storelocation returns LocalMachine and CurrentUser" {
        $result = & certz '[complete]' --position 41 "certz store list --storelocation "
        $result | Should -Contain "LocalMachine"
        $result | Should -Contain "CurrentUser"
    }

    It "--subject-c returns ISO 3166-1 country codes" {
        $result = & certz '[complete]' --position 35 "certz create dev --subject-c "
        $result | Should -Contain "US"
        $result | Should -Contain "GB"
        $result | Should -Contain "DE"
    }

    It "--hash-algorithm returns all hash options including auto" {
        $result = & certz '[complete]' --position 40 "certz create dev --hash-algorithm "
        $result | Should -Contain "auto"
        $result | Should -Contain "SHA256"
        $result | Should -Contain "SHA512"
    }
}

Describe "context-aware completions" {
    It "--key-size completes when --key-type RSA is typed" {
        $result = & certz '[complete]' --position 50 "certz create dev --key-type RSA --key-size "
        $result | Should -Contain "2048"
        $result | Should -Contain "3072"
        $result | Should -Contain "4096"
    }

    It "--key-size returns nothing when --key-type is ECDSA" {
        $result = & certz '[complete]' --position 57 "certz create dev --key-type ECDSA-P256 --key-size "
        $result | Should -BeNullOrEmpty
    }

    It "--rsa-padding completes when --key-type RSA is typed" {
        $result = & certz '[complete]' --position 52 "certz create dev --key-type RSA --rsa-padding "
        $result | Should -Contain "pkcs1"
        $result | Should -Contain "pss"
    }
}

Describe "typo correction" {
    It "suggests nearest option when a close typo is provided" {
        $result = & certz create dev --cn test.local --key-tpe RSA 2>&1
        "$result" | Should -Match "Did you mean"
    }

    It "does not suggest when the typo is too far from any option" {
        $result = & certz create dev --cn test.local --zzzzzzz 2>&1
        "$result" | Should -Not -Match "Did you mean"
    }
}
```

---

## Verification Checklist

- [ ] `certz completion powershell` outputs a valid `Register-ArgumentCompleter` block
- [ ] `certz completion powershell --explain` outputs install instructions (no script code)
- [ ] After sourcing the script in PowerShell, `--key-type <TAB>` cycles through all four key types
- [ ] `--eku <TAB>` shows ServerAuth, ClientAuth, CodeSigning, EmailProtection, TimeStamping, OCSPSigning
- [ ] `--days <TAB>` shows 30, 90, 180, 365, 398
- [ ] `--hash-algorithm <TAB>` shows auto, SHA256, SHA384, SHA512
- [ ] `--pfx-encryption <TAB>` shows modern, legacy
- [ ] `--format <TAB>` shows text, json
- [ ] `--pipe-format <TAB>` shows pem, pfx, cert, key
- [ ] `--storename <TAB>` shows all StoreName enum values
- [ ] `--storelocation <TAB>` and `--trust-location <TAB>` show LocalMachine, CurrentUser
- [ ] `--subject-c <TAB>` shows ISO 3166-1 alpha-2 country codes
- [ ] `--key-size <TAB>` shows 2048/3072/4096 only when `--key-type RSA` is already typed
- [ ] `--key-size <TAB>` shows nothing when `--key-type ECDSA-P256` is already typed
- [ ] `--rsa-padding <TAB>` shows pkcs1/pss only when `--key-type RSA` is already typed
- [ ] File options (`--file`, `--out-cert`, etc.) complete to .pem/.pfx/.crt/.cer/.key/.p12 files
- [ ] Mistyped option (e.g. `--key-tpe`) triggers `Did you mean '--key-type'?` on stderr
- [ ] Distant/unrecognized typo does NOT produce a false "Did you mean?" suggestion
- [ ] All `test/test-completion.ps1` tests pass
- [ ] Single-file exe builds successfully after all changes (`.\build-release.ps1`)
- [ ] `README.md` has a Shell Completion section with PowerShell one-liner install command
- [ ] `docs/guides/completion.md` exists with full per-shell installation guide

---

## Out of Scope (follow-up issue)

- Bash completion (requires cross-platform certz binary -- certz.csproj is currently win-x64)
- Zsh completion (same dependency)
- Fish completion
- `--thumbprint` completion from live Windows certificate store (performance + elevation concerns)
- `--san` completion (free-form hostnames/IPs; unpredictable)
