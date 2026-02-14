# Phase 10: Global `--guided` Wizard Mode

**Status:** Complete
**Last Updated:** 2026-02-14

## Overview

`--guided` currently exists only as a per-subcommand flag on `create dev` and `create ca`. Running `certz --guided` at the root level produces no effect — there is no global handler for it.

This phase adds a **top-level interactive wizard** that is invoked when the user runs `certz --guided` with no subcommand. The wizard presents a task-selection menu, then routes to the appropriate guided flow for every major certz capability.

The goal is that a user unfamiliar with certz can run a single command (`certz --guided`) and be walked through any operation interactively.

---

## Design Decisions

### 1. Root-Level Option + Action

`--guided` is registered as a global option on the root command in `Program.cs`. A `SetAction` on the root command is added to intercept invocations where no subcommand is provided and `--guided` is set.

**Why not a subcommand (`certz guided`)?**
The requirement in CLAUDE.md specifies `--guided` as a flag pattern, consistent with how it already appears on `create dev` and `create ca`. A flag also makes it composable (future: `certz inspect --guided`).

**System.CommandLine 2.x note:** When `SetAction` is added to the root command and a valid subcommand is also parsed, System.CommandLine gives priority to the matched subcommand's action. Root `SetAction` only fires when no subcommand is matched — which is exactly the `certz --guided` case.

### 2. Two-Tier Wizard Architecture

```
RunGlobalWizard()          ← NEW: top-level task menu
    ├─ RunDevCertificateWizard()    ← EXISTING, reused as-is
    ├─ RunCACertificateWizard()     ← EXISTING, reused as-is
    ├─ RunInspectWizard()           ← NEW
    ├─ RunLintWizard()              ← NEW
    ├─ RunTrustWizard()             ← NEW
    ├─ RunConvertWizard()           ← NEW
    ├─ RunMonitorWizard()           ← NEW
    └─ RunRenewWizard()             ← NEW
```

Each new wizard method collects inputs interactively, builds an options object, then calls the existing service layer directly. This reuses all existing business logic and avoids duplication.

### 3. "Do Another Operation?" Loop

After completing any operation, the global wizard offers to return to the task menu. This lets users chain multiple operations in a single session without re-running the binary.

### 4. Command Echo

After collecting all inputs, each wizard displays the equivalent CLI command before confirming. This teaches users the non-guided syntax and helps them build automation scripts.

Example:
```
Equivalent command:
  certz create dev api.local --san 127.0.0.1 --days 90 --trust

Create certificate with these settings? [Y/n]
```

### 5. Backward Compatibility

- `certz create dev --guided` and `certz create ca --guided` continue to work exactly as before.
- `certz --guided` is the new top-level entry point that routes to all capabilities.
- No existing options, exit codes, or service signatures change.

---

## Progress Tracker

| # | Step | Status | Notes |
|---|------|--------|-------|
| 1 | Register `--guided` on root command in `Program.cs` | [x] | |
| 2 | Add root `SetAction` to handle `certz --guided` | [x] | |
| 3 | Add `RunGlobalWizard()` to `CertificateWizard.cs` | [x] | Task-selection menu |
| 4 | Add `RunInspectWizard()` | [x] | File/URL/store source selection |
| 5 | Add `RunLintWizard()` | [x] | File/URL/store source selection |
| 6 | Add `RunTrustAddWizard()` + `RunTrustRemoveWizard()` | [x] | Separate add/remove flows |
| 7 | Add `RunConvertWizard()` | [x] | Format picker + file paths |
| 8 | Add `RunMonitorWizard()` | [x] | Path/URL input + threshold |
| 9 | Add `RunRenewWizard()` | [x] | Source detection + output options |
| 10 | Update README.md with `certz --guided` usage | [x] | |
| 11 | Write test-guided.ps1 | [ ] | Future work |

---

## Implementation Steps

### Step 1: Register `--guided` on Root Command

**File:** `src/certz/Program.cs`

Add a global `--guided` option and a `SetAction` on `rootCommand`. The action only fires when no subcommand is matched (which is the `certz --guided` invocation scenario).

```csharp
// In Program.cs, after adding formatOption

var guidedOption = OptionBuilders.CreateGuidedOption();
rootCommand.Options.Add(guidedOption);

rootCommand.SetAction(async (parseResult) =>
{
    var guided = parseResult.GetValue(guidedOption);

    if (!guided)
    {
        // No subcommand and no --guided: show help (default behavior)
        parseResult.Invoke("--help");
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
        // User cancelled — exit cleanly
    }
});
```

**Important:** System.CommandLine 2.x fires a registered subcommand's action in preference to the root action when a subcommand is matched. The root `SetAction` only runs when the user invokes `certz` (or `certz --guided`) with no subcommand specified.

---

### Step 2: Add `RunGlobalWizard()` to `CertificateWizard.cs`

This method is the entry point for `certz --guided`. It presents a Spectre.Console `SelectionPrompt` of all major operations, dispatches to the appropriate wizard method, then offers to loop.

```csharp
internal static async Task RunGlobalWizard(IOutputFormatter formatter)
{
    WriteWelcome("Certz Interactive Wizard",
        "Welcome to the certz guided mode.",
        "Answer a few questions and certz will handle the rest.",
        "Press Ctrl+C at any time to cancel.");

    while (true)
    {
        AnsiConsole.WriteLine();

        var task = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[bold green]?[/] What would you like to do?")
                .AddChoiceGroup("Create", new[]
                {
                    "Create a development certificate",
                    "Create a Certificate Authority (CA)"
                })
                .AddChoiceGroup("Inspect & Validate", new[]
                {
                    "Inspect a certificate",
                    "Lint / validate a certificate"
                })
                .AddChoiceGroup("Manage", new[]
                {
                    "Trust / untrust a certificate",
                    "Convert certificate format",
                    "Monitor certificates for expiration",
                    "Renew a certificate"
                })
                .AddChoices("Exit")
                .HighlightStyle(HighlightStyle));

        switch (task)
        {
            case "Create a development certificate":
                var devOptions = RunDevCertificateWizard();
                var devResult = await CreateService.CreateDevCertificate(devOptions);
                formatter.WriteCertificateCreated(devResult);
                break;

            case "Create a Certificate Authority (CA)":
                var caOptions = RunCACertificateWizard();
                var caResult = await CreateService.CreateCACertificate(caOptions);
                formatter.WriteCertificateCreated(caResult);
                break;

            case "Inspect a certificate":
                var inspectOptions = RunInspectWizard();
                var inspectResult = await InspectService.Inspect(inspectOptions);
                formatter.WriteCertificateInfo(inspectResult);
                break;

            case "Lint / validate a certificate":
                var lintOptions = RunLintWizard();
                LintService.Lint(lintOptions, formatter);
                break;

            case "Trust / untrust a certificate":
                await RunTrustWizard(formatter);
                break;

            case "Convert certificate format":
                var convertOptions = RunConvertWizard();
                var convertResult = await ConvertService.Convert(convertOptions);
                formatter.WriteConversionResult(convertResult);
                break;

            case "Monitor certificates for expiration":
                var monitorOptions = RunMonitorWizard();
                var monitorResults = await MonitorService.Monitor(monitorOptions);
                formatter.WriteMonitorResults(monitorResults);
                break;

            case "Renew a certificate":
                var renewOptions = RunRenewWizard();
                var renewResult = await RenewService.Renew(renewOptions);
                formatter.WriteCertificateCreated(renewResult);
                break;

            case "Exit":
                AnsiConsole.MarkupLine("[grey]Goodbye.[/]");
                return;
        }

        AnsiConsole.WriteLine();
        var doAnother = AnsiConsole.Confirm("[green]?[/] Do another operation?", defaultValue: false);
        if (!doAnother) break;
    }
}
```

---

### Step 3: Add `RunInspectWizard()`

Covers all three inspect sources: file, URL, or store.

```csharp
internal static InspectOptions RunInspectWizard()
{
    WriteWelcome("Inspect Certificate",
        "Inspect a certificate from a file, remote URL, or the Windows certificate store.");

    var source = AnsiConsole.Prompt(
        new SelectionPrompt<string>()
            .Title("[green]?[/] Certificate source:")
            .AddChoices("File", "URL (HTTPS endpoint)", "Windows Store (thumbprint)")
            .HighlightStyle(HighlightStyle));

    return source switch
    {
        "File" => BuildInspectFileOptions(),
        "URL (HTTPS endpoint)" => BuildInspectUrlOptions(),
        _ => BuildInspectStoreOptions()
    };
}

private static InspectOptions BuildInspectFileOptions()
{
    var path = AnsiConsole.Prompt(
        new TextPrompt<string>("[green]?[/] Certificate file path:")
            .Validate(p => File.Exists(p) ? ValidationResult.Success()
                                           : ValidationResult.Error("[red]File not found[/]")));

    var password = AnsiConsole.Prompt(
        new TextPrompt<string>("[green]?[/] Password (leave blank if none):")
            .AllowEmpty()
            .Secret());

    WriteEquivalentCommand($"certz inspect \"{path}\"{(string.IsNullOrEmpty(password) ? "" : " --password <hidden>")}");

    return new InspectOptions
    {
        Source = InspectSource.File,
        File = new FileInfo(path),
        Password = string.IsNullOrEmpty(password) ? null : password
    };
}

private static InspectOptions BuildInspectUrlOptions()
{
    var url = AnsiConsole.Prompt(
        new TextPrompt<string>("[green]?[/] HTTPS URL (e.g. https://example.com):")
            .Validate(u => u.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
                ? ValidationResult.Success()
                : ValidationResult.Error("[red]URL must start with https://[/]")));

    WriteEquivalentCommand($"certz inspect {url}");

    return new InspectOptions
    {
        Source = InspectSource.Url,
        Url = url
    };
}

private static InspectOptions BuildInspectStoreOptions()
{
    var thumbprint = AnsiConsole.Prompt(
        new TextPrompt<string>("[green]?[/] Certificate thumbprint (full or partial):")
            .Validate(t => !string.IsNullOrWhiteSpace(t)));

    var store = AnsiConsole.Prompt(
        new SelectionPrompt<string>()
            .Title("[green]?[/] Store to search:")
            .AddChoices("My", "Root", "CA", "TrustedPeople")
            .HighlightStyle(HighlightStyle));

    WriteEquivalentCommand($"certz inspect {thumbprint} --store {store}");

    return new InspectOptions
    {
        Source = InspectSource.Store,
        Thumbprint = thumbprint,
        StoreName = store
    };
}
```

---

### Step 4: Add `RunLintWizard()`

Lint wizard mirrors the inspect source selection since lint accepts the same input types.

```csharp
internal static LintOptions RunLintWizard()
{
    WriteWelcome("Lint Certificate",
        "Check a certificate against CA/Browser Forum and Mozilla NSS requirements.");

    var source = AnsiConsole.Prompt(
        new SelectionPrompt<string>()
            .Title("[green]?[/] Certificate source:")
            .AddChoices("File", "URL (HTTPS endpoint)", "Windows Store (thumbprint)")
            .HighlightStyle(HighlightStyle));

    // [implementation mirrors RunInspectWizard but builds LintOptions]
    // ...

    WriteEquivalentCommand($"certz lint \"{source}\"");

    return new LintOptions { /* ... */ };
}
```

---

### Step 5: Add `RunTrustWizard()`

Trust has sub-operations (add/remove/list), so this wizard presents a second-level menu.

```csharp
internal static async Task RunTrustWizard(IOutputFormatter formatter)
{
    WriteWelcome("Trust Store",
        "Add, remove, or list trusted certificates in the Windows certificate store.");

    var operation = AnsiConsole.Prompt(
        new SelectionPrompt<string>()
            .Title("[green]?[/] Trust operation:")
            .AddChoices("Add certificate to trust store",
                        "Remove certificate from trust store",
                        "List trusted certificates")
            .HighlightStyle(HighlightStyle));

    // Route to each trust sub-wizard...
}
```

---

### Step 6: Add `RunConvertWizard()`

Guides the user through picking source format, target format, and file paths.

```csharp
internal static ConvertOptions RunConvertWizard()
{
    WriteWelcome("Convert Certificate Format",
        "Convert between PEM, DER, and PFX/PKCS#12 formats.");

    var inputPath = AnsiConsole.Prompt(
        new TextPrompt<string>("[green]?[/] Input certificate file:")
            .Validate(p => File.Exists(p) ? ValidationResult.Success()
                                           : ValidationResult.Error("[red]File not found[/]")));

    // Auto-detect source format using FormatDetectionService
    var detectedFormat = FormatDetectionService.Detect(new FileInfo(inputPath));
    AnsiConsole.MarkupLine($"[grey]  Detected format: [cyan]{detectedFormat}[/][/]");

    var targetFormat = AnsiConsole.Prompt(
        new SelectionPrompt<string>()
            .Title("[green]?[/] Target format:")
            .AddChoices("PEM (.pem / .crt)", "DER (.der / .cer)", "PFX / PKCS#12 (.pfx)")
            .HighlightStyle(HighlightStyle));

    // Prompt for output path, password if needed...

    WriteEquivalentCommand($"certz convert \"{inputPath}\" --to {targetFormat}");

    return new ConvertOptions { /* ... */ };
}
```

---

### Step 7: Add `RunMonitorWizard()`

Collects paths or URLs to scan, and the warning threshold in days.

```csharp
internal static MonitorOptions RunMonitorWizard()
{
    WriteWelcome("Monitor Certificates",
        "Scan certificate files or URLs for upcoming expiration.");

    var sources = new List<string>();
    AnsiConsole.MarkupLine("[grey]  Enter file paths or HTTPS URLs to monitor. Leave blank to finish.[/]");

    while (true)
    {
        var entry = AnsiConsole.Prompt(
            new TextPrompt<string>("[green]?[/] Path or URL:")
                .AllowEmpty());
        if (string.IsNullOrWhiteSpace(entry)) break;
        sources.Add(entry);
    }

    var threshold = AnsiConsole.Prompt(
        new TextPrompt<int>("[green]?[/] Warn when expiring within (days):")
            .DefaultValue(30)
            .Validate(d => d > 0));

    WriteEquivalentCommand($"certz monitor {string.Join(" ", sources.Select(s => $"\"{s}\""))} --warn {threshold}");

    return new MonitorOptions
    {
        Sources = sources.ToArray(),
        WarnThresholdDays = threshold
    };
}
```

---

### Step 8: Add `RunRenewWizard()`

Detects existing certificate parameters and guides through extending validity.

```csharp
internal static RenewOptions RunRenewWizard()
{
    WriteWelcome("Renew Certificate",
        "Extend the validity of an existing certificate.",
        "Existing parameters (SANs, key type) are detected automatically.");

    var sourcePath = AnsiConsole.Prompt(
        new TextPrompt<string>("[green]?[/] Source certificate file (PFX/PEM):")
            .Validate(p => File.Exists(p) ? ValidationResult.Success()
                                           : ValidationResult.Error("[red]File not found[/]")));

    var password = AnsiConsole.Prompt(
        new TextPrompt<string>("[green]?[/] Password (leave blank if none):")
            .AllowEmpty()
            .Secret());

    var days = AnsiConsole.Prompt(
        new TextPrompt<int>("[green]?[/] New validity period (days):")
            .DefaultValue(90)
            .Validate(d => d >= 1 && d <= 398));

    WriteEquivalentCommand($"certz renew \"{sourcePath}\" --days {days}");

    return new RenewOptions
    {
        SourceFile = new FileInfo(sourcePath),
        Password = string.IsNullOrEmpty(password) ? null : password,
        Days = days
    };
}
```

---

### Step 9: Add `WriteEquivalentCommand()` Helper

This private helper is called by every wizard flow to show the equivalent CLI command before confirmation. Add to `CertificateWizard.cs`.

```csharp
private static void WriteEquivalentCommand(string command)
{
    AnsiConsole.WriteLine();
    AnsiConsole.Write(new Rule("[dim]Equivalent command[/]")
    {
        Justification = Justify.Left,
        Style = Style.Parse("grey dim")
    });
    AnsiConsole.MarkupLine($"  [bold cyan]{command}[/]");
    AnsiConsole.WriteLine();
}
```

---

### Step 10: Update README.md

Add a `certz --guided` entry to the **Quick Start** section and the **Command Reference** table.

**Quick Start addition:**
```bash
# Interactive wizard — guided mode for all operations
certz --guided
```

**Command Reference table addition:**
```
certz --guided    Launch interactive wizard for any operation
```

---

## Tests

### test/test-guided.ps1

Because the global wizard is fully interactive (requires console input), automated testing covers:

1. **Exit code verification** — `certz --guided` should not error on launch (non-interactive environments will fail to read stdin; test that graceful cancellation exits 0 or 130).
2. **Fallback to help** — `certz` with no args and no `--guided` should display help (exit 0).
3. **No regression on subcommands** — `certz create dev --guided` still works as before.

```powershell
# Test: certz (no args) shows help and exits 0
$result = & "$releasePath\certz.exe" 2>&1
$LASTEXITCODE | Should -Be 0

# Test: create dev --guided still works (smoke test - cancel immediately)
# NOTE: Cannot automate full wizard interaction, verify binary runs
```

> **Limitation:** Full wizard interaction cannot be automated under the test isolation principle (single certz.exe invocation, no piped stdin allowed as it breaks Spectre.Console). Document this in test/coverage-analysis.md.

---

## Verification Checklist

- [ ] `certz --guided` launches the global wizard with a task-selection menu
- [ ] Each menu option routes to the correct wizard flow
- [ ] Dev certificate wizard creates a valid certificate via the global entry point
- [ ] CA certificate wizard creates a valid CA certificate via the global entry point
- [ ] Inspect wizard prompts for source type and displays certificate details
- [ ] Lint wizard prompts for source type and runs validation
- [ ] Trust wizard presents add/remove/list sub-menu
- [ ] Convert wizard auto-detects input format
- [ ] Monitor wizard accepts multiple sources and a threshold
- [ ] Renew wizard detects existing cert parameters
- [ ] "Equivalent command" is shown before every confirmation prompt
- [ ] "Do another operation?" loop returns to main menu
- [ ] Ctrl+C at any point exits cleanly (no stack trace)
- [ ] `certz create dev --guided` and `certz create ca --guided` still work unchanged
- [ ] `certz` with no arguments still shows help (no regression)
- [ ] README updated with `certz --guided` usage

---

## Key Files Modified

| File | Change |
|------|--------|
| `src/certz/Program.cs` | Add global `--guided` option + root `SetAction` |
| `src/certz/Services/CertificateWizard.cs` | Add `RunGlobalWizard()` + 6 new wizard methods + `WriteEquivalentCommand()` |
| `README.md` | Add `certz --guided` to Quick Start and Command Reference |
| `test/test-guided.ps1` | New test script (smoke tests only due to interactive limitation) |
| `test/coverage-analysis.md` | Note interactive wizard limitation |
| `docs/README.md` | Add Phase 10 row to feature table |
