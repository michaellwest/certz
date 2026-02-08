# Phase 3: Interactive/Guided Mode

**Status:** Complete
**Last Updated:** 2026-02-07

## Overview
Implement Phase 3 of the certz v2.0 migration: add `--guided` flag for interactive wizard mode using Spectre.Console prompts. The wizard provides step-by-step certificate creation with explanations, recommendations, and smart defaults.

## Design Decisions

The following decisions apply to Phase 3 (documented in feature-plan-recommendations.md):

| Area | Decision | Rationale |
|------|----------|-----------|
| **Wizard Framework** | Spectre.Console prompts | Rich interactive UI with validation |
| **Scope** | `create ca` and `create dev` | Focus on certificate creation wizards |
| **Explanations** | Inline help at each step | Educate users about certificate options |
| **Smart Defaults** | Use-case based | Suggest appropriate values based on context |
| **Validation** | Real-time input validation | Prevent invalid entries before proceeding |
| **Summary** | Show before execution | Confirm all settings before creating cert |

## Progress Tracker

| # | Step | Status | Notes |
|---|------|--------|-------|
| 1 | Create test-guided.ps1 Test Script | [ ] | Deferred - manual testing performed |
| 2 | Add IWizardService Interface | [x] | Simplified: used static CertificateWizard class |
| 3 | Create Base Wizard Infrastructure | [x] | Implemented in Services/CertificateWizard.cs |
| 4 | Implement CreateDevWizard | [x] | RunDevCertificateWizard() with 6 steps |
| 5 | Implement CreateCaWizard | [x] | RunCACertificateWizard() with 5 steps |
| 6 | Add --guided Flag to Commands | [x] | Already existed, enhanced with cancellation handling |
| 7 | Add Wizard Result Summary Display | [x] | DisplaySummaryAndConfirm() with Spectre.Console Table |
| 8 | Update Formatters for Wizard Output | [x] | Wizard uses Spectre.Console directly |

## Implementation Notes

The implementation took a simpler approach than originally planned:
- Instead of separate wizard classes per command, used a single `CertificateWizard.cs` static class
- Wizard methods return the options directly, reusing existing `DevCertificateOptions` and `CACertificateOptions`
- Used Spectre.Console's `Rule`, `Panel`, `Table`, `SelectionPrompt`, and `TextPrompt` for beautiful UI
- Each step includes inline help text explaining the concept
- Summary table shows all settings before final confirmation

---

## Implementation Steps

### Step 1: Create test-guided.ps1 Test Script
**New file:** `test-guided.ps1`

Create a dedicated test script for the `--guided` wizard mode. Testing interactive mode requires simulating user input.

**Test Isolation Rules:**
- Each test invokes `certz.exe` exactly ONCE
- Use PowerShell process input simulation for interactive prompts
- Assert against created certificate properties, NOT console output

**Script Structure:**
```powershell
<#
.SYNOPSIS
    Test suite for certz --guided wizard mode.
.PARAMETER TestId
    Run specific tests by ID. Example: -TestId "gui-1.1", "gui-2.1"
.PARAMETER Category
    Run tests by category: guided-dev, guided-ca
.PARAMETER SkipCleanup
    Keep test files after running.
.PARAMETER Verbose
    Show detailed output.
#>
param(
    [switch]$SkipCleanup,
    [switch]$Verbose,
    [string[]]$TestId,
    [string[]]$Category
)

$ErrorActionPreference = "Stop"
$script:FailedTests = @()
$script:PassedTests = @()
$script:TestCount = 0

# Test categories
$script:TestCategories = @{
    "guided-dev" = @("gui-1.1", "gui-1.2", "gui-1.3")
    "guided-ca" = @("gui-2.1", "gui-2.2")
}
```

**Test Cases to Implement:**

| Test ID | Category | Description | certz Command |
|---------|----------|-------------|---------------|
| gui-1.1 | guided-dev | Dev cert wizard with defaults | `create dev --guided` (simulated input) |
| gui-1.2 | guided-dev | Dev cert wizard with custom domain | `create dev --guided` (input: custom.local) |
| gui-1.3 | guided-dev | Dev cert wizard with trust option | `create dev --guided` (input: enable trust) |
| gui-2.1 | guided-ca | CA cert wizard with defaults | `create ca --guided` (simulated input) |
| gui-2.2 | guided-ca | CA cert wizard with custom settings | `create ca --guided` (custom name, duration) |

**Sample Test Implementation:**
```powershell
Invoke-Test -TestId "gui-1.1" -TestName "Dev cert wizard with defaults" -FilePrefix "gui-dev" -TestScript {
    # SETUP: Prepare simulated input
    $inputLines = @(
        ""          # Accept default domain (localhost)
        ""          # Accept default duration (90 days)
        "n"         # Don't trust
        ""          # Accept default output filename
    )
    $inputText = $inputLines -join "`n"

    try {
        # ACTION: Run wizard with simulated input
        $process = Start-Process -FilePath ".\certz.exe" `
            -ArgumentList "create", "dev", "--guided" `
            -NoNewWindow -PassThru -Wait `
            -RedirectStandardInput (New-TemporaryFile | ForEach-Object {
                Set-Content $_.FullName $inputText -NoNewline
                $_.FullName
            }) `
            -RedirectStandardOutput "gui-dev-stdout.txt"

        # ASSERTION 1: Exit code
        if ($process.ExitCode -ne 0) {
            throw "Expected exit code 0, got $($process.ExitCode)"
        }

        # ASSERTION 2: Output file exists
        $outputFile = Get-ChildItem "certz-localhost*.pfx" | Select-Object -First 1
        if (-not $outputFile) {
            throw "Expected output PFX file to be created"
        }

        # ASSERTION 3: Certificate has correct properties
        $password = Get-Content "gui-dev-stdout.txt" |
            Select-String "Password: (.+)" |
            ForEach-Object { $_.Matches[0].Groups[1].Value }
        $secPassword = ConvertTo-SecureString $password -AsPlainText -Force
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            $outputFile.FullName, $secPassword)

        if ($cert.Subject -notmatch "localhost") {
            throw "Certificate subject should contain 'localhost'"
        }

        @{ Success = $true; Details = "Wizard created cert with defaults" }
    }
    finally {
        # CLEANUP
        Remove-Item "gui-dev-stdout.txt" -Force -ErrorAction SilentlyContinue
        Remove-Item "certz-localhost*.pfx" -Force -ErrorAction SilentlyContinue
    }
}
```

**Status:** [ ] Not Started

---

### Step 2: Add IWizardService Interface
**New file:** `Services/Interactive/IWizardService.cs`

Define the interface for wizard services:

```csharp
namespace certz.Services.Interactive;

public interface IWizardService<TOptions, TResult>
{
    /// <summary>
    /// Run the interactive wizard and return the configured options.
    /// </summary>
    Task<TOptions> RunWizardAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Display a summary of the configured options before execution.
    /// </summary>
    void DisplaySummary(TOptions options);

    /// <summary>
    /// Confirm the user wants to proceed with the configured options.
    /// </summary>
    bool ConfirmExecution();
}

public interface IWizardStep
{
    string Title { get; }
    string Description { get; }
    bool IsRequired { get; }
}
```

**Status:** [ ] Not Started

---

### Step 3: Create Base Wizard Infrastructure
**New file:** `Services/Interactive/WizardBase.cs`

Create base class with common wizard functionality:

```csharp
namespace certz.Services.Interactive;

public abstract class WizardBase<TOptions> where TOptions : new()
{
    protected readonly IAnsiConsole _console;

    protected WizardBase(IAnsiConsole console)
    {
        _console = console;
    }

    protected void WriteHeader(string title)
    {
        _console.Write(new Rule($"[bold blue]{title}[/]").LeftJustified());
        _console.WriteLine();
    }

    protected void WriteHelp(string helpText)
    {
        _console.MarkupLine($"[dim]{helpText}[/]");
        _console.WriteLine();
    }

    protected string PromptText(string prompt, string defaultValue = "", string? helpText = null)
    {
        if (helpText != null)
        {
            WriteHelp(helpText);
        }

        var textPrompt = new TextPrompt<string>($"[green]{prompt}[/]")
            .AllowEmpty();

        if (!string.IsNullOrEmpty(defaultValue))
        {
            textPrompt.DefaultValue(defaultValue);
        }

        return _console.Prompt(textPrompt);
    }

    protected T PromptSelection<T>(string prompt, IEnumerable<T> choices, string? helpText = null) where T : notnull
    {
        if (helpText != null)
        {
            WriteHelp(helpText);
        }

        return _console.Prompt(
            new SelectionPrompt<T>()
                .Title($"[green]{prompt}[/]")
                .AddChoices(choices));
    }

    protected bool PromptConfirm(string prompt, bool defaultValue = false)
    {
        return _console.Confirm(prompt, defaultValue);
    }

    protected int PromptNumber(string prompt, int defaultValue, int min, int max, string? helpText = null)
    {
        if (helpText != null)
        {
            WriteHelp(helpText);
        }

        return _console.Prompt(
            new TextPrompt<int>($"[green]{prompt}[/]")
                .DefaultValue(defaultValue)
                .Validate(n => n >= min && n <= max
                    ? ValidationResult.Success()
                    : ValidationResult.Error($"[red]Value must be between {min} and {max}[/]")));
    }

    protected void DisplaySummaryTable(Dictionary<string, string> values)
    {
        var table = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("[bold]Setting[/]")
            .AddColumn("[bold]Value[/]");

        foreach (var (key, value) in values)
        {
            table.AddRow(key, $"[cyan]{value}[/]");
        }

        _console.Write(table);
        _console.WriteLine();
    }
}
```

**Status:** [ ] Not Started

---

### Step 4: Implement CreateDevWizard
**New file:** `Services/Interactive/CreateDevWizard.cs`

Implement the development certificate wizard:

```csharp
namespace certz.Services.Interactive;

public class CreateDevWizard : WizardBase<CreateDevOptions>, IWizardService<CreateDevOptions, CertificateResult>
{
    public CreateDevWizard(IAnsiConsole console) : base(console) { }

    public async Task<CreateDevOptions> RunWizardAsync(CancellationToken cancellationToken = default)
    {
        var options = new CreateDevOptions();

        // Welcome
        _console.Write(new FigletText("certz").Color(Color.Blue));
        _console.MarkupLine("[bold]Development Certificate Wizard[/]");
        _console.MarkupLine("[dim]This wizard will guide you through creating a development certificate.[/]");
        _console.WriteLine();

        // Step 1: Domain
        WriteHeader("Step 1: Domain Name");
        options.Domain = PromptText(
            "Primary domain name",
            "localhost",
            "The main domain for your certificate. For local development, 'localhost' is recommended.\n" +
            "You can also use a custom domain like 'myapp.local' or 'api.dev'.");

        // Step 2: Additional SANs
        WriteHeader("Step 2: Subject Alternative Names (SANs)");
        _console.MarkupLine("[dim]SANs allow your certificate to be valid for multiple domains.[/]");
        _console.MarkupLine("[dim]Common additions: 127.0.0.1, ::1, *.localhost[/]");
        _console.WriteLine();

        var addSans = PromptConfirm("Add additional SANs beyond the primary domain?", false);
        if (addSans)
        {
            while (true)
            {
                var san = PromptText("Additional SAN (leave empty to finish)", "");
                if (string.IsNullOrEmpty(san)) break;
                options.SubjectAlternativeNames.Add(san);
            }
        }

        // Step 3: Validity
        WriteHeader("Step 3: Certificate Validity");
        options.Days = PromptNumber(
            "Validity period (days)",
            90, 1, 398,
            "How long the certificate should be valid.\n" +
            "Recommended: 90 days for development (aligns with Let's Encrypt).\n" +
            "Maximum: 398 days (CA/Browser Forum limit).");

        // Step 4: Key Type
        WriteHeader("Step 4: Key Algorithm");
        var keyTypeChoice = PromptSelection(
            "Select key algorithm",
            new[] { "ECDSA P-256 (Recommended)", "ECDSA P-384", "RSA 3072", "RSA 4096" },
            "ECDSA is modern, fast, and optimized for TLS 1.3.\n" +
            "RSA has wider compatibility with older systems.");

        options.KeyType = keyTypeChoice switch
        {
            "ECDSA P-256 (Recommended)" => "ECDSA-P256",
            "ECDSA P-384" => "ECDSA-P384",
            "RSA 3072" => "RSA",
            "RSA 4096" => "RSA",
            _ => "ECDSA-P256"
        };

        if (keyTypeChoice == "RSA 4096")
        {
            options.KeySize = 4096;
        }

        // Step 5: Trust Store
        WriteHeader("Step 5: Trust Store Installation");
        options.Trust = PromptConfirm(
            "Install certificate to system trust store?",
            false);

        if (options.Trust)
        {
            _console.MarkupLine("[yellow]Note: The certificate will be added to your Trusted Root store.[/]");
            _console.MarkupLine("[yellow]You may see a Windows security prompt.[/]");
        }

        // Step 6: Output
        WriteHeader("Step 6: Output Files");
        var defaultFilename = $"certz-{options.Domain.Replace("*.", "wildcard-")}.pfx";
        options.OutputFile = PromptText(
            "Output filename",
            defaultFilename,
            "The PFX file will contain both the certificate and private key.");

        var exportSeparate = PromptConfirm("Also export separate .cer and .key files?", false);
        if (exportSeparate)
        {
            options.CertFile = Path.ChangeExtension(options.OutputFile, ".cer");
            options.KeyFile = Path.ChangeExtension(options.OutputFile, ".key");
        }

        return options;
    }

    public void DisplaySummary(CreateDevOptions options)
    {
        WriteHeader("Summary");

        var summary = new Dictionary<string, string>
        {
            ["Domain"] = options.Domain,
            ["SANs"] = options.SubjectAlternativeNames.Count > 0
                ? string.Join(", ", options.SubjectAlternativeNames)
                : "(auto: localhost, 127.0.0.1)",
            ["Validity"] = $"{options.Days} days",
            ["Key Type"] = options.KeyType,
            ["Trust Store"] = options.Trust ? "Yes (Trusted Root)" : "No",
            ["Output File"] = options.OutputFile
        };

        if (options.CertFile != null)
        {
            summary["Certificate File"] = options.CertFile;
            summary["Key File"] = options.KeyFile!;
        }

        DisplaySummaryTable(summary);
    }

    public bool ConfirmExecution()
    {
        return PromptConfirm("[bold]Create certificate with these settings?[/]", true);
    }
}
```

**Status:** [ ] Not Started

---

### Step 5: Implement CreateCaWizard
**New file:** `Services/Interactive/CreateCaWizard.cs`

Implement the CA certificate wizard:

```csharp
namespace certz.Services.Interactive;

public class CreateCaWizard : WizardBase<CreateCaOptions>, IWizardService<CreateCaOptions, CertificateResult>
{
    public CreateCaWizard(IAnsiConsole console) : base(console) { }

    public async Task<CreateCaOptions> RunWizardAsync(CancellationToken cancellationToken = default)
    {
        var options = new CreateCaOptions();

        // Welcome
        _console.Write(new FigletText("certz").Color(Color.Blue));
        _console.MarkupLine("[bold]Certificate Authority Wizard[/]");
        _console.MarkupLine("[dim]This wizard will guide you through creating a Certificate Authority.[/]");
        _console.WriteLine();

        // Step 1: CA Type
        WriteHeader("Step 1: CA Type");
        var caType = PromptSelection(
            "What type of CA are you creating?",
            new[] { "Root CA (Self-signed)", "Intermediate CA (Signed by another CA)" },
            "A Root CA is the top of your certificate chain and signs itself.\n" +
            "An Intermediate CA is signed by a Root CA and issues end-entity certificates.");

        options.IsRoot = caType == "Root CA (Self-signed)";

        if (!options.IsRoot)
        {
            WriteHeader("Issuing CA Certificate");
            options.IssuerFile = PromptText(
                "Path to issuing CA certificate (PFX)",
                "",
                "The PFX file of the CA that will sign this intermediate CA.");
            options.IssuerPassword = PromptText("Issuing CA password", "");
        }

        // Step 2: CA Name
        WriteHeader("Step 2: CA Identity");
        options.Name = PromptText(
            "CA Common Name",
            options.IsRoot ? "Development Root CA" : "Development Intermediate CA",
            "A descriptive name for your CA. This appears in certificate details.");

        // Optional: Organization details
        var addOrgDetails = PromptConfirm("Add organization details?", false);
        if (addOrgDetails)
        {
            options.Organization = PromptText("Organization (O)", "");
            options.OrganizationalUnit = PromptText("Organizational Unit (OU)", "");
            options.Country = PromptText("Country (2-letter code)", "");
        }

        // Step 3: Validity
        WriteHeader("Step 3: Certificate Validity");
        var defaultYears = options.IsRoot ? 10 : 5;
        var maxYears = options.IsRoot ? 20 : 10;

        options.Years = PromptNumber(
            "Validity period (years)",
            defaultYears, 1, maxYears,
            $"How long the CA certificate should be valid.\n" +
            $"Recommended: {defaultYears} years for {(options.IsRoot ? "Root" : "Intermediate")} CA.\n" +
            $"Note: Certificates issued by this CA cannot exceed its validity period.");

        // Step 4: Path Length
        WriteHeader("Step 4: Path Length Constraint");
        options.PathLength = PromptNumber(
            "Maximum chain depth (path length)",
            options.IsRoot ? 2 : 0,
            0, 5,
            "How many levels of CAs can exist below this one.\n" +
            "0 = Can only issue end-entity certificates (leaf CA)\n" +
            "1 = Can issue one level of intermediate CAs\n" +
            "2+ = Can create deeper CA hierarchies");

        // Step 5: Key Type
        WriteHeader("Step 5: Key Algorithm");
        var keyTypeChoice = PromptSelection(
            "Select key algorithm",
            new[] { "ECDSA P-384 (Recommended for CA)", "ECDSA P-521", "RSA 4096" },
            "For CA certificates, stronger keys are recommended.\n" +
            "ECDSA P-384 provides excellent security with good performance.");

        options.KeyType = keyTypeChoice switch
        {
            "ECDSA P-384 (Recommended for CA)" => "ECDSA-P384",
            "ECDSA P-521" => "ECDSA-P521",
            "RSA 4096" => "RSA",
            _ => "ECDSA-P384"
        };

        if (keyTypeChoice == "RSA 4096")
        {
            options.KeySize = 4096;
        }

        // Step 6: Trust Store
        WriteHeader("Step 6: Trust Store Installation");
        options.Trust = PromptConfirm(
            "Install CA certificate to system trust store?",
            true);

        if (options.Trust)
        {
            _console.MarkupLine("[yellow]Note: The CA will be added to Trusted Root Certification Authorities.[/]");
            _console.MarkupLine("[yellow]Certificates signed by this CA will be trusted by your system.[/]");
        }

        // Step 7: Output
        WriteHeader("Step 7: Output Files");
        var defaultFilename = $"certz-ca-{options.Name.ToLower().Replace(" ", "-")}.pfx";
        options.OutputFile = PromptText("Output filename", defaultFilename);

        return options;
    }

    public void DisplaySummary(CreateCaOptions options)
    {
        WriteHeader("Summary");

        var summary = new Dictionary<string, string>
        {
            ["CA Type"] = options.IsRoot ? "Root CA (Self-signed)" : "Intermediate CA",
            ["Common Name"] = options.Name,
            ["Validity"] = $"{options.Years} years",
            ["Path Length"] = options.PathLength.ToString(),
            ["Key Type"] = options.KeyType,
            ["Trust Store"] = options.Trust ? "Yes (Trusted Root)" : "No",
            ["Output File"] = options.OutputFile
        };

        if (!string.IsNullOrEmpty(options.Organization))
        {
            summary["Organization"] = options.Organization;
        }

        if (!options.IsRoot)
        {
            summary["Issuer"] = options.IssuerFile!;
        }

        DisplaySummaryTable(summary);
    }

    public bool ConfirmExecution()
    {
        return PromptConfirm("[bold]Create CA certificate with these settings?[/]", true);
    }
}
```

**Status:** [ ] Not Started

---

### Step 6: Add --guided Flag to Commands
**Modify:** `Commands/Create/CreateDevCommand.cs`, `Commands/Create/CreateCaCommand.cs`

Add the `--guided` option and integrate with wizards:

```csharp
// In CreateDevCommand.cs
var guidedOption = new Option<bool>("--guided", "Run interactive wizard mode");

command.SetHandler(async (context) =>
{
    var guided = context.ParseResult.GetValueForOption(guidedOption);

    if (guided)
    {
        var wizard = new CreateDevWizard(AnsiConsole.Console);
        var options = await wizard.RunWizardAsync(context.GetCancellationToken());
        wizard.DisplaySummary(options);

        if (!wizard.ConfirmExecution())
        {
            AnsiConsole.MarkupLine("[yellow]Operation cancelled.[/]");
            context.ExitCode = 1;
            return;
        }

        // Execute with wizard-collected options
        // ... existing creation logic using options ...
    }
    else
    {
        // ... existing non-guided logic ...
    }
});
```

**Status:** [ ] Not Started

---

### Step 7: Add Wizard Result Summary Display
**New file:** `Services/Interactive/WizardSummary.cs`

Create a service for displaying wizard results:

```csharp
namespace certz.Services.Interactive;

public class WizardSummary
{
    private readonly IAnsiConsole _console;

    public WizardSummary(IAnsiConsole console)
    {
        _console = console;
    }

    public void DisplaySuccess(CertificateResult result)
    {
        _console.WriteLine();
        _console.Write(new Rule("[green]Certificate Created Successfully[/]").LeftJustified());
        _console.WriteLine();

        var panel = new Panel(new Markup(
            $"[bold]Subject:[/] {result.Subject}\n" +
            $"[bold]Thumbprint:[/] [cyan]{result.Thumbprint}[/]\n" +
            $"[bold]Valid Until:[/] {result.NotAfter:yyyy-MM-dd}\n" +
            $"[bold]Output File:[/] {result.OutputFile}"))
        {
            Border = BoxBorder.Rounded,
            Padding = new Padding(1)
        };

        _console.Write(panel);

        if (!string.IsNullOrEmpty(result.GeneratedPassword))
        {
            _console.WriteLine();
            _console.MarkupLine("[yellow]Generated Password (save this securely):[/]");
            _console.MarkupLine($"[bold cyan]{result.GeneratedPassword}[/]");
            _console.MarkupLine("[dim]This password will not be shown again.[/]");
        }
    }

    public void DisplayError(string message)
    {
        _console.WriteLine();
        _console.MarkupLine($"[red]Error:[/] {message}");
    }
}
```

**Status:** [ ] Not Started

---

### Step 8: Update Formatters for Wizard Output
**Modify:** `Formatters/TextFormatter.cs`

Add wizard-specific output methods:

```csharp
// TextFormatter.cs additions
public void WriteWizardHeader(string title)
{
    _console.Write(new Rule($"[bold blue]{title}[/]").LeftJustified());
    _console.WriteLine();
}

public void WriteWizardStep(int stepNumber, int totalSteps, string title)
{
    _console.MarkupLine($"[dim]Step {stepNumber} of {totalSteps}[/]");
    _console.MarkupLine($"[bold]{title}[/]");
    _console.WriteLine();
}

public void WriteWizardHelp(string helpText)
{
    var panel = new Panel(new Markup($"[dim]{helpText}[/]"))
    {
        Border = BoxBorder.None,
        Padding = new Padding(2, 0, 0, 0)
    };
    _console.Write(panel);
}
```

**Status:** [ ] Not Started

---

## New Command Specifications

### `certz create dev --guided`
```
certz create dev --guided

Interactive wizard that prompts for:
1. Primary domain name (default: localhost)
2. Additional Subject Alternative Names
3. Validity period (1-398 days, default: 90)
4. Key algorithm (ECDSA P-256 recommended)
5. Trust store installation (yes/no)
6. Output filename

Wizard features:
- Inline help explaining each option
- Smart defaults based on use case
- Real-time input validation
- Summary display before execution
- Confirmation prompt
```

### `certz create ca --guided`
```
certz create ca --guided

Interactive wizard that prompts for:
1. CA type (Root or Intermediate)
2. Issuing CA certificate (for Intermediate)
3. CA Common Name
4. Organization details (optional)
5. Validity period (1-20 years)
6. Path length constraint
7. Key algorithm (ECDSA P-384 recommended for CA)
8. Trust store installation
9. Output filename

Wizard features:
- Explanations of CA concepts
- Recommendations for secure settings
- Validation of issuer certificate
- Summary display before execution
```

---

## Critical Files Reference

| File | Action |
|------|--------|
| `test-guided.ps1` | New file - test script for guided mode |
| `Services/Interactive/IWizardService.cs` | New file - wizard interface |
| `Services/Interactive/WizardBase.cs` | New file - base wizard class |
| `Services/Interactive/CreateDevWizard.cs` | New file - dev cert wizard |
| `Services/Interactive/CreateCaWizard.cs` | New file - CA cert wizard |
| `Services/Interactive/WizardSummary.cs` | New file - result display |
| `Commands/Create/CreateDevCommand.cs` | Modify - add --guided flag |
| `Commands/Create/CreateCaCommand.cs` | Modify - add --guided flag |
| `Formatters/TextFormatter.cs` | Modify - add wizard output methods |

---

## Verification Checklist

- [ ] `.\test-guided.ps1` runs and all tests pass
- [ ] `dotnet build` succeeds
- [ ] `certz create dev --guided` launches interactive wizard
- [ ] Wizard displays inline help at each step
- [ ] Wizard validates input in real-time
- [ ] Wizard shows summary before execution
- [ ] Wizard prompts for confirmation
- [ ] `certz create dev --guided` creates valid certificate
- [ ] `certz create ca --guided` launches CA wizard
- [ ] CA wizard handles Root vs Intermediate selection
- [ ] CA wizard validates issuer certificate for Intermediate
- [ ] `certz create ca --guided` creates valid CA certificate
- [ ] Generated password is displayed securely
- [ ] Trust store installation works from wizard
- [ ] Wizard can be cancelled at any step

---

## Notes & Adjustments

*Record any changes to the plan during implementation:*

1. _(none yet)_
