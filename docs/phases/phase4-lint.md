# Phase 4: Lint & Validation Commands

**Status:** Complete
**Started:** 2026-02-08
**Completed:** 2026-02-08

## Overview

Implement Phase 4 of the certz v2.0 roadmap: add `lint` command for certificate validation against industry standards (CA/B Forum Baseline Requirements, Mozilla NSS Policy). This phase also prepares for future `renew` and chain visualization features.

## Design Decisions

| Area                  | Decision                                | Rationale                             |
| --------------------- | --------------------------------------- | ------------------------------------- |
| **Command Structure** | `certz lint <source>`                   | Consistent with `inspect` pattern     |
| **Policy Sets**       | CA/B Forum BR + Mozilla NSS             | Industry-standard requirements        |
| **Output**            | Structured results with severity levels | Actionable feedback for users         |
| **Formatters**        | Text + JSON output                      | CI/CD integration support             |
| **Service Pattern**   | `LintService.cs` with `LintResult`      | Consistent with existing architecture |

## Progress Tracker

| #   | Step                         | Status | Notes                                  |
| --- | ---------------------------- | ------ | -------------------------------------- |
| 1   | Create LintResult model      | [x]    | src/certz/Models/LintResult.cs         |
| 2   | Create LintService.cs        | [x]    | src/certz/Services/LintService.cs      |
| 3   | Implement CA/B Forum checks  | [x]    | In LintService.cs                      |
| 4   | Implement Mozilla NSS checks | [x]    | In LintService.cs                      |
| 5   | Add LintCommand.cs           | [x]    | src/certz/Commands/Lint/LintCommand.cs |
| 6   | Add formatter methods        | [x]    | WriteLintResult in formatters          |
| 7   | Create test-lint.ps1         | [x]    | test/test-lint.ps1                     |
| 8   | Update documentation         | [x]    | README.md, TESTING.md                  |

---

## Lint Rules Reference

### CA/B Forum Baseline Requirements (v2.0.x)

These are mandatory requirements for publicly-trusted TLS certificates:

| Rule ID  | Category   | Description                                       | Severity |
| -------- | ---------- | ------------------------------------------------- | -------- |
| `BR-001` | Validity   | Maximum validity 398 days for leaf certs          | Error    |
| `BR-002` | Validity   | CA certs may have longer validity                 | Info     |
| `BR-003` | Key Size   | RSA minimum 2048 bits                             | Error    |
| `BR-004` | Key Size   | ECDSA minimum P-256                               | Error    |
| `BR-005` | Signature  | SHA-1 prohibited for new certs                    | Error    |
| `BR-006` | Signature  | SHA-256 or stronger required                      | Error    |
| `BR-007` | SAN        | Subject Alternative Name required                 | Error    |
| `BR-008` | SAN        | CN must be in SAN if present                      | Warning  |
| `BR-009` | Extensions | Basic Constraints required for CA                 | Error    |
| `BR-010` | Extensions | Key Usage required                                | Warning  |
| `BR-011` | Extensions | Extended Key Usage recommended                    | Info     |
| `BR-012` | Extensions | Authority Key Identifier required (non-root)      | Warning  |
| `BR-013` | Extensions | Subject Key Identifier recommended                | Info     |
| `BR-014` | Extensions | CRL Distribution Points or OCSP required (public) | Warning  |
| `BR-015` | Subject    | Country code must be 2 letters if present         | Error    |
| `BR-016` | Subject    | Organization requires Country                     | Error    |
| `BR-017` | Wildcards  | Wildcard only in leftmost label                   | Error    |
| `BR-018` | Wildcards  | No wildcards in public suffix                     | Error    |

### Mozilla NSS Policy (v2.8.x)

Additional requirements for Firefox/Thunderbird trust:

| Rule ID   | Category   | Description                                    | Severity |
| --------- | ---------- | ---------------------------------------------- | -------- |
| `NSS-001` | Key Size   | RSA minimum 2048 bits (aligned with BR)        | Error    |
| `NSS-002` | Validity   | Root CA max 25 years recommended               | Warning  |
| `NSS-003` | Validity   | Intermediate CA max 10 years recommended       | Warning  |
| `NSS-004` | Extensions | Name Constraints recommended for intermediates | Info     |
| `NSS-005` | Extensions | CRL/OCSP must be accessible                    | Warning  |
| `NSS-006` | Revocation | OCSP must staple not required                  | Info     |

### Development Certificate Checks

For self-signed/development certificates, use relaxed rules:

| Rule ID   | Category | Description                     | Severity |
| --------- | -------- | ------------------------------- | -------- |
| `DEV-001` | Validity | Warn if > 398 days              | Warning  |
| `DEV-002` | Trust    | Warn if not in trusted store    | Info     |
| `DEV-003` | SAN      | Recommend localhost + 127.0.0.1 | Info     |

---

## Implementation Steps

### Step 1: Create LintResult Model

**New file:** `src/certz/Models/LintResult.cs`

```csharp
namespace certz.Models;

/// <summary>
/// Severity level for lint findings.
/// </summary>
internal enum LintSeverity
{
    Info,
    Warning,
    Error
}

/// <summary>
/// A single lint finding.
/// </summary>
internal record LintFinding
{
    /// <summary>
    /// Rule identifier (e.g., "BR-001", "NSS-001").
    /// </summary>
    public required string RuleId { get; init; }

    /// <summary>
    /// Human-readable rule name.
    /// </summary>
    public required string RuleName { get; init; }

    /// <summary>
    /// Severity of the finding.
    /// </summary>
    public required LintSeverity Severity { get; init; }

    /// <summary>
    /// Detailed message explaining the issue.
    /// </summary>
    public required string Message { get; init; }

    /// <summary>
    /// Policy source (e.g., "CA/B Forum BR", "Mozilla NSS").
    /// </summary>
    public required string Policy { get; init; }

    /// <summary>
    /// Actual value found in the certificate.
    /// </summary>
    public string? ActualValue { get; init; }

    /// <summary>
    /// Expected or required value.
    /// </summary>
    public string? ExpectedValue { get; init; }
}

/// <summary>
/// Result of linting a certificate.
/// </summary>
internal record LintResult
{
    /// <summary>
    /// The certificate subject.
    /// </summary>
    public required string Subject { get; init; }

    /// <summary>
    /// The certificate thumbprint.
    /// </summary>
    public required string Thumbprint { get; init; }

    /// <summary>
    /// Whether all checks passed (no errors).
    /// </summary>
    public required bool Passed { get; init; }

    /// <summary>
    /// All lint findings.
    /// </summary>
    public required List<LintFinding> Findings { get; init; }

    /// <summary>
    /// Count of errors.
    /// </summary>
    public int ErrorCount => Findings.Count(f => f.Severity == LintSeverity.Error);

    /// <summary>
    /// Count of warnings.
    /// </summary>
    public int WarningCount => Findings.Count(f => f.Severity == LintSeverity.Warning);

    /// <summary>
    /// Count of informational findings.
    /// </summary>
    public int InfoCount => Findings.Count(f => f.Severity == LintSeverity.Info);

    /// <summary>
    /// The policy set used for linting.
    /// </summary>
    public required string PolicySet { get; init; }

    /// <summary>
    /// Whether this is a CA certificate.
    /// </summary>
    public bool IsCa { get; init; }

    /// <summary>
    /// Source path of the certificate.
    /// </summary>
    public string? SourcePath { get; init; }
}
```

**Status:** [x] Completed

---

### Step 2: Create LintOptions Model

**New file:** `src/certz/Models/LintOptions.cs`

```csharp
namespace certz.Models;

/// <summary>
/// Options for the lint command.
/// </summary>
internal record LintOptions
{
    /// <summary>
    /// Source: file path, URL, or thumbprint.
    /// </summary>
    public required string Source { get; init; }

    /// <summary>
    /// Password for PFX/P12 files.
    /// </summary>
    public string? Password { get; init; }

    /// <summary>
    /// Policy set to use: "cabf" (default), "mozilla", "dev", or "all".
    /// </summary>
    public string PolicySet { get; init; } = "cabf";

    /// <summary>
    /// Minimum severity to report: "info", "warning", or "error".
    /// </summary>
    public LintSeverity MinSeverity { get; init; } = LintSeverity.Info;

    /// <summary>
    /// Certificate store name (for thumbprint lookups).
    /// </summary>
    public string? StoreName { get; init; }

    /// <summary>
    /// Certificate store location.
    /// </summary>
    public string? StoreLocation { get; init; }
}
```

**Status:** [x] Completed

---

### Step 3: Create LintService.cs

**New file:** `src/certz/Services/LintService.cs`

```csharp
namespace certz.Services;

/// <summary>
/// Service for linting certificates against industry standards.
/// </summary>
internal static class LintService
{
    /// <summary>
    /// Lint a certificate from a file.
    /// </summary>
    internal static LintResult LintFile(LintOptions options)
    {
        var cert = LoadCertificate(options.Source, options.Password);
        return PerformLint(cert, options);
    }

    /// <summary>
    /// Lint a certificate from a URL.
    /// </summary>
    internal static async Task<LintResult> LintUrlAsync(LintOptions options)
    {
        var cert = await FetchCertificateFromUrl(options.Source);
        return PerformLint(cert, options);
    }

    /// <summary>
    /// Lint a certificate from the certificate store.
    /// </summary>
    internal static LintResult LintFromStore(LintOptions options)
    {
        var cert = LoadCertificateFromStore(options);
        return PerformLint(cert, options);
    }

    private static LintResult PerformLint(X509Certificate2 cert, LintOptions options)
    {
        var findings = new List<LintFinding>();
        var isCa = IsCaCertificate(cert);

        // Apply policy checks based on selected policy set
        switch (options.PolicySet.ToLowerInvariant())
        {
            case "cabf":
                findings.AddRange(CheckCaBForumRules(cert, isCa));
                break;
            case "mozilla":
                findings.AddRange(CheckCaBForumRules(cert, isCa));
                findings.AddRange(CheckMozillaNssRules(cert, isCa));
                break;
            case "dev":
                findings.AddRange(CheckDevCertRules(cert));
                break;
            case "all":
                findings.AddRange(CheckCaBForumRules(cert, isCa));
                findings.AddRange(CheckMozillaNssRules(cert, isCa));
                findings.AddRange(CheckDevCertRules(cert));
                break;
            default:
                findings.AddRange(CheckCaBForumRules(cert, isCa));
                break;
        }

        // Filter by minimum severity
        findings = findings
            .Where(f => f.Severity >= options.MinSeverity)
            .ToList();

        var hasErrors = findings.Any(f => f.Severity == LintSeverity.Error);

        return new LintResult
        {
            Subject = cert.SubjectName.Format(false),
            Thumbprint = cert.Thumbprint,
            Passed = !hasErrors,
            Findings = findings,
            PolicySet = options.PolicySet,
            IsCa = isCa,
            SourcePath = options.Source
        };
    }

    // Rule check methods implemented in subsequent steps...
}
```

**Status:** [x] Completed

---

### Step 4: Implement CA/B Forum Checks

**Add to:** `src/certz/Services/LintService.cs`

```csharp
private static List<LintFinding> CheckCaBForumRules(X509Certificate2 cert, bool isCa)
{
    var findings = new List<LintFinding>();

    // BR-001: Maximum validity 398 days for leaf certs
    if (!isCa)
    {
        var validityDays = (cert.NotAfter - cert.NotBefore).Days;
        if (validityDays > 398)
        {
            findings.Add(new LintFinding
            {
                RuleId = "BR-001",
                RuleName = "Maximum Validity Period",
                Severity = LintSeverity.Error,
                Message = "Leaf certificate validity exceeds 398 days (CA/B Forum limit)",
                Policy = "CA/B Forum BR",
                ActualValue = $"{validityDays} days",
                ExpectedValue = "≤ 398 days"
            });
        }
    }

    // BR-003: RSA minimum 2048 bits
    if (cert.PublicKey.Oid.FriendlyName == "RSA")
    {
        var rsa = cert.GetRSAPublicKey();
        if (rsa != null && rsa.KeySize < 2048)
        {
            findings.Add(new LintFinding
            {
                RuleId = "BR-003",
                RuleName = "RSA Key Size",
                Severity = LintSeverity.Error,
                Message = "RSA key size is below minimum 2048 bits",
                Policy = "CA/B Forum BR",
                ActualValue = $"{rsa.KeySize} bits",
                ExpectedValue = "≥ 2048 bits"
            });
        }
    }

    // BR-005: SHA-1 prohibited
    if (cert.SignatureAlgorithm.FriendlyName?.Contains("SHA1") == true ||
        cert.SignatureAlgorithm.FriendlyName?.Contains("sha1") == true)
    {
        findings.Add(new LintFinding
        {
            RuleId = "BR-005",
            RuleName = "SHA-1 Signature",
            Severity = LintSeverity.Error,
            Message = "SHA-1 signatures are prohibited for new certificates",
            Policy = "CA/B Forum BR",
            ActualValue = cert.SignatureAlgorithm.FriendlyName
        });
    }

    // BR-007: SAN required
    var sanExtension = cert.Extensions
        .OfType<X509SubjectAlternativeNameExtension>()
        .FirstOrDefault();

    if (sanExtension == null && !isCa)
    {
        findings.Add(new LintFinding
        {
            RuleId = "BR-007",
            RuleName = "Subject Alternative Name Required",
            Severity = LintSeverity.Error,
            Message = "Subject Alternative Name extension is required for TLS certificates",
            Policy = "CA/B Forum BR"
        });
    }

    // BR-009: Basic Constraints required for CA
    if (isCa)
    {
        var basicConstraints = cert.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .FirstOrDefault();

        if (basicConstraints == null)
        {
            findings.Add(new LintFinding
            {
                RuleId = "BR-009",
                RuleName = "Basic Constraints Required",
                Severity = LintSeverity.Error,
                Message = "CA certificates must have Basic Constraints extension",
                Policy = "CA/B Forum BR"
            });
        }
    }

    // BR-010: Key Usage required
    var keyUsage = cert.Extensions
        .OfType<X509KeyUsageExtension>()
        .FirstOrDefault();

    if (keyUsage == null)
    {
        findings.Add(new LintFinding
        {
            RuleId = "BR-010",
            RuleName = "Key Usage Recommended",
            Severity = LintSeverity.Warning,
            Message = "Key Usage extension is recommended",
            Policy = "CA/B Forum BR"
        });
    }

    // BR-012: Authority Key Identifier for non-root
    var isRoot = cert.Subject == cert.Issuer;
    if (!isRoot)
    {
        var aki = cert.Extensions["2.5.29.35"]; // Authority Key Identifier OID
        if (aki == null)
        {
            findings.Add(new LintFinding
            {
                RuleId = "BR-012",
                RuleName = "Authority Key Identifier Required",
                Severity = LintSeverity.Warning,
                Message = "Non-root certificates should have Authority Key Identifier",
                Policy = "CA/B Forum BR"
            });
        }
    }

    // Additional checks...

    return findings;
}
```

**Status:** [x] Completed

---

### Step 5: Implement Mozilla NSS Checks

**Add to:** `src/certz/Services/LintService.cs`

```csharp
private static List<LintFinding> CheckMozillaNssRules(X509Certificate2 cert, bool isCa)
{
    var findings = new List<LintFinding>();
    var isRoot = cert.Subject == cert.Issuer;
    var validityYears = (cert.NotAfter - cert.NotBefore).Days / 365.0;

    // NSS-002: Root CA max 25 years recommended
    if (isCa && isRoot && validityYears > 25)
    {
        findings.Add(new LintFinding
        {
            RuleId = "NSS-002",
            RuleName = "Root CA Maximum Validity",
            Severity = LintSeverity.Warning,
            Message = "Root CA validity exceeds recommended 25 years",
            Policy = "Mozilla NSS",
            ActualValue = $"{validityYears:F1} years",
            ExpectedValue = "≤ 25 years"
        });
    }

    // NSS-003: Intermediate CA max 10 years recommended
    if (isCa && !isRoot && validityYears > 10)
    {
        findings.Add(new LintFinding
        {
            RuleId = "NSS-003",
            RuleName = "Intermediate CA Maximum Validity",
            Severity = LintSeverity.Warning,
            Message = "Intermediate CA validity exceeds recommended 10 years",
            Policy = "Mozilla NSS",
            ActualValue = $"{validityYears:F1} years",
            ExpectedValue = "≤ 10 years"
        });
    }

    // NSS-004: Name Constraints recommended for intermediates
    if (isCa && !isRoot)
    {
        var nameConstraints = cert.Extensions["2.5.29.30"]; // Name Constraints OID
        if (nameConstraints == null)
        {
            findings.Add(new LintFinding
            {
                RuleId = "NSS-004",
                RuleName = "Name Constraints Recommended",
                Severity = LintSeverity.Info,
                Message = "Name Constraints extension is recommended for intermediate CAs",
                Policy = "Mozilla NSS"
            });
        }
    }

    return findings;
}
```

**Status:** [x] Completed

---

### Step 6: Implement Development Certificate Checks

**Add to:** `src/certz/Services/LintService.cs`

```csharp
private static List<LintFinding> CheckDevCertRules(X509Certificate2 cert)
{
    var findings = new List<LintFinding>();
    var validityDays = (cert.NotAfter - cert.NotBefore).Days;

    // DEV-001: Warn if > 398 days
    if (validityDays > 398)
    {
        findings.Add(new LintFinding
        {
            RuleId = "DEV-001",
            RuleName = "Development Certificate Long Validity",
            Severity = LintSeverity.Warning,
            Message = "Development certificate has unusually long validity period",
            Policy = "Development",
            ActualValue = $"{validityDays} days",
            ExpectedValue = "≤ 398 days recommended"
        });
    }

    // DEV-003: Recommend localhost + 127.0.0.1
    var sanExtension = cert.Extensions
        .OfType<X509SubjectAlternativeNameExtension>()
        .FirstOrDefault();

    if (sanExtension != null)
    {
        var sans = new List<string>();
        foreach (var name in sanExtension.EnumerateDnsNames())
        {
            sans.Add(name);
        }
        foreach (var ip in sanExtension.EnumerateIPAddresses())
        {
            sans.Add(ip.ToString());
        }

        var hasLocalhost = sans.Any(s =>
            s.Equals("localhost", StringComparison.OrdinalIgnoreCase));
        var hasLoopback = sans.Any(s =>
            s == "127.0.0.1" || s == "::1");

        if (!hasLocalhost || !hasLoopback)
        {
            findings.Add(new LintFinding
            {
                RuleId = "DEV-003",
                RuleName = "Local Development SANs",
                Severity = LintSeverity.Info,
                Message = "Consider adding localhost and 127.0.0.1 to SANs for local development",
                Policy = "Development",
                ActualValue = string.Join(", ", sans)
            });
        }
    }

    return findings;
}
```

**Status:** [x] Completed

---

### Step 7: Add LintCommand.cs

**New file:** `src/certz/Commands/Lint/LintCommand.cs`

```csharp
using certz.Formatters;
using certz.Models;
using certz.Services;

namespace certz.Commands.Lint;

/// <summary>
/// The lint command for validating certificates against industry standards.
/// </summary>
internal static class LintCommand
{
    /// <summary>
    /// Adds the lint command to the root command.
    /// </summary>
    internal static void AddLintCommand(this RootCommand rootCommand)
    {
        var command = BuildLintCommand();
        rootCommand.Add(command);
    }

    private static Command BuildLintCommand()
    {
        // Source argument
        var sourceArgument = new Argument<string>("source")
        {
            Description = "File path, URL (https://...), or certificate thumbprint"
        };

        // Options
        var passwordOption = OptionBuilders.CreatePasswordOption();

        var policyOption = new Option<string>("--policy", "-p")
        {
            Description = "Policy set: cabf (default), mozilla, dev, or all",
            DefaultValueFactory = _ => "cabf"
        };
        policyOption.Validators.Add(result =>
        {
            var policy = result.GetValueOrDefault<string>()?.ToLowerInvariant();
            var valid = new[] { "cabf", "mozilla", "dev", "all" };
            if (!valid.Contains(policy))
            {
                result.AddError("Policy must be 'cabf', 'mozilla', 'dev', or 'all'.");
            }
        });

        var severityOption = new Option<string>("--severity", "-s")
        {
            Description = "Minimum severity to report: info (default), warning, or error",
            DefaultValueFactory = _ => "info"
        };

        var storeOption = new Option<string?>("--store")
        {
            Description = "Certificate store name (My, Root, CA)"
        };

        var locationOption = new Option<string?>("--location", "-l")
        {
            Description = "Store location (CurrentUser or LocalMachine)"
        };

        var formatOption = OptionBuilders.CreateFormatOption();

        var command = new Command("lint", "Validate certificate against CA/B Forum and Mozilla NSS requirements")
        {
            sourceArgument,
            passwordOption,
            policyOption,
            severityOption,
            storeOption,
            locationOption,
            formatOption
        };

        command.SetAction(async (parseResult) =>
        {
            var source = parseResult.GetValue(sourceArgument)
                ?? throw new ArgumentException("Source argument is required.");
            var password = parseResult.GetValue(passwordOption);
            var policy = parseResult.GetValue(policyOption) ?? "cabf";
            var severityStr = parseResult.GetValue(severityOption) ?? "info";
            var storeName = parseResult.GetValue(storeOption);
            var storeLocation = parseResult.GetValue(locationOption);
            var format = parseResult.GetValue(formatOption) ?? "text";

            var severity = severityStr.ToLowerInvariant() switch
            {
                "warning" => LintSeverity.Warning,
                "error" => LintSeverity.Error,
                _ => LintSeverity.Info
            };

            var formatter = FormatterFactory.Create(format);

            var options = new LintOptions
            {
                Source = source,
                Password = password,
                PolicySet = policy,
                MinSeverity = severity,
                StoreName = storeName,
                StoreLocation = storeLocation
            };

            // Detect source type and dispatch
            var sourceType = DetectSourceType(source, storeName);

            var result = sourceType switch
            {
                InspectSource.Url => await LintService.LintUrlAsync(options),
                InspectSource.Store => LintService.LintFromStore(options),
                InspectSource.File => LintService.LintFile(options),
                _ => throw new InvalidOperationException($"Unknown source type for: {source}")
            };

            formatter.WriteLintResult(result);

            // Return non-zero exit code if there are errors
            if (!result.Passed)
            {
                Environment.ExitCode = 1;
            }
        });

        return command;
    }

    private static InspectSource DetectSourceType(string source, string? storeName)
    {
        if (source.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            return InspectSource.Url;
        if (!string.IsNullOrEmpty(storeName))
            return InspectSource.Store;
        if (File.Exists(source))
            return InspectSource.File;
        if (IsValidThumbprint(source))
            return InspectSource.Store;

        throw new FileNotFoundException($"File not found: {source}");
    }

    private static bool IsValidThumbprint(string value) =>
        !string.IsNullOrEmpty(value) &&
        value.Length == 40 &&
        value.All(c => char.IsAsciiHexDigit(c));
}
```

**Status:** [x] Completed

---

### Step 8: Add Formatter Methods

**Modify:** `src/certz/Formatters/IOutputFormatter.cs`, `src/certz/Formatters/TextFormatter.cs`, `src/certz/Formatters/JsonFormatter.cs`

Add to interface:

```csharp
void WriteLintResult(LintResult result);
```

Text formatter implementation:

```csharp
public void WriteLintResult(LintResult result)
{
    var statusColor = result.Passed ? "green" : "red";
    var statusText = result.Passed ? "PASSED" : "FAILED";

    _console.Write(new Rule($"[bold]Certificate Lint: [{statusColor}]{statusText}[/][/]").LeftJustified());
    _console.WriteLine();

    _console.MarkupLine($"[bold]Subject:[/] {result.Subject}");
    _console.MarkupLine($"[bold]Thumbprint:[/] {result.Thumbprint}");
    _console.MarkupLine($"[bold]Policy Set:[/] {result.PolicySet}");
    _console.WriteLine();

    if (result.Findings.Count == 0)
    {
        _console.MarkupLine("[green]No issues found.[/]");
        return;
    }

    // Summary
    _console.MarkupLine($"[bold]Findings:[/] {result.ErrorCount} errors, {result.WarningCount} warnings, {result.InfoCount} info");
    _console.WriteLine();

    // Details table
    var table = new Table()
        .Border(TableBorder.Rounded)
        .AddColumn("[bold]Severity[/]")
        .AddColumn("[bold]Rule[/]")
        .AddColumn("[bold]Message[/]");

    foreach (var finding in result.Findings.OrderByDescending(f => f.Severity))
    {
        var severityColor = finding.Severity switch
        {
            LintSeverity.Error => "red",
            LintSeverity.Warning => "yellow",
            _ => "dim"
        };

        var severityText = finding.Severity.ToString().ToUpper();
        var ruleText = $"{finding.RuleId}\n[dim]{finding.RuleName}[/]";
        var messageText = finding.Message;

        if (finding.ActualValue != null)
        {
            messageText += $"\n[dim]Actual: {finding.ActualValue}[/]";
        }
        if (finding.ExpectedValue != null)
        {
            messageText += $"\n[dim]Expected: {finding.ExpectedValue}[/]";
        }

        table.AddRow(
            $"[{severityColor}]{severityText}[/]",
            ruleText,
            messageText);
    }

    _console.Write(table);
}
```

**Status:** [x] Completed

---

### Step 9: Create test-lint.ps1

**New file:** `test/test-lint.ps1`

```powershell
#requires -version 7

<#
.SYNOPSIS
    Test suite for certz lint command.

.DESCRIPTION
    This script tests the lint command functionality against
    CA/B Forum Baseline Requirements and Mozilla NSS Policy.
    It follows test isolation principles from test-isolation-plan.md.

.PARAMETER TestId
    Run specific tests by ID. Example: -TestId "lin-1.1", "lin-2.1"

.PARAMETER Category
    Run tests by category: cabf, mozilla, dev, format

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

# Test categories
$script:TestCategories = @{
    "cabf" = @("lin-1.1", "lin-1.2", "lin-1.3", "lin-1.4", "lin-1.5")
    "mozilla" = @("lin-2.1", "lin-2.2")
    "dev" = @("lin-3.1", "lin-3.2")
    "format" = @("fmt-1.1")
}

# Test cases:
# lin-1.1: Lint valid certificate (should pass)
# lin-1.2: Lint certificate with > 398 day validity (BR-001 error)
# lin-1.3: Lint certificate with SHA-1 signature (BR-005 error)
# lin-1.4: Lint certificate without SAN (BR-007 error)
# lin-1.5: Lint CA without Basic Constraints (BR-009 error)
# lin-2.1: Lint Root CA with > 25 year validity (NSS-002 warning)
# lin-2.2: Lint Intermediate CA with > 10 year validity (NSS-003 warning)
# lin-3.1: Lint dev cert with localhost + 127.0.0.1 (should pass)
# lin-3.2: Lint dev cert without loopback (DEV-003 info)
# fmt-1.1: Lint with --format json output
```

**Status:** [x] Completed

---

## Command Specification

### `certz lint <source>`

```
certz lint <source> [options]

Arguments:
  source              File path, URL, or certificate thumbprint

Options:
  --password, -p      Password for PFX/P12 files
  --policy            Policy set: cabf (default), mozilla, dev, or all
  --severity, -s      Minimum severity: info (default), warning, or error
  --store             Certificate store name (My, Root, CA)
  --location, -l      Store location (CurrentUser or LocalMachine)
  --format            Output format: text (default) or json

Examples:
  certz lint server.pfx --password secret
  certz lint https://example.com --policy mozilla
  certz lint mycert.pem --severity warning
  certz lint ABC123... --store My --format json
```

---

## New Files Reference

| File                                     | Purpose                        |
| ---------------------------------------- | ------------------------------ |
| `src/certz/Models/LintResult.cs`         | Lint finding and result models |
| `src/certz/Models/LintOptions.cs`        | Lint command options           |
| `src/certz/Services/LintService.cs`      | Lint logic and rule checks     |
| `src/certz/Commands/Lint/LintCommand.cs` | Command definition             |
| `test/test-lint.ps1`                     | Test suite                     |

---

## Verification Checklist

- [ ] `dotnet build` succeeds
- [ ] `certz lint --help` shows correct usage
- [ ] `certz lint mycert.pfx` runs CA/B Forum checks
- [ ] `certz lint mycert.pfx --policy mozilla` adds NSS checks
- [ ] `certz lint mycert.pfx --policy dev` runs dev checks
- [ ] `certz lint mycert.pfx --severity error` filters to errors only
- [ ] `certz lint https://example.com` works for URLs
- [ ] `certz lint ABC123... --store My` works for store
- [ ] `certz lint mycert.pfx --format json` outputs valid JSON
- [ ] Exit code is 1 when errors found, 0 otherwise
- [ ] `.\test-lint.ps1` runs and all tests pass

---

## Future Phase 4 Features (After Lint)

### Renew Command

```
certz renew <source> [options]
  --issuer            Issuing CA certificate (for re-signing)
  --days              New validity period
  --keep-key          Preserve existing private key
```

### Chain Visualization

```
certz inspect <source> --chain --tree

Output:
└─ Root CA (CN=Development Root CA)
   └─ Intermediate CA (CN=Development Intermediate CA)
      └─ Server (CN=myapp.local)
         ├─ Valid: 2026-02-08 to 2026-05-09
         ├─ Key: ECDSA P-256
         └─ SANs: myapp.local, localhost, 127.0.0.1
```

### Expiration Monitoring

```
certz monitor <directory|url> [options]
  --warn              Warning threshold (days)
  --format            Output format (text, json)
  --recursive         Scan subdirectories
```

---

## Notes & Adjustments

_Record any changes to the plan during implementation:_

1. _(none yet)_
