# Phase 8: Ephemeral Mode and Pipe Output

**Status:** Completed
**Created:** 2026-02-08
**Completed:** 2026-02-09

## Objective

Implement `--ephemeral` flag for in-memory certificate generation (no disk writes) and `--pipe` flag for streaming certificate output to stdout, enabling integration with other tools and secure testing workflows.

## Project Context

This is a .NET 10 CLI tool using:
- **System.CommandLine** for command parsing
- **Spectre.Console** for display formatting
- **Record types** for options and results

### Established Patterns

**Command Structure:** `Commands/<Feature>/<Feature>Command.cs`
- Static class with `Build<Feature>Command()` method
- Returns `Command` with options and `SetAction` handler
- Uses `OptionBuilders` for standard options
- Calls service layer, formats with `FormatterFactory.Create(format)`

**Service Layer:** `Services/<Feature>Service.cs`
- Static class with internal methods
- Returns result record types
- Contains business logic

**Models:** `Models/<Feature>Options.cs` and `Models/<Feature>Result.cs`
- Record types with `required` and `init` properties

**Testing:** `test/test-<feature>.ps1`
- PowerShell 7.5+ scripts
- Each test invokes certz.exe exactly ONCE
- Setup/cleanup in PowerShell only
- Assert system state, not console output

---

## Problem Statement

### Current Behavior

When creating certificates with `certz create dev` or `certz create ca`, files are always written to disk (PFX, PEM, or both). This creates issues for:

1. **Testing & CI/CD Pipelines** - Integration tests leave file artifacts requiring cleanup
2. **Security-Sensitive Environments** - Private keys on disk may violate security policies
3. **Quick Verification** - Iterating on certificate parameters requires repeated cleanup
4. **Tool Integration** - No way to pipe certificates directly to other commands

### Solution

Add two complementary flags:
- `--ephemeral` - Generate certificate in memory, display properties, never write to disk
- `--pipe` - Stream certificate content to stdout for piping to other tools

---

## Command Specification

### Ephemeral Mode

```
certz create dev <domain> --ephemeral [options]
certz create ca <name> --ephemeral [options]

Restrictions (mutually exclusive with --ephemeral):
  --file, -f          Cannot specify output file
  --cert              Cannot write PEM certificate
  --key               Cannot write PEM key
  --trust             Cannot install to trust store
  --password-file     No file to protect

Output:
  - Displays all certificate properties (subject, thumbprint, SANs, validity, etc.)
  - Shows warning that certificate is ephemeral
  - Certificate discarded when command exits
```

### Pipe Mode

```
certz create dev <domain> --pipe [--pipe-format <format>] [options]
certz create ca <name> --pipe [--pipe-format <format>] [options]

Options:
  --pipe              Stream certificate to stdout (no files written)
  --pipe-format       Output format: pem (default), pfx, cert, key
  --pipe-password     Password for PFX output (required for pfx format)

Formats:
  pem     - Full PEM (certificate + private key concatenated)
  pfx     - Base64-encoded PFX (password via --pipe-password or stderr)
  cert    - Certificate only (PEM format)
  key     - Private key only (PEM format)

Restrictions (mutually exclusive with --pipe):
  --file, -f          Cannot specify output file
  --cert              Cannot write PEM certificate file
  --key               Cannot write PEM key file
  --trust             Cannot install to trust store
```

---

## Use Cases

### Development & Testing

| Use Case | Command | Benefit |
|----------|---------|---------|
| **Validate certificate settings** | `certz create dev app.local --ephemeral --san "*.app.local"` | See exact output before committing to files |
| **Unit test fixtures** | `certz create dev test.local --ephemeral --format json` | Generate certificates as test data without cleanup |
| **Integration test isolation** | `certz create dev test-$ID.local --ephemeral` | Each test run gets fresh certs; no state leakage |
| **Load testing** | Loop with `--ephemeral` | Rapidly generate unique certificates for stress testing |
| **Mocking HTTPS endpoints** | `certz create dev mock.local --pipe \| start-server` | Spin up temporary HTTPS servers |

### Security & Compliance

| Use Case | Command | Benefit |
|----------|---------|---------|
| **Air-gapped validation** | `certz create ca "Test CA" --ephemeral` | Verify generation works without creating artifacts |
| **Key ceremony dry runs** | `certz create ca "Root CA" --ephemeral --key-type rsa-4096` | Practice workflows without real keys |
| **Audit trail verification** | `certz create dev audit.local --ephemeral` | Confirm expected properties without persistence |
| **PCI-DSS/HIPAA environments** | `certz create dev secure.local --ephemeral` | Keys never touch disk |

### DevOps & Automation

| Use Case | Command | Benefit |
|----------|---------|---------|
| **Pipeline validation** | `certz create dev $APP.local --ephemeral` | Validate config before actual generation |
| **Docker container builds** | `certz create dev app.local --pipe \| ...` | Certs die with the container |
| **Kubernetes secrets** | `certz create dev app.local --pipe --pipe-format pem \| kubectl create secret tls` | Direct secret creation |
| **Terraform preview** | `certz create dev $DOMAIN --ephemeral --format json` | Show what would be created |
| **GitOps dry-run** | `certz create dev prod.local --ephemeral` | Preview before commit |

### Education & Debugging

| Use Case | Command | Benefit |
|----------|---------|---------|
| **Teaching PKI concepts** | `certz create ca "Demo CA" --ephemeral` | No student machine clutter |
| **Debugging SAN configs** | `certz create dev test.local --ephemeral --san "a,b,c"` | Quick iteration |
| **Comparing key types** | `certz create dev test.local --ephemeral --key-type rsa-2048` | Side-by-side comparison |
| **Troubleshooting chains** | `certz create dev signed.local --ephemeral --issuer-cert ca.pfx` | Verify signing works |

### Advanced Scenarios

| Use Case | Command | Benefit |
|----------|---------|---------|
| **In-memory TLS termination** | Application calls certz with `--pipe` | Service mesh sidecars |
| **Ephemeral mTLS** | Both ends use `--ephemeral` certs | Short-lived connections only |
| **Certificate rotation testing** | Loop with `--ephemeral` | Simulate rotation scenarios |
| **Thumbprint pre-calculation** | `certz create dev test.local --ephemeral \| grep Thumbprint` | Get thumbprint before persisting |
| **Process substitution** | `nginx -c <(certz create dev test.local --pipe)` | Direct configuration |

---

## Design Decisions

| Area | Decision | Rationale |
|------|----------|-----------|
| **Flag names** | `--ephemeral` and `--pipe` | Clear intent, common terminology |
| **Default pipe format** | PEM (cert + key) | Most versatile, works with most tools |
| **PFX password handling** | Required `--pipe-password` or generated to stderr | Security: don't embed passwords in stdout |
| **Mutual exclusivity** | `--ephemeral`/`--pipe` conflict with file options | Prevents confusion about output location |
| **Existing infrastructure** | Reuse `X509KeyStorageFlags.EphemeralKeySet` | Already in CertificateUtilities.cs line 80 |
| **Output channels** | Cert to stdout, metadata to stderr | Standard Unix convention for piping |

---

## Pipe Format Details

### PEM Format (Default)

```bash
certz create dev example.com --pipe
```

**stdout:**
```
-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAK...
-----END CERTIFICATE-----
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIDvB...
-----END EC PRIVATE KEY-----
```

### PFX Format

```bash
certz create dev example.com --pipe --pipe-format pfx --pipe-password "MySecret"
```

**stdout:** Base64-encoded PFX data
```
MIIJqQIBAzCCCW8GCSqGSIb3DQEHAaCCCWAEgglcMIIJWDCCA88GCSqGSIb3DQEH...
```

**If no `--pipe-password` specified:**
- Generate random password
- Write password to stderr: `PASSWORD: ABC123XYZ`
- User can capture separately: `certz create dev x.com --pipe --pipe-format pfx 2>password.txt | base64 -d > cert.pfx`

### Cert-Only Format

```bash
certz create dev example.com --pipe --pipe-format cert
```

**stdout:** Certificate PEM only (no private key)

### Key-Only Format

```bash
certz create dev example.com --pipe --pipe-format key
```

**stdout:** Private key PEM only (no certificate)

---

## Progress Tracker

| # | Step | Status | Notes |
|---|------|--------|-------|
| 1 | Add Ephemeral property to DevCertificateOptions | [x] | Models/DevCertificateOptions.cs |
| 2 | Add Ephemeral property to CACertificateOptions | [x] | Models/CACertificateOptions.cs |
| 3 | Add IsEphemeral to CertificateCreationResult | [x] | Models/CertificateCreationResult.cs |
| 4 | Add pipe-related properties to options | [x] | Pipe, PipeFormat, PipePassword |
| 5 | Create option builders | [x] | OptionBuilders.cs |
| 6 | Update CreateDevCommand | [x] | Add options, validation |
| 7 | Update CreateCaCommand | [x] | Add options, validation |
| 8 | Update CreateService | [x] | Conditional file writing |
| 9 | Add PipeOutputService | [x] | Handle pipe format output |
| 10 | Update TextFormatter | [x] | Ephemeral warning display |
| 11 | Update JsonFormatter | [x] | Add isEphemeral field |
| 12 | Create tests | [x] | test/test-ephemeral.ps1 |
| 13 | Update documentation | [x] | README.md |

---

## Implementation Steps

### Step 1: Add Ephemeral Property to DevCertificateOptions

**Modify:** `Models/DevCertificateOptions.cs`

```csharp
/// <summary>
/// Generate certificate in memory only (no files written).
/// </summary>
public bool Ephemeral { get; init; }

/// <summary>
/// Stream certificate output to stdout.
/// </summary>
public bool Pipe { get; init; }

/// <summary>
/// Format for pipe output: pem (default), pfx, cert, key.
/// </summary>
public string? PipeFormat { get; init; }

/// <summary>
/// Password for PFX pipe output.
/// </summary>
public string? PipePassword { get; init; }
```

**Status:** [ ] Not Started

---

### Step 2: Add Ephemeral Property to CACertificateOptions

**Modify:** `Models/CACertificateOptions.cs`

Add same properties as Step 1.

**Status:** [ ] Not Started

---

### Step 3: Add IsEphemeral to CertificateCreationResult

**Modify:** `Models/CertificateCreationResult.cs`

```csharp
/// <summary>
/// Indicates the certificate was generated in ephemeral mode (not persisted).
/// </summary>
public bool IsEphemeral { get; init; }

/// <summary>
/// Indicates output was piped to stdout.
/// </summary>
public bool WasPiped { get; init; }
```

**Status:** [ ] Not Started

---

### Step 4: Create Option Builders

**Modify:** `Options/OptionBuilders.cs`

```csharp
/// <summary>
/// Creates the --ephemeral option for in-memory certificate generation.
/// </summary>
internal static Option<bool> CreateEphemeralOption()
{
    return new Option<bool>("--ephemeral", "-e")
    {
        Description = "Generate certificate in memory only (no files written to disk)",
        DefaultValueFactory = _ => false
    };
}

/// <summary>
/// Creates the --pipe option for streaming output to stdout.
/// </summary>
internal static Option<bool> CreatePipeOption()
{
    return new Option<bool>("--pipe")
    {
        Description = "Stream certificate to stdout (no files written)"
    };
}

/// <summary>
/// Creates the --pipe-format option.
/// </summary>
internal static Option<string?> CreatePipeFormatOption()
{
    var option = new Option<string?>("--pipe-format")
    {
        Description = "Pipe output format: pem (default), pfx, cert, key"
    };
    option.AddValidator(result =>
    {
        var value = result.GetValueOrDefault<string?>();
        if (value != null && !new[] { "pem", "pfx", "cert", "key" }.Contains(value.ToLowerInvariant()))
        {
            result.AddError("--pipe-format must be one of: pem, pfx, cert, key");
        }
    });
    return option;
}

/// <summary>
/// Creates the --pipe-password option for PFX pipe output.
/// </summary>
internal static Option<string?> CreatePipePasswordOption()
{
    return new Option<string?>("--pipe-password")
    {
        Description = "Password for PFX pipe output (required for --pipe-format pfx)"
    };
}
```

**Status:** [ ] Not Started

---

### Step 5: Update CreateDevCommand

**Modify:** `Commands/Create/CreateDevCommand.cs`

```csharp
// Add options
var ephemeralOption = OptionBuilders.CreateEphemeralOption();
var pipeOption = OptionBuilders.CreatePipeOption();
var pipeFormatOption = OptionBuilders.CreatePipeFormatOption();
var pipePasswordOption = OptionBuilders.CreatePipePasswordOption();

command.Add(ephemeralOption);
command.Add(pipeOption);
command.Add(pipeFormatOption);
command.Add(pipePasswordOption);

// In action handler - validation
var ephemeral = parseResult.GetValue(ephemeralOption);
var pipe = parseResult.GetValue(pipeOption);
var pipeFormat = parseResult.GetValue(pipeFormatOption);
var pipePassword = parseResult.GetValue(pipePasswordOption);

// Validate mutual exclusivity
if (ephemeral || pipe)
{
    if (pfxFile != null || certFile != null || keyFile != null)
    {
        formatter.WriteError("--ephemeral and --pipe cannot be used with file output options (--file, --cert, --key).");
        return 1;
    }
    if (trust)
    {
        formatter.WriteError("--ephemeral and --pipe cannot be used with --trust.");
        return 1;
    }
    if (passwordFile != null)
    {
        formatter.WriteError("--ephemeral and --pipe cannot be used with --password-file.");
        return 1;
    }
}

if (ephemeral && pipe)
{
    formatter.WriteError("--ephemeral and --pipe are mutually exclusive. Use one or the other.");
    return 1;
}

// Validate pipe-format requires pipe
if (pipeFormat != null && !pipe)
{
    formatter.WriteError("--pipe-format requires --pipe flag.");
    return 1;
}

// Validate PFX pipe format requires password (or we generate one)
if (pipeFormat?.ToLowerInvariant() == "pfx" && pipePassword == null)
{
    // Will generate password and output to stderr
}
```

**Status:** [ ] Not Started

---

### Step 6: Update CreateService for Conditional File Writing

**Modify:** `Services/CreateService.cs`

```csharp
internal static async Task<CertificateCreationResult> CreateDevCertificate(DevCertificateOptions options)
{
    // ... existing certificate generation code ...

    var outputFiles = new List<string>();

    // Handle pipe mode
    if (options.Pipe)
    {
        await PipeOutputService.WritePipeOutput(
            certificate,
            options.PipeFormat ?? "pem",
            options.PipePassword);

        return new CertificateCreationResult
        {
            Subject = certificate.Subject,
            Thumbprint = certificate.Thumbprint,
            NotBefore = certificate.NotBefore,
            NotAfter = certificate.NotAfter,
            KeyType = keyType,
            SANs = sans,
            OutputFiles = Array.Empty<string>(),
            IsEphemeral = false,
            WasPiped = true
        };
    }

    // Handle ephemeral mode - skip all file writing
    if (options.Ephemeral)
    {
        return new CertificateCreationResult
        {
            Subject = certificate.Subject,
            Thumbprint = certificate.Thumbprint,
            NotBefore = certificate.NotBefore,
            NotAfter = certificate.NotAfter,
            KeyType = keyType,
            SANs = sans,
            OutputFiles = Array.Empty<string>(),
            IsEphemeral = true,
            WasPiped = false
        };
    }

    // Normal file writing (existing code)
    if (options.PfxFile != null)
    {
        await CertificateUtilities.WriteCertificateToFile(...);
        outputFiles.Add(options.PfxFile.FullName);
    }
    // ... rest of file writing ...
}
```

**Status:** [ ] Not Started

---

### Step 7: Create PipeOutputService

**Create:** `Services/PipeOutputService.cs`

```csharp
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace certz.Services;

/// <summary>
/// Handles streaming certificate output to stdout for pipe mode.
/// </summary>
internal static class PipeOutputService
{
    /// <summary>
    /// Writes certificate in specified format to stdout.
    /// </summary>
    internal static async Task WritePipeOutput(
        X509Certificate2 certificate,
        string format,
        string? password)
    {
        switch (format.ToLowerInvariant())
        {
            case "pem":
                await WritePemOutput(certificate);
                break;
            case "pfx":
                await WritePfxOutput(certificate, password);
                break;
            case "cert":
                await WriteCertOnlyOutput(certificate);
                break;
            case "key":
                await WriteKeyOnlyOutput(certificate);
                break;
            default:
                throw new ArgumentException($"Unknown pipe format: {format}");
        }
    }

    private static async Task WritePemOutput(X509Certificate2 certificate)
    {
        // Certificate PEM
        var certPem = new StringBuilder();
        certPem.AppendLine("-----BEGIN CERTIFICATE-----");
        certPem.AppendLine(Convert.ToBase64String(certificate.RawData, Base64FormattingOptions.InsertLineBreaks));
        certPem.AppendLine("-----END CERTIFICATE-----");

        // Private key PEM
        if (certificate.HasPrivateKey)
        {
            var keyPem = ExportPrivateKeyPem(certificate);
            certPem.AppendLine(keyPem);
        }

        await Console.Out.WriteAsync(certPem.ToString());
    }

    private static async Task WritePfxOutput(X509Certificate2 certificate, string? password)
    {
        var actualPassword = password;

        if (string.IsNullOrEmpty(actualPassword))
        {
            // Generate random password and output to stderr
            actualPassword = CertificateUtilities.GeneratePassword();
            await Console.Error.WriteLineAsync($"PASSWORD: {actualPassword}");
        }

        var pfxBytes = certificate.Export(X509ContentType.Pfx, actualPassword);
        var base64 = Convert.ToBase64String(pfxBytes);
        await Console.Out.WriteAsync(base64);
    }

    private static async Task WriteCertOnlyOutput(X509Certificate2 certificate)
    {
        var certPem = new StringBuilder();
        certPem.AppendLine("-----BEGIN CERTIFICATE-----");
        certPem.AppendLine(Convert.ToBase64String(certificate.RawData, Base64FormattingOptions.InsertLineBreaks));
        certPem.AppendLine("-----END CERTIFICATE-----");

        await Console.Out.WriteAsync(certPem.ToString());
    }

    private static async Task WriteKeyOnlyOutput(X509Certificate2 certificate)
    {
        if (!certificate.HasPrivateKey)
        {
            throw new InvalidOperationException("Certificate does not have a private key.");
        }

        var keyPem = ExportPrivateKeyPem(certificate);
        await Console.Out.WriteAsync(keyPem);
    }

    private static string ExportPrivateKeyPem(X509Certificate2 certificate)
    {
        var sb = new StringBuilder();

        using var ecdsa = certificate.GetECDsaPrivateKey();
        if (ecdsa != null)
        {
            var keyBytes = ecdsa.ExportPkcs8PrivateKey();
            sb.AppendLine("-----BEGIN PRIVATE KEY-----");
            sb.AppendLine(Convert.ToBase64String(keyBytes, Base64FormattingOptions.InsertLineBreaks));
            sb.AppendLine("-----END PRIVATE KEY-----");
            return sb.ToString();
        }

        using var rsa = certificate.GetRSAPrivateKey();
        if (rsa != null)
        {
            var keyBytes = rsa.ExportPkcs8PrivateKey();
            sb.AppendLine("-----BEGIN PRIVATE KEY-----");
            sb.AppendLine(Convert.ToBase64String(keyBytes, Base64FormattingOptions.InsertLineBreaks));
            sb.AppendLine("-----END PRIVATE KEY-----");
            return sb.ToString();
        }

        throw new InvalidOperationException("Unsupported key type for export.");
    }
}
```

**Status:** [ ] Not Started

---

### Step 8: Update TextFormatter

**Modify:** `Formatters/TextFormatter.cs`

```csharp
public void WriteCertificateCreated(CertificateCreationResult result)
{
    // ... existing header and certificate info display ...

    if (result.IsEphemeral)
    {
        AnsiConsole.WriteLine();
        var warningPanel = new Panel(
            new Rows(
                new Markup("[bold yellow]EPHEMERAL MODE[/]"),
                new Markup(""),
                new Markup("Certificate exists in memory only."),
                new Markup("No files were written to disk."),
                new Markup("[dim]Certificate will be discarded when this command exits.[/]")
            ))
            .Border(BoxBorder.Double)
            .BorderColor(Color.Yellow);
        AnsiConsole.Write(warningPanel);
    }
    else if (result.WasPiped)
    {
        // Pipe mode - minimal output to stderr, content went to stdout
        // Don't display file list since there are none
    }
    else if (result.OutputFiles.Length > 0)
    {
        // Existing file list display
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[bold]Saved Files:[/]");
        foreach (var file in result.OutputFiles)
        {
            AnsiConsole.MarkupLine($"  [blue]-[/] {Markup.Escape(file)}");
        }
    }

    // ... rest of existing code (password display, etc.) ...
}
```

**Status:** [ ] Not Started

---

### Step 9: Update JsonFormatter

**Modify:** `Formatters/JsonFormatter.cs`

Update `CertificateCreatedOutput` record:

```csharp
internal record CertificateCreatedOutput(
    bool Success,
    string Subject,
    string Thumbprint,
    string NotBefore,
    string NotAfter,
    string KeyType,
    string[]? SANs,
    string[]? OutputFiles,
    string? Password,
    bool PasswordWasGenerated,
    bool IsEphemeral,    // Add this
    bool WasPiped        // Add this
);
```

Update the method that creates this output to include the new fields.

**Status:** [ ] Not Started

---

### Step 10: Create Tests

**Create:** `test/test-ephemeral.ps1`

```powershell
#Requires -Version 7.5

<#
.SYNOPSIS
    Tests for ephemeral and pipe certificate generation modes.
#>

param(
    [string[]]$TestId,
    [string[]]$Category
)

. "$PSScriptRoot\test-helper.ps1"

$TestCategories = @{
    "ephemeral" = @("eph-1.1", "eph-1.2", "eph-1.3", "eph-2.1", "eph-2.2")
    "pipe"      = @("eph-3.1", "eph-3.2", "eph-3.3", "eph-3.4", "eph-3.5")
    "errors"    = @("eph-4.1", "eph-4.2", "eph-4.3", "eph-4.4")
}

Initialize-TestEnvironment -TestId $TestId -Category $Category -TestCategories $TestCategories
Build-Certz

Write-TestHeader "Ephemeral Certificate Generation Tests"
Write-Host "========================================`n"

# ============================================================================
# EPHEMERAL MODE TESTS
# ============================================================================

Write-TestHeader "Testing Ephemeral Mode"

# eph-1.1: Basic ephemeral dev certificate
Invoke-Test -TestId "eph-1.1" -TestName "Ephemeral dev certificate" -TestScript {
    $output = & certz create dev ephemeral-test.local --ephemeral 2>&1
    $exitCode = $LASTEXITCODE

    # Should succeed
    Assert-ExitCode -Expected 0

    # Should show certificate details
    $hasSubject = $output -match "ephemeral-test.local"
    $hasThumbprint = $output -match "Thumbprint"

    # Should NOT create any files
    $pfxExists = Test-Path "ephemeral-test.local.pfx"
    $pemExists = Test-Path "ephemeral-test.local.pem"

    if ($hasSubject -and $hasThumbprint -and -not $pfxExists -and -not $pemExists) {
        return @{ Success = $true; Details = "Certificate displayed, no files created" }
    }
    return @{ Success = $false; Details = "Expected no files, got pfx=$pfxExists pem=$pemExists" }
}

# eph-1.2: Ephemeral with custom options
Invoke-Test -TestId "eph-1.2" -TestName "Ephemeral with SANs and key type" -TestScript {
    $output = & certz create dev custom.local --ephemeral --san "alt.local,192.168.1.1" --key-type rsa-2048 2>&1

    Assert-ExitCode -Expected 0

    $hasRSA = $output -match "RSA"
    $hasSAN = $output -match "alt.local"

    # No files should exist
    $anyFiles = Get-ChildItem -Path . -Filter "custom*" -ErrorAction SilentlyContinue

    if ($hasRSA -and $hasSAN -and $anyFiles.Count -eq 0) {
        return @{ Success = $true; Details = "RSA key and SANs displayed, no files" }
    }
    return @{ Success = $false; Details = "Missing expected output or files exist" }
}

# eph-1.3: Ephemeral CA certificate
Invoke-Test -TestId "eph-1.3" -TestName "Ephemeral CA certificate" -TestScript {
    $output = & certz create ca "Ephemeral Test CA" --ephemeral 2>&1

    Assert-ExitCode -Expected 0

    $hasCA = $output -match "Ephemeral Test CA"
    $anyFiles = Get-ChildItem -Path . -Filter "*Ephemeral*" -ErrorAction SilentlyContinue

    if ($hasCA -and $anyFiles.Count -eq 0) {
        return @{ Success = $true; Details = "CA cert displayed, no files" }
    }
    return @{ Success = $false; Details = "CA not displayed or files exist" }
}

# eph-2.1: Ephemeral with JSON output
Invoke-Test -TestId "eph-2.1" -TestName "Ephemeral with JSON format" -TestScript {
    $output = & certz create dev json-test.local --ephemeral --format json 2>&1

    Assert-ExitCode -Expected 0

    try {
        $json = $output | ConvertFrom-Json
        $isEphemeral = $json.isEphemeral -eq $true
        $noFiles = ($json.outputFiles.Count -eq 0) -or ($null -eq $json.outputFiles)

        if ($isEphemeral -and $noFiles) {
            return @{ Success = $true; Details = "JSON shows isEphemeral=true, no outputFiles" }
        }
        return @{ Success = $false; Details = "JSON missing isEphemeral or has files" }
    }
    catch {
        return @{ Success = $false; Details = "Invalid JSON output" }
    }
}

# ============================================================================
# PIPE MODE TESTS
# ============================================================================

Write-TestHeader "Testing Pipe Mode"

# eph-3.1: Pipe PEM output
Invoke-Test -TestId "eph-3.1" -TestName "Pipe PEM format to stdout" -TestScript {
    $output = & certz create dev pipe-test.local --pipe 2>&1

    Assert-ExitCode -Expected 0

    $hasCertBegin = $output -match "-----BEGIN CERTIFICATE-----"
    $hasCertEnd = $output -match "-----END CERTIFICATE-----"
    $hasKeyBegin = $output -match "-----BEGIN PRIVATE KEY-----"
    $hasKeyEnd = $output -match "-----END PRIVATE KEY-----"

    # No files should exist
    $anyFiles = Get-ChildItem -Path . -Filter "pipe-test*" -ErrorAction SilentlyContinue

    if ($hasCertBegin -and $hasCertEnd -and $hasKeyBegin -and $hasKeyEnd -and $anyFiles.Count -eq 0) {
        return @{ Success = $true; Details = "Full PEM output to stdout, no files" }
    }
    return @{ Success = $false; Details = "Missing PEM markers or files exist" }
}

# eph-3.2: Pipe cert-only format
Invoke-Test -TestId "eph-3.2" -TestName "Pipe cert-only format" -TestScript {
    $output = & certz create dev cert-only.local --pipe --pipe-format cert 2>&1

    Assert-ExitCode -Expected 0

    $hasCert = $output -match "-----BEGIN CERTIFICATE-----"
    $hasKey = $output -match "-----BEGIN PRIVATE KEY-----"

    if ($hasCert -and -not $hasKey) {
        return @{ Success = $true; Details = "Certificate only, no private key" }
    }
    return @{ Success = $false; Details = "Expected cert only, got key=$hasKey" }
}

# eph-3.3: Pipe key-only format
Invoke-Test -TestId "eph-3.3" -TestName "Pipe key-only format" -TestScript {
    $output = & certz create dev key-only.local --pipe --pipe-format key 2>&1

    Assert-ExitCode -Expected 0

    $hasCert = $output -match "-----BEGIN CERTIFICATE-----"
    $hasKey = $output -match "-----BEGIN PRIVATE KEY-----"

    if (-not $hasCert -and $hasKey) {
        return @{ Success = $true; Details = "Private key only, no certificate" }
    }
    return @{ Success = $false; Details = "Expected key only, got cert=$hasCert" }
}

# eph-3.4: Pipe PFX with password
Invoke-Test -TestId "eph-3.4" -TestName "Pipe PFX format with password" -TestScript {
    $output = & certz create dev pfx-pipe.local --pipe --pipe-format pfx --pipe-password "TestPass123" 2>&1

    Assert-ExitCode -Expected 0

    # Output should be base64 (no PEM markers)
    $noPemMarkers = -not ($output -match "-----BEGIN")
    $isBase64 = $output -match "^[A-Za-z0-9+/=]+$"

    if ($noPemMarkers) {
        return @{ Success = $true; Details = "Base64 PFX output" }
    }
    return @{ Success = $false; Details = "Expected base64 PFX, got PEM markers" }
}

# eph-3.5: Pipe PFX generates password to stderr
Invoke-Test -TestId "eph-3.5" -TestName "Pipe PFX auto-generates password to stderr" -TestScript {
    # Capture stdout and stderr separately
    $stdout = & certz create dev pfx-auto.local --pipe --pipe-format pfx 2>$null
    $stderr = & certz create dev pfx-auto2.local --pipe --pipe-format pfx 2>&1 | Where-Object { $_ -match "PASSWORD:" }

    $hasPassword = $stderr -match "PASSWORD:"

    if ($hasPassword) {
        return @{ Success = $true; Details = "Auto-generated password written to stderr" }
    }
    return @{ Success = $false; Details = "Expected PASSWORD: on stderr" }
}

# ============================================================================
# ERROR HANDLING TESTS
# ============================================================================

Write-TestHeader "Testing Error Handling"

# eph-4.1: Ephemeral with file option
Invoke-Test -TestId "eph-4.1" -TestName "Error: ephemeral with --file" -TestScript {
    $output = & certz create dev conflict.local --ephemeral --file conflict.pfx 2>&1
    $exitCode = $LASTEXITCODE

    $hasError = $output -match "cannot be used with"

    if ($exitCode -ne 0 -and $hasError) {
        return @{ Success = $true; Details = "Correctly rejected conflicting options" }
    }
    return @{ Success = $false; Details = "Expected error for conflicting options" }
}

# eph-4.2: Ephemeral with --trust
Invoke-Test -TestId "eph-4.2" -TestName "Error: ephemeral with --trust" -TestScript {
    $output = & certz create dev trust-conflict.local --ephemeral --trust 2>&1
    $exitCode = $LASTEXITCODE

    $hasError = $output -match "cannot be used with"

    if ($exitCode -ne 0 -and $hasError) {
        return @{ Success = $true; Details = "Correctly rejected --trust with ephemeral" }
    }
    return @{ Success = $false; Details = "Expected error for --trust conflict" }
}

# eph-4.3: Pipe with file option
Invoke-Test -TestId "eph-4.3" -TestName "Error: pipe with --file" -TestScript {
    $output = & certz create dev pipe-conflict.local --pipe --file pipe.pfx 2>&1
    $exitCode = $LASTEXITCODE

    $hasError = $output -match "cannot be used with"

    if ($exitCode -ne 0 -and $hasError) {
        return @{ Success = $true; Details = "Correctly rejected conflicting options" }
    }
    return @{ Success = $false; Details = "Expected error for conflicting options" }
}

# eph-4.4: Both ephemeral and pipe
Invoke-Test -TestId "eph-4.4" -TestName "Error: both ephemeral and pipe" -TestScript {
    $output = & certz create dev both.local --ephemeral --pipe 2>&1
    $exitCode = $LASTEXITCODE

    $hasError = $output -match "mutually exclusive"

    if ($exitCode -ne 0 -and $hasError) {
        return @{ Success = $true; Details = "Correctly rejected both flags" }
    }
    return @{ Success = $false; Details = "Expected mutual exclusivity error" }
}

# ============================================================================
# SUMMARY
# ============================================================================

$exitCode = Write-TestSummary
exit $exitCode
```

**Status:** [ ] Not Started

---

### Step 11: Update Documentation

**Modify:** `README.md`

Add section after Certificate Creation:

```markdown
## Ephemeral & Pipe Modes

### Ephemeral Mode

Generate certificates in memory without writing files to disk:

```bash
# Create ephemeral certificate (displays details, no files)
certz create dev example.com --ephemeral

# Ephemeral with custom options
certz create dev app.local --ephemeral --san "*.app.local" --key-type rsa-4096

# Ephemeral CA certificate
certz create ca "Test CA" --ephemeral

# JSON output for scripting
certz create dev test.local --ephemeral --format json
```

**Use cases:**
- Testing certificate settings before committing to files
- CI/CD pipelines without cleanup requirements
- Security-sensitive environments (keys never touch disk)
- Training and demonstrations

### Pipe Mode

Stream certificate content to stdout for piping to other tools:

```bash
# Pipe full PEM (cert + key) to stdout
certz create dev example.com --pipe

# Pipe to kubectl to create Kubernetes secret
certz create dev app.local --pipe | kubectl create secret tls my-cert --cert=/dev/stdin --key=/dev/stdin

# Pipe certificate only (no private key)
certz create dev example.com --pipe --pipe-format cert

# Pipe private key only
certz create dev example.com --pipe --pipe-format key

# Pipe as base64 PFX with specified password
certz create dev example.com --pipe --pipe-format pfx --pipe-password "MySecret"

# Pipe PFX with auto-generated password (password written to stderr)
certz create dev example.com --pipe --pipe-format pfx 2>password.txt > cert.b64
```

**Pipe Formats:**

| Format | Output |
|--------|--------|
| `pem` (default) | Certificate + private key in PEM format |
| `pfx` | Base64-encoded PFX (password required or auto-generated to stderr) |
| `cert` | Certificate only (PEM format) |
| `key` | Private key only (PEM format) |

### Restrictions

Both `--ephemeral` and `--pipe` are mutually exclusive with:
- `--file`, `--cert`, `--key` (file output options)
- `--trust` (cannot install in-memory certificate)
- `--password-file` (no file to protect)

You cannot use both `--ephemeral` and `--pipe` together.
```

**Status:** [ ] Not Started

---

## Verification Checklist

### Ephemeral Mode
- [ ] `certz create dev x.local --ephemeral` displays cert, creates no files
- [ ] `certz create ca "X" --ephemeral` displays CA cert, creates no files
- [ ] `--ephemeral --format json` includes `isEphemeral: true`
- [ ] `--ephemeral --file x.pfx` returns error
- [ ] `--ephemeral --trust` returns error
- [ ] Certificate properties (thumbprint, SANs, validity) are displayed

### Pipe Mode
- [ ] `--pipe` outputs full PEM to stdout
- [ ] `--pipe --pipe-format cert` outputs certificate PEM only
- [ ] `--pipe --pipe-format key` outputs private key PEM only
- [ ] `--pipe --pipe-format pfx --pipe-password X` outputs base64 PFX
- [ ] `--pipe --pipe-format pfx` (no password) generates password to stderr
- [ ] Piped output can be consumed by other tools (openssl, kubectl, etc.)
- [ ] No files are created in any pipe mode

### Error Handling
- [ ] `--ephemeral --pipe` returns mutual exclusivity error
- [ ] `--pipe --file x.pfx` returns error
- [ ] `--pipe-format` without `--pipe` returns error
- [ ] Invalid `--pipe-format` value returns error

### Integration
- [ ] All existing create tests still pass
- [ ] New test-ephemeral.ps1 tests pass
- [ ] Build completes without warnings
- [ ] JSON output schema includes new fields

---

## Security Considerations

1. **Ephemeral key material**: When using `--ephemeral`, private keys exist only in process memory and are disposed when the command exits
2. **Pipe mode security**: PFX passwords written to stderr can be captured separately from the certificate data
3. **No disk persistence**: Neither mode writes any files, preventing forensic recovery of deleted keys
4. **Process isolation**: Certificates are only accessible within the creating process

---

## Implementation Notes

### Existing Infrastructure

The codebase already has foundational support for ephemeral certificates:
- `CertificateUtilities.GetKeyStorageFlags()` supports `X509KeyStorageFlags.EphemeralKeySet` (line 80)
- Conditional file output patterns exist in `CreateService.cs`
- `OptionBuilders` provides reusable option creation

### Backward Compatibility

- Both flags default to `false`, preserving existing behavior
- Existing tests remain unaffected
- File output remains the default mode
