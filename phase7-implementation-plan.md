# Phase 7: Certificate Renewal Command

**Status:** Not Started
**Created:** 2026-02-08

## Objective

Implement `certz renew <source>` command that reads an existing certificate, auto-detects its parameters (subject, SANs, key type, etc.), and creates a new certificate with extended validity.

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

## Command Specification

```
certz renew <source> [options]

Arguments:
  source              Existing certificate (file path or thumbprint)

Options:
  --days, -d          New validity period in days (default: same as original, max 398)
  --password, -p      Password for source PFX (or env: CERTZ_PASSWORD)
  --out, -o           Output file path (default: <original>-renewed.pfx)
  --out-password      Password for output file (generates if not specified)
  --keep-key          Preserve existing private key (default: generate new)
  --issuer-cert       CA certificate for signing (required if original was CA-signed)
  --issuer-key        CA private key (PEM format)
  --issuer-password   Password for issuer PFX
  --store             Source store name for thumbprint lookup
  --location          Store location (CurrentUser, LocalMachine)
  --format            Output format: text (default), json

Exit Codes:
  0 = Success
  1 = Source certificate not found or invalid
  2 = Cannot renew (missing issuer for CA-signed cert)
```

## Design Decisions

| Area | Decision | Rationale |
|------|----------|-----------|
| **Default validity** | Preserve original duration (max 398) | Consistency with original cert |
| **Key handling** | Generate new key by default | Security best practice |
| **CA-signed detection** | Compare Subject vs Issuer | Standard approach |
| **Output naming** | `<original>-renewed.pfx` | Clear naming convention |
| **Password handling** | Generate if not specified | Consistent with create commands |

## Progress Tracker

| # | Step | Status | Notes |
|---|------|--------|-------|
| 1 | Create RenewOptions model | [ ] | Models/RenewOptions.cs |
| 2 | Create RenewResult model | [ ] | Models/RenewResult.cs |
| 3 | Create RenewService | [ ] | Services/RenewService.cs |
| 4 | Create RenewCommand | [ ] | Commands/Renew/RenewCommand.cs |
| 5 | Add formatter methods | [ ] | IOutputFormatter, TextFormatter, JsonFormatter |
| 6 | Register command | [ ] | Program.cs |
| 7 | Create tests | [ ] | test/test-renew.ps1 |
| 8 | Update documentation | [ ] | README.md |

---

## Implementation Steps

### Step 1: Create RenewOptions Model

**Create:** `Models/RenewOptions.cs`

```csharp
namespace certz.Models;

/// <summary>
/// Options for the renew command.
/// </summary>
internal record RenewOptions
{
    /// <summary>
    /// Source certificate (file path or thumbprint).
    /// </summary>
    public required string Source { get; init; }

    /// <summary>
    /// New validity period in days. Null preserves original duration.
    /// </summary>
    public int? Days { get; init; }

    /// <summary>
    /// Password for source PFX file.
    /// </summary>
    public string? Password { get; init; }

    /// <summary>
    /// Output file path.
    /// </summary>
    public FileInfo? OutputFile { get; init; }

    /// <summary>
    /// Password for output file.
    /// </summary>
    public string? OutputPassword { get; init; }

    /// <summary>
    /// Preserve existing private key instead of generating new.
    /// </summary>
    public bool KeepKey { get; init; }

    /// <summary>
    /// Issuer certificate for signing (required for CA-signed certs).
    /// </summary>
    public FileInfo? IssuerCert { get; init; }

    /// <summary>
    /// Issuer private key file (PEM format).
    /// </summary>
    public FileInfo? IssuerKey { get; init; }

    /// <summary>
    /// Password for issuer PFX.
    /// </summary>
    public string? IssuerPassword { get; init; }

    /// <summary>
    /// Certificate store name for thumbprint lookup.
    /// </summary>
    public string? StoreName { get; init; }

    /// <summary>
    /// Store location (CurrentUser, LocalMachine).
    /// </summary>
    public string? StoreLocation { get; init; }
}
```

**Status:** [ ] Not Started

---

### Step 2: Create RenewResult Model

**Create:** `Models/RenewResult.cs`

```csharp
namespace certz.Models;

/// <summary>
/// Result of certificate renewal operation.
/// </summary>
internal record RenewResult
{
    /// <summary>
    /// Whether the renewal succeeded.
    /// </summary>
    public bool Success { get; init; }

    /// <summary>
    /// Error message if renewal failed.
    /// </summary>
    public string? ErrorMessage { get; init; }

    // Original certificate info
    /// <summary>
    /// Subject of the original certificate.
    /// </summary>
    public required string OriginalSubject { get; init; }

    /// <summary>
    /// Thumbprint of the original certificate.
    /// </summary>
    public required string OriginalThumbprint { get; init; }

    /// <summary>
    /// Expiration date of the original certificate.
    /// </summary>
    public required DateTime OriginalNotAfter { get; init; }

    // Renewed certificate info
    /// <summary>
    /// Subject of the renewed certificate.
    /// </summary>
    public string? NewSubject { get; init; }

    /// <summary>
    /// Thumbprint of the renewed certificate.
    /// </summary>
    public string? NewThumbprint { get; init; }

    /// <summary>
    /// Start date of the renewed certificate.
    /// </summary>
    public DateTime? NewNotBefore { get; init; }

    /// <summary>
    /// Expiration date of the renewed certificate.
    /// </summary>
    public DateTime? NewNotAfter { get; init; }

    /// <summary>
    /// Path to the output file.
    /// </summary>
    public string? OutputFile { get; init; }

    /// <summary>
    /// Password for the output file (if generated).
    /// </summary>
    public string? Password { get; init; }

    /// <summary>
    /// Whether the password was auto-generated.
    /// </summary>
    public bool PasswordWasGenerated { get; init; }

    // Detected parameters (for display)
    /// <summary>
    /// Subject Alternative Names from the certificate.
    /// </summary>
    public string[]? SANs { get; init; }

    /// <summary>
    /// Key algorithm used.
    /// </summary>
    public string? KeyType { get; init; }

    /// <summary>
    /// Whether the original key was preserved.
    /// </summary>
    public bool KeyWasPreserved { get; init; }

    /// <summary>
    /// Whether the cert was re-signed by a CA.
    /// </summary>
    public bool WasResigned { get; init; }
}
```

**Status:** [ ] Not Started

---

### Step 3: Create RenewService

**Create:** `Services/RenewService.cs`

```csharp
using certz.Models;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace certz.Services;

/// <summary>
/// Service for renewing certificates.
/// </summary>
internal static class RenewService
{
    /// <summary>
    /// Renews a certificate by creating a new one with the same parameters.
    /// </summary>
    internal static async Task<RenewResult> RenewCertificate(RenewOptions options)
    {
        // 1. Load source certificate
        X509Certificate2 sourceCert;
        try
        {
            sourceCert = LoadSourceCertificate(options);
        }
        catch (Exception ex)
        {
            return new RenewResult
            {
                Success = false,
                ErrorMessage = $"Failed to load source certificate: {ex.Message}",
                OriginalSubject = options.Source,
                OriginalThumbprint = "",
                OriginalNotAfter = DateTime.MinValue
            };
        }

        // 2. Extract parameters from existing cert
        var detectedParams = ExtractCertificateParameters(sourceCert);

        // 3. Determine if CA-signed
        var isSelfSigned = sourceCert.Subject == sourceCert.Issuer;
        if (!isSelfSigned && options.IssuerCert == null)
        {
            return new RenewResult
            {
                Success = false,
                ErrorMessage = "Certificate was signed by a CA. Provide --issuer-cert to renew.",
                OriginalSubject = sourceCert.Subject,
                OriginalThumbprint = sourceCert.Thumbprint,
                OriginalNotAfter = sourceCert.NotAfter,
                SANs = detectedParams.SANs,
                KeyType = detectedParams.KeyType
            };
        }

        // 4. Calculate new validity
        var originalDays = (sourceCert.NotAfter - sourceCert.NotBefore).Days;
        var newDays = options.Days ?? Math.Min(originalDays, 398);

        // 5. Handle password
        bool passwordWasGenerated = false;
        var outputPassword = options.OutputPassword;
        if (string.IsNullOrEmpty(outputPassword))
        {
            outputPassword = CertificateUtilities.GenerateSecurePassword();
            passwordWasGenerated = true;
        }

        // 6. Determine output file
        var outputFile = options.OutputFile?.FullName
            ?? GetDefaultOutputPath(options.Source);

        // 7. Generate or preserve key, create new certificate
        X509Certificate2 renewedCert;
        try
        {
            if (options.KeepKey && sourceCert.HasPrivateKey)
            {
                renewedCert = RenewWithExistingKey(sourceCert, detectedParams, newDays, options);
            }
            else
            {
                renewedCert = RenewWithNewKey(sourceCert, detectedParams, newDays, options);
            }
        }
        catch (Exception ex)
        {
            return new RenewResult
            {
                Success = false,
                ErrorMessage = $"Failed to create renewed certificate: {ex.Message}",
                OriginalSubject = sourceCert.Subject,
                OriginalThumbprint = sourceCert.Thumbprint,
                OriginalNotAfter = sourceCert.NotAfter
            };
        }

        // 8. Save to output file
        await CertificateUtilities.WriteCertificateToFile(
            renewedCert,
            outputFile,
            outputPassword,
            CertificateFileType.Pfx,
            displayPassword: false,
            passwordFile: null,
            pfxEncryption: "modern",
            quiet: true);

        return new RenewResult
        {
            Success = true,
            OriginalSubject = sourceCert.Subject,
            OriginalThumbprint = sourceCert.Thumbprint,
            OriginalNotAfter = sourceCert.NotAfter,
            NewSubject = renewedCert.Subject,
            NewThumbprint = renewedCert.Thumbprint,
            NewNotBefore = renewedCert.NotBefore,
            NewNotAfter = renewedCert.NotAfter,
            OutputFile = outputFile,
            Password = passwordWasGenerated ? outputPassword : null,
            PasswordWasGenerated = passwordWasGenerated,
            SANs = detectedParams.SANs,
            KeyType = detectedParams.KeyType,
            KeyWasPreserved = options.KeepKey,
            WasResigned = !isSelfSigned
        };
    }

    private static X509Certificate2 LoadSourceCertificate(RenewOptions options)
    {
        // Check if source is a file
        if (File.Exists(options.Source))
        {
            var ext = Path.GetExtension(options.Source).ToLowerInvariant();
            if (ext is ".pfx" or ".p12")
            {
                var password = options.Password ?? Environment.GetEnvironmentVariable("CERTZ_PASSWORD");
                return X509CertificateLoader.LoadPkcs12FromFile(
                    options.Source,
                    password,
                    X509KeyStorageFlags.Exportable);
            }
            else
            {
                return new X509Certificate2(options.Source);
            }
        }

        // Try as thumbprint in store
        var storeName = options.StoreName ?? "My";
        var storeLocation = options.StoreLocation == "LocalMachine"
            ? StoreLocation.LocalMachine
            : StoreLocation.CurrentUser;

        using var store = new X509Store(storeName, storeLocation);
        store.Open(OpenFlags.ReadOnly);
        var found = store.Certificates.Find(X509FindType.FindByThumbprint, options.Source, false);
        if (found.Count == 0)
        {
            throw new FileNotFoundException($"Certificate not found: {options.Source}");
        }
        return found[0];
    }

    private static CertificateParameters ExtractCertificateParameters(X509Certificate2 cert)
    {
        var sans = new List<string>();
        var sanExt = cert.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
        if (sanExt != null)
        {
            foreach (var dns in sanExt.EnumerateDnsNames()) sans.Add(dns);
            foreach (var ip in sanExt.EnumerateIPAddresses()) sans.Add(ip.ToString());
        }

        string keyType;
        int keySize;
        if (cert.GetECDsaPublicKey() is ECDsa ecdsa)
        {
            keySize = ecdsa.KeySize;
            keyType = keySize switch
            {
                256 => "ECDSA-P256",
                384 => "ECDSA-P384",
                521 => "ECDSA-P521",
                _ => $"ECDSA-{keySize}"
            };
        }
        else if (cert.GetRSAPublicKey() is RSA rsa)
        {
            keySize = rsa.KeySize;
            keyType = "RSA";
        }
        else
        {
            keyType = "Unknown";
            keySize = 0;
        }

        var isCa = cert.Extensions.OfType<X509BasicConstraintsExtension>()
            .FirstOrDefault()?.CertificateAuthority ?? false;

        return new CertificateParameters
        {
            Subject = cert.Subject,
            SANs = sans.ToArray(),
            KeyType = keyType,
            KeySize = keySize,
            IsCA = isCa,
            HashAlgorithm = cert.SignatureAlgorithm.FriendlyName ?? "SHA256"
        };
    }

    private static string GetDefaultOutputPath(string source)
    {
        if (File.Exists(source))
        {
            var dir = Path.GetDirectoryName(source) ?? ".";
            var name = Path.GetFileNameWithoutExtension(source);
            return Path.Combine(dir, $"{name}-renewed.pfx");
        }
        return $"renewed-{source[..8]}.pfx";
    }

    private static X509Certificate2 RenewWithExistingKey(
        X509Certificate2 source,
        CertificateParameters detectedParams,
        int days,
        RenewOptions options)
    {
        // Implementation: Create new cert request with existing key
        // Sign with self or issuer
        throw new NotImplementedException("Implement key preservation logic");
    }

    private static X509Certificate2 RenewWithNewKey(
        X509Certificate2 source,
        CertificateParameters detectedParams,
        int days,
        RenewOptions options)
    {
        // Implementation: Generate new key, create cert with same parameters
        // Use CertificateGeneration.GenerateCertificate or GenerateSignedCertificate
        throw new NotImplementedException("Implement new key generation logic");
    }

    private record CertificateParameters
    {
        public required string Subject { get; init; }
        public required string[] SANs { get; init; }
        public required string KeyType { get; init; }
        public required int KeySize { get; init; }
        public required bool IsCA { get; init; }
        public required string HashAlgorithm { get; init; }
    }
}
```

**Status:** [ ] Not Started

---

### Step 4: Create RenewCommand

**Create:** `Commands/Renew/RenewCommand.cs`

```csharp
using certz.Formatters;
using certz.Models;
using certz.Options;
using certz.Services;

namespace certz.Commands.Renew;

/// <summary>
/// The renew command for extending certificate validity.
/// </summary>
internal static class RenewCommand
{
    /// <summary>
    /// Adds the renew command to the root command.
    /// </summary>
    internal static void AddRenewCommand(this RootCommand rootCommand)
    {
        var command = BuildRenewCommand();
        rootCommand.Add(command);
    }

    private static Command BuildRenewCommand()
    {
        // Source argument
        var sourceArgument = new Argument<string>("source")
        {
            Description = "Existing certificate (file path or thumbprint)"
        };

        // Options
        var daysOption = new Option<int?>("--days", "-d")
        {
            Description = "New validity period in days (default: same as original, max 398)"
        };

        var passwordOption = OptionBuilders.CreatePasswordOption();

        var outOption = new Option<FileInfo?>("--out", "-o")
        {
            Description = "Output file path (default: <original>-renewed.pfx)"
        };

        var outPasswordOption = new Option<string?>("--out-password")
        {
            Description = "Password for output file (generates if not specified)"
        };

        var keepKeyOption = new Option<bool>("--keep-key")
        {
            Description = "Preserve existing private key instead of generating new",
            DefaultValueFactory = _ => false
        };

        var issuerCertOption = OptionBuilders.CreateIssuerCertOption();
        var issuerKeyOption = OptionBuilders.CreateIssuerKeyOption();
        var issuerPasswordOption = OptionBuilders.CreateIssuerPasswordOption();

        var storeOption = new Option<string?>("--store")
        {
            Description = "Certificate store name for thumbprint lookup (My, Root, CA)"
        };

        var locationOption = new Option<string?>("--location", "-l")
        {
            Description = "Store location (CurrentUser, LocalMachine)"
        };

        var formatOption = OptionBuilders.CreateFormatOption();

        var command = new Command("renew", "Renew an existing certificate with extended validity")
        {
            sourceArgument,
            daysOption,
            passwordOption,
            outOption,
            outPasswordOption,
            keepKeyOption,
            issuerCertOption,
            issuerKeyOption,
            issuerPasswordOption,
            storeOption,
            locationOption,
            formatOption
        };

        command.SetAction(async (parseResult) =>
        {
            var source = parseResult.GetValue(sourceArgument)
                ?? throw new ArgumentException("Source argument is required.");
            var format = parseResult.GetValue(formatOption) ?? "text";
            var formatter = FormatterFactory.Create(format);

            var options = new RenewOptions
            {
                Source = source,
                Days = parseResult.GetValue(daysOption),
                Password = parseResult.GetValue(passwordOption),
                OutputFile = parseResult.GetValue(outOption),
                OutputPassword = parseResult.GetValue(outPasswordOption),
                KeepKey = parseResult.GetValue(keepKeyOption),
                IssuerCert = parseResult.GetValue(issuerCertOption),
                IssuerKey = parseResult.GetValue(issuerKeyOption),
                IssuerPassword = parseResult.GetValue(issuerPasswordOption),
                StoreName = parseResult.GetValue(storeOption),
                StoreLocation = parseResult.GetValue(locationOption)
            };

            var result = await RenewService.RenewCertificate(options);
            formatter.WriteRenewResult(result);

            // Set exit code based on result
            if (!result.Success)
            {
                Environment.ExitCode = result.ErrorMessage?.Contains("CA") == true ? 2 : 1;
            }
        });

        return command;
    }
}
```

**Status:** [ ] Not Started

---

### Step 5: Add Formatter Methods

**Modify:** `Formatters/IOutputFormatter.cs`

```csharp
void WriteRenewResult(RenewResult result);
```

**Modify:** `Formatters/TextFormatter.cs`

```csharp
public void WriteRenewResult(RenewResult result)
{
    if (!result.Success)
    {
        _console.MarkupLine($"[red]Renewal Failed[/]");
        _console.MarkupLine($"[red]Error:[/] {result.ErrorMessage}");
        _console.WriteLine();
        _console.MarkupLine($"[bold]Original Certificate:[/]");
        _console.MarkupLine($"  Subject: {result.OriginalSubject}");
        _console.MarkupLine($"  Thumbprint: {result.OriginalThumbprint}");
        _console.MarkupLine($"  Expires: {result.OriginalNotAfter:yyyy-MM-dd}");
        return;
    }

    _console.Write(new Rule("[green]Certificate Renewed[/]").LeftJustified());
    _console.WriteLine();

    // Original cert info
    var table = new Table()
        .Border(TableBorder.Rounded)
        .AddColumn("[bold]Property[/]")
        .AddColumn("[bold]Original[/]")
        .AddColumn("[bold]Renewed[/]");

    table.AddRow("Subject", result.OriginalSubject, result.NewSubject ?? "-");
    table.AddRow("Thumbprint",
        $"[dim]{result.OriginalThumbprint[..16]}...[/]",
        $"[cyan]{result.NewThumbprint?[..16]}...[/]");
    table.AddRow("Expires",
        $"[yellow]{result.OriginalNotAfter:yyyy-MM-dd}[/]",
        $"[green]{result.NewNotAfter:yyyy-MM-dd}[/]");

    _console.Write(table);
    _console.WriteLine();

    // Details
    _console.MarkupLine($"[bold]Key:[/] {result.KeyType} {(result.KeyWasPreserved ? "[dim](preserved)[/]" : "[dim](new)[/]")}");

    if (result.SANs?.Length > 0)
    {
        _console.MarkupLine($"[bold]SANs:[/] {string.Join(", ", result.SANs)}");
    }

    _console.MarkupLine($"[bold]Output:[/] {result.OutputFile}");

    if (result.PasswordWasGenerated && result.Password != null)
    {
        _console.WriteLine();
        _console.MarkupLine("[yellow]Generated Password (save securely):[/]");
        _console.MarkupLine($"[bold cyan]{result.Password}[/]");
    }
}
```

**Modify:** `Formatters/JsonFormatter.cs`

Add DTO and serialization for RenewResult.

**Status:** [ ] Not Started

---

### Step 6: Register Command

**Modify:** `Program.cs`

```csharp
using certz.Commands.Renew;

// In command registration section:
rootCommand.AddRenewCommand();
```

**Status:** [ ] Not Started

---

### Step 7: Create Tests

**Create:** `test/test-renew.ps1`

```powershell
#Requires -Version 7.5

<#
.SYNOPSIS
    Test suite for certz renew command.

.DESCRIPTION
    Tests certificate renewal functionality including self-signed certs,
    CA-signed certs, key preservation, and custom validity periods.
    Follows test isolation principles from test-isolation-plan.md.

.PARAMETER TestId
    Run specific tests by ID. Example: -TestId "ren-1.1", "ren-2.1"

.PARAMETER Category
    Run tests by category: self-signed, ca-signed, keep-key, validity, errors, format

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
. "$PSScriptRoot\test-helper.ps1"

# Test categories
$script:TestCategories = @{
    "self-signed" = @("ren-1.1", "ren-1.2", "ren-1.3")
    "ca-signed" = @("ren-2.1", "ren-2.2")
    "keep-key" = @("ren-3.1", "ren-3.2")
    "validity" = @("ren-4.1", "ren-4.2")
    "errors" = @("ren-5.1", "ren-5.2")
    "format" = @("ren-6.1")
}

# ren-1.1: Renew self-signed certificate with default options
Invoke-Test -TestId "ren-1.1" -TestName "Renew self-signed cert (defaults)" -FilePrefix "ren" -TestScript {
    # SETUP: Create self-signed certificate
    $testGuid = [guid]::NewGuid().ToString().Substring(0, 8)
    $subject = "CN=renew-test-$testGuid"
    $password = ConvertTo-SecureString "testpass" -AsPlainText -Force

    $cert = New-SelfSignedCertificate -Subject $subject -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(30)
    Export-PfxCertificate -Cert $cert -FilePath "ren-original-$testGuid.pfx" -Password $password | Out-Null
    Remove-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)" -Force

    try {
        # ACTION: Single certz invocation
        & .\certz.exe renew "ren-original-$testGuid.pfx" --password testpass --out "ren-renewed-$testGuid.pfx" --out-password testpass
        $exitCode = $LASTEXITCODE

        # ASSERTIONS
        if ($exitCode -ne 0) {
            throw "Expected exit code 0, got $exitCode"
        }

        if (-not (Test-Path "ren-renewed-$testGuid.pfx")) {
            throw "Output file not created"
        }

        $renewed = Get-PfxCertificate -FilePath "ren-renewed-$testGuid.pfx" -Password $password
        if ($renewed.Subject -ne $subject) {
            throw "Subject mismatch: expected '$subject', got '$($renewed.Subject)'"
        }
        if ($renewed.NotAfter -le (Get-Date)) {
            throw "Renewed cert should have future expiration"
        }

        @{ Success = $true; Details = "Self-signed certificate renewed successfully" }
    }
    finally {
        # CLEANUP
        if (-not $SkipCleanup) {
            Remove-Item "ren-original-$testGuid.pfx", "ren-renewed-$testGuid.pfx" -Force -ErrorAction SilentlyContinue
        }
    }
}

# ren-2.1: Renew CA-signed certificate with issuer
Invoke-Test -TestId "ren-2.1" -TestName "Renew CA-signed cert with issuer" -FilePrefix "ren" -TestScript {
    # SETUP: Create CA and signed certificate using PowerShell
    $testGuid = [guid]::NewGuid().ToString().Substring(0, 8)
    $password = ConvertTo-SecureString "testpass" -AsPlainText -Force

    # Create CA
    $ca = New-SelfSignedCertificate -Subject "CN=Test CA $testGuid" -CertStoreLocation Cert:\CurrentUser\My `
        -KeyUsage CertSign, CRLSign -TextExtension @("2.5.29.19={critical}{text}CA=true")
    Export-PfxCertificate -Cert $ca -FilePath "ren-ca-$testGuid.pfx" -Password $password | Out-Null

    # Create signed cert
    $signed = New-SelfSignedCertificate -Subject "CN=Signed Cert $testGuid" -CertStoreLocation Cert:\CurrentUser\My `
        -Signer $ca -NotAfter (Get-Date).AddDays(30)
    Export-PfxCertificate -Cert $signed -FilePath "ren-signed-$testGuid.pfx" -Password $password | Out-Null

    Remove-Item "Cert:\CurrentUser\My\$($ca.Thumbprint)" -Force
    Remove-Item "Cert:\CurrentUser\My\$($signed.Thumbprint)" -Force

    try {
        # ACTION: Single certz invocation
        & .\certz.exe renew "ren-signed-$testGuid.pfx" --password testpass `
            --issuer-cert "ren-ca-$testGuid.pfx" --issuer-password testpass `
            --out "ren-renewed-$testGuid.pfx" --out-password testpass
        $exitCode = $LASTEXITCODE

        # ASSERTIONS
        if ($exitCode -ne 0) {
            throw "Expected exit code 0, got $exitCode"
        }

        if (-not (Test-Path "ren-renewed-$testGuid.pfx")) {
            throw "Output file not created"
        }

        @{ Success = $true; Details = "CA-signed certificate renewed with issuer" }
    }
    finally {
        # CLEANUP
        if (-not $SkipCleanup) {
            Remove-Item "ren-ca-$testGuid.pfx", "ren-signed-$testGuid.pfx", "ren-renewed-$testGuid.pfx" -Force -ErrorAction SilentlyContinue
        }
    }
}

# ren-5.1: Error when CA-signed cert renewed without issuer
Invoke-Test -TestId "ren-5.1" -TestName "Error: CA-signed cert without issuer" -FilePrefix "ren" -TestScript {
    # SETUP: Create CA-signed certificate
    $testGuid = [guid]::NewGuid().ToString().Substring(0, 8)
    $password = ConvertTo-SecureString "testpass" -AsPlainText -Force

    $ca = New-SelfSignedCertificate -Subject "CN=Test CA $testGuid" -CertStoreLocation Cert:\CurrentUser\My `
        -KeyUsage CertSign -TextExtension @("2.5.29.19={critical}{text}CA=true")
    $signed = New-SelfSignedCertificate -Subject "CN=Signed $testGuid" -CertStoreLocation Cert:\CurrentUser\My -Signer $ca
    Export-PfxCertificate -Cert $signed -FilePath "ren-signed-$testGuid.pfx" -Password $password | Out-Null

    Remove-Item "Cert:\CurrentUser\My\$($ca.Thumbprint)" -Force
    Remove-Item "Cert:\CurrentUser\My\$($signed.Thumbprint)" -Force

    try {
        # ACTION: Single certz invocation (should fail)
        & .\certz.exe renew "ren-signed-$testGuid.pfx" --password testpass 2>&1 | Out-Null
        $exitCode = $LASTEXITCODE

        # ASSERTIONS
        if ($exitCode -ne 2) {
            throw "Expected exit code 2 (missing issuer), got $exitCode"
        }

        @{ Success = $true; Details = "Correctly failed with exit code 2 for missing issuer" }
    }
    finally {
        # CLEANUP
        if (-not $SkipCleanup) {
            Remove-Item "ren-signed-$testGuid.pfx" -Force -ErrorAction SilentlyContinue
        }
    }
}

# ren-6.1: JSON output format
Invoke-Test -TestId "ren-6.1" -TestName "JSON output format" -FilePrefix "ren" -TestScript {
    # SETUP
    $testGuid = [guid]::NewGuid().ToString().Substring(0, 8)
    $password = ConvertTo-SecureString "testpass" -AsPlainText -Force

    $cert = New-SelfSignedCertificate -Subject "CN=json-test-$testGuid" -CertStoreLocation Cert:\CurrentUser\My
    Export-PfxCertificate -Cert $cert -FilePath "ren-json-$testGuid.pfx" -Password $password | Out-Null
    Remove-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)" -Force

    try {
        # ACTION
        $output = & .\certz.exe renew "ren-json-$testGuid.pfx" --password testpass --out "ren-json-renewed-$testGuid.pfx" --out-password testpass --format json
        $exitCode = $LASTEXITCODE

        # ASSERTIONS
        if ($exitCode -ne 0) {
            throw "Expected exit code 0, got $exitCode"
        }

        $json = $output | ConvertFrom-Json
        if (-not $json.success) {
            throw "Expected success=true in JSON"
        }
        if (-not $json.newThumbprint) {
            throw "Expected newThumbprint in JSON"
        }

        @{ Success = $true; Details = "Valid JSON output with expected fields" }
    }
    finally {
        if (-not $SkipCleanup) {
            Remove-Item "ren-json-$testGuid.pfx", "ren-json-renewed-$testGuid.pfx" -Force -ErrorAction SilentlyContinue
        }
    }
}

# Run tests
Invoke-TestSuite -TestId $TestId -Category $Category -Verbose:$Verbose
```

**Status:** [ ] Not Started

---

### Step 8: Update Documentation

**Modify:** `README.md`

Add renew command section with examples:

```markdown
## Renew Command

Renew an existing certificate with extended validity while preserving its parameters.

### Basic Usage

```bash
# Renew a self-signed certificate
certz renew server.pfx --password secret

# Renew with custom validity
certz renew server.pfx --password secret --days 90

# Renew CA-signed certificate (requires issuer)
certz renew server.pfx --password secret --issuer-cert ca.pfx --issuer-password capass

# Preserve original private key
certz renew server.pfx --password secret --keep-key

# Specify output file
certz renew server.pfx --password secret --out server-2024.pfx
```

### Options

| Option | Description |
|--------|-------------|
| `--days, -d` | New validity period (default: original, max 398) |
| `--password, -p` | Password for source PFX |
| `--out, -o` | Output file path |
| `--out-password` | Password for output (auto-generated if not set) |
| `--keep-key` | Preserve existing private key |
| `--issuer-cert` | CA certificate for re-signing |
| `--issuer-key` | CA private key (PEM) |
| `--issuer-password` | CA certificate password |
| `--format` | Output format: text, json |
```

**Status:** [ ] Not Started

---

## Verification Checklist

- [ ] `dotnet build` succeeds
- [ ] `certz renew --help` shows correct usage
- [ ] Self-signed cert renewal works
- [ ] CA-signed cert renewal with `--issuer-cert` works
- [ ] `--keep-key` preserves private key
- [ ] `--days` sets custom validity (capped at 398)
- [ ] Missing issuer for CA-signed cert returns exit code 2
- [ ] `--format json` outputs valid JSON
- [ ] Exit codes are correct (0=success, 1=not found, 2=missing issuer)
- [ ] `.\test\test-renew.ps1` passes

---

## Reference Files

Review these for implementation patterns:
- `Commands/Create/CreateDevCommand.cs` - command structure
- `Services/CreateService.cs` - certificate generation flow
- `Models/DevCertificateOptions.cs` - options pattern
- `Services/CertificateInspector.cs` - loading certs from various sources
- `Services/CertificateGeneration.cs` - key and cert generation
- `test/test-create.ps1` - test structure

---

## Notes & Adjustments

*Record any changes during implementation:*

1. _(none yet)_
