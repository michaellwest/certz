# Phase 1: Infrastructure + Create Commands

**Status:** Completed
**Last Updated:** 2026-02-01

## Overview
Implement Phase 1 of the certz v2.0 migration: add Spectre.Console, output formatters, and hierarchical `create dev`/`create ca` commands.

## Progress Tracker

| # | Step | Status | Notes |
|---|------|--------|-------|
| 1 | Create test-create.ps1 Test Script | [x] | Completed |
| 2 | Add Spectre.Console Package | [x] | Completed |
| 3 | Create Output Formatter Infrastructure | [x] | Completed |
| 4 | Add Result Models | [x] | Completed |
| 5 | Add Global --format Option | [x] | Completed |
| 6 | Create Certificate Wizard Service | [x] | Completed |
| 7 | Create Hierarchical Command Structure | [x] | Completed |
| 8 | Transform CreateCommand to Parent | [x] | Completed |
| 9 | Add Issuer Signing Support | [x] | Completed |
| 10 | Create V2 Operations Wrapper | [x] | Completed |
| 11 | Update GlobalUsings | [x] | Completed |

---

## Implementation Steps

### Step 1: Create test-create.ps1 Test Script
**New file:** `test-create.ps1`

Create a dedicated test script for the `create` command (and subcommands `create dev`, `create ca`). This script follows the test isolation principles from test-isolation-plan.md:

**Test Isolation Rules:**
- Each test invokes `certz.exe` exactly ONCE
- Setup and teardown use pure PowerShell (no certz calls)
- Assert against system state (files, cert store), NOT console output

**Script Structure:**
```powershell
<#
.SYNOPSIS
    Test suite for certz create commands (create dev, create ca).
.PARAMETER TestId
    Run specific tests by ID. Example: -TestId "dev-1.1", "ca-1.1"
.PARAMETER Category
    Run tests by category: create-dev, create-ca, format, issuer, trust
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
    "create-dev" = @("dev-1.1", "dev-1.2", "dev-1.3", "dev-1.4", "dev-1.5")
    "create-ca" = @("ca-1.1", "ca-1.2", "ca-1.3")
    "format" = @("fmt-1.1", "fmt-1.2")
    "issuer" = @("iss-1.1", "iss-1.2")
    "trust" = @("tru-1.1", "tru-1.2")
    "guided" = @("gui-1.1")  # Interactive tests (manual only)
}

# Include shared assertion functions (or copy from test-all.ps1)
# Assert-FileExists, Assert-CertificateInStore, etc.
```

**Test Cases to Implement:**

| Test ID | Category | Description | certz Command |
|---------|----------|-------------|---------------|
| dev-1.1 | create-dev | Basic dev cert with domain argument | `create dev api.local --f test.pfx --p Pass` |
| dev-1.2 | create-dev | Dev cert with custom SANs | `create dev api.local --san localhost --san 127.0.0.1 --f test.pfx --p Pass` |
| dev-1.3 | create-dev | Dev cert with ECDSA-P384 key | `create dev api.local --key-type ECDSA-P384 --f test.pfx --p Pass` |
| dev-1.4 | create-dev | Dev cert with RSA-3072 key | `create dev api.local --key-type RSA --key-size 3072 --f test.pfx --p Pass` |
| dev-1.5 | create-dev | Dev cert with custom validity | `create dev api.local --days 30 --f test.pfx --p Pass` |
| ca-1.1 | create-ca | Basic CA cert with name | `create ca --name "Dev Root CA" --f ca.pfx --p Pass` |
| ca-1.2 | create-ca | CA cert with path length 1 | `create ca --name "Intermediate CA" --path-length 1 --f ca.pfx --p Pass` |
| ca-1.3 | create-ca | CA cert with 10-year validity | `create ca --name "Root CA" --days 3650 --f ca.pfx --p Pass` |
| fmt-1.1 | format | Dev cert with JSON output | `create dev localhost --format json --f test.pfx --p Pass` |
| fmt-1.2 | format | CA cert with JSON output | `create ca --name "CA" --format json --f ca.pfx --p Pass` |
| iss-1.1 | issuer | Dev cert signed by CA (PFX issuer) | `create dev api.local --issuer-cert ca.pfx --issuer-password CaPass --f dev.pfx --p Pass` |
| iss-1.2 | issuer | Dev cert signed by CA (PEM issuer) | `create dev api.local --issuer-cert ca.cer --issuer-key ca.key --f dev.pfx --p Pass` |
| tru-1.1 | trust | Dev cert with --trust flag | `create dev localhost --trust --f test.pfx --p Pass` |
| tru-1.2 | trust | CA cert with --trust flag | `create ca --name "Trusted CA" --trust --f ca.pfx --p Pass` |
| gui-1.1 | guided | Interactive wizard (manual) | `create dev --guided` |

**Sample Test Implementation:**
```powershell
Invoke-Test -TestId "dev-1.1" -TestName "Create dev cert with domain argument" -FilePrefix "dev-basic" -TestScript {
    # SETUP: None needed (file-based test)

    # ACTION: Single certz.exe call
    $output = & .\certz.exe create dev api.local --f dev-basic.pfx --p TestPass123 2>&1

    # ASSERTION 1: Exit code
    Assert-ExitCode -Expected 0

    # ASSERTION 2: File exists
    Assert-FileExists "dev-basic.pfx"

    # ASSERTION 3: Certificate has correct subject (PowerShell verification)
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        (Resolve-Path "dev-basic.pfx").Path, "TestPass123")
    if ($cert.Subject -notmatch "api\.local") {
        throw "Certificate subject should contain api.local, got: $($cert.Subject)"
    }

    # CLEANUP: Remove test file
    Remove-Item "dev-basic.pfx" -Force -ErrorAction SilentlyContinue

    @{ Success = $true; Details = "Dev cert created with correct subject" }
}

Invoke-Test -TestId "tru-1.1" -TestName "Create dev cert with --trust flag" -FilePrefix "dev-trust" -TestScript {
    $uniqueDomain = "trusttest-$([guid]::NewGuid().ToString().Substring(0,8)).local"

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe create dev $uniqueDomain --trust --f dev-trust.pfx --p TrustPass123 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: File exists
        Assert-FileExists "dev-trust.pfx"

        # ASSERTION 3: Certificate in trust store (PowerShell verification)
        $cert = Assert-CertificateInStore -SubjectPattern "*$uniqueDomain*" -StoreName "Root" -StoreLocation "CurrentUser"

        @{ Success = $true; Details = "Dev cert created and trusted" }
    }
    finally {
        # CLEANUP: Remove from store and file (PowerShell only)
        Get-ChildItem "Cert:\CurrentUser\Root" |
            Where-Object { $_.Subject -like "*$uniqueDomain*" } |
            Remove-Item -Force -ErrorAction SilentlyContinue
        Remove-Item "dev-trust.pfx" -Force -ErrorAction SilentlyContinue
    }
}

Invoke-Test -TestId "fmt-1.1" -TestName "Create dev cert with JSON output" -FilePrefix "fmt-json" -TestScript {
    # ACTION: Single certz.exe call
    $output = & .\certz.exe create dev localhost --format json --f fmt-json.pfx --p TestPass123 2>&1
    $outputStr = $output -join "`n"

    # ASSERTION 1: Exit code
    Assert-ExitCode -Expected 0

    # ASSERTION 2: Valid JSON output
    try {
        $json = $outputStr | ConvertFrom-Json
        if (-not $json.success) { throw "JSON 'success' field should be true" }
        if (-not $json.certificate.thumbprint) { throw "JSON should contain certificate.thumbprint" }
    }
    catch {
        throw "Output is not valid JSON: $outputStr"
    }

    # CLEANUP
    Remove-Item "fmt-json.pfx" -Force -ErrorAction SilentlyContinue

    @{ Success = $true; Details = "Valid JSON output with certificate info" }
}

Invoke-Test -TestId "iss-1.1" -TestName "Create dev cert signed by CA" -FilePrefix "iss-chain" -TestScript {
    # SETUP: Create CA certificate using PowerShell (NOT certz)
    $caParams = @{
        Subject = "CN=Test Issuer CA"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddYears(1)
        KeyUsage = "CertSign", "CRLSign"
        TextExtension = @("2.5.29.19={critical}{text}CA=TRUE")
    }
    $caCert = New-SelfSignedCertificate @caParams

    # Export CA to PFX for certz to use
    $caPassword = ConvertTo-SecureString "CaPass123" -AsPlainText -Force
    Export-PfxCertificate -Cert $caCert -FilePath "iss-chain-ca.pfx" -Password $caPassword | Out-Null

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe create dev signed.local --issuer-cert iss-chain-ca.pfx --issuer-password CaPass123 --f iss-chain-dev.pfx --p DevPass123 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: File exists
        Assert-FileExists "iss-chain-dev.pfx"

        # ASSERTION 3: Certificate has correct issuer (PowerShell verification)
        $devCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            (Resolve-Path "iss-chain-dev.pfx").Path, "DevPass123")
        if ($devCert.Issuer -notmatch "Test Issuer CA") {
            throw "Certificate issuer should be 'Test Issuer CA', got: $($devCert.Issuer)"
        }

        @{ Success = $true; Details = "Dev cert correctly signed by CA" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item $caCert.PSPath -Force -ErrorAction SilentlyContinue
        Remove-Item "iss-chain-ca.pfx" -Force -ErrorAction SilentlyContinue
        Remove-Item "iss-chain-dev.pfx" -Force -ErrorAction SilentlyContinue
    }
}
```

**Status:** [ ] Not Started

---

### Step 2: Add Spectre.Console Package
**File:** `src/certz/certz.csproj`

Add package reference:
```xml
<PackageReference Include="Spectre.Console" Version="0.49.1" />
```

**Status:** [ ] Not Started

---

### Step 3: Create Output Formatter Infrastructure
**New files in `Formatters/`:**

| File | Purpose |
|------|---------|
| `IOutputFormatter.cs` | Interface with `WriteCertificateCreated()`, `WriteError()`, `WriteWarning()`, `WriteSuccess()` |
| `TextFormatter.cs` | Spectre.Console rich text output with tables/panels |
| `JsonFormatter.cs` | JSON output using System.Text.Json |
| `FormatterFactory.cs` | Factory: `Create(string format)` returns appropriate formatter |

**Status:** [ ] Not Started

---

### Step 4: Add Result Models
**New files in `Models/`:**

| File | Purpose |
|------|---------|
| `CertificateCreationResult.cs` | Record with Subject, Thumbprint, NotBefore, NotAfter, SANs, OutputFiles, Password, WasTrusted |
| `DevCertificateOptions.cs` | Options record for dev certificate creation |
| `CACertificateOptions.cs` | Options record for CA certificate creation |

**Status:** [ ] Not Started

---

### Step 5: Add Global --format Option
**File:** `src/certz/Program.cs`

Add global option before command registration:
```csharp
var formatOption = new Option<string>("--format", "--fmt")
{
    Description = "Output format: text (default) or json",
    DefaultValueFactory = _ => "text"
};
rootCommand.Options.Add(formatOption);
```

**Status:** [ ] Not Started

---

### Step 6: Create Certificate Wizard Service
**New file:** `src/certz/Services/CertificateWizard.cs`

Interactive prompts using Spectre.Console:
- `RunDevCertificateWizard()` → prompts for domain, SANs, days, key type, trust
- `RunCACertificateWizard()` → prompts for name, duration, path length

**Status:** [ ] Not Started

---

### Step 7: Create Hierarchical Command Structure
**New directory:** `src/certz/Commands/Create/`

| File | Purpose |
|------|---------|
| `CreateDevCommand.cs` | `certz create dev <domain>` with --guided, --trust, --issuer options |
| `CreateCaCommand.cs` | `certz create ca --name <name>` with CA-specific options |

**Status:** [ ] Not Started

---

### Step 8: Transform CreateCommand to Parent
**Modify:** `src/certz/Commands/CreateCommand.cs`

Change from flat command to parent with subcommands:
```csharp
internal static void AddCreateCommand(this RootCommand rootCommand)
{
    var createCommand = new Command("create", "Certificate creation commands");
    createCommand.AddCommand(CreateDevCommand.BuildCreateDevCommand());
    createCommand.AddCommand(CreateCaCommand.BuildCreateCaCommand());
    rootCommand.Add(createCommand);
}
```

**Status:** [ ] Not Started

---

### Step 9: Add Issuer Signing Support
**Modify:** `src/certz/Services/CertificateGeneration.cs`

Add `GenerateSignedCertificate()` method that:
- Accepts issuer certificate + key
- Uses `CertificateRequest.Create(issuer, ...)` instead of `CreateSelfSigned()`
- Sets proper AKI pointing to issuer

**Status:** [ ] Not Started

---

### Step 10: Create V2 Operations Wrapper
**New file:** `src/certz/Services/CertificateOperationsV2.cs`

Wraps existing operations returning structured `CertificateCreationResult`:
- `CreateDevCertificate(DevCertificateOptions)`
- `CreateCACertificate(CACertificateOptions)`

**Status:** [ ] Not Started

---

### Step 11: Update GlobalUsings
**Modify:** `src/certz/GlobalUsings.cs`
```csharp
global using Spectre.Console;
```

**Status:** [ ] Not Started

---

## New Command Specifications

### `certz create dev`
```
certz create dev <domain> [options]

Arguments:
  domain          Primary domain name (optional if --guided)

Options:
  --guided, -g    Launch interactive wizard
  --trust, -t     Install to CurrentUser\Root store after creation
  --issuer-cert   Path to issuing CA certificate (PFX or PEM)
  --issuer-key    Path to issuing CA private key (if PEM)
  --issuer-password  Password for issuer PFX
  --san           Additional SANs (can repeat)
  --days          Validity period (default: 90)
  --key-type      Key algorithm (default: ECDSA-P256)
  --file, -f      Output PFX path
  --cert, -c      Output certificate PEM path
  --key, -k       Output private key PEM path
  --password, -p  PFX password
  --format        Output format: text or json
```

### `certz create ca`
```
certz create ca [options]

Options:
  --name          CA subject name (required unless --guided)
  --guided, -g    Launch interactive wizard
  --days          Validity period (default: 3650)
  --path-length   Path length constraint (default: 0)
  --crl-url       CRL distribution point URL
  --ocsp-url      OCSP responder URL
  --key-type      Key algorithm (default: ECDSA-P256)
  --file, -f      Output PFX path
  --cert, -c      Output certificate PEM path
  --key, -k       Output private key PEM path
  --password, -p  PFX password
  --format        Output format: text or json
```

---

## Critical Files Reference

| File | Action |
|------|--------|
| `test-create.ps1` | New file - test script for create commands |
| `src/certz/certz.csproj` | Add Spectre.Console package |
| `src/certz/Program.cs` | Add --format global option |
| `src/certz/GlobalUsings.cs` | Add Spectre.Console using |
| `src/certz/Commands/CreateCommand.cs` | Transform to parent command |
| `src/certz/Commands/Create/CreateDevCommand.cs` | New file |
| `src/certz/Commands/Create/CreateCaCommand.cs` | New file |
| `src/certz/Formatters/IOutputFormatter.cs` | New file |
| `src/certz/Formatters/TextFormatter.cs` | New file |
| `src/certz/Formatters/JsonFormatter.cs` | New file |
| `src/certz/Formatters/FormatterFactory.cs` | New file |
| `src/certz/Models/CertificateCreationResult.cs` | New file |
| `src/certz/Models/DevCertificateOptions.cs` | New file |
| `src/certz/Models/CACertificateOptions.cs` | New file |
| `src/certz/Services/CertificateWizard.cs` | New file |
| `src/certz/Services/CertificateOperationsV2.cs` | New file |
| `src/certz/Services/CertificateGeneration.cs` | Add GenerateSignedCertificate method |

---

## Verification Checklist

- [ ] `.\test-create.ps1` runs and all tests pass
- [x] `dotnet build` succeeds
- [x] `certz create dev api.local --f test.pfx --p TestPass123` creates valid cert
- [ ] `certz create dev --guided` launches interactive wizard (manual test)
- [ ] `certz create dev localhost --trust --f test.pfx --p TestPass` installs cert
- [x] `certz create ca --name "Dev Root CA" --f ca.pfx --p CaPass` creates CA cert
- [x] `certz create dev localhost --format json --f test.pfx --p TestPass` outputs JSON
- [x] Issuer chain: dev cert signed by CA cert works
- [ ] `.\test-create.ps1 -Category create-dev` passes
- [ ] `.\test-create.ps1 -Category create-ca` passes
- [ ] `.\test-create.ps1 -Category format` passes

---

## Notes & Adjustments

*Record any changes to the plan during implementation:*

1. **Added `--trust-location` option** (2026-02-01): Added `--trust-location` / `--tl` option to both `create dev` and `create ca` commands to allow users to choose between `CurrentUser` (default, no admin required) and `LocalMachine` (requires admin, system-wide) trust stores.

2. **Fixed JSON serialization for AOT** (2026-02-01): Updated `JsonFormatter.cs` to use source generators (`JsonSerializerContext`) instead of reflection-based serialization, which was failing under Native AOT compilation. Created concrete DTO types (`CertificateDto`, `CertificateCreatedOutput`, etc.) for proper serialization.

