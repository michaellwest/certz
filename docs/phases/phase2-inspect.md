# Phase 2: Inspect + Trust Commands

**Status:** Complete
**Last Updated:** 2026-02-02

## Overview
Implement Phase 2 of the certz v2.0 migration: add the `inspect` command suite (file, URL, thumbprint inspection with chain visualization), `store list` command, and `trust add/remove` commands for trust store management.

## Design Decisions

The following decisions were made for Phase 2 (documented in feature-plan-recommendations.md):

| Area | Decision | Rationale |
|------|----------|-----------|
| **Browser Trust Stores** | Defer to Phase 5 | Separate phase for browser-specific complexity |
| **Revocation Checking** | OCSP preferred, CRL fallback | `--crl` checks OCSP first (faster), falls back to CRL if unavailable |
| **Trust Remove Confirmation** | Interactive unless `--force` | Safer default; prompt before destructive operations |
| **Multiple Subject Matches** | List + require `--force` | Show matching certs; require `--force` to delete multiple at once |
| **Inspect Source Detection** | File exists first | Check if argument is existing file; use `--store` flag to force thumbprint lookup |
| **LocalMachine Permissions** | Fail with clear error | No silent fallback or auto-elevation; provide actionable error message |
| **Export Format** | PEM default + `--save-format` | `--save` defaults to PEM; use `--save-format pem\|der` for explicit format |

## Progress Tracker

| # | Step | Status | Notes |
|---|------|--------|-------|
| 1 | Create test-inspect.ps1 Test Script | [x] | test-inspect.ps1 |
| 2 | Create test-trust.ps1 Test Script | [x] | test-trust.ps1 |
| 3 | Add Certificate Chain Validation Service | [x] | src/certz/Services/Validation/ChainValidator.cs |
| 4 | Add Chain Visualization Service | [x] | src/certz/Services/Validation/ChainVisualizer.cs |
| 5 | Add Inspect Result Models | [x] | src/certz/Models/CertificateInspectResult.cs, src/certz/Models/InspectSource.cs, src/certz/Models/ChainElementInfo.cs, src/certz/Models/InspectOptions.cs |
| 6 | Create Inspect Command Structure | [x] | src/certz/Commands/Inspect/InspectCommand.cs |
| 7 | Implement File Inspection | [x] | src/certz/Services/CertificateInspector.cs - InspectFile() |
| 8 | Implement URL Inspection | [x] | src/certz/Services/CertificateInspector.cs - InspectUrlAsync() |
| 9 | Implement Thumbprint/Store Inspection | [x] | src/certz/Services/CertificateInspector.cs - InspectFromStore() |
| 10 | Add --save and --save-key Export Options | [x] | src/certz/Services/CertificateInspector.cs - SaveCertificate(), SavePrivateKey() |
| 11 | Create Store List Command | [x] | src/certz/Commands/Store/StoreListCommand.cs, src/certz/Services/StoreListHandler.cs |
| 12 | Create Trust Add Command | [x] | src/certz/Commands/Trust/TrustCommand.cs, src/certz/Services/TrustHandler.cs |
| 13 | Create Trust Remove Command | [x] | src/certz/Commands/Trust/TrustCommand.cs - BuildRemoveCommand() |
| 14 | Update Formatters for Inspect Output | [x] | IOutputFormatter, TextFormatter, JsonFormatter |

---

## Implementation Steps

### Step 1: Create test-inspect.ps1 Test Script
**New file:** `test-inspect.ps1`

Create a dedicated test script for the `inspect` command. This script follows the test isolation principles from test-isolation-plan.md:

**Test Isolation Rules:**
- Each test invokes `certz.exe` exactly ONCE
- Setup and teardown use pure PowerShell (no certz calls)
- Assert against system state (files, cert store), NOT console output

**Script Structure:**
```powershell
<#
.SYNOPSIS
    Test suite for certz inspect command.
.PARAMETER TestId
    Run specific tests by ID. Example: -TestId "ins-1.1", "ins-2.1"
.PARAMETER Category
    Run tests by category: inspect-file, inspect-url, inspect-store, chain, save
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
    "inspect-file" = @("ins-1.1", "ins-1.2", "ins-1.3", "ins-1.4", "ins-1.5")
    "inspect-url" = @("ins-2.1", "ins-2.2", "ins-2.3")
    "inspect-store" = @("ins-3.1", "ins-3.2")
    "chain" = @("chn-1.1", "chn-1.2")
    "save" = @("sav-1.1", "sav-1.2", "sav-1.3", "sav-1.4", "sav-1.5")
    "format" = @("fmt-2.1", "fmt-2.2")
}

# Include shared assertion functions
# Assert-FileExists, Assert-CertificateInStore, etc.
```

**Test Cases to Implement:**

| Test ID | Category | Description | certz Command |
|---------|----------|-------------|---------------|
| ins-1.1 | inspect-file | Inspect PFX file | `inspect test.pfx --password Pass` |
| ins-1.2 | inspect-file | Inspect PEM certificate | `inspect test.cer` |
| ins-1.3 | inspect-file | Inspect DER certificate | `inspect test.der` |
| ins-1.4 | inspect-file | Inspect PEM with private key | `inspect test.pem` |
| ins-1.5 | inspect-file | Inspect with expiration warning | `inspect test.pfx --password Pass --warn 30` |
| ins-2.1 | inspect-url | Inspect remote HTTPS URL | `inspect https://example.com` |
| ins-2.2 | inspect-url | Inspect URL with custom port | `inspect https://localhost:8443` |
| ins-2.3 | inspect-url | Inspect URL with chain | `inspect https://example.com --chain` |
| ins-3.1 | inspect-store | Inspect by thumbprint | `inspect <thumbprint>` |
| ins-3.2 | inspect-store | Inspect by thumbprint with store | `inspect <thumbprint> --store CurrentUser` |
| chn-1.1 | chain | Display certificate chain tree | `inspect test.pfx --password Pass --chain` |
| chn-1.2 | chain | Chain with revocation check (OCSP/CRL) | `inspect test.pfx --password Pass --chain --crl` |
| sav-1.1 | save | Save certificate to PEM (default) | `inspect test.pfx --password Pass --save out.cer` |
| sav-1.2 | save | Save certificate and key to PEM | `inspect test.pfx --password Pass --save out.cer --save-key out.key` |
| sav-1.3 | save | Save remote certificate | `inspect https://example.com --save remote.cer` |
| sav-1.4 | save | Save certificate to DER format | `inspect test.pfx --password Pass --save out.der --save-format der` |
| sav-1.5 | save | Save certificate and key to DER | `inspect test.pfx --password Pass --save out.der --save-key out.key --save-format der` |
| fmt-2.1 | format | Inspect with JSON output | `inspect test.pfx --password Pass --format json` |
| fmt-2.2 | format | Inspect URL with JSON output | `inspect https://example.com --format json` |

**Sample Test Implementation:**
```powershell
Invoke-Test -TestId "ins-1.1" -TestName "Inspect PFX file" -FilePrefix "ins-pfx" -TestScript {
    # SETUP: Create a test certificate using PowerShell
    $certParams = @{
        Subject = "CN=ins-test.local"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $password = ConvertTo-SecureString "TestPass123" -AsPlainText -Force
    Export-PfxCertificate -Cert $cert -FilePath "ins-pfx.pfx" -Password $password | Out-Null
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe inspect ins-pfx.pfx --password TestPass123 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Output contains certificate info
        if ($outputStr -notmatch "ins-test\.local") {
            throw "Output should contain subject name 'ins-test.local'"
        }
        if ($outputStr -notmatch "ECDSA") {
            throw "Output should contain key algorithm info"
        }

        @{ Success = $true; Details = "PFX inspection shows certificate details" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item "ins-pfx.pfx" -Force -ErrorAction SilentlyContinue
    }
}

Invoke-Test -TestId "chn-1.1" -TestName "Display certificate chain tree" -FilePrefix "chn-tree" -TestScript {
    # SETUP: Create a CA and signed certificate chain using PowerShell
    $caParams = @{
        Subject = "CN=Chain Test CA"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddYears(1)
        KeyUsage = "CertSign", "CRLSign"
        TextExtension = @("2.5.29.19={critical}{text}CA=TRUE")
    }
    $caCert = New-SelfSignedCertificate @caParams

    $endParams = @{
        Subject = "CN=chain-end.local"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
        Signer = $caCert
    }
    $endCert = New-SelfSignedCertificate @endParams

    $password = ConvertTo-SecureString "ChainPass123" -AsPlainText -Force
    Export-PfxCertificate -Cert $endCert -FilePath "chn-tree.pfx" -Password $password -ChainOption BuildChain | Out-Null

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe inspect chn-tree.pfx --password ChainPass123 --chain 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Output shows chain structure (tree format)
        if ($outputStr -notmatch "Chain Test CA") {
            throw "Chain output should show issuer CA"
        }
        if ($outputStr -notmatch "chain-end\.local") {
            throw "Chain output should show end entity certificate"
        }

        @{ Success = $true; Details = "Chain tree displayed correctly" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item $caCert.PSPath -Force -ErrorAction SilentlyContinue
        Remove-Item $endCert.PSPath -Force -ErrorAction SilentlyContinue
        Remove-Item "chn-tree.pfx" -Force -ErrorAction SilentlyContinue
    }
}

Invoke-Test -TestId "sav-1.1" -TestName "Save certificate to PEM" -FilePrefix "sav-pem" -TestScript {
    # SETUP: Create a test certificate using PowerShell
    $certParams = @{
        Subject = "CN=save-test.local"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $password = ConvertTo-SecureString "SavePass123" -AsPlainText -Force
    Export-PfxCertificate -Cert $cert -FilePath "sav-pem.pfx" -Password $password | Out-Null
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe inspect sav-pem.pfx --password SavePass123 --save sav-pem-out.cer 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Output file exists
        Assert-FileExists "sav-pem-out.cer"

        # ASSERTION 3: Output file contains PEM certificate
        $content = Get-Content "sav-pem-out.cer" -Raw
        if ($content -notmatch "-----BEGIN CERTIFICATE-----") {
            throw "Output file should contain PEM-encoded certificate"
        }

        @{ Success = $true; Details = "Certificate saved to PEM format" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item "sav-pem.pfx" -Force -ErrorAction SilentlyContinue
        Remove-Item "sav-pem-out.cer" -Force -ErrorAction SilentlyContinue
    }
}

Invoke-Test -TestId "sav-1.4" -TestName "Save certificate to DER format" -FilePrefix "sav-der" -TestScript {
    # SETUP: Create a test certificate using PowerShell
    $certParams = @{
        Subject = "CN=save-der-test.local"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $password = ConvertTo-SecureString "SaveDerPass123" -AsPlainText -Force
    Export-PfxCertificate -Cert $cert -FilePath "sav-der.pfx" -Password $password | Out-Null
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe inspect sav-der.pfx --password SaveDerPass123 --save sav-der-out.der --save-format der 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Output file exists
        Assert-FileExists "sav-der-out.der"

        # ASSERTION 3: Output file is DER format (binary, no PEM header)
        $content = Get-Content "sav-der-out.der" -Raw -ErrorAction SilentlyContinue
        if ($content -match "-----BEGIN CERTIFICATE-----") {
            throw "Output file should be DER format (binary), not PEM"
        }

        # ASSERTION 4: File can be loaded as DER certificate
        $derCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            (Resolve-Path "sav-der-out.der").Path)
        if ($derCert.Subject -notmatch "save-der-test\.local") {
            throw "DER certificate subject mismatch"
        }

        @{ Success = $true; Details = "Certificate saved to DER format" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item "sav-der.pfx" -Force -ErrorAction SilentlyContinue
        Remove-Item "sav-der-out.der" -Force -ErrorAction SilentlyContinue
    }
}
```

**Status:** [ ] Not Started

---

### Step 2: Create test-trust.ps1 Test Script
**New file:** `test-trust.ps1`

Create a dedicated test script for `trust add`, `trust remove`, and `store list` commands.

**Script Structure:**
```powershell
<#
.SYNOPSIS
    Test suite for certz trust and store commands.
.PARAMETER TestId
    Run specific tests by ID. Example: -TestId "tru-1.1", "sto-1.1"
.PARAMETER Category
    Run tests by category: trust-add, trust-remove, store-list
.PARAMETER SkipCleanup
    Keep test artifacts after running.
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
    "trust-add" = @("tru-1.1", "tru-1.2", "tru-1.3")
    "trust-remove" = @("trm-1.1", "trm-1.2", "trm-1.3")
    "store-list" = @("sto-1.1", "sto-1.2", "sto-1.3")
}
```

**Test Cases to Implement:**

| Test ID | Category | Description | certz Command |
|---------|----------|-------------|---------------|
| tru-1.1 | trust-add | Add certificate to Root store | `trust add test.cer --store root` |
| tru-1.2 | trust-add | Add PFX to Root store | `trust add test.pfx --password Pass --store root` |
| tru-1.3 | trust-add | Add to LocalMachine store (admin) | `trust add test.cer --store root --location LocalMachine` |
| tru-1.4 | trust-add | LocalMachine without admin fails | `trust add test.cer --location LocalMachine` (expect error) |
| trm-1.1 | trust-remove | Remove by thumbprint with --force | `trust remove <thumbprint> --force` |
| trm-1.2 | trust-remove | Remove by subject pattern with --force | `trust remove --subject "CN=test*" --force` |
| trm-1.3 | trust-remove | Remove from specific store | `trust remove <thumbprint> --store root --force` |
| trm-1.4 | trust-remove | Multiple matches without --force fails | `trust remove --subject "CN=multi*"` (expect error listing matches) |
| sto-1.1 | store-list | List certificates in My store | `store list` |
| sto-1.2 | store-list | List certificates in Root store | `store list --store root` |
| sto-1.3 | store-list | List with JSON output | `store list --format json` |

**Sample Test Implementation:**
```powershell
Invoke-Test -TestId "tru-1.1" -TestName "Add certificate to Root store" -FilePrefix "tru-add" -TestScript {
    $uniqueCN = "trust-add-test-$([guid]::NewGuid().ToString().Substring(0,8))"

    # SETUP: Create a test certificate using PowerShell
    $certParams = @{
        Subject = "CN=$uniqueCN"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    Export-Certificate -Cert $cert -FilePath "tru-add.cer" -Type CERT | Out-Null
    $thumbprint = $cert.Thumbprint
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe trust add tru-add.cer --store root 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Certificate in store (PowerShell verification)
        $foundCert = Get-ChildItem "Cert:\CurrentUser\Root" |
            Where-Object { $_.Thumbprint -eq $thumbprint }
        if (-not $foundCert) {
            throw "Certificate should be in CurrentUser\Root store"
        }

        @{ Success = $true; Details = "Certificate added to Root store" }
    }
    finally {
        # CLEANUP: PowerShell only
        Get-ChildItem "Cert:\CurrentUser\Root" |
            Where-Object { $_.Thumbprint -eq $thumbprint } |
            Remove-Item -Force -ErrorAction SilentlyContinue
        Remove-Item "tru-add.cer" -Force -ErrorAction SilentlyContinue
    }
}

Invoke-Test -TestId "trm-1.1" -TestName "Remove certificate by thumbprint" -FilePrefix "trm-thumb" -TestScript {
    $uniqueCN = "trust-remove-test-$([guid]::NewGuid().ToString().Substring(0,8))"

    # SETUP: Create and install a test certificate using PowerShell
    $certParams = @{
        Subject = "CN=$uniqueCN"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\Root"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $thumbprint = $cert.Thumbprint

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe trust remove $thumbprint 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Certificate removed from store (PowerShell verification)
        $foundCert = Get-ChildItem "Cert:\CurrentUser\Root" |
            Where-Object { $_.Thumbprint -eq $thumbprint }
        if ($foundCert) {
            throw "Certificate should have been removed from store"
        }

        @{ Success = $true; Details = "Certificate removed by thumbprint" }
    }
    finally {
        # CLEANUP: PowerShell only (in case test failed)
        Get-ChildItem "Cert:\CurrentUser\Root" |
            Where-Object { $_.Thumbprint -eq $thumbprint } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
}

Invoke-Test -TestId "tru-1.4" -TestName "LocalMachine without admin fails" -FilePrefix "tru-noadmin" -TestScript {
    # SETUP: Create a test certificate using PowerShell
    $certParams = @{
        Subject = "CN=noadmin-test"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    Export-Certificate -Cert $cert -FilePath "tru-noadmin.cer" -Type CERT | Out-Null
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call (should fail without admin)
        $output = & .\certz.exe trust add tru-noadmin.cer --location LocalMachine 2>&1
        $exitCode = $LASTEXITCODE

        # ASSERTION: Should fail with permission error (unless running as admin)
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

        if (-not $isAdmin) {
            if ($exitCode -eq 0) {
                throw "Command should have failed without admin privileges"
            }
            $outputStr = $output -join "`n"
            if ($outputStr -notmatch "Administrator") {
                throw "Error message should mention Administrator requirement"
            }
        }

        @{ Success = $true; Details = "LocalMachine permission check works correctly" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item "tru-noadmin.cer" -Force -ErrorAction SilentlyContinue
    }
}

Invoke-Test -TestId "trm-1.4" -TestName "Multiple matches without --force fails" -FilePrefix "trm-multi" -TestScript {
    $uniquePrefix = "multi-test-$([guid]::NewGuid().ToString().Substring(0,8))"

    # SETUP: Create TWO certificates with similar subjects using PowerShell
    $cert1 = New-SelfSignedCertificate -Subject "CN=$uniquePrefix-1" -KeyAlgorithm ECDSA_nistP256 -KeyExportPolicy Exportable -CertStoreLocation "Cert:\CurrentUser\Root" -NotAfter (Get-Date).AddDays(90)
    $cert2 = New-SelfSignedCertificate -Subject "CN=$uniquePrefix-2" -KeyAlgorithm ECDSA_nistP256 -KeyExportPolicy Exportable -CertStoreLocation "Cert:\CurrentUser\Root" -NotAfter (Get-Date).AddDays(90)

    try {
        # ACTION: Single certz.exe call (should fail without --force)
        $output = & .\certz.exe trust remove --subject "CN=$uniquePrefix*" 2>&1
        $exitCode = $LASTEXITCODE
        $outputStr = $output -join "`n"

        # ASSERTION 1: Should fail (exit code non-zero)
        if ($exitCode -eq 0) {
            throw "Command should have failed when multiple certificates match without --force"
        }

        # ASSERTION 2: Output should list matching certificates
        if ($outputStr -notmatch "$uniquePrefix-1" -or $outputStr -notmatch "$uniquePrefix-2") {
            throw "Output should list both matching certificates"
        }

        @{ Success = $true; Details = "Multiple matches correctly requires --force" }
    }
    finally {
        # CLEANUP: PowerShell only
        Get-ChildItem "Cert:\CurrentUser\Root" |
            Where-Object { $_.Subject -like "*$uniquePrefix*" } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
}

Invoke-Test -TestId "sto-1.1" -TestName "List certificates in My store" -FilePrefix "sto-list" -TestScript {
    # SETUP: Ensure at least one certificate exists
    $certParams = @{
        Subject = "CN=store-list-test"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $thumbprint = $cert.Thumbprint

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe store list 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Output contains certificate information
        if ($outputStr -notmatch "store-list-test") {
            throw "Output should list the test certificate"
        }

        @{ Success = $true; Details = "Store list shows certificates" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item $cert.PSPath -Force -ErrorAction SilentlyContinue
    }
}
```

**Status:** [ ] Not Started

---

### Step 3: Add Certificate Chain Validation Service
**New file:** `src/certz/Services/Validation/ChainValidator.cs`

Create a service to build and validate certificate chains.

**Design Decision:** The `--crl` flag uses OCSP preferred with CRL fallback. .NET's `X509RevocationMode.Online` automatically handles this - it checks OCSP first (if AIA extension present), then falls back to CRL.

```csharp
namespace certz.Services.Validation;

public interface IChainValidator
{
    ChainValidationResult ValidateChain(X509Certificate2 certificate, bool checkRevocation = false);
    ChainValidationResult ValidateChain(X509Certificate2Collection certificates, bool checkRevocation = false);
}

public class ChainValidator : IChainValidator
{
    public ChainValidationResult ValidateChain(X509Certificate2 certificate, bool checkRevocation = false)
    {
        using var chain = new X509Chain();

        // OCSP preferred, CRL fallback - .NET handles this automatically with Online mode
        // It checks OCSP first (via AIA extension), falls back to CRL if OCSP unavailable
        chain.ChainPolicy.RevocationMode = checkRevocation
            ? X509RevocationMode.Online
            : X509RevocationMode.NoCheck;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

        // Set reasonable timeout for revocation checks (10 seconds)
        chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(10);

        var isValid = chain.Build(certificate);

        return new ChainValidationResult
        {
            IsValid = isValid,
            ChainElements = chain.ChainElements.Cast<X509ChainElement>()
                .Select(e => new ChainElement
                {
                    Certificate = e.Certificate,
                    Status = e.ChainElementStatus.ToList()
                }).ToList(),
            ChainStatus = chain.ChainStatus.ToList()
        };
    }
}

public record ChainValidationResult
{
    public bool IsValid { get; init; }
    public List<ChainElement> ChainElements { get; init; } = [];
    public List<X509ChainStatus> ChainStatus { get; init; } = [];
}

public record ChainElement
{
    public X509Certificate2 Certificate { get; init; } = null!;
    public List<X509ChainStatus> Status { get; init; } = [];
}
```

**Status:** [ ] Not Started

---

### Step 4: Add Chain Visualization Service
**New file:** `src/certz/Services/Validation/ChainVisualizer.cs`

Create a service to render certificate chains as ASCII trees using Spectre.Console:

```csharp
namespace certz.Services.Validation;

public interface IChainVisualizer
{
    void RenderChain(ChainValidationResult result, IAnsiConsole console);
}

public class ChainVisualizer : IChainVisualizer
{
    public void RenderChain(ChainValidationResult result, IAnsiConsole console)
    {
        var root = new Tree("[bold]Certificate Chain[/]");

        if (result.ChainElements.Count == 0)
        {
            root.AddNode("[red]No chain elements found[/]");
            console.Write(root);
            return;
        }

        // Build tree from root CA down to end entity
        TreeNode? currentNode = null;
        for (int i = result.ChainElements.Count - 1; i >= 0; i--)
        {
            var element = result.ChainElements[i];
            var cert = element.Certificate;

            var nodeText = BuildNodeText(cert, element.Status, i == 0);

            if (currentNode == null)
            {
                currentNode = root.AddNode(nodeText);
            }
            else
            {
                currentNode = currentNode.AddNode(nodeText);
            }
        }

        console.Write(root);

        // Show overall chain status
        if (!result.IsValid)
        {
            console.MarkupLine("");
            console.MarkupLine("[red]⚠ Chain validation failed:[/]");
            foreach (var status in result.ChainStatus)
            {
                console.MarkupLine($"  [yellow]• {status.StatusInformation}[/]");
            }
        }
        else
        {
            console.MarkupLine("");
            console.MarkupLine("[green]✓ Chain validation successful[/]");
        }
    }

    private static string BuildNodeText(X509Certificate2 cert, List<X509ChainStatus> status, bool isEndEntity)
    {
        var sb = new StringBuilder();

        // Certificate type indicator
        var typeIcon = isEndEntity ? "📄" : (cert.Extensions["2.5.29.19"] != null ? "🏛️" : "📄");

        // Subject
        var subject = cert.GetNameInfo(X509NameType.SimpleName, false);
        sb.Append($"{typeIcon} [bold]{subject}[/]");

        // Validity indicator
        var now = DateTime.Now;
        if (cert.NotAfter < now)
        {
            sb.Append(" [red](EXPIRED)[/]");
        }
        else if (cert.NotBefore > now)
        {
            sb.Append(" [yellow](NOT YET VALID)[/]");
        }
        else
        {
            var daysRemaining = (cert.NotAfter - now).Days;
            if (daysRemaining < 30)
            {
                sb.Append($" [yellow]({daysRemaining} days remaining)[/]");
            }
        }

        // Status issues
        foreach (var s in status.Where(s => s.Status != X509ChainStatusFlags.NoError))
        {
            sb.Append($"\n  [red]⚠ {s.StatusInformation}[/]");
        }

        return sb.ToString();
    }
}
```

**Status:** [ ] Not Started

---

### Step 5: Add Inspect Result Models
**New files in `Models/`:**

| File | Purpose |
|------|---------|
| `CertificateInspectResult.cs` | Record with certificate details, chain info, warnings |
| `src/certz/Models/ChainElementInfo.cs` | Information about a single chain element |
| `src/certz/Models/InspectSource.cs` | Enum: File, Url, Store |

```csharp
// src/certz/Models/CertificateInspectResult.cs
namespace certz.Models;

public record CertificateInspectResult
{
    public required string Subject { get; init; }
    public required string Issuer { get; init; }
    public required string Thumbprint { get; init; }
    public required string SerialNumber { get; init; }
    public required DateTime NotBefore { get; init; }
    public required DateTime NotAfter { get; init; }
    public required int DaysRemaining { get; init; }
    public required string KeyAlgorithm { get; init; }
    public required int KeySize { get; init; }
    public required string SignatureAlgorithm { get; init; }
    public required List<string> SubjectAlternativeNames { get; init; }
    public required List<string> KeyUsages { get; init; }
    public required List<string> EnhancedKeyUsages { get; init; }
    public required bool IsCa { get; init; }
    public required int? PathLengthConstraint { get; init; }
    public required bool HasPrivateKey { get; init; }
    public InspectSource Source { get; init; }
    public string? SourcePath { get; init; }
    public List<ChainElementInfo>? Chain { get; init; }
    public List<string> Warnings { get; init; } = [];
    public bool ChainIsValid { get; init; }
}

public record ChainElementInfo
{
    public required string Subject { get; init; }
    public required string Issuer { get; init; }
    public required string Thumbprint { get; init; }
    public required DateTime NotBefore { get; init; }
    public required DateTime NotAfter { get; init; }
    public required bool IsCa { get; init; }
    public List<string> ValidationErrors { get; init; } = [];
}

public enum InspectSource
{
    File,
    Url,
    Store
}
```

**Status:** [ ] Not Started

---

### Step 6: Create Inspect Command Structure
**New directory:** `src/certz/Commands/Inspect/`

| File | Purpose |
|------|---------|
| `InspectCommand.cs` | Main `certz inspect` command with argument detection |

The command should auto-detect the source type:
- If argument starts with `https://` → URL inspection
- If `--store` flag is provided → thumbprint lookup (even if file exists)
- If file exists at path → file inspection
- If argument is a 40-char hex string and file doesn't exist → thumbprint lookup
- Otherwise → error (file not found)

**Design Decision:** File existence takes priority over thumbprint detection. Use `--store` flag to explicitly force thumbprint lookup when a file with the same name exists.

```csharp
// src/certz/Commands/Inspect/InspectCommand.cs
namespace certz.Commands.Inspect;

internal static class InspectCommand
{
    internal static Command BuildInspectCommand()
    {
        var sourceArgument = new Argument<string>("source", "File path, URL, or certificate thumbprint");

        var passwordOption = OptionBuilders.PasswordOption();
        var chainOption = new Option<bool>(["--chain", "-c"], "Show certificate chain");
        var crlOption = new Option<bool>("--crl", "Check certificate revocation status");
        var warnOption = new Option<int?>(["--warn", "-w"], "Warn if certificate expires within N days");
        var saveOption = new Option<string?>("--save", "Save certificate to file");
        var saveKeyOption = new Option<string?>("--save-key", "Save private key to file");
        var saveFormatOption = new Option<string>("--save-format", () => "pem", "Export format: pem (default) or der");
        var storeOption = new Option<string?>("--store", "Certificate store name (My, Root, CA, etc.)");
        var locationOption = new Option<string?>(["--location", "-l"], "Store location (CurrentUser or LocalMachine)");

        var command = new Command("inspect", "Inspect certificate from file, URL, or store")
        {
            sourceArgument,
            passwordOption,
            chainOption,
            crlOption,
            warnOption,
            saveOption,
            saveKeyOption,
            saveFormatOption,
            storeOption,
            locationOption
        };

        command.SetHandler(async (context) =>
        {
            var source = context.ParseResult.GetValueForArgument(sourceArgument);
            var password = context.ParseResult.GetValueForOption(passwordOption);
            var showChain = context.ParseResult.GetValueForOption(chainOption);
            var checkCrl = context.ParseResult.GetValueForOption(crlOption);
            var warnDays = context.ParseResult.GetValueForOption(warnOption);
            var savePath = context.ParseResult.GetValueForOption(saveOption);
            var saveKeyPath = context.ParseResult.GetValueForOption(saveKeyOption);
            var storeName = context.ParseResult.GetValueForOption(storeOption);
            var storeLocation = context.ParseResult.GetValueForOption(locationOption);
            var format = context.ParseResult.GetValueForOption(Program.FormatOption);

            // Detect source type and dispatch
            var handler = new InspectHandler();
            var result = await handler.InspectAsync(new InspectOptions
            {
                Source = source,
                Password = password,
                ShowChain = showChain,
                CheckCrl = checkCrl,
                WarnDays = warnDays,
                SavePath = savePath,
                SaveKeyPath = saveKeyPath,
                StoreName = storeName,
                StoreLocation = storeLocation
            });

            // Output result using formatter
            var formatter = FormatterFactory.Create(format ?? "text");
            formatter.WriteCertificateInspected(result);

            context.ExitCode = result.Warnings.Any() ? 1 : 0;
        });

        return command;
    }
}
```

**Status:** [ ] Not Started

---

### Step 7: Implement File Inspection
**New file:** `src/certz/Services/CertificateInspector.cs`

Add file inspection logic that handles PFX, PEM, and DER formats:

```csharp
public class CertificateInspector
{
    public CertificateInspectResult InspectFile(string filePath, string? password)
    {
        var (cert, chain) = LoadCertificateFromFile(filePath, password);
        return BuildInspectResult(cert, chain, InspectSource.File, filePath);
    }

    private (X509Certificate2, X509Certificate2Collection?) LoadCertificateFromFile(string path, string? password)
    {
        var extension = Path.GetExtension(path).ToLowerInvariant();

        return extension switch
        {
            ".pfx" or ".p12" => LoadPfx(path, password),
            ".pem" or ".crt" or ".cer" => LoadPem(path),
            ".der" => LoadDer(path),
            _ => throw new InvalidOperationException($"Unsupported file extension: {extension}")
        };
    }
}
```

**Status:** [ ] Not Started

---

### Step 8: Implement URL Inspection
**Modify:** `src/certz/Services/CertificateInspector.cs`

Add HTTPS inspection that retrieves the certificate from a remote server:

```csharp
public async Task<CertificateInspectResult> InspectUrlAsync(string url, bool includeChain)
{
    var uri = new Uri(url);
    var port = uri.Port > 0 ? uri.Port : 443;

    X509Certificate2? certificate = null;
    X509Chain? chain = null;

    var handler = new HttpClientHandler
    {
        ServerCertificateCustomValidationCallback = (message, cert, certChain, errors) =>
        {
            if (cert != null)
            {
                certificate = new X509Certificate2(cert);
                if (includeChain && certChain != null)
                {
                    chain = certChain;
                }
            }
            return true; // Accept all certs for inspection purposes
        }
    };

    using var client = new HttpClient(handler);
    try
    {
        await client.GetAsync(url);
    }
    catch (HttpRequestException)
    {
        // Connection errors are expected for some sites, but we still got the cert
    }

    if (certificate == null)
    {
        throw new InvalidOperationException($"Could not retrieve certificate from {url}");
    }

    return BuildInspectResult(certificate, null, InspectSource.Url, url);
}
```

**Status:** [ ] Not Started

---

### Step 9: Implement Thumbprint/Store Inspection
**Modify:** `src/certz/Services/CertificateInspector.cs`

Add certificate store lookup by thumbprint:

```csharp
public CertificateInspectResult InspectFromStore(string thumbprint, string? storeName, string? storeLocation)
{
    var location = storeLocation?.ToLowerInvariant() switch
    {
        "localmachine" => StoreLocation.LocalMachine,
        _ => StoreLocation.CurrentUser
    };

    var name = storeName?.ToLowerInvariant() switch
    {
        "root" => StoreName.Root,
        "ca" => StoreName.CertificateAuthority,
        "my" or null => StoreName.My,
        _ => StoreName.My
    };

    using var store = new X509Store(name, location);
    store.Open(OpenFlags.ReadOnly);

    var cert = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false)
        .OfType<X509Certificate2>()
        .FirstOrDefault();

    if (cert == null)
    {
        throw new InvalidOperationException($"Certificate with thumbprint {thumbprint} not found in {location}\\{name}");
    }

    return BuildInspectResult(cert, null, InspectSource.Store, $"{location}\\{name}\\{thumbprint}");
}
```

**Status:** [ ] Not Started

---

### Step 10: Add --save, --save-key, and --save-format Export Options
**Modify:** `src/certz/Services/CertificateInspector.cs`

Add export functionality to save certificates and keys in PEM (default) or DER format:

```csharp
public enum ExportFormat
{
    Pem,
    Der
}

public void SaveCertificate(X509Certificate2 certificate, string outputPath, ExportFormat format = ExportFormat.Pem)
{
    switch (format)
    {
        case ExportFormat.Pem:
            var pem = certificate.ExportCertificatePem();
            File.WriteAllText(outputPath, pem);
            break;

        case ExportFormat.Der:
            var der = certificate.RawData;
            File.WriteAllBytes(outputPath, der);
            break;

        default:
            throw new ArgumentOutOfRangeException(nameof(format), $"Unsupported format: {format}");
    }
}

public void SavePrivateKey(X509Certificate2 certificate, string outputPath, ExportFormat format = ExportFormat.Pem)
{
    if (!certificate.HasPrivateKey)
    {
        throw new InvalidOperationException("Certificate does not have a private key");
    }

    var key = certificate.GetRSAPrivateKey() ??
              certificate.GetECDsaPrivateKey() as AsymmetricAlgorithm ??
              throw new InvalidOperationException("Unsupported key type");

    switch (format)
    {
        case ExportFormat.Pem:
            var pem = key switch
            {
                RSA rsa => rsa.ExportRSAPrivateKeyPem(),
                ECDsa ecdsa => ecdsa.ExportECPrivateKeyPem(),
                _ => throw new InvalidOperationException("Unsupported key type")
            };
            File.WriteAllText(outputPath, pem);
            break;

        case ExportFormat.Der:
            var der = key switch
            {
                RSA rsa => rsa.ExportRSAPrivateKey(),
                ECDsa ecdsa => ecdsa.ExportECPrivateKey(),
                _ => throw new InvalidOperationException("Unsupported key type")
            };
            File.WriteAllBytes(outputPath, der);
            break;

        default:
            throw new ArgumentOutOfRangeException(nameof(format), $"Unsupported format: {format}");
    }
}

public static ExportFormat ParseExportFormat(string format)
{
    return format.ToLowerInvariant() switch
    {
        "pem" => ExportFormat.Pem,
        "der" => ExportFormat.Der,
        _ => throw new ArgumentException($"Invalid export format: {format}. Use 'pem' or 'der'.")
    };
}
```

**Status:** [ ] Not Started

---

### Step 11: Create Store List Command
**New file:** `src/certz/Commands/Store/StoreListCommand.cs`

```csharp
namespace certz.Commands.Store;

internal static class StoreListCommand
{
    internal static Command BuildStoreCommand()
    {
        var storeCommand = new Command("store", "Certificate store operations");
        storeCommand.AddCommand(BuildListCommand());
        return storeCommand;
    }

    private static Command BuildListCommand()
    {
        var storeOption = new Option<string?>(["--store", "-s"], () => "My", "Store name (My, Root, CA)");
        var locationOption = new Option<string?>(["--location", "-l"], () => "CurrentUser", "Store location (CurrentUser, LocalMachine)");
        var expiredOption = new Option<bool>("--expired", "Show only expired certificates");
        var expiringOption = new Option<int?>("--expiring", "Show certificates expiring within N days");

        var command = new Command("list", "List certificates in a store")
        {
            storeOption,
            locationOption,
            expiredOption,
            expiringOption
        };

        command.SetHandler(async (context) =>
        {
            var storeName = context.ParseResult.GetValueForOption(storeOption);
            var storeLocation = context.ParseResult.GetValueForOption(locationOption);
            var showExpired = context.ParseResult.GetValueForOption(expiredOption);
            var expiringDays = context.ParseResult.GetValueForOption(expiringOption);
            var format = context.ParseResult.GetValueForOption(Program.FormatOption);

            var handler = new StoreListHandler();
            var result = handler.ListCertificates(new StoreListOptions
            {
                StoreName = storeName,
                StoreLocation = storeLocation,
                ShowExpired = showExpired,
                ExpiringDays = expiringDays
            });

            var formatter = FormatterFactory.Create(format ?? "text");
            formatter.WriteStoreList(result);
        });

        return command;
    }
}
```

**Status:** [ ] Not Started

---

### Step 12: Create Trust Add Command
**New file:** `src/certz/Commands/Trust/TrustAddCommand.cs`

**Design Decision:** LocalMachine operations require admin rights. If not running elevated, fail with a clear error message explaining the requirement. No silent fallback or auto-elevation.

```csharp
namespace certz.Commands.Trust;

internal static class TrustCommand
{
    internal static Command BuildTrustCommand()
    {
        var trustCommand = new Command("trust", "Trust store management");
        trustCommand.AddCommand(BuildAddCommand());
        trustCommand.AddCommand(BuildRemoveCommand());
        return trustCommand;
    }

    private static Command BuildAddCommand()
    {
        var fileArgument = new Argument<string>("file", "Certificate file to add");
        var passwordOption = OptionBuilders.PasswordOption();
        var storeOption = new Option<string>(["--store", "-s"], () => "Root", "Target store (Root, CA, My)");
        var locationOption = new Option<string>(["--location", "-l"], () => "CurrentUser", "Store location (CurrentUser, LocalMachine)");

        var command = new Command("add", "Add certificate to trust store")
        {
            fileArgument,
            passwordOption,
            storeOption,
            locationOption
        };

        command.SetHandler(async (context) =>
        {
            var filePath = context.ParseResult.GetValueForArgument(fileArgument);
            var password = context.ParseResult.GetValueForOption(passwordOption);
            var storeName = context.ParseResult.GetValueForOption(storeOption);
            var storeLocation = context.ParseResult.GetValueForOption(locationOption);
            var format = context.ParseResult.GetValueForOption(Program.FormatOption);

            // Design Decision: Fail with clear error for LocalMachine without admin
            if (storeLocation.Equals("LocalMachine", StringComparison.OrdinalIgnoreCase))
            {
                if (!IsRunningAsAdmin())
                {
                    throw new InvalidOperationException(
                        "Administrator privileges required to modify LocalMachine certificate store. " +
                        "Run the command as Administrator, or use '--location CurrentUser' for user-level trust.");
                }
            }

            var handler = new TrustHandler();
            var result = handler.AddToStore(filePath, password, storeName, storeLocation);

            var formatter = FormatterFactory.Create(format ?? "text");
            formatter.WriteTrustAdded(result);
        });

        return command;
    }

    private static bool IsRunningAsAdmin()
    {
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var principal = new System.Security.Principal.WindowsPrincipal(identity);
        return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }

        return command;
    }
}
```

**Status:** [ ] Not Started

---

### Step 13: Create Trust Remove Command
**Modify:** `src/certz/Commands/Trust/TrustAddCommand.cs` (add remove command)

```csharp
private static Command BuildRemoveCommand()
{
    var thumbprintArgument = new Argument<string?>("thumbprint", () => null, "Certificate thumbprint to remove");
    var subjectOption = new Option<string?>("--subject", "Remove certificates matching subject pattern");
    var storeOption = new Option<string>(["--store", "-s"], () => "Root", "Target store (Root, CA, My)");
    var locationOption = new Option<string>(["--location", "-l"], () => "CurrentUser", "Store location (CurrentUser, LocalMachine)");
    var forceOption = new Option<bool>(["--force", "-f"], "Remove without confirmation (required for multiple matches)");

    var command = new Command("remove", "Remove certificate from trust store")
    {
        thumbprintArgument,
        subjectOption,
        storeOption,
        locationOption,
        forceOption
    };

    command.SetHandler(async (context) =>
    {
        var thumbprint = context.ParseResult.GetValueForArgument(thumbprintArgument);
        var subject = context.ParseResult.GetValueForOption(subjectOption);
        var storeName = context.ParseResult.GetValueForOption(storeOption);
        var storeLocation = context.ParseResult.GetValueForOption(locationOption);
        var force = context.ParseResult.GetValueForOption(forceOption);
        var format = context.ParseResult.GetValueForOption(Program.FormatOption);

        if (string.IsNullOrEmpty(thumbprint) && string.IsNullOrEmpty(subject))
        {
            throw new InvalidOperationException("Either thumbprint or --subject must be specified");
        }

        var handler = new TrustHandler();

        // Design Decision: Interactive confirmation unless --force
        // - Single match: prompt for confirmation (unless --force)
        // - Multiple matches with --subject: list matches, require --force
        var matchingCerts = handler.FindMatchingCertificates(thumbprint, subject, storeName, storeLocation);

        if (matchingCerts.Count == 0)
        {
            throw new InvalidOperationException("No matching certificates found");
        }

        if (matchingCerts.Count > 1 && !force)
        {
            // List matching certificates and require --force
            var formatter = FormatterFactory.Create(format ?? "text");
            formatter.WriteMultipleMatchesWarning(matchingCerts);
            context.ExitCode = 1;
            return;
        }

        if (!force && format != "json")
        {
            // Interactive confirmation for single match (text mode only)
            var cert = matchingCerts.First();
            if (!AnsiConsole.Confirm($"Remove certificate '{cert.Subject}' ({cert.Thumbprint})?", false))
            {
                AnsiConsole.MarkupLine("[yellow]Operation cancelled[/]");
                context.ExitCode = 1;
                return;
            }
        }

        var result = handler.RemoveFromStore(matchingCerts);

        var outputFormatter = FormatterFactory.Create(format ?? "text");
        outputFormatter.WriteTrustRemoved(result);
    });

    return command;
}
```

**Status:** [ ] Not Started

---

### Step 14: Update Formatters for Inspect Output
**Modify:** `src/certz/Formatters/IOutputFormatter.cs`, `TextFormatter.cs`, `JsonFormatter.cs`

Add new methods to the formatter interface and implementations:

```csharp
// IOutputFormatter.cs additions
void WriteCertificateInspected(CertificateInspectResult result);
void WriteStoreList(StoreListResult result);
void WriteTrustAdded(TrustOperationResult result);
void WriteTrustRemoved(TrustOperationResult result);
void WriteMultipleMatchesWarning(List<X509Certificate2> matchingCerts);

// TextFormatter.cs - sample implementation
public void WriteCertificateInspected(CertificateInspectResult result)
{
    var table = new Table();
    table.AddColumn("Property");
    table.AddColumn("Value");

    table.AddRow("Subject", result.Subject);
    table.AddRow("Issuer", result.Issuer);
    table.AddRow("Thumbprint", result.Thumbprint);
    table.AddRow("Serial Number", result.SerialNumber);
    table.AddRow("Valid From", result.NotBefore.ToString("yyyy-MM-dd HH:mm:ss"));
    table.AddRow("Valid To", result.NotAfter.ToString("yyyy-MM-dd HH:mm:ss"));
    table.AddRow("Days Remaining", result.DaysRemaining.ToString());
    table.AddRow("Key Algorithm", $"{result.KeyAlgorithm} ({result.KeySize} bits)");
    table.AddRow("Signature Algorithm", result.SignatureAlgorithm);
    table.AddRow("Is CA", result.IsCa ? "Yes" : "No");
    table.AddRow("Has Private Key", result.HasPrivateKey ? "Yes" : "No");

    if (result.SubjectAlternativeNames.Any())
    {
        table.AddRow("SANs", string.Join(", ", result.SubjectAlternativeNames));
    }

    _console.Write(table);

    // Show warnings
    foreach (var warning in result.Warnings)
    {
        _console.MarkupLine($"[yellow]⚠ {warning}[/]");
    }
}
```

**Status:** [ ] Not Started

---

## New Command Specifications

### `certz inspect`
```
certz inspect <source> [options]

Arguments:
  source          File path, URL (https://...), or certificate thumbprint

Options:
  --password, -p  Password for PFX files
  --chain, -c     Show certificate chain
  --crl           Check certificate revocation status (OCSP preferred, CRL fallback)
  --warn, -w      Warn if certificate expires within N days
  --save          Save certificate to file
  --save-key      Save private key to file
  --save-format   Export format: pem (default) or der
  --store         Store name for thumbprint lookup (My, Root, CA) - forces thumbprint mode
  --location, -l  Store location (CurrentUser, LocalMachine)
  --format        Output format: text or json

Source Detection:
  1. If source starts with "https://" → URL inspection
  2. If --store flag provided → thumbprint lookup (even if file exists)
  3. If file exists at path → file inspection
  4. If 40-char hex string → thumbprint lookup
  5. Otherwise → error (file not found)
```

### `certz store list`
```
certz store list [options]

Options:
  --store, -s     Store name (default: My)
  --location, -l  Store location (default: CurrentUser)
  --expired       Show only expired certificates
  --expiring      Show certificates expiring within N days
  --format        Output format: text or json
```

### `certz trust add`
```
certz trust add <file> [options]

Arguments:
  file            Certificate file to add (PFX, PEM, DER)

Options:
  --password, -p  Password for PFX files
  --store, -s     Target store (default: Root)
  --location, -l  Store location (default: CurrentUser; LocalMachine requires admin)
  --format        Output format: text or json

Behavior:
  - LocalMachine location: requires Administrator privileges (fails with clear error if not elevated)
```

### `certz trust remove`
```
certz trust remove [thumbprint] [options]

Arguments:
  thumbprint      Certificate thumbprint (optional if --subject used)

Options:
  --subject       Remove certificates matching subject pattern (wildcards supported)
  --store, -s     Target store (default: Root)
  --location, -l  Store location (default: CurrentUser; LocalMachine requires admin)
  --force, -f     Remove without confirmation (required when multiple certs match)
  --format        Output format: text or json

Behavior:
  - Single match: prompts for confirmation (unless --force or --format json)
  - Multiple matches: lists matching certs and requires --force to proceed
  - LocalMachine location: requires Administrator privileges
```

---

## Critical Files Reference

| File | Action |
|------|--------|
| `test-inspect.ps1` | New file - test script for inspect command |
| `test-trust.ps1` | New file - test script for trust/store commands |
| `src/certz/Program.cs` | Add inspect, store, trust commands |
| `src/certz/Commands/Inspect/InspectCommand.cs` | New file |
| `src/certz/Commands/Store/StoreListCommand.cs` | New file |
| `src/certz/Commands/Trust/TrustCommand.cs` | New file (add + remove) |
| `src/certz/Services/CertificateInspector.cs` | New file |
| `src/certz/Services/Validation/ChainValidator.cs` | New file |
| `src/certz/Services/Validation/ChainVisualizer.cs` | New file |
| `src/certz/Services/TrustHandler.cs` | New file (includes FindMatchingCertificates, AddToStore, RemoveFromStore) |
| `src/certz/Services/StoreListHandler.cs` | New file |
| `src/certz/Models/CertificateInspectResult.cs` | New file |
| `src/certz/Models/ExportFormat.cs` | New file (enum: Pem, Der) |
| `src/certz/Models/StoreListResult.cs` | New file |
| `src/certz/Models/TrustOperationResult.cs` | New file |
| `src/certz/Formatters/IOutputFormatter.cs` | Add new methods |
| `src/certz/Formatters/TextFormatter.cs` | Add new output methods |
| `src/certz/Formatters/JsonFormatter.cs` | Add new output methods |

---

## Verification Checklist

- [x] `.\test-inspect.ps1` runs and all tests pass
- [x] `.\test-trust.ps1` runs and all tests pass
- [x] `dotnet build` succeeds
- [x] `certz inspect test.pfx --password Pass` shows certificate details
- [x] `certz inspect https://example.com` retrieves remote certificate
- [x] `certz inspect https://example.com --chain` shows certificate chain tree
- [x] `certz inspect https://example.com --crl` checks revocation (OCSP/CRL)
- [x] `certz inspect test.pfx --password Pass --save out.cer` exports to PEM (default)
- [x] `certz inspect test.pfx --password Pass --save out.der --save-format der` exports to DER
- [x] `certz inspect <thumbprint>` finds certificate in store (when file doesn't exist)
- [x] `certz inspect <thumbprint> --store My` forces thumbprint lookup
- [x] `certz store list` lists certificates in default store
- [x] `certz store list --store root --format json` outputs JSON
- [x] `certz trust add cert.cer` adds certificate to Root store
- [x] `certz trust add cert.cer --location LocalMachine` fails without admin (clear error)
- [x] `certz trust remove <thumbprint> --force` removes certificate from store
- [x] `certz trust remove --subject "CN=test*"` prompts/lists when multiple match
- [x] `certz trust remove --subject "CN=test*" --force` removes all matching
- [x] `.\test-inspect.ps1 -Category inspect-file` passes
- [x] `.\test-inspect.ps1 -Category chain` passes
- [x] `.\test-trust.ps1 -Category trust-add` passes
- [x] `.\test-trust.ps1 -Category trust-remove` passes

---

## Notes & Adjustments

*Record any changes to the plan during implementation:*

1. _(none yet)_
