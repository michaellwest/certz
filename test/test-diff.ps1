#requires -version 7

<#
.SYNOPSIS
    Test suite for certz diff command.

.DESCRIPTION
    This script tests the diff command: comparing two certificates side-by-side,
    highlighting differences, JSON output, and exit code behavior.
    It follows test isolation principles from test-isolation-plan.md:
    - Each test invokes certz.exe exactly ONCE
    - Setup and teardown use pure PowerShell (no certz calls)
    - Assert against system state (files, exit codes, output structure)

.PARAMETER TestId
    Run specific tests by ID. Example: -TestId "dif-1.1", "dif-2.1"

.PARAMETER Category
    Run tests by category: identical, changed, json, sources

.PARAMETER SkipCleanup
    Keep test files after running.

.PARAMETER Verbose
    Show detailed output.

.EXAMPLE
    .\test-diff.ps1
    Runs all tests with default settings.

.EXAMPLE
    .\test-diff.ps1 -Category identical
    Runs only identical-certificate tests.
#>
param(
    [switch]$SkipCleanup,
    [switch]$Verbose,
    [string[]]$TestId,
    [string[]]$Category
)

$ErrorActionPreference = "Stop"

# Load shared test helper functions
. "$PSScriptRoot\test-helper.ps1"

# Test categories
$TestCategories = @{
    "identical"  = @("dif-1.1", "dif-1.2")
    "changed"    = @("dif-2.1", "dif-2.2", "dif-2.3")
    "json"       = @("dif-3.1", "dif-3.2")
    "sources"    = @("dif-4.1")
}

# Initialize test environment
Initialize-TestEnvironment -TestId $TestId -Category $Category -TestCategories $TestCategories
Set-VerboseOutput -Enabled $Verbose

# Display banner
Write-Host "`nCertz Diff Command Test Suite" -ForegroundColor Magenta
Write-Host "==============================`n" -ForegroundColor Magenta

# Display active filters
if ($TestId -or $Category) {
    Write-Host "Test Filters Active:" -ForegroundColor Yellow
    if ($TestId) {
        Write-Host "  Test IDs: $($TestId -join ', ')" -ForegroundColor Gray
    }
    if ($Category) {
        Write-Host "  Categories: $($Category -join ', ')" -ForegroundColor Gray
    }
    Write-Host ""
}

# Build certz
Build-Certz -Verbose:$Verbose

# Change to tools directory (syncs both PowerShell and .NET current directories)
Enter-ToolsDirectory

# Initial cleanup
Write-Host "Initializing test environment..." -ForegroundColor Yellow
Remove-TestFiles

# Helper: create a PEM certificate file from a store cert
function New-PemCertFile {
    param($Cert, $Path)
    $certPem = [Convert]::ToBase64String($Cert.RawData, [Base64FormattingOptions]::InsertLineBreaks)
    $pemContent = "-----BEGIN CERTIFICATE-----`n$certPem`n-----END CERTIFICATE-----"
    Set-Content -Path $Path -Value $pemContent
}

# ============================================================================
# IDENTICAL CERTIFICATE TESTS
# ============================================================================
Write-TestHeader "Testing DIFF with Identical Certificates"

# Test dif-1.1: Same cert vs itself — should exit 0, all fields unchanged
Invoke-Test -TestId "dif-1.1" -TestName "Same certificate vs itself exits 0" -FilePrefix "dif-same" -TestScript {
    # SETUP: Create one certificate using PowerShell
    $certParams = @{
        Subject          = "CN=certz-diff-same.local"
        KeyAlgorithm     = "ECDSA_nistP256"
        KeyExportPolicy  = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter         = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    New-PemCertFile -Cert $cert -Path "dif-same.cer"
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe diff dif-same.cer dif-same.cer 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code 0 — certificates are identical
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Output indicates identical
        if ($outputStr -notmatch "identical|unchanged") {
            throw "Output should indicate certificates are identical"
        }

        [PSCustomObject]@{ Success = $true; Details = "Same cert vs itself exits 0, shows identical" }
    }
    finally {
        Remove-Item "dif-same.cer" -Force -ErrorAction SilentlyContinue
    }
}

# Test dif-1.2: Same cert vs itself with JSON — areIdentical=true
Invoke-Test -TestId "dif-1.2" -TestName "Same cert JSON output has areIdentical=true" -FilePrefix "dif-same-json" -TestScript {
    # SETUP: Create one certificate using PowerShell
    $certParams = @{
        Subject          = "CN=certz-diff-same-json.local"
        KeyAlgorithm     = "ECDSA_nistP256"
        KeyExportPolicy  = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter         = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    New-PemCertFile -Cert $cert -Path "dif-same-json.cer"
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe diff dif-same-json.cer dif-same-json.cer --format json 2>&1

        # ASSERTION 1: Exit code 0
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Valid JSON with areIdentical = true
        try {
            $json = $output | ConvertFrom-Json
            if (-not $json.areIdentical) {
                throw "JSON areIdentical should be true for identical certs"
            }
            if ($json.differenceCount -ne 0) {
                throw "JSON differenceCount should be 0 for identical certs"
            }
            if (-not $json.fields) {
                throw "JSON should contain a fields array"
            }
            $changedFields = $json.fields | Where-Object { $_.status -eq "changed" }
            if ($changedFields) {
                throw "No fields should be 'changed' for identical certs"
            }
        }
        catch {
            if ($_.Exception.Message -match "JSON") {
                throw "Output is not valid JSON: $($output)"
            }
            throw $_
        }

        [PSCustomObject]@{ Success = $true; Details = "JSON output shows areIdentical=true and differenceCount=0" }
    }
    finally {
        Remove-Item "dif-same-json.cer" -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# CHANGED CERTIFICATE TESTS
# ============================================================================
Write-TestHeader "Testing DIFF with Different Certificates"

# Test dif-2.1: Two different certs — exits 1 with changed fields highlighted
Invoke-Test -TestId "dif-2.1" -TestName "Different certs exits 1 with changed fields" -FilePrefix "dif-diff" -TestScript {
    # SETUP: Create two certificates with different CNs using PowerShell
    $certParams1 = @{
        Subject          = "CN=certz-diff-left.local"
        KeyAlgorithm     = "ECDSA_nistP256"
        KeyExportPolicy  = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter         = (Get-Date).AddDays(90)
    }
    $certParams2 = @{
        Subject          = "CN=certz-diff-right.local"
        KeyAlgorithm     = "ECDSA_nistP256"
        KeyExportPolicy  = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter         = (Get-Date).AddDays(90)
    }
    $cert1 = New-SelfSignedCertificate @certParams1
    $cert2 = New-SelfSignedCertificate @certParams2
    New-PemCertFile -Cert $cert1 -Path "dif-diff-1.cer"
    New-PemCertFile -Cert $cert2 -Path "dif-diff-2.cer"
    Remove-Item $cert1.PSPath -Force
    Remove-Item $cert2.PSPath -Force

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe diff dif-diff-1.cer dif-diff-2.cer 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code 1 — certificates differ
        Assert-ExitCode -Expected 1

        # ASSERTION 2: Output shows source file names in the footer
        if ($outputStr -notmatch "dif-diff-1\.cer") {
            throw "Output should reference left source file"
        }
        if ($outputStr -notmatch "dif-diff-2\.cer") {
            throw "Output should reference right source file"
        }

        # ASSERTION 3: Output indicates changed fields
        if ($outputStr -notmatch "changed") {
            throw "Output should show 'changed' fields"
        }

        [PSCustomObject]@{ Success = $true; Details = "Different certs exits 1 and shows changed fields" }
    }
    finally {
        Remove-Item "dif-diff-1.cer" -Force -ErrorAction SilentlyContinue
        Remove-Item "dif-diff-2.cer" -Force -ErrorAction SilentlyContinue
    }
}

# Test dif-2.2: Two certs with different validity — Valid From/To changed
Invoke-Test -TestId "dif-2.2" -TestName "Different validity periods show Valid From/To as changed" -FilePrefix "dif-validity" -TestScript {
    # SETUP: Create two certificates with different expiry dates
    $certParams1 = @{
        Subject          = "CN=certz-diff-validity.local"
        KeyAlgorithm     = "ECDSA_nistP256"
        KeyExportPolicy  = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter         = (Get-Date).AddDays(30)
    }
    $certParams2 = @{
        Subject          = "CN=certz-diff-validity.local"
        KeyAlgorithm     = "ECDSA_nistP256"
        KeyExportPolicy  = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter         = (Get-Date).AddDays(90)
    }
    $cert1 = New-SelfSignedCertificate @certParams1
    $cert2 = New-SelfSignedCertificate @certParams2
    New-PemCertFile -Cert $cert1 -Path "dif-validity-1.cer"
    New-PemCertFile -Cert $cert2 -Path "dif-validity-2.cer"
    Remove-Item $cert1.PSPath -Force
    Remove-Item $cert2.PSPath -Force

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe diff dif-validity-1.cer dif-validity-2.cer 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code 1 — certificates differ (serial, thumbprint, validity)
        Assert-ExitCode -Expected 1

        # ASSERTION 2: Output shows Valid To as changed
        if ($outputStr -notmatch "Valid To") {
            throw "Output should show 'Valid To' field"
        }

        [PSCustomObject]@{ Success = $true; Details = "Validity period difference detected" }
    }
    finally {
        Remove-Item "dif-validity-1.cer" -Force -ErrorAction SilentlyContinue
        Remove-Item "dif-validity-2.cer" -Force -ErrorAction SilentlyContinue
    }
}

# Test dif-2.3: Two certs with different key algorithms — Key Algorithm changed
Invoke-Test -TestId "dif-2.3" -TestName "Different key algorithms show Key Algorithm as changed" -FilePrefix "dif-keyalg" -TestScript {
    # SETUP: Create two certificates with different key algorithms
    $certParams1 = @{
        Subject          = "CN=certz-diff-keyalg.local"
        KeyAlgorithm     = "ECDSA_nistP256"
        KeyExportPolicy  = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter         = (Get-Date).AddDays(90)
    }
    $certParams2 = @{
        Subject          = "CN=certz-diff-keyalg.local"
        KeyAlgorithm     = "RSA"
        KeyLength        = 2048
        KeyExportPolicy  = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter         = (Get-Date).AddDays(90)
    }
    $cert1 = New-SelfSignedCertificate @certParams1
    $cert2 = New-SelfSignedCertificate @certParams2
    New-PemCertFile -Cert $cert1 -Path "dif-keyalg-1.cer"
    New-PemCertFile -Cert $cert2 -Path "dif-keyalg-2.cer"
    Remove-Item $cert1.PSPath -Force
    Remove-Item $cert2.PSPath -Force

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe diff dif-keyalg-1.cer dif-keyalg-2.cer 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code 1 — certificates differ
        Assert-ExitCode -Expected 1

        # ASSERTION 2: Output shows Key Algorithm field
        if ($outputStr -notmatch "Key Algorithm") {
            throw "Output should show 'Key Algorithm' field"
        }

        [PSCustomObject]@{ Success = $true; Details = "Key algorithm difference detected" }
    }
    finally {
        Remove-Item "dif-keyalg-1.cer" -Force -ErrorAction SilentlyContinue
        Remove-Item "dif-keyalg-2.cer" -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# JSON OUTPUT TESTS
# ============================================================================
Write-TestHeader "Testing DIFF JSON Output"

# Test dif-3.1: Different certs with JSON — structured diff with changed/unchanged fields
Invoke-Test -TestId "dif-3.1" -TestName "JSON output for different certs has structured diff" -FilePrefix "dif-json-diff" -TestScript {
    # SETUP: Create two certificates with different CNs
    $certParams1 = @{
        Subject          = "CN=certz-diff-json-left.local"
        KeyAlgorithm     = "ECDSA_nistP256"
        KeyExportPolicy  = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter         = (Get-Date).AddDays(90)
    }
    $certParams2 = @{
        Subject          = "CN=certz-diff-json-right.local"
        KeyAlgorithm     = "ECDSA_nistP256"
        KeyExportPolicy  = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter         = (Get-Date).AddDays(90)
    }
    $cert1 = New-SelfSignedCertificate @certParams1
    $cert2 = New-SelfSignedCertificate @certParams2
    New-PemCertFile -Cert $cert1 -Path "dif-json-diff-1.cer"
    New-PemCertFile -Cert $cert2 -Path "dif-json-diff-2.cer"
    Remove-Item $cert1.PSPath -Force
    Remove-Item $cert2.PSPath -Force

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe diff dif-json-diff-1.cer dif-json-diff-2.cer --format json 2>&1

        # ASSERTION 1: Exit code 1
        Assert-ExitCode -Expected 1

        # ASSERTION 2: Valid JSON with expected structure
        try {
            $json = $output | ConvertFrom-Json

            if ($json.success -ne $true) {
                throw "JSON success should be true"
            }
            if ($json.areIdentical -ne $false) {
                throw "JSON areIdentical should be false for different certs"
            }
            if ($json.differenceCount -lt 1) {
                throw "JSON differenceCount should be >= 1"
            }
            if (-not $json.fields -or $json.fields.Count -eq 0) {
                throw "JSON fields array should not be empty"
            }

            # Check that Subject is marked as changed
            $subjectField = $json.fields | Where-Object { $_.name -eq "Subject" }
            if (-not $subjectField) {
                throw "JSON fields should include Subject"
            }
            if ($subjectField.status -ne "changed") {
                throw "Subject field should be 'changed'"
            }
            if ($subjectField.leftValue -notmatch "json-left") {
                throw "Left value should contain the left cert's CN"
            }
            if ($subjectField.rightValue -notmatch "json-right") {
                throw "Right value should contain the right cert's CN"
            }

            # Check that Key Algorithm is unchanged
            $keyField = $json.fields | Where-Object { $_.name -eq "Key Algorithm" }
            if (-not $keyField) {
                throw "JSON fields should include Key Algorithm"
            }
            if ($keyField.status -ne "unchanged") {
                throw "Key Algorithm should be 'unchanged' (both ECDSA P-256)"
            }
        }
        catch {
            if ($_.Exception.Message -match "JSON") {
                throw "Output is not valid JSON: $($output)"
            }
            throw $_
        }

        [PSCustomObject]@{ Success = $true; Details = "JSON diff has correct structure with changed/unchanged fields" }
    }
    finally {
        Remove-Item "dif-json-diff-1.cer" -Force -ErrorAction SilentlyContinue
        Remove-Item "dif-json-diff-2.cer" -Force -ErrorAction SilentlyContinue
    }
}

# Test dif-3.2: JSON output contains source1 and source2 fields
Invoke-Test -TestId "dif-3.2" -TestName "JSON output includes source1 and source2" -FilePrefix "dif-json-src" -TestScript {
    # SETUP: Create one cert
    $certParams = @{
        Subject          = "CN=certz-diff-json-src.local"
        KeyAlgorithm     = "ECDSA_nistP256"
        KeyExportPolicy  = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter         = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    New-PemCertFile -Cert $cert -Path "dif-json-src.cer"
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call — same cert for simplicity
        $output = & .\certz.exe diff dif-json-src.cer dif-json-src.cer --format json 2>&1

        # ASSERTION 1: Exit code 0
        Assert-ExitCode -Expected 0

        # ASSERTION 2: JSON contains source1 and source2
        try {
            $json = $output | ConvertFrom-Json
            if (-not $json.source1) {
                throw "JSON should contain source1"
            }
            if (-not $json.source2) {
                throw "JSON should contain source2"
            }
        }
        catch {
            if ($_.Exception.Message -match "JSON") {
                throw "Output is not valid JSON: $($output)"
            }
            throw $_
        }

        [PSCustomObject]@{ Success = $true; Details = "JSON includes source1 and source2 fields" }
    }
    finally {
        Remove-Item "dif-json-src.cer" -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# SOURCE TYPES TESTS
# ============================================================================
Write-TestHeader "Testing DIFF with Different Source Types"

# Test dif-4.1: PFX file with password
Invoke-Test -TestId "dif-4.1" -TestName "Diff two PFX files with passwords" -FilePrefix "dif-pfx" -TestScript {
    # SETUP: Create two PFX certificates using PowerShell
    $certParams1 = @{
        Subject          = "CN=certz-diff-pfx1.local"
        KeyAlgorithm     = "ECDSA_nistP256"
        KeyExportPolicy  = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter         = (Get-Date).AddDays(90)
    }
    $certParams2 = @{
        Subject          = "CN=certz-diff-pfx2.local"
        KeyAlgorithm     = "ECDSA_nistP256"
        KeyExportPolicy  = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter         = (Get-Date).AddDays(90)
    }
    $cert1 = New-SelfSignedCertificate @certParams1
    $cert2 = New-SelfSignedCertificate @certParams2
    $pass1 = ConvertTo-SecureString "DiffPass1" -AsPlainText -Force
    $pass2 = ConvertTo-SecureString "DiffPass2" -AsPlainText -Force
    Export-PfxCertificate -Cert $cert1 -FilePath "dif-pfx-1.pfx" -Password $pass1 | Out-Null
    Export-PfxCertificate -Cert $cert2 -FilePath "dif-pfx-2.pfx" -Password $pass2 | Out-Null
    Remove-Item $cert1.PSPath -Force
    Remove-Item $cert2.PSPath -Force

    try {
        # ACTION: Single certz.exe call with --password and --password2
        $output = & .\certz.exe diff dif-pfx-1.pfx dif-pfx-2.pfx --password DiffPass1 --password2 DiffPass2 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code 1 — certs differ
        Assert-ExitCode -Expected 1

        # ASSERTION 2: Source file names appear in footer
        if ($outputStr -notmatch "dif-pfx-1\.pfx") {
            throw "Output should reference left PFX source file"
        }
        if ($outputStr -notmatch "dif-pfx-2\.pfx") {
            throw "Output should reference right PFX source file"
        }

        [PSCustomObject]@{ Success = $true; Details = "PFX diff with separate passwords works" }
    }
    finally {
        Remove-Item "dif-pfx-1.pfx" -Force -ErrorAction SilentlyContinue
        Remove-Item "dif-pfx-2.pfx" -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# CLEANUP AND SUMMARY
# ============================================================================
if (-not $SkipCleanup) {
    Write-TestHeader "Cleaning Up Test Environment"
    Remove-TestFiles
    Write-Host "Test files removed" -ForegroundColor Gray
} else {
    Write-Host "`nSkipping cleanup (test files preserved for inspection)" -ForegroundColor Yellow
}

# Return to original directory
Exit-ToolsDirectory

# Display summary and exit
$exitCode = Write-TestSummary -SkipCleanup:$SkipCleanup
exit $exitCode
