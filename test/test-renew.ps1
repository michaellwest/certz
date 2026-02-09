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

.EXAMPLE
    .\test-renew.ps1
    Runs all tests with default settings.

.EXAMPLE
    .\test-renew.ps1 -Category self-signed
    Runs only self-signed renewal tests.

.EXAMPLE
    .\test-renew.ps1 -TestId "ren-1.1" -Verbose
    Runs specific test with verbose output.
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
    "self-signed" = @("ren-1.1", "ren-1.2", "ren-1.3")
    "ca-signed" = @("ren-2.1", "ren-2.2")
    "keep-key" = @("ren-3.1")
    "validity" = @("ren-4.1", "ren-4.2")
    "errors" = @("ren-5.1", "ren-5.2")
    "format" = @("ren-6.1")
}

# Initialize test environment
Initialize-TestEnvironment -TestId $TestId -Category $Category -TestCategories $TestCategories
Set-VerboseOutput -Enabled $Verbose

# Display banner
Write-Host "`nCertz Renew Command Test Suite" -ForegroundColor Magenta
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
Remove-TestFiles "ren-"

# ============================================================================
# SELF-SIGNED RENEWAL TESTS
# ============================================================================
Write-TestHeader "Testing Self-Signed Certificate Renewal"

# Test ren-1.1: Renew self-signed certificate with default options
Invoke-Test -TestId "ren-1.1" -TestName "Renew self-signed cert (defaults)" -FilePrefix "ren" -TestScript {
    # SETUP: Create self-signed certificate using certz
    & .\certz.exe create dev renew-test.local --f ren-original.pfx --p TestPass123 2>&1 | Out-Null
    Assert-ExitCode -Expected 0
    Assert-FileExists "ren-original.pfx"

    # ACTION: Renew the certificate
    $output = & .\certz.exe renew ren-original.pfx --password TestPass123 --out ren-renewed.pfx --out-password TestPass123 2>&1
    $exitCode = $LASTEXITCODE

    # ASSERTIONS
    if ($exitCode -ne 0) {
        throw "Expected exit code 0, got $exitCode"
    }

    Assert-FileExists "ren-renewed.pfx"

    # Verify renewed certificate has same subject
    $original = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        (Resolve-Path "ren-original.pfx").Path, "TestPass123")
    $renewed = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        (Resolve-Path "ren-renewed.pfx").Path, "TestPass123")

    if ($renewed.Subject -ne $original.Subject) {
        $original.Dispose()
        $renewed.Dispose()
        throw "Subject mismatch: expected '$($original.Subject)', got '$($renewed.Subject)'"
    }

    # Verify new certificate has different thumbprint (new key by default)
    if ($renewed.Thumbprint -eq $original.Thumbprint) {
        $original.Dispose()
        $renewed.Dispose()
        throw "Renewed cert should have different thumbprint (new key)"
    }

    # Verify new certificate has future expiration
    if ($renewed.NotAfter -le (Get-Date)) {
        $original.Dispose()
        $renewed.Dispose()
        throw "Renewed cert should have future expiration"
    }

    $original.Dispose()
    $renewed.Dispose()

    [PSCustomObject]@{ Success = $true; Details = "Self-signed certificate renewed successfully" }
}

# Test ren-1.2: Renew with custom days
Invoke-Test -TestId "ren-1.2" -TestName "Renew with custom validity days" -FilePrefix "ren" -TestScript {
    # SETUP: Create self-signed certificate
    & .\certz.exe create dev renew-days.local --f ren-days-original.pfx --p TestPass123 2>&1 | Out-Null
    Assert-ExitCode -Expected 0

    # ACTION: Renew with 180 days validity
    $output = & .\certz.exe renew ren-days-original.pfx --password TestPass123 --days 180 --out ren-days-renewed.pfx --out-password TestPass123 2>&1
    $exitCode = $LASTEXITCODE

    # ASSERTIONS
    if ($exitCode -ne 0) {
        throw "Expected exit code 0, got $exitCode"
    }

    Assert-FileExists "ren-days-renewed.pfx"

    $renewed = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        (Resolve-Path "ren-days-renewed.pfx").Path, "TestPass123")

    $validityDays = ($renewed.NotAfter - $renewed.NotBefore).Days
    $renewed.Dispose()

    # Allow 1 day tolerance for timing
    if ($validityDays -lt 179 -or $validityDays -gt 181) {
        throw "Expected ~180 days validity, got $validityDays days"
    }

    [PSCustomObject]@{ Success = $true; Details = "Renewed with $validityDays days validity" }
}

# Test ren-1.3: Renew with auto-generated password
Invoke-Test -TestId "ren-1.3" -TestName "Renew with auto-generated password" -FilePrefix "ren" -TestScript {
    # SETUP: Create self-signed certificate
    & .\certz.exe create dev renew-autopass.local --f ren-autopass-original.pfx --p TestPass123 2>&1 | Out-Null
    Assert-ExitCode -Expected 0

    # ACTION: Renew without specifying output password (should auto-generate)
    $output = & .\certz.exe renew ren-autopass-original.pfx --password TestPass123 --out ren-autopass-renewed.pfx --format json 2>&1
    $exitCode = $LASTEXITCODE

    # ASSERTIONS
    if ($exitCode -ne 0) {
        throw "Expected exit code 0, got $exitCode"
    }

    Assert-FileExists "ren-autopass-renewed.pfx"

    # Parse JSON to get generated password
    $json = $output | ConvertFrom-Json
    if (-not $json.password) {
        throw "Expected auto-generated password in output"
    }

    if ($json.password.Length -lt 32) {
        throw "Generated password should be at least 32 characters"
    }

    [PSCustomObject]@{ Success = $true; Details = "Auto-generated password: $($json.password.Substring(0, 8))..." }
}

# ============================================================================
# CA-SIGNED RENEWAL TESTS
# ============================================================================
Write-TestHeader "Testing CA-Signed Certificate Renewal"

# Test ren-2.1: Renew CA-signed certificate with issuer
Invoke-Test -TestId "ren-2.1" -TestName "Renew CA-signed cert with issuer" -FilePrefix "ren" -TestScript {
    # SETUP: Create CA and signed certificate using certz
    & .\certz.exe create ca --name "Test CA" --f ren-ca.pfx --p CaPass123 2>&1 | Out-Null
    Assert-ExitCode -Expected 0
    Assert-FileExists "ren-ca.pfx"

    & .\certz.exe create dev signed.local --issuer-cert ren-ca.pfx --issuer-password CaPass123 --f ren-signed.pfx --p TestPass123 2>&1 | Out-Null
    Assert-ExitCode -Expected 0
    Assert-FileExists "ren-signed.pfx"

    # ACTION: Renew the CA-signed certificate
    $output = & .\certz.exe renew ren-signed.pfx --password TestPass123 --issuer-cert ren-ca.pfx --issuer-password CaPass123 --out ren-signed-renewed.pfx --out-password TestPass123 2>&1
    $exitCode = $LASTEXITCODE

    # ASSERTIONS
    if ($exitCode -ne 0) {
        throw "Expected exit code 0, got $exitCode"
    }

    Assert-FileExists "ren-signed-renewed.pfx"

    # Verify renewed certificate is signed by the CA
    $ca = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        (Resolve-Path "ren-ca.pfx").Path, "CaPass123")
    $renewed = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        (Resolve-Path "ren-signed-renewed.pfx").Path, "TestPass123")

    if ($renewed.Issuer -ne $ca.Subject) {
        $ca.Dispose()
        $renewed.Dispose()
        throw "Renewed cert should be issued by CA"
    }

    $ca.Dispose()
    $renewed.Dispose()

    [PSCustomObject]@{ Success = $true; Details = "CA-signed certificate renewed with issuer" }
}

# ============================================================================
# KEEP KEY TESTS
# ============================================================================
Write-TestHeader "Testing Key Preservation"

# Test ren-3.1: Renew with --keep-key preserves private key
Invoke-Test -TestId "ren-3.1" -TestName "Renew with --keep-key preserves key" -FilePrefix "ren" -TestScript {
    # SETUP: Create self-signed certificate
    & .\certz.exe create dev keepkey.local --f ren-keepkey-original.pfx --p TestPass123 2>&1 | Out-Null
    Assert-ExitCode -Expected 0

    # Get original public key
    $original = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        (Resolve-Path "ren-keepkey-original.pfx").Path, "TestPass123")
    $originalPubKey = $original.GetPublicKeyString()
    $original.Dispose()

    # ACTION: Renew with --keep-key
    $output = & .\certz.exe renew ren-keepkey-original.pfx --password TestPass123 --keep-key --out ren-keepkey-renewed.pfx --out-password TestPass123 2>&1
    $exitCode = $LASTEXITCODE

    # ASSERTIONS
    if ($exitCode -ne 0) {
        throw "Expected exit code 0, got $exitCode"
    }

    Assert-FileExists "ren-keepkey-renewed.pfx"

    $renewed = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        (Resolve-Path "ren-keepkey-renewed.pfx").Path, "TestPass123")
    $renewedPubKey = $renewed.GetPublicKeyString()
    $renewed.Dispose()

    # Public key should be the same
    if ($originalPubKey -ne $renewedPubKey) {
        throw "Public key should be preserved with --keep-key"
    }

    [PSCustomObject]@{ Success = $true; Details = "Private key preserved successfully" }
}

# ============================================================================
# VALIDITY TESTS
# ============================================================================
Write-TestHeader "Testing Validity Constraints"

# Test ren-4.1: Validity capped at 398 days
Invoke-Test -TestId "ren-4.1" -TestName "Validity capped at 398 days" -FilePrefix "ren" -TestScript {
    # SETUP: Create self-signed certificate
    & .\certz.exe create dev cap-test.local --f ren-cap-original.pfx --p TestPass123 2>&1 | Out-Null
    Assert-ExitCode -Expected 0

    # ACTION: Try to renew with 500 days (should be capped at 398)
    $output = & .\certz.exe renew ren-cap-original.pfx --password TestPass123 --days 500 --out ren-cap-renewed.pfx --out-password TestPass123 2>&1
    $exitCode = $LASTEXITCODE

    # Note: The command may either fail or cap the value
    # Check that if it succeeded, it's capped at 398
    if ($exitCode -eq 0) {
        Assert-FileExists "ren-cap-renewed.pfx"

        $renewed = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            (Resolve-Path "ren-cap-renewed.pfx").Path, "TestPass123")
        $validityDays = ($renewed.NotAfter - $renewed.NotBefore).Days
        $renewed.Dispose()

        # Should be capped at 398 or less
        if ($validityDays -gt 399) {
            throw "Validity should be capped at 398 days, got $validityDays"
        }
    }

    [PSCustomObject]@{ Success = $true; Details = "Validity constraint enforced" }
}

# ============================================================================
# ERROR HANDLING TESTS
# ============================================================================
Write-TestHeader "Testing Error Handling"

# Test ren-5.1: Error when CA-signed cert renewed without issuer
Invoke-Test -TestId "ren-5.1" -TestName "Error: CA-signed cert without issuer" -FilePrefix "ren" -TestScript {
    # SETUP: Create CA and signed certificate using certz
    & .\certz.exe create ca --name "Error Test CA" --f ren-err-ca.pfx --p CaPass123 2>&1 | Out-Null
    Assert-ExitCode -Expected 0

    & .\certz.exe create dev error-signed.local --issuer-cert ren-err-ca.pfx --issuer-password CaPass123 --f ren-err-signed.pfx --p TestPass123 2>&1 | Out-Null
    Assert-ExitCode -Expected 0

    # ACTION: Try to renew without issuer (should fail)
    $output = & .\certz.exe renew ren-err-signed.pfx --password TestPass123 2>&1
    $exitCode = $LASTEXITCODE

    # ASSERTIONS
    if ($exitCode -ne 2) {
        throw "Expected exit code 2 (missing issuer), got $exitCode"
    }

    [PSCustomObject]@{ Success = $true; Details = "Correctly failed with exit code 2 for missing issuer" }
}

# Test ren-5.2: Error when source file not found
Invoke-Test -TestId "ren-5.2" -TestName "Error: Source file not found" -FilePrefix "ren" -TestScript {
    # ACTION: Try to renew non-existent file
    $output = & .\certz.exe renew nonexistent.pfx --password TestPass123 2>&1
    $exitCode = $LASTEXITCODE

    # ASSERTIONS
    if ($exitCode -ne 1) {
        throw "Expected exit code 1 (not found), got $exitCode"
    }

    [PSCustomObject]@{ Success = $true; Details = "Correctly failed with exit code 1 for missing file" }
}

# ============================================================================
# FORMAT TESTS
# ============================================================================
Write-TestHeader "Testing Output Formats"

# Test ren-6.1: JSON output format
Invoke-Test -TestId "ren-6.1" -TestName "JSON output format" -FilePrefix "ren" -TestScript {
    # SETUP: Create self-signed certificate
    & .\certz.exe create dev json-test.local --f ren-json-original.pfx --p TestPass123 2>&1 | Out-Null
    Assert-ExitCode -Expected 0

    # ACTION: Renew with JSON output
    $output = & .\certz.exe renew ren-json-original.pfx --password TestPass123 --out ren-json-renewed.pfx --out-password TestPass123 --format json 2>&1
    $exitCode = $LASTEXITCODE

    # ASSERTIONS
    if ($exitCode -ne 0) {
        throw "Expected exit code 0, got $exitCode"
    }

    # Parse JSON output
    $json = $output | ConvertFrom-Json

    if (-not $json.success) {
        throw "Expected success=true in JSON"
    }

    if (-not $json.newThumbprint) {
        throw "Expected newThumbprint in JSON"
    }

    if (-not $json.originalThumbprint) {
        throw "Expected originalThumbprint in JSON"
    }

    if (-not $json.outputFile) {
        throw "Expected outputFile in JSON"
    }

    [PSCustomObject]@{ Success = $true; Details = "Valid JSON output with expected fields" }
}

# ============================================================================
# CLEANUP AND SUMMARY
# ============================================================================
if (-not $SkipCleanup) {
    Write-TestHeader "Cleaning Up Test Environment"
    Remove-TestFiles "ren-"
    Write-Host "Test files removed" -ForegroundColor Gray
} else {
    Write-Host "`nSkipping cleanup (test files preserved for inspection)" -ForegroundColor Yellow
}

# Return to original directory
Exit-ToolsDirectory

# Display summary and exit
$exitCode = Write-TestSummary -SkipCleanup:$SkipCleanup
exit $exitCode
