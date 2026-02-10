#Requires -Version 7.5

<#
.SYNOPSIS
    Test suite for certz verify command.

.DESCRIPTION
    Tests certificate verification functionality including expiration checks,
    chain validation, trust verification, and warning-days detection.
    Follows test isolation principles from test-isolation-plan.md.

.PARAMETER TestId
    Run specific tests by ID. Example: -TestId "ver-1.1", "ver-3.1"

.PARAMETER Category
    Run tests by category: file, store, errors, format

.PARAMETER SkipCleanup
    Keep test files after running.

.PARAMETER Verbose
    Show detailed output.

.EXAMPLE
    .\test-verify.ps1
    Runs all tests with default settings.

.EXAMPLE
    .\test-verify.ps1 -Category file
    Runs only file-based verification tests.

.EXAMPLE
    .\test-verify.ps1 -TestId "ver-1.2" -Verbose
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
    "file"   = @("ver-1.1", "ver-1.2", "ver-1.3")
    "store"  = @("ver-2.1")
    "errors" = @("ver-3.1", "ver-3.2")
    "format" = @("ver-4.1")
}

# Initialize test environment
Initialize-TestEnvironment -TestId $TestId -Category $Category -TestCategories $TestCategories
Set-VerboseOutput -Enabled $Verbose

# Display banner
Write-Host "`nCertz Verify Command Test Suite" -ForegroundColor Magenta
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
Remove-TestFiles "ver-"

# ============================================================================
# FILE-BASED VERIFICATION TESTS
# ============================================================================
Write-TestHeader "Testing File-Based Verification"

# Test ver-1.1: Verify valid self-signed cert from file
Invoke-Test -TestId "ver-1.1" -TestName "Verify valid self-signed cert from file" -FilePrefix "ver" -TestScript {
    # SETUP: Create a valid self-signed certificate using PowerShell (NOT certz)
    $cert = New-SelfSignedCertificate `
        -Subject "CN=ver-valid-test.local" `
        -DnsName "ver-valid-test.local" `
        -KeyAlgorithm ECDSA_nistP256 `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -NotAfter (Get-Date).AddDays(365) `
        -KeyExportPolicy Exportable
    $pw = ConvertTo-SecureString "TestPass123" -AsPlainText -Force
    Export-PfxCertificate -Cert $cert -FilePath "ver-valid.pfx" -Password $pw | Out-Null
    Remove-Item $cert.PSPath -Force

    # ACTION: Verify the certificate with JSON output (single certz.exe call)
    $output = & .\certz.exe verify --file ver-valid.pfx --password TestPass123 --format json 2>&1
    $exitCode = $LASTEXITCODE

    # ASSERTIONS: Command succeeds (exit code 0) even for self-signed certs
    if ($exitCode -ne 0) {
        throw "Expected exit code 0, got $exitCode. Output: $output"
    }

    # Parse JSON to verify basic structure
    $json = $output | ConvertFrom-Json
    if (-not $json.subject -or $json.subject -notmatch "ver-valid-test\.local") {
        throw "Expected subject containing ver-valid-test.local"
    }

    [PSCustomObject]@{ Success = $true; Details = "Verification completed for valid self-signed cert" }
}

# Test ver-1.2: Verify expired cert from file
Invoke-Test -TestId "ver-1.2" -TestName "Verify expired cert from file (JSON)" -FilePrefix "ver" -TestScript {
    # SETUP: Create an expired certificate using PowerShell (NOT certz)
    $cert = New-SelfSignedCertificate `
        -Subject "CN=ver-expired-test.local" `
        -DnsName "ver-expired-test.local" `
        -KeyAlgorithm ECDSA_nistP256 `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -NotBefore (Get-Date).AddDays(-400) `
        -NotAfter (Get-Date).AddDays(-1) `
        -KeyExportPolicy Exportable
    $pw = ConvertTo-SecureString "TestPass123" -AsPlainText -Force
    Export-PfxCertificate -Cert $cert -FilePath "ver-expired.pfx" -Password $pw | Out-Null
    Remove-Item $cert.PSPath -Force

    # ACTION: Verify the expired certificate with JSON output (single certz.exe call)
    $output = & .\certz.exe verify --file ver-expired.pfx --password TestPass123 --format json 2>&1
    $exitCode = $LASTEXITCODE

    # ASSERTIONS: Command succeeds (returns result) but cert is expired
    if ($exitCode -ne 0) {
        throw "Expected exit code 0, got $exitCode. Output: $output"
    }

    # Parse JSON to verify expiration detection
    $json = $output | ConvertFrom-Json
    if (-not $json.expirationCheck.isExpired) {
        throw "Expected expirationCheck.isExpired=true for expired cert"
    }
    if ($json.expirationCheck.passed) {
        throw "Expected expirationCheck.passed=false for expired cert"
    }

    [PSCustomObject]@{ Success = $true; Details = "Expired certificate correctly detected" }
}

# Test ver-1.3: Verify with --warning-days detects expiring-soon cert
Invoke-Test -TestId "ver-1.3" -TestName "Warning-days detects expiring-soon cert" -FilePrefix "ver" -TestScript {
    # SETUP: Create a certificate expiring in 15 days using PowerShell (NOT certz)
    $cert = New-SelfSignedCertificate `
        -Subject "CN=ver-expiring-test.local" `
        -DnsName "ver-expiring-test.local" `
        -KeyAlgorithm ECDSA_nistP256 `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -NotAfter (Get-Date).AddDays(15) `
        -KeyExportPolicy Exportable
    $pw = ConvertTo-SecureString "TestPass123" -AsPlainText -Force
    Export-PfxCertificate -Cert $cert -FilePath "ver-expiring.pfx" -Password $pw | Out-Null
    Remove-Item $cert.PSPath -Force

    # ACTION: Verify with 30-day warning threshold (single certz.exe call)
    $output = & .\certz.exe verify --file ver-expiring.pfx --password TestPass123 --warning-days 30 --format json 2>&1
    $exitCode = $LASTEXITCODE

    # ASSERTIONS
    if ($exitCode -ne 0) {
        throw "Expected exit code 0, got $exitCode. Output: $output"
    }

    $json = $output | ConvertFrom-Json
    if (-not $json.expirationCheck.isExpiringSoon) {
        throw "Expected expirationCheck.isExpiringSoon=true (cert expires in 15 days, threshold 30)"
    }
    if ($json.expirationCheck.warningThreshold -ne 30) {
        throw "Expected warningThreshold=30, got $($json.expirationCheck.warningThreshold)"
    }

    [PSCustomObject]@{ Success = $true; Details = "Expiring-soon correctly detected with warning-days" }
}

# ============================================================================
# STORE-BASED VERIFICATION TESTS
# ============================================================================
Write-TestHeader "Testing Store-Based Verification"

# Test ver-2.1: Verify from store by thumbprint
Invoke-Test -TestId "ver-2.1" -TestName "Verify from store by thumbprint" -FilePrefix "ver" -TestScript {
    # SETUP: Create certificate in store using PowerShell (NOT certz)
    $cert = New-SelfSignedCertificate `
        -Subject "CN=ver-store-test.local" `
        -DnsName "ver-store-test.local" `
        -KeyAlgorithm ECDSA_nistP256 `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -NotAfter (Get-Date).AddDays(365) `
        -KeyExportPolicy Exportable
    $thumbprint = $cert.Thumbprint

    try {
        # ACTION: Verify from store by thumbprint (single certz.exe call)
        $output = & .\certz.exe verify --thumbprint $thumbprint --storelocation CurrentUser --format json 2>&1
        $exitCode = $LASTEXITCODE

        # ASSERTIONS
        if ($exitCode -ne 0) {
            throw "Expected exit code 0, got $exitCode. Output: $output"
        }

        [PSCustomObject]@{ Success = $true; Details = "Verified certificate from store by thumbprint" }
    }
    finally {
        # CLEANUP: Remove cert from store
        Remove-Item $cert.PSPath -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# ERROR HANDLING TESTS
# ============================================================================
Write-TestHeader "Testing Error Handling"

# Test ver-3.1: Error when file not found
Invoke-Test -TestId "ver-3.1" -TestName "Error: file not found" -FilePrefix "ver" -TestScript {
    # ACTION: Verify non-existent file (single certz.exe call)
    $output = & .\certz.exe verify --file nonexistent-ver.pfx 2>&1
    $exitCode = $LASTEXITCODE

    # ASSERTIONS: FileNotFoundException caught by Program.cs -> exit code 1
    if ($exitCode -ne 1) {
        throw "Expected exit code 1 (file not found), got $exitCode"
    }

    [PSCustomObject]@{ Success = $true; Details = "Correctly failed with exit code 1 for missing file" }
}

# Test ver-3.2: Error when no source specified
Invoke-Test -TestId "ver-3.2" -TestName "Error: no source specified" -FilePrefix "ver" -TestScript {
    # ACTION: Verify without file or thumbprint (single certz.exe call)
    # Note: VerifyCommand.cs uses formatter.WriteError() + return (no exception).
    # This documents current behavior.
    $output = & .\certz.exe verify 2>&1
    $exitCode = $LASTEXITCODE

    # The error message should indicate a source is required
    $outputText = $output -join "`n"
    if ($outputText -notmatch "specify|source|file|thumbprint") {
        throw "Expected error message about missing source. Got: $outputText"
    }

    [PSCustomObject]@{ Success = $true; Details = "Error message displayed for missing source" }
}

# ============================================================================
# FORMAT TESTS
# ============================================================================
Write-TestHeader "Testing Output Formats"

# Test ver-4.1: JSON output format
Invoke-Test -TestId "ver-4.1" -TestName "JSON output format" -FilePrefix "ver" -TestScript {
    # SETUP: Create certificate using PowerShell (NOT certz)
    $cert = New-SelfSignedCertificate `
        -Subject "CN=ver-json-test.local" `
        -DnsName "ver-json-test.local" `
        -KeyAlgorithm ECDSA_nistP256 `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -NotAfter (Get-Date).AddDays(365) `
        -KeyExportPolicy Exportable
    $pw = ConvertTo-SecureString "TestPass123" -AsPlainText -Force
    Export-PfxCertificate -Cert $cert -FilePath "ver-json.pfx" -Password $pw | Out-Null
    Remove-Item $cert.PSPath -Force

    # ACTION: Verify with JSON output (single certz.exe call)
    $output = & .\certz.exe verify --file ver-json.pfx --password TestPass123 --format json 2>&1
    $exitCode = $LASTEXITCODE

    # ASSERTIONS
    if ($exitCode -ne 0) {
        throw "Expected exit code 0, got $exitCode. Output: $output"
    }

    # Parse JSON and verify structure
    $json = $output | ConvertFrom-Json

    if ($null -eq $json.success) {
        throw "Expected 'success' field in JSON"
    }
    if (-not $json.subject) {
        throw "Expected 'subject' field in JSON"
    }
    if (-not $json.thumbprint) {
        throw "Expected 'thumbprint' field in JSON"
    }
    if ($null -eq $json.expirationCheck) {
        throw "Expected 'expirationCheck' object in JSON"
    }
    if ($null -eq $json.chainValidation) {
        throw "Expected 'chainValidation' object in JSON"
    }
    if ($null -eq $json.trustCheck) {
        throw "Expected 'trustCheck' object in JSON"
    }

    [PSCustomObject]@{ Success = $true; Details = "Valid JSON output with expected structure" }
}

# ============================================================================
# CLEANUP AND SUMMARY
# ============================================================================
if (-not $SkipCleanup) {
    Write-TestHeader "Cleaning Up Test Environment"
    Remove-TestFiles "ver-"
    Write-Host "Test files removed" -ForegroundColor Gray
} else {
    Write-Host "`nSkipping cleanup (test files preserved for inspection)" -ForegroundColor Yellow
}

# Return to original directory
Exit-ToolsDirectory

# Display summary and exit
$exitCode = Write-TestSummary -SkipCleanup:$SkipCleanup
exit $exitCode
