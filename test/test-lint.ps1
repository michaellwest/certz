#Requires -Version 7.5

<#
.SYNOPSIS
    Test suite for certz lint command.

.DESCRIPTION
    This script tests the lint command for certificate validation against:
    - CA/B Forum Baseline Requirements
    - Mozilla NSS Policy
    - Development certificate best practices

    It follows test isolation principles from test-isolation-plan.md:
    - Each test invokes certz.exe exactly ONCE
    - Setup and teardown use pure PowerShell (no certz calls)
    - Assert against system state (exit codes, JSON output), NOT console output

.PARAMETER TestId
    Run specific tests by ID. Example: -TestId "lin-1.1", "lin-2.1"

.PARAMETER Category
    Run tests by category: cabf, mozilla, dev, format

.PARAMETER SkipCleanup
    Keep test files after running.

.PARAMETER Verbose
    Show detailed output.

.EXAMPLE
    .\test-lint.ps1
    Runs all tests with default settings.

.EXAMPLE
    .\test-lint.ps1 -Category cabf
    Runs only CA/B Forum rule tests.

.EXAMPLE
    .\test-lint.ps1 -TestId "lin-1.1", "lin-2.1" -Verbose
    Runs specific tests with verbose output.
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
    "cabf" = @("lin-1.1", "lin-1.2", "lin-1.3", "lin-1.4")
    "mozilla" = @("lin-2.1", "lin-2.2")
    "dev" = @("lin-3.1", "lin-3.2")
    "format" = @("fmt-1.1", "fmt-1.2")
}

# Initialize test environment
Initialize-TestEnvironment -TestId $TestId -Category $Category -TestCategories $TestCategories
Set-VerboseOutput -Enabled $Verbose

# Display banner
Write-Host "`nCertz Lint Command Test Suite" -ForegroundColor Magenta
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

# ============================================================================
# CA/B FORUM BASELINE REQUIREMENTS TESTS
# ============================================================================
Write-TestHeader "Testing CA/B Forum Rules"

# Test lin-1.1: Lint valid certificate (should pass)
Invoke-Test -TestId "lin-1.1" -TestName "Lint valid certificate (should pass)" -FilePrefix "lint-valid" -TestScript {
    # SETUP: Create a valid certificate using PowerShell
    $cert = New-SelfSignedCertificate -DnsName "localhost", "127.0.0.1" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyAlgorithm ECDSA_nistP256 `
        -NotAfter (Get-Date).AddDays(90) `
        -HashAlgorithm SHA256

    try {
        # Export to file
        $password = ConvertTo-SecureString "TestPass123" -AsPlainText -Force
        Export-PfxCertificate -Cert $cert -FilePath "lint-valid.pfx" -Password $password | Out-Null

        # ACTION: Single certz.exe call
        $output = & .\certz.exe lint lint-valid.pfx --password TestPass123 --format json 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code (0 = passed)
        Assert-ExitCode -Expected 0

        # ASSERTION 2: JSON indicates passed
        $json = $outputStr | ConvertFrom-Json
        if (-not $json.passed) {
            throw "Expected passed=true, got passed=$($json.passed)"
        }

        # ASSERTION 3: No errors
        if ($json.errorCount -gt 0) {
            throw "Expected no errors, got $($json.errorCount)"
        }

        [PSCustomObject]@{ Success = $true; Details = "Valid certificate passed lint" }
    }
    finally {
        # CLEANUP: Remove from cert store
        Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -ErrorAction SilentlyContinue
    }
}

# Test lin-1.2: Lint certificate with > 398 day validity (BR-001 error)
Invoke-Test -TestId "lin-1.2" -TestName "Lint cert with > 398 day validity (BR-001 error)" -FilePrefix "lint-long" -TestScript {
    # SETUP: Create a certificate with long validity
    $cert = New-SelfSignedCertificate -DnsName "localhost" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyAlgorithm ECDSA_nistP256 `
        -NotAfter (Get-Date).AddDays(500) `
        -HashAlgorithm SHA256

    try {
        # Export to file
        $password = ConvertTo-SecureString "TestPass123" -AsPlainText -Force
        Export-PfxCertificate -Cert $cert -FilePath "lint-long.pfx" -Password $password | Out-Null

        # ACTION: Single certz.exe call
        $output = & .\certz.exe lint lint-long.pfx --password TestPass123 --format json 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code (1 = failed)
        Assert-ExitCode -Expected 1

        # ASSERTION 2: JSON indicates failed
        $json = $outputStr | ConvertFrom-Json
        if ($json.passed) {
            throw "Expected passed=false, got passed=$($json.passed)"
        }

        # ASSERTION 3: Has BR-001 error
        $br001 = $json.findings | Where-Object { $_.ruleId -eq "BR-001" }
        if (-not $br001) {
            throw "Expected BR-001 finding for validity > 398 days"
        }

        [PSCustomObject]@{ Success = $true; Details = "Long validity detected as BR-001 error" }
    }
    finally {
        # CLEANUP: Remove from cert store
        Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -ErrorAction SilentlyContinue
    }
}

# Test lin-1.3: Lint URL (remote certificate)
Invoke-Test -TestId "lin-1.3" -TestName "Lint remote certificate from URL" -FilePrefix "lint-url" -TestScript {
    # ACTION: Single certz.exe call to lint a real website
    $output = & .\certz.exe lint https://www.google.com --format json 2>&1
    $outputStr = $output -join "`n"

    # ASSERTION 1: Exit code (0 = passed, or 1 if issues found)
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0 -and $exitCode -ne 1) {
        throw "Expected exit code 0 or 1, got $exitCode"
    }

    # ASSERTION 2: JSON is valid and has expected fields
    $json = $outputStr | ConvertFrom-Json
    if (-not $json.subject) {
        throw "Expected subject field in JSON output"
    }
    if (-not $json.thumbprint) {
        throw "Expected thumbprint field in JSON output"
    }

    [PSCustomObject]@{ Success = $true; Details = "Remote certificate linted successfully" }
}

# Test lin-1.4: Lint with severity filter
Invoke-Test -TestId "lin-1.4" -TestName "Lint with --severity error filter" -FilePrefix "lint-severity" -TestScript {
    # SETUP: Create a certificate with long validity (generates warning/error)
    $cert = New-SelfSignedCertificate -DnsName "localhost" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyAlgorithm ECDSA_nistP256 `
        -NotAfter (Get-Date).AddDays(500) `
        -HashAlgorithm SHA256

    try {
        # Export to file
        $password = ConvertTo-SecureString "TestPass123" -AsPlainText -Force
        Export-PfxCertificate -Cert $cert -FilePath "lint-severity.pfx" -Password $password | Out-Null

        # ACTION: Single certz.exe call with severity filter
        $output = & .\certz.exe lint lint-severity.pfx --password TestPass123 --severity error --format json 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: JSON is valid
        $json = $outputStr | ConvertFrom-Json

        # ASSERTION 2: Only errors are reported (no warnings or info)
        $nonErrors = $json.findings | Where-Object { $_.severity -ne "Error" }
        if ($nonErrors -and $nonErrors.Count -gt 0) {
            throw "Expected only Error severity findings, but found other severities"
        }

        [PSCustomObject]@{ Success = $true; Details = "Severity filter works correctly" }
    }
    finally {
        # CLEANUP: Remove from cert store
        Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# MOZILLA NSS POLICY TESTS
# ============================================================================
Write-TestHeader "Testing Mozilla NSS Rules"

# Test lin-2.1: Lint with mozilla policy
Invoke-Test -TestId "lin-2.1" -TestName "Lint with mozilla policy set" -FilePrefix "lint-mozilla" -TestScript {
    # SETUP: Create a valid certificate
    $cert = New-SelfSignedCertificate -DnsName "localhost" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyAlgorithm ECDSA_nistP256 `
        -NotAfter (Get-Date).AddDays(90) `
        -HashAlgorithm SHA256

    try {
        # Export to file
        $password = ConvertTo-SecureString "TestPass123" -AsPlainText -Force
        Export-PfxCertificate -Cert $cert -FilePath "lint-mozilla.pfx" -Password $password | Out-Null

        # ACTION: Single certz.exe call with mozilla policy
        $output = & .\certz.exe lint lint-mozilla.pfx --password TestPass123 --policy mozilla --format json 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: JSON is valid
        $json = $outputStr | ConvertFrom-Json

        # ASSERTION 2: Policy set is mozilla
        if ($json.policySet -ne "mozilla") {
            throw "Expected policySet=mozilla, got policySet=$($json.policySet)"
        }

        [PSCustomObject]@{ Success = $true; Details = "Mozilla policy applied successfully" }
    }
    finally {
        # CLEANUP: Remove from cert store
        Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -ErrorAction SilentlyContinue
    }
}

# Test lin-2.2: Lint with all policies
Invoke-Test -TestId "lin-2.2" -TestName "Lint with all policy sets combined" -FilePrefix "lint-all" -TestScript {
    # SETUP: Create a valid certificate
    $cert = New-SelfSignedCertificate -DnsName "localhost" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyAlgorithm ECDSA_nistP256 `
        -NotAfter (Get-Date).AddDays(90) `
        -HashAlgorithm SHA256

    try {
        # Export to file
        $password = ConvertTo-SecureString "TestPass123" -AsPlainText -Force
        Export-PfxCertificate -Cert $cert -FilePath "lint-all.pfx" -Password $password | Out-Null

        # ACTION: Single certz.exe call with all policies
        $output = & .\certz.exe lint lint-all.pfx --password TestPass123 --policy all --format json 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: JSON is valid
        $json = $outputStr | ConvertFrom-Json

        # ASSERTION 2: Policy set is all
        if ($json.policySet -ne "all") {
            throw "Expected policySet=all, got policySet=$($json.policySet)"
        }

        [PSCustomObject]@{ Success = $true; Details = "All policies applied successfully" }
    }
    finally {
        # CLEANUP: Remove from cert store
        Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# DEVELOPMENT CERTIFICATE TESTS
# ============================================================================
Write-TestHeader "Testing Development Certificate Rules"

# Test lin-3.1: Lint with dev policy (good cert)
Invoke-Test -TestId "lin-3.1" -TestName "Lint dev cert with localhost + 127.0.0.1" -FilePrefix "lint-dev-good" -TestScript {
    # SETUP: Create a good dev certificate with localhost and 127.0.0.1
    $cert = New-SelfSignedCertificate -DnsName "localhost", "127.0.0.1" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyAlgorithm ECDSA_nistP256 `
        -NotAfter (Get-Date).AddDays(90) `
        -HashAlgorithm SHA256

    try {
        # Export to file
        $password = ConvertTo-SecureString "TestPass123" -AsPlainText -Force
        Export-PfxCertificate -Cert $cert -FilePath "lint-dev-good.pfx" -Password $password | Out-Null

        # ACTION: Single certz.exe call with dev policy
        $output = & .\certz.exe lint lint-dev-good.pfx --password TestPass123 --policy dev --format json 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: JSON indicates passed
        $json = $outputStr | ConvertFrom-Json
        if (-not $json.passed) {
            throw "Expected passed=true for good dev cert"
        }

        # ASSERTION 3: No DEV-003 warning (has all recommended SANs)
        $dev003 = $json.findings | Where-Object { $_.ruleId -eq "DEV-003" }
        if ($dev003) {
            throw "Did not expect DEV-003 warning for cert with localhost and 127.0.0.1"
        }

        [PSCustomObject]@{ Success = $true; Details = "Good dev cert passed" }
    }
    finally {
        # CLEANUP: Remove from cert store
        Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -ErrorAction SilentlyContinue
    }
}

# Test lin-3.2: Lint dev cert missing 127.0.0.1 (DEV-003 info)
Invoke-Test -TestId "lin-3.2" -TestName "Lint dev cert missing 127.0.0.1 (DEV-003 info)" -FilePrefix "lint-dev-info" -TestScript {
    # SETUP: Create a dev certificate without 127.0.0.1
    $cert = New-SelfSignedCertificate -DnsName "myapp.local" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyAlgorithm ECDSA_nistP256 `
        -NotAfter (Get-Date).AddDays(90) `
        -HashAlgorithm SHA256

    try {
        # Export to file
        $password = ConvertTo-SecureString "TestPass123" -AsPlainText -Force
        Export-PfxCertificate -Cert $cert -FilePath "lint-dev-info.pfx" -Password $password | Out-Null

        # ACTION: Single certz.exe call with dev policy
        $output = & .\certz.exe lint lint-dev-info.pfx --password TestPass123 --policy dev --format json 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code (should pass since DEV-003 is info level)
        Assert-ExitCode -Expected 0

        # ASSERTION 2: JSON is valid
        $json = $outputStr | ConvertFrom-Json

        # ASSERTION 3: Has DEV-003 info
        $dev003 = $json.findings | Where-Object { $_.ruleId -eq "DEV-003" }
        if (-not $dev003) {
            throw "Expected DEV-003 info for cert missing localhost/127.0.0.1"
        }

        [PSCustomObject]@{ Success = $true; Details = "DEV-003 info detected correctly" }
    }
    finally {
        # CLEANUP: Remove from cert store
        Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# FORMAT OUTPUT TESTS
# ============================================================================
Write-TestHeader "Testing Output Format"

# Test fmt-1.1: Text output format
Invoke-Test -TestId "fmt-1.1" -TestName "Lint with text output format" -FilePrefix "lint-text" -TestScript {
    # SETUP: Create a valid certificate
    $cert = New-SelfSignedCertificate -DnsName "localhost" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyAlgorithm ECDSA_nistP256 `
        -NotAfter (Get-Date).AddDays(90) `
        -HashAlgorithm SHA256

    try {
        # Export to file
        $password = ConvertTo-SecureString "TestPass123" -AsPlainText -Force
        Export-PfxCertificate -Cert $cert -FilePath "lint-text.pfx" -Password $password | Out-Null

        # ACTION: Single certz.exe call with text format (default)
        $output = & .\certz.exe lint lint-text.pfx --password TestPass123 --format text 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Output contains expected text elements
        if ($outputStr -notmatch "Certificate Lint") {
            throw "Expected 'Certificate Lint' in text output"
        }
        if ($outputStr -notmatch "PASSED|FAILED") {
            throw "Expected 'PASSED' or 'FAILED' in text output"
        }

        [PSCustomObject]@{ Success = $true; Details = "Text output format works" }
    }
    finally {
        # CLEANUP: Remove from cert store
        Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -ErrorAction SilentlyContinue
    }
}

# Test fmt-1.2: JSON output format
Invoke-Test -TestId "fmt-1.2" -TestName "Lint with JSON output format" -FilePrefix "lint-json" -TestScript {
    # SETUP: Create a valid certificate
    $cert = New-SelfSignedCertificate -DnsName "localhost" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyAlgorithm ECDSA_nistP256 `
        -NotAfter (Get-Date).AddDays(90) `
        -HashAlgorithm SHA256

    try {
        # Export to file
        $password = ConvertTo-SecureString "TestPass123" -AsPlainText -Force
        Export-PfxCertificate -Cert $cert -FilePath "lint-json.pfx" -Password $password | Out-Null

        # ACTION: Single certz.exe call with JSON format
        $output = & .\certz.exe lint lint-json.pfx --password TestPass123 --format json 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Output is valid JSON
        $json = $outputStr | ConvertFrom-Json
        if (-not $json) {
            throw "Output is not valid JSON"
        }

        # ASSERTION 3: JSON has required fields
        if ($null -eq $json.success) {
            throw "Missing 'success' field in JSON"
        }
        if ($null -eq $json.passed) {
            throw "Missing 'passed' field in JSON"
        }
        if (-not $json.thumbprint) {
            throw "Missing 'thumbprint' field in JSON"
        }

        [PSCustomObject]@{ Success = $true; Details = "JSON output format works" }
    }
    finally {
        # CLEANUP: Remove from cert store
        Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# CLEANUP AND REPORT
# ============================================================================
if (-not $SkipCleanup) {
    Write-Host "`nCleaning up test files..." -ForegroundColor Yellow
    Remove-TestFiles
}

# Return to original directory
Exit-ToolsDirectory

# Show summary
Write-TestSummary
