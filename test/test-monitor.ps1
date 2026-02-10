#requires -version 7

<#
.SYNOPSIS
    Test suite for certz monitor command.

.DESCRIPTION
    This script tests the monitor command for certificate expiration monitoring:
    - File monitoring (PFX, PEM, directory scanning)
    - URL monitoring (remote certificate retrieval)
    - Store monitoring (certificate store scanning)
    - Threshold and exit codes
    - JSON output format

    It follows test isolation principles from test-isolation-plan.md:
    - Each test invokes certz.exe exactly ONCE
    - Setup and teardown use pure PowerShell (no certz calls)
    - Assert against system state (exit codes, JSON output), NOT console output

.PARAMETER TestId
    Run specific tests by ID. Example: -TestId "mon-1.1", "mon-2.1"

.PARAMETER Category
    Run tests by category: file, url, store, threshold, format

.PARAMETER SkipCleanup
    Keep test files after running.

.PARAMETER Verbose
    Show detailed output.

.EXAMPLE
    .\test-monitor.ps1
    Runs all tests with default settings.

.EXAMPLE
    .\test-monitor.ps1 -Category file
    Runs only file monitoring tests.

.EXAMPLE
    .\test-monitor.ps1 -TestId "mon-1.1", "mon-2.1" -Verbose
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
    "file" = @("mon-1.1", "mon-1.2", "mon-1.3", "mon-1.4")
    "url" = @("mon-2.1")
    "store" = @("mon-3.1", "mon-3.2")
    "threshold" = @("mon-4.1", "mon-4.2", "mon-4.3")
    "format" = @("mon-5.1", "mon-5.2")
}

# Initialize test environment
Initialize-TestEnvironment -TestId $TestId -Category $Category -TestCategories $TestCategories
Set-VerboseOutput -Enabled $Verbose

# Display banner
Write-Host "`nCertz Monitor Command Test Suite" -ForegroundColor Magenta
Write-Host "=================================`n" -ForegroundColor Magenta

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
# FILE MONITORING TESTS
# ============================================================================
Write-TestHeader "Testing File Monitoring"

# Test mon-1.1: Monitor single PFX file
Invoke-Test -TestId "mon-1.1" -TestName "Monitor single PFX file" -FilePrefix "monitor-single" -TestScript {
    # SETUP: Create a certificate with 60 days validity
    $cert = New-SelfSignedCertificate -DnsName "localhost" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyAlgorithm ECDSA_nistP256 `
        -NotAfter (Get-Date).AddDays(60) `
        -HashAlgorithm SHA256

    try {
        # Export to file
        $password = ConvertTo-SecureString "TestPass123" -AsPlainText -Force
        Export-PfxCertificate -Cert $cert -FilePath "monitor-single.pfx" -Password $password | Out-Null

        # ACTION: Single certz.exe call
        $output = & .\certz.exe monitor monitor-single.pfx --password TestPass123 --format json 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code (0 = all valid)
        Assert-ExitCode -Expected 0

        # ASSERTION 2: JSON indicates success
        $json = $outputStr | ConvertFrom-Json
        if (-not $json.success) {
            throw "Expected success=true, got success=$($json.success)"
        }

        # ASSERTION 3: Total scanned is 1
        if ($json.totalScanned -ne 1) {
            throw "Expected totalScanned=1, got $($json.totalScanned)"
        }

        # ASSERTION 4: Certificate is valid (60 days > 30 day threshold)
        if ($json.validCount -ne 1) {
            throw "Expected validCount=1, got $($json.validCount)"
        }

        [PSCustomObject]@{ Success = $true; Details = "Single PFX file monitored successfully" }
    }
    finally {
        # CLEANUP: Remove from cert store
        Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -ErrorAction SilentlyContinue
    }
}

# Test mon-1.2: Monitor directory with multiple certificates
Invoke-Test -TestId "mon-1.2" -TestName "Monitor directory with multiple certificates" -FilePrefix "monitor-dir" -TestScript {
    # SETUP: Create a test directory with multiple certificates
    $testDir = "monitor-test-dir"
    New-Item -ItemType Directory -Path $testDir -Force | Out-Null

    $cert1 = New-SelfSignedCertificate -DnsName "cert1.local" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyAlgorithm ECDSA_nistP256 `
        -NotAfter (Get-Date).AddDays(60) `
        -HashAlgorithm SHA256

    $cert2 = New-SelfSignedCertificate -DnsName "cert2.local" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyAlgorithm ECDSA_nistP256 `
        -NotAfter (Get-Date).AddDays(90) `
        -HashAlgorithm SHA256

    try {
        # Export to files
        $password = ConvertTo-SecureString "TestPass123" -AsPlainText -Force
        Export-PfxCertificate -Cert $cert1 -FilePath "$testDir\cert1.pfx" -Password $password | Out-Null
        Export-PfxCertificate -Cert $cert2 -FilePath "$testDir\cert2.pfx" -Password $password | Out-Null

        # ACTION: Single certz.exe call
        $output = & .\certz.exe monitor $testDir --password TestPass123 --format json 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code (0 = all valid)
        Assert-ExitCode -Expected 0

        # ASSERTION 2: JSON indicates success
        $json = $outputStr | ConvertFrom-Json
        if (-not $json.success) {
            throw "Expected success=true"
        }

        # ASSERTION 3: Total scanned is 2
        if ($json.totalScanned -ne 2) {
            throw "Expected totalScanned=2, got $($json.totalScanned)"
        }

        [PSCustomObject]@{ Success = $true; Details = "Directory with 2 certificates monitored" }
    }
    finally {
        # CLEANUP
        Remove-Item -Path "Cert:\CurrentUser\My\$($cert1.Thumbprint)" -ErrorAction SilentlyContinue
        Remove-Item -Path "Cert:\CurrentUser\My\$($cert2.Thumbprint)" -ErrorAction SilentlyContinue
        Remove-Item -Path $testDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Test mon-1.3: Monitor with recursive directory scan
Invoke-Test -TestId "mon-1.3" -TestName "Monitor directory recursively" -FilePrefix "monitor-recursive" -TestScript {
    # SETUP: Create nested directory structure
    $testDir = "monitor-recursive-dir"
    $subDir = "$testDir\subdir"
    New-Item -ItemType Directory -Path $subDir -Force | Out-Null

    $cert1 = New-SelfSignedCertificate -DnsName "root.local" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyAlgorithm ECDSA_nistP256 `
        -NotAfter (Get-Date).AddDays(60) `
        -HashAlgorithm SHA256

    $cert2 = New-SelfSignedCertificate -DnsName "nested.local" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyAlgorithm ECDSA_nistP256 `
        -NotAfter (Get-Date).AddDays(90) `
        -HashAlgorithm SHA256

    try {
        # Export to files
        $password = ConvertTo-SecureString "TestPass123" -AsPlainText -Force
        Export-PfxCertificate -Cert $cert1 -FilePath "$testDir\root.pfx" -Password $password | Out-Null
        Export-PfxCertificate -Cert $cert2 -FilePath "$subDir\nested.pfx" -Password $password | Out-Null

        # ACTION: Single certz.exe call with --recursive
        $output = & .\certz.exe monitor $testDir --recursive --password TestPass123 --format json 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code (0 = all valid)
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Total scanned is 2 (both root and nested)
        $json = $outputStr | ConvertFrom-Json
        if ($json.totalScanned -ne 2) {
            throw "Expected totalScanned=2 (recursive), got $($json.totalScanned)"
        }

        [PSCustomObject]@{ Success = $true; Details = "Recursive scan found 2 certificates" }
    }
    finally {
        # CLEANUP
        Remove-Item -Path "Cert:\CurrentUser\My\$($cert1.Thumbprint)" -ErrorAction SilentlyContinue
        Remove-Item -Path "Cert:\CurrentUser\My\$($cert2.Thumbprint)" -ErrorAction SilentlyContinue
        Remove-Item -Path $testDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Test mon-1.4: Monitor PEM certificate file
Invoke-Test -TestId "mon-1.4" -TestName "Monitor PEM certificate file" -FilePrefix "monitor-pem" -TestScript {
    # SETUP: Create a certificate and export as PEM
    $cert = New-SelfSignedCertificate -DnsName "localhost" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyAlgorithm ECDSA_nistP256 `
        -NotAfter (Get-Date).AddDays(60) `
        -HashAlgorithm SHA256

    try {
        # Export as Base64 (PEM format)
        $base64 = [Convert]::ToBase64String($cert.RawData)
        $pem = "-----BEGIN CERTIFICATE-----`n"
        for ($i = 0; $i -lt $base64.Length; $i += 64) {
            $pem += $base64.Substring($i, [Math]::Min(64, $base64.Length - $i)) + "`n"
        }
        $pem += "-----END CERTIFICATE-----"
        Set-Content -Path "monitor-pem.pem" -Value $pem

        # ACTION: Single certz.exe call
        $output = & .\certz.exe monitor monitor-pem.pem --format json 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code (0 = valid)
        Assert-ExitCode -Expected 0

        # ASSERTION 2: JSON indicates success
        $json = $outputStr | ConvertFrom-Json
        if ($json.totalScanned -ne 1) {
            throw "Expected totalScanned=1, got $($json.totalScanned)"
        }

        [PSCustomObject]@{ Success = $true; Details = "PEM file monitored successfully" }
    }
    finally {
        # CLEANUP
        Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# URL MONITORING TESTS
# ============================================================================
Write-TestHeader "Testing URL Monitoring"

# Test mon-2.1: Monitor certificate from URL
Invoke-Test -TestId "mon-2.1" -TestName "Monitor certificate from URL" -FilePrefix "monitor-url" -TestScript {
    # ACTION: Single certz.exe call to monitor a real website
    $output = & .\certz.exe monitor https://www.google.com --format json 2>&1
    $outputStr = $output -join "`n"

    # ASSERTION 1: Exit code (0 or may vary based on certificate status)
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0 -and $exitCode -ne 1 -and $exitCode -ne 2) {
        throw "Expected exit code 0, 1, or 2, got $exitCode"
    }

    # ASSERTION 2: JSON is valid
    $json = $outputStr | ConvertFrom-Json
    if (-not $json) {
        throw "Invalid JSON output"
    }

    # ASSERTION 3: At least one certificate was scanned
    if ($json.totalScanned -lt 1) {
        throw "Expected at least 1 certificate scanned from URL"
    }

    [PSCustomObject]@{ Success = $true; Details = "URL certificate monitored successfully" }
}

# ============================================================================
# STORE MONITORING TESTS
# ============================================================================
Write-TestHeader "Testing Store Monitoring"

# Test mon-3.1: Monitor certificate store
Invoke-Test -TestId "mon-3.1" -TestName "Monitor CurrentUser\\My store" -FilePrefix "monitor-store" -TestScript {
    # ACTION: Single certz.exe call to scan the store
    $output = & .\certz.exe monitor --store My --location CurrentUser --format json 2>&1
    $outputStr = $output -join "`n"

    # ASSERTION 1: Exit code (varies based on store contents)
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0 -and $exitCode -ne 1 -and $exitCode -ne 2) {
        throw "Expected exit code 0, 1, or 2, got $exitCode"
    }

    # ASSERTION 2: JSON is valid
    $json = $outputStr | ConvertFrom-Json
    if (-not $json) {
        throw "Invalid JSON output"
    }

    # ASSERTION 3: Has expected fields
    if ($null -eq $json.totalScanned) {
        throw "Missing totalScanned field in JSON"
    }

    [PSCustomObject]@{ Success = $true; Details = "Store monitored with $($json.totalScanned) certificates" }
}

# Test mon-3.2: Monitor Root store
Invoke-Test -TestId "mon-3.2" -TestName "Monitor CurrentUser\\Root store" -FilePrefix "monitor-root-store" -TestScript {
    # ACTION: Single certz.exe call to scan the Root store
    $output = & .\certz.exe monitor --store Root --location CurrentUser --format json 2>&1
    $outputStr = $output -join "`n"

    # ASSERTION 1: Exit code (varies based on store contents)
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0 -and $exitCode -ne 1 -and $exitCode -ne 2) {
        throw "Expected exit code 0, 1, or 2, got $exitCode"
    }

    # ASSERTION 2: JSON is valid
    $json = $outputStr | ConvertFrom-Json
    if (-not $json) {
        throw "Invalid JSON output"
    }

    [PSCustomObject]@{ Success = $true; Details = "Root store monitored with $($json.totalScanned) certificates" }
}

# ============================================================================
# THRESHOLD AND EXIT CODE TESTS
# ============================================================================
Write-TestHeader "Testing Threshold and Exit Codes"

# Test mon-4.1: Certificate expiring within threshold triggers warning
Invoke-Test -TestId "mon-4.1" -TestName "Certificate expiring within threshold" -FilePrefix "monitor-expiring" -TestScript {
    # SETUP: Create a certificate expiring in 15 days (within 30 day default threshold)
    $cert = New-SelfSignedCertificate -DnsName "expiring.local" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyAlgorithm ECDSA_nistP256 `
        -NotAfter (Get-Date).AddDays(15) `
        -HashAlgorithm SHA256

    try {
        # Export to file
        $password = ConvertTo-SecureString "TestPass123" -AsPlainText -Force
        Export-PfxCertificate -Cert $cert -FilePath "monitor-expiring.pfx" -Password $password | Out-Null

        # ACTION: Single certz.exe call (default 30 day threshold)
        $output = & .\certz.exe monitor monitor-expiring.pfx --password TestPass123 --format json 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code (0 without --fail-on-warning)
        Assert-ExitCode -Expected 0

        # ASSERTION 2: expiringCount is 1
        $json = $outputStr | ConvertFrom-Json
        if ($json.expiringCount -ne 1) {
            throw "Expected expiringCount=1, got $($json.expiringCount)"
        }

        # ASSERTION 3: Certificate status is Expiring
        $cert = $json.certificates | Where-Object { $_.status -eq "Expiring" }
        if (-not $cert) {
            throw "Expected certificate with status=Expiring"
        }

        [PSCustomObject]@{ Success = $true; Details = "Expiring certificate detected correctly" }
    }
    finally {
        # CLEANUP
        Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -ErrorAction SilentlyContinue
    }
}

# Test mon-4.2: --fail-on-warning returns exit code 1
Invoke-Test -TestId "mon-4.2" -TestName "--fail-on-warning returns exit code 1" -FilePrefix "monitor-failwarn" -TestScript {
    # SETUP: Create a certificate expiring in 15 days
    $cert = New-SelfSignedCertificate -DnsName "expiring.local" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyAlgorithm ECDSA_nistP256 `
        -NotAfter (Get-Date).AddDays(15) `
        -HashAlgorithm SHA256

    try {
        # Export to file
        $password = ConvertTo-SecureString "TestPass123" -AsPlainText -Force
        Export-PfxCertificate -Cert $cert -FilePath "monitor-failwarn.pfx" -Password $password | Out-Null

        # ACTION: Single certz.exe call with --fail-on-warning
        $output = & .\certz.exe monitor monitor-failwarn.pfx --password TestPass123 --fail-on-warning --format json 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code 1 (warning threshold reached)
        Assert-ExitCode -Expected 1

        [PSCustomObject]@{ Success = $true; Details = "Exit code 1 returned with --fail-on-warning" }
    }
    finally {
        # CLEANUP
        Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -ErrorAction SilentlyContinue
    }
}

# Test mon-4.3: Custom warning threshold
Invoke-Test -TestId "mon-4.3" -TestName "Custom warning threshold (--warn 90)" -FilePrefix "monitor-threshold" -TestScript {
    # SETUP: Create a certificate expiring in 60 days
    $cert = New-SelfSignedCertificate -DnsName "threshold.local" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyAlgorithm ECDSA_nistP256 `
        -NotAfter (Get-Date).AddDays(60) `
        -HashAlgorithm SHA256

    try {
        # Export to file
        $password = ConvertTo-SecureString "TestPass123" -AsPlainText -Force
        Export-PfxCertificate -Cert $cert -FilePath "monitor-threshold.pfx" -Password $password | Out-Null

        # ACTION: Single certz.exe call with --warn 90 (60 days < 90 day threshold)
        $output = & .\certz.exe monitor monitor-threshold.pfx --password TestPass123 --warn 90 --format json 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code 0 (no --fail-on-warning)
        Assert-ExitCode -Expected 0

        # ASSERTION 2: warnThreshold is 90
        $json = $outputStr | ConvertFrom-Json
        if ($json.warnThreshold -ne 90) {
            throw "Expected warnThreshold=90, got $($json.warnThreshold)"
        }

        # ASSERTION 3: expiringCount is 1 (60 < 90)
        if ($json.expiringCount -ne 1) {
            throw "Expected expiringCount=1, got $($json.expiringCount)"
        }

        [PSCustomObject]@{ Success = $true; Details = "Custom 90-day threshold detected expiring cert" }
    }
    finally {
        # CLEANUP
        Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# FORMAT OUTPUT TESTS
# ============================================================================
Write-TestHeader "Testing Output Format"

# Test mon-5.1: Text output format
Invoke-Test -TestId "mon-5.1" -TestName "Monitor with text output format" -FilePrefix "monitor-text" -TestScript {
    # SETUP: Create a valid certificate
    $cert = New-SelfSignedCertificate -DnsName "localhost" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyAlgorithm ECDSA_nistP256 `
        -NotAfter (Get-Date).AddDays(60) `
        -HashAlgorithm SHA256

    try {
        # Export to file
        $password = ConvertTo-SecureString "TestPass123" -AsPlainText -Force
        Export-PfxCertificate -Cert $cert -FilePath "monitor-text.pfx" -Password $password | Out-Null

        # ACTION: Single certz.exe call with text format (default)
        $output = & .\certz.exe monitor monitor-text.pfx --password TestPass123 --format text 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Output contains expected text elements
        if ($outputStr -notmatch "Certificate Expiration Monitor") {
            throw "Expected 'Certificate Expiration Monitor' in text output"
        }
        if ($outputStr -notmatch "Threshold") {
            throw "Expected 'Threshold' in text output"
        }

        [PSCustomObject]@{ Success = $true; Details = "Text output format works" }
    }
    finally {
        # CLEANUP
        Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -ErrorAction SilentlyContinue
    }
}

# Test mon-5.2: JSON output format
Invoke-Test -TestId "mon-5.2" -TestName "Monitor with JSON output format" -FilePrefix "monitor-json" -TestScript {
    # SETUP: Create a valid certificate
    $cert = New-SelfSignedCertificate -DnsName "localhost" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyAlgorithm ECDSA_nistP256 `
        -NotAfter (Get-Date).AddDays(60) `
        -HashAlgorithm SHA256

    try {
        # Export to file
        $password = ConvertTo-SecureString "TestPass123" -AsPlainText -Force
        Export-PfxCertificate -Cert $cert -FilePath "monitor-json.pfx" -Password $password | Out-Null

        # ACTION: Single certz.exe call with JSON format
        $output = & .\certz.exe monitor monitor-json.pfx --password TestPass123 --format json 2>&1
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
        if ($null -eq $json.totalScanned) {
            throw "Missing 'totalScanned' field in JSON"
        }
        if ($null -eq $json.validCount) {
            throw "Missing 'validCount' field in JSON"
        }
        if ($null -eq $json.expiringCount) {
            throw "Missing 'expiringCount' field in JSON"
        }
        if ($null -eq $json.expiredCount) {
            throw "Missing 'expiredCount' field in JSON"
        }
        if ($null -eq $json.warnThreshold) {
            throw "Missing 'warnThreshold' field in JSON"
        }
        if (-not $json.certificates) {
            throw "Missing 'certificates' field in JSON"
        }

        [PSCustomObject]@{ Success = $true; Details = "JSON output format works" }
    }
    finally {
        # CLEANUP
        Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# CLEANUP AND REPORT
# ============================================================================
if (-not $SkipCleanup) {
    Write-Host "`nCleaning up test files..." -ForegroundColor Yellow
    Remove-TestFiles
    # Clean up test directories
    Remove-Item -Path "monitor-test-dir" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "monitor-recursive-dir" -Recurse -Force -ErrorAction SilentlyContinue
}

# Return to original directory
Exit-ToolsDirectory

# Show summary
Write-TestSummary
