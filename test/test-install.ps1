#Requires -Version 7.5

<#
.SYNOPSIS
    Test suite for certz install command.

.DESCRIPTION
    Tests certificate installation functionality into Windows certificate stores.
    Follows test isolation principles from test-isolation-plan.md.

.PARAMETER TestId
    Run specific tests by ID. Example: -TestId "ist-1.1", "ist-2.1"

.PARAMETER Category
    Run tests by category: store, exportable, errors

.PARAMETER SkipCleanup
    Keep test files after running.

.PARAMETER Verbose
    Show detailed output.

.EXAMPLE
    .\test-install.ps1
    Runs all tests with default settings.

.EXAMPLE
    .\test-install.ps1 -Category store
    Runs only store installation tests.

.EXAMPLE
    .\test-install.ps1 -TestId "ist-1.1" -Verbose
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
    "store"      = @("ist-1.1", "ist-1.2")
    "exportable" = @("ist-2.1", "ist-2.2")
    "errors"     = @("ist-3.1", "ist-3.2")
}

# Initialize test environment
Initialize-TestEnvironment -TestId $TestId -Category $Category -TestCategories $TestCategories
Set-VerboseOutput -Enabled $Verbose

# Display banner
Write-Host "`nCertz Install Command Test Suite" -ForegroundColor Magenta
Write-Host "================================`n" -ForegroundColor Magenta

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
Remove-TestFiles "ist-"

# ============================================================================
# STORE INSTALLATION TESTS
# ============================================================================
Write-TestHeader "Testing Store Installation"

# Test ist-1.1: Install PFX to CurrentUser\My store
Invoke-Test -TestId "ist-1.1" -TestName "Install PFX to CurrentUser\My store" -FilePrefix "ist" -TestScript {
    # SETUP: Create a certificate using PowerShell (NOT certz)
    $cert = New-SelfSignedCertificate `
        -Subject "CN=ist-install-test.local" `
        -DnsName "ist-install-test.local" `
        -KeyAlgorithm ECDSA_nistP256 `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -NotAfter (Get-Date).AddDays(365) `
        -KeyExportPolicy Exportable
    $thumbprint = $cert.Thumbprint
    $pw = ConvertTo-SecureString "TestPass123" -AsPlainText -Force
    Export-PfxCertificate -Cert $cert -FilePath "ist-install.pfx" -Password $pw | Out-Null
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Install to CurrentUser\My (single certz.exe call)
        $output = & .\certz.exe install --file ist-install.pfx --password TestPass123 --sn My --sl CurrentUser 2>&1
        $exitCode = $LASTEXITCODE

        # ASSERTIONS
        if ($exitCode -ne 0) {
            throw "Expected exit code 0, got $exitCode. Output: $output"
        }

        # Verify cert is now in store
        $installed = Assert-CertificateInStore -Thumbprint $thumbprint -StoreName "My" -StoreLocation "CurrentUser"
        if (-not $installed) {
            throw "Certificate not found in CurrentUser\My store after install"
        }

        [PSCustomObject]@{ Success = $true; Details = "Installed to CurrentUser\My store" }
    }
    finally {
        # CLEANUP: Remove cert from store using PowerShell
        $toRemove = Get-ChildItem "Cert:\CurrentUser\My" -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $thumbprint }
        if ($toRemove) { Remove-Item $toRemove.PSPath -Force -ErrorAction SilentlyContinue }
    }
}

# Test ist-1.2: Install PFX to CurrentUser\CA store
# Note: CurrentUser\Root triggers a UI confirmation dialog and cannot be tested non-interactively.
# Using CA store instead, which is accessible without UI prompts.
Invoke-Test -TestId "ist-1.2" -TestName "Install PFX to CurrentUser\CA store" -FilePrefix "ist" -TestScript {
    # SETUP: Create a certificate using PowerShell (NOT certz)
    $cert = New-SelfSignedCertificate `
        -Subject "CN=ist-ca-store-test.local" `
        -DnsName "ist-ca-store-test.local" `
        -KeyAlgorithm ECDSA_nistP256 `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -NotAfter (Get-Date).AddDays(365) `
        -KeyExportPolicy Exportable
    $thumbprint = $cert.Thumbprint
    $pw = ConvertTo-SecureString "TestPass123" -AsPlainText -Force
    Export-PfxCertificate -Cert $cert -FilePath "ist-ca-store.pfx" -Password $pw | Out-Null
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Install to CurrentUser\CertificateAuthority (single certz.exe call)
        $output = & .\certz.exe install --file ist-ca-store.pfx --password TestPass123 --sn CertificateAuthority --sl CurrentUser 2>&1
        $exitCode = $LASTEXITCODE

        # ASSERTIONS
        if ($exitCode -ne 0) {
            throw "Expected exit code 0, got $exitCode. Output: $output"
        }

        # Verify cert is now in CertificateAuthority store
        # Note: PowerShell cert provider uses "CA" as the path alias for CertificateAuthority
        $installed = Assert-CertificateInStore -Thumbprint $thumbprint -StoreName "CA" -StoreLocation "CurrentUser"
        if (-not $installed) {
            throw "Certificate not found in CurrentUser\CA store after install"
        }

        [PSCustomObject]@{ Success = $true; Details = "Installed to CurrentUser\CertificateAuthority store" }
    }
    finally {
        # CLEANUP: Remove cert from store using PowerShell
        $toRemove = Get-ChildItem "Cert:\CurrentUser\CA" -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $thumbprint }
        if ($toRemove) { Remove-Item $toRemove.PSPath -Force -ErrorAction SilentlyContinue }
    }
}

# ============================================================================
# EXPORTABLE OPTION TESTS
# ============================================================================
Write-TestHeader "Testing Exportable Option"

# Test ist-2.1: Install with exportable key (default)
Invoke-Test -TestId "ist-2.1" -TestName "Install with exportable key (default)" -FilePrefix "ist" -TestScript {
    # SETUP: Create a certificate using PowerShell (NOT certz)
    $cert = New-SelfSignedCertificate `
        -Subject "CN=ist-exportable-test.local" `
        -DnsName "ist-exportable-test.local" `
        -KeyAlgorithm ECDSA_nistP256 `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -NotAfter (Get-Date).AddDays(365) `
        -KeyExportPolicy Exportable
    $thumbprint = $cert.Thumbprint
    $pw = ConvertTo-SecureString "TestPass123" -AsPlainText -Force
    Export-PfxCertificate -Cert $cert -FilePath "ist-exportable.pfx" -Password $pw | Out-Null
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Install with --exportable true (single certz.exe call)
        $output = & .\certz.exe install --file ist-exportable.pfx --password TestPass123 --sn My --sl CurrentUser --exportable true 2>&1
        $exitCode = $LASTEXITCODE

        # ASSERTIONS
        if ($exitCode -ne 0) {
            throw "Expected exit code 0, got $exitCode. Output: $output"
        }

        # Verify cert is in store and key is exportable
        $installed = Get-ChildItem "Cert:\CurrentUser\My" -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $thumbprint }
        if (-not $installed) {
            throw "Certificate not found in store after install"
        }

        # Try to export the private key - should succeed
        $exportSuccess = $false
        try {
            $exported = $installed.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, "ExportTest123")
            $exportSuccess = $exported.Length -gt 0
        } catch {
            $exportSuccess = $false
        }

        if (-not $exportSuccess) {
            throw "Private key should be exportable but export failed"
        }

        [PSCustomObject]@{ Success = $true; Details = "Private key is exportable" }
    }
    finally {
        # CLEANUP: Remove cert from store using PowerShell
        $toRemove = Get-ChildItem "Cert:\CurrentUser\My" -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $thumbprint }
        if ($toRemove) { Remove-Item $toRemove.PSPath -Force -ErrorAction SilentlyContinue }
    }
}

# Test ist-2.2: Install with non-exportable key
Invoke-Test -TestId "ist-2.2" -TestName "Install with non-exportable key" -FilePrefix "ist" -TestScript {
    # SETUP: Create a certificate using PowerShell (NOT certz)
    $cert = New-SelfSignedCertificate `
        -Subject "CN=ist-nonexport-test.local" `
        -DnsName "ist-nonexport-test.local" `
        -KeyAlgorithm ECDSA_nistP256 `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -NotAfter (Get-Date).AddDays(365) `
        -KeyExportPolicy Exportable
    $thumbprint = $cert.Thumbprint
    $pw = ConvertTo-SecureString "TestPass123" -AsPlainText -Force
    Export-PfxCertificate -Cert $cert -FilePath "ist-nonexport.pfx" -Password $pw | Out-Null
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Install with --exportable false (single certz.exe call)
        $output = & .\certz.exe install --file ist-nonexport.pfx --password TestPass123 --sn My --sl CurrentUser --exportable false 2>&1
        $exitCode = $LASTEXITCODE

        # ASSERTIONS
        if ($exitCode -ne 0) {
            throw "Expected exit code 0, got $exitCode. Output: $output"
        }

        # Verify cert is in store
        $installed = Get-ChildItem "Cert:\CurrentUser\My" -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $thumbprint }
        if (-not $installed) {
            throw "Certificate not found in store after install"
        }

        # Try to export the private key - should fail
        $exportFailed = $false
        try {
            $exported = $installed.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, "ExportTest123")
        } catch {
            $exportFailed = $true
        }

        if (-not $exportFailed) {
            throw "Private key should NOT be exportable but export succeeded"
        }

        [PSCustomObject]@{ Success = $true; Details = "Private key is non-exportable" }
    }
    finally {
        # CLEANUP: Remove cert from store using PowerShell
        $toRemove = Get-ChildItem "Cert:\CurrentUser\My" -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $thumbprint }
        if ($toRemove) { Remove-Item $toRemove.PSPath -Force -ErrorAction SilentlyContinue }
    }
}

# ============================================================================
# ERROR HANDLING TESTS
# ============================================================================
Write-TestHeader "Testing Error Handling"

# Test ist-3.1: Error when file not found
Invoke-Test -TestId "ist-3.1" -TestName "Error: file not found" -FilePrefix "ist" -TestScript {
    # ACTION: Install non-existent file (single certz.exe call)
    $output = & .\certz.exe install --file nonexistent-ist.pfx --password TestPass123 2>&1
    $exitCode = $LASTEXITCODE

    # ASSERTIONS: FileNotFoundException caught by Program.cs -> exit code 1
    if ($exitCode -ne 1) {
        throw "Expected exit code 1 (file not found), got $exitCode"
    }

    [PSCustomObject]@{ Success = $true; Details = "Correctly failed with exit code 1 for missing file" }
}

# Test ist-3.2: Error when password is wrong
Invoke-Test -TestId "ist-3.2" -TestName "Error: wrong password" -FilePrefix "ist" -TestScript {
    # SETUP: Create a certificate using PowerShell (NOT certz)
    $cert = New-SelfSignedCertificate `
        -Subject "CN=ist-badpw-test.local" `
        -DnsName "ist-badpw-test.local" `
        -KeyAlgorithm ECDSA_nistP256 `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -NotAfter (Get-Date).AddDays(365) `
        -KeyExportPolicy Exportable
    $pw = ConvertTo-SecureString "CorrectPass" -AsPlainText -Force
    Export-PfxCertificate -Cert $cert -FilePath "ist-badpw.pfx" -Password $pw | Out-Null
    Remove-Item $cert.PSPath -Force

    # ACTION: Install with wrong password (single certz.exe call)
    $output = & .\certz.exe install --file ist-badpw.pfx --password WrongPassword 2>&1
    $exitCode = $LASTEXITCODE

    # ASSERTIONS: Should fail with non-zero exit code
    if ($exitCode -eq 0) {
        throw "Expected non-zero exit code for wrong password, got 0"
    }

    [PSCustomObject]@{ Success = $true; Details = "Correctly failed for wrong password" }
}

# ============================================================================
# CLEANUP AND SUMMARY
# ============================================================================
if (-not $SkipCleanup) {
    Write-TestHeader "Cleaning Up Test Environment"
    Remove-TestFiles "ist-"
    Write-Host "Test files removed" -ForegroundColor Gray
} else {
    Write-Host "`nSkipping cleanup (test files preserved for inspection)" -ForegroundColor Yellow
}

# Return to original directory
Exit-ToolsDirectory

# Display summary and exit
$exitCode = Write-TestSummary -SkipCleanup:$SkipCleanup
exit $exitCode
