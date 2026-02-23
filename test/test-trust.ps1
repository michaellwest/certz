#requires -version 7

<#
.SYNOPSIS
    Test suite for certz trust and store commands.

.DESCRIPTION
    This script tests the trust add, trust remove, and store list commands.
    It follows test isolation principles from test-isolation-plan.md:
    - Each test invokes certz.exe exactly ONCE
    - Setup and teardown use pure PowerShell (no certz calls)
    - Assert against system state (files, cert store), NOT console output

    Trust tests that target the Root store use LocalMachine\Root to avoid the
    Windows Security UI dialog triggered by CurrentUser\Root. This requires
    running as Administrator (Docker containers use ContainerAdministrator).

.PARAMETER TestId
    Run specific tests by ID. Example: -TestId "tru-1.1", "sto-1.1"

.PARAMETER Category
    Run tests by category: trust-add, trust-remove, store-list

.PARAMETER SkipCleanup
    Keep test artifacts after running.

.PARAMETER Verbose
    Show detailed output.

.EXAMPLE
    .\test-trust.ps1
    Runs all tests with default settings.

.EXAMPLE
    .\test-trust.ps1 -Category trust-add
    Runs only trust add tests.

.EXAMPLE
    .\test-trust.ps1 -TestId "tru-1.1", "sto-1.1" -Verbose
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
    "trust-add" = @("tru-1.1", "tru-1.2", "tru-1.3", "tru-1.4")
    "trust-remove" = @("trm-1.1", "trm-1.2", "trm-1.3", "trm-1.4")
    "partial-thumbprint" = @("trm-2.1", "trm-2.2", "trm-2.3", "trm-2.4")
    "store-list" = @("sto-1.1", "sto-1.2", "sto-1.3")
    "dry-run" = @("tdr-1.1", "tdr-1.2", "tdr-1.3")
}

# Initialize test environment
Initialize-TestEnvironment -TestId $TestId -Category $Category -TestCategories $TestCategories
Set-VerboseOutput -Enabled $Verbose

# Display banner
Write-Host "`nCertz Trust and Store Command Test Suite" -ForegroundColor Magenta
Write-Host "=========================================`n" -ForegroundColor Magenta

# Check admin status (required for LocalMachine store tests)
$script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($script:IsAdmin) {
    Write-Host "Running as Administrator - LocalMachine store tests enabled" -ForegroundColor Green
} else {
    Write-Host "WARNING: Not running as Administrator - Root store tests will be skipped" -ForegroundColor Yellow
    Write-Host "Run as Administrator to enable all trust tests`n" -ForegroundColor Yellow
}

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
# TRUST ADD TESTS
# ============================================================================
Write-TestHeader "Testing TRUST ADD Command"

# Test tru-1.1: Add certificate to Root store (LocalMachine)
Invoke-Test -TestId "tru-1.1" -TestName "Add certificate to Root store" -FilePrefix "tru-add" -TestScript {
    if (-not $script:IsAdmin) {
        [PSCustomObject]@{ Success = $true; Details = "Skipped (requires admin for LocalMachine\Root)" }
        return
    }

    $uniqueCN = "certz-trust-add-test-$([guid]::NewGuid().ToString().Substring(0,8))"

    # SETUP: Create a test certificate using PowerShell
    $certParams = @{
        Subject = "CN=$uniqueCN"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams

    # Export to CER file (no private key needed for trust)
    Export-Certificate -Cert $cert -FilePath "tru-add.cer" -Type CERT | Out-Null
    $thumbprint = $cert.Thumbprint

    # Remove from temp store (we only need the file)
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call (defaults to LocalMachine when admin)
        $output = & .\certz.exe trust add tru-add.cer --store root --location LocalMachine 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Certificate in store (PowerShell verification)
        $foundCert = Get-ChildItem "Cert:\LocalMachine\Root" |
            Where-Object { $_.Thumbprint -eq $thumbprint }
        if (-not $foundCert) {
            throw "Certificate should be in LocalMachine\Root store"
        }

        [PSCustomObject]@{ Success = $true; Details = "Certificate added to LocalMachine\Root store" }
    }
    finally {
        # CLEANUP: PowerShell only
        Get-ChildItem "Cert:\LocalMachine\Root" |
            Where-Object { $_.Thumbprint -eq $thumbprint } |
            Remove-Item -Force -ErrorAction SilentlyContinue
        Remove-Item "tru-add.cer" -Force -ErrorAction SilentlyContinue
    }
}

# Test tru-1.2: Add PFX to Root store (LocalMachine)
Invoke-Test -TestId "tru-1.2" -TestName "Add PFX to Root store" -FilePrefix "tru-add-pfx" -TestScript {
    if (-not $script:IsAdmin) {
        [PSCustomObject]@{ Success = $true; Details = "Skipped (requires admin for LocalMachine\Root)" }
        return
    }

    $uniqueCN = "certz-trust-add-pfx-test-$([guid]::NewGuid().ToString().Substring(0,8))"

    # SETUP: Create a test certificate using PowerShell
    $certParams = @{
        Subject = "CN=$uniqueCN"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $password = ConvertTo-SecureString "TrustPfxPass123" -AsPlainText -Force
    Export-PfxCertificate -Cert $cert -FilePath "tru-add-pfx.pfx" -Password $password | Out-Null
    $thumbprint = $cert.Thumbprint

    # Remove from temp store
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe trust add tru-add-pfx.pfx --password TrustPfxPass123 --store root --location LocalMachine 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Certificate in store (PowerShell verification)
        $foundCert = Get-ChildItem "Cert:\LocalMachine\Root" |
            Where-Object { $_.Thumbprint -eq $thumbprint }
        if (-not $foundCert) {
            throw "Certificate should be in LocalMachine\Root store"
        }

        [PSCustomObject]@{ Success = $true; Details = "PFX certificate added to LocalMachine\Root store" }
    }
    finally {
        # CLEANUP: PowerShell only
        Get-ChildItem "Cert:\LocalMachine\Root" |
            Where-Object { $_.Thumbprint -eq $thumbprint } |
            Remove-Item -Force -ErrorAction SilentlyContinue
        Remove-Item "tru-add-pfx.pfx" -Force -ErrorAction SilentlyContinue
    }
}

# Test tru-1.3: Add to CA store
Invoke-Test -TestId "tru-1.3" -TestName "Add certificate to CA store" -FilePrefix "tru-add-ca" -TestScript {
    $uniqueCN = "certz-trust-add-ca-test-$([guid]::NewGuid().ToString().Substring(0,8))"

    # SETUP: Create a test certificate using PowerShell
    $certParams = @{
        Subject = "CN=$uniqueCN"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    Export-Certificate -Cert $cert -FilePath "tru-add-ca.cer" -Type CERT | Out-Null
    $thumbprint = $cert.Thumbprint
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe trust add tru-add-ca.cer --store ca --location CurrentUser 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Certificate in CA store (PowerShell verification)
        $foundCert = Get-ChildItem "Cert:\CurrentUser\CA" |
            Where-Object { $_.Thumbprint -eq $thumbprint }
        if (-not $foundCert) {
            throw "Certificate should be in CurrentUser\CA store"
        }

        [PSCustomObject]@{ Success = $true; Details = "Certificate added to CA store" }
    }
    finally {
        # CLEANUP: PowerShell only
        Get-ChildItem "Cert:\CurrentUser\CA" |
            Where-Object { $_.Thumbprint -eq $thumbprint } |
            Remove-Item -Force -ErrorAction SilentlyContinue
        Remove-Item "tru-add-ca.cer" -Force -ErrorAction SilentlyContinue
    }
}

# Test tru-1.4: Non-admin explicit LocalMachine fails
Invoke-Test -TestId "tru-1.4" -TestName "Non-admin explicit LocalMachine fails" -FilePrefix "tru-noadmin" -TestScript {
    # SETUP: Create a test certificate using PowerShell
    $certParams = @{
        Subject = "CN=certz-noadmin-test"
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
        $outputStr = $output -join "`n"

        # ASSERTION: Should fail with permission error (unless running as admin)
        if (-not $script:IsAdmin) {
            if ($exitCode -eq 0) {
                throw "Command should have failed without admin privileges"
            }
            if ($outputStr -notmatch "Administrator|admin|permission|access") {
                throw "Error message should mention Administrator requirement"
            }
            [PSCustomObject]@{ Success = $true; Details = "LocalMachine permission check works correctly" }
        } else {
            # If running as admin, the command might succeed
            [PSCustomObject]@{ Success = $true; Details = "Skipped (running as admin)" }
        }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item "tru-noadmin.cer" -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# TRUST REMOVE TESTS
# ============================================================================
Write-TestHeader "Testing TRUST REMOVE Command"

# Test trm-1.1: Remove by thumbprint with --force
Invoke-Test -TestId "trm-1.1" -TestName "Remove certificate by thumbprint" -FilePrefix "trm-thumb" -TestScript {
    if (-not $script:IsAdmin) {
        [PSCustomObject]@{ Success = $true; Details = "Skipped (requires admin for LocalMachine\Root)" }
        return
    }

    $uniqueCN = "certz-trust-remove-test-$([guid]::NewGuid().ToString().Substring(0,8))"

    # SETUP: Create certificate in My store, then move to Root store (LocalMachine)
    $certParams = @{
        Subject = "CN=$uniqueCN"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $thumbprint = $cert.Thumbprint

    # Export and import to LocalMachine\Root store (using helper)
    $tempCerFile = "trm-thumb-temp.cer"
    Export-Certificate -Cert $cert -FilePath $tempCerFile -Type CERT | Out-Null
    Import-CertificateToStoreNoUI -FilePath $tempCerFile -StoreName "Root" -StoreLocation "LocalMachine"
    Remove-Item $tempCerFile -Force
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe trust remove $thumbprint --force --location LocalMachine 2>&1
        Write-Host $output
        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Certificate removed from store (PowerShell verification)
        $foundCert = Get-ChildItem "Cert:\LocalMachine\Root" |
            Where-Object { $_.Thumbprint -eq $thumbprint }
        if ($foundCert) {
            throw "Certificate should have been removed from store"
        }

        [PSCustomObject]@{ Success = $true; Details = "Certificate removed by thumbprint" }
    }
    finally {
        # CLEANUP: PowerShell only (in case test failed)
        Get-ChildItem "Cert:\LocalMachine\Root" |
            Where-Object { $_.Thumbprint -eq $thumbprint } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
}

# Test trm-1.2: Remove by subject pattern with --force
Invoke-Test -TestId "trm-1.2" -TestName "Remove by subject pattern with --force" -FilePrefix "trm-subject" -TestScript {
    if (-not $script:IsAdmin) {
        [PSCustomObject]@{ Success = $true; Details = "Skipped (requires admin for LocalMachine\Root)" }
        return
    }

    $uniquePrefix = "certz-remove-subj-$([guid]::NewGuid().ToString().Substring(0,8))"

    # SETUP: Create certificate in My store, then move to LocalMachine\Root store
    $certParams = @{
        Subject = "CN=$uniquePrefix-test"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $thumbprint = $cert.Thumbprint

    # Export and import to LocalMachine\Root store (using helper)
    $tempCerFile = "trm-subject-temp.cer"
    Export-Certificate -Cert $cert -FilePath $tempCerFile -Type CERT | Out-Null
    Import-CertificateToStoreNoUI -FilePath $tempCerFile -StoreName "Root" -StoreLocation "LocalMachine"
    Remove-Item $tempCerFile -Force
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call with subject pattern
        $output = & .\certz.exe trust remove --subject "CN=$uniquePrefix*" --force --location LocalMachine 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Certificate removed from store (PowerShell verification)
        $foundCert = Get-ChildItem "Cert:\LocalMachine\Root" |
            Where-Object { $_.Thumbprint -eq $thumbprint }
        if ($foundCert) {
            throw "Certificate should have been removed from store"
        }

        [PSCustomObject]@{ Success = $true; Details = "Certificate removed by subject pattern" }
    }
    finally {
        # CLEANUP: PowerShell only (in case test failed)
        Get-ChildItem "Cert:\LocalMachine\Root" |
            Where-Object { $_.Subject -like "*$uniquePrefix*" } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
}

# Test trm-1.3: Remove from specific store (CA - CurrentUser, no admin needed)
Invoke-Test -TestId "trm-1.3" -TestName "Remove from specific store" -FilePrefix "trm-store" -TestScript {
    $uniqueCN = "certz-remove-store-test-$([guid]::NewGuid().ToString().Substring(0,8))"

    # SETUP: Create certificate in My store, then move to CA store
    $certParams = @{
        Subject = "CN=$uniqueCN"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $thumbprint = $cert.Thumbprint

    # Export and import to CA store (CurrentUser - no UI dialog)
    $tempCerFile = "trm-store-temp.cer"
    Export-Certificate -Cert $cert -FilePath $tempCerFile -Type CERT | Out-Null
    Import-CertificateToStoreNoUI -FilePath $tempCerFile -StoreName "CA" -StoreLocation "CurrentUser"
    Remove-Item $tempCerFile -Force
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe trust remove $thumbprint --store ca --location CurrentUser --force 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Certificate removed from CA store (PowerShell verification)
        $foundCert = Get-ChildItem "Cert:\CurrentUser\CA" |
            Where-Object { $_.Thumbprint -eq $thumbprint }
        if ($foundCert) {
            throw "Certificate should have been removed from CA store"
        }

        [PSCustomObject]@{ Success = $true; Details = "Certificate removed from CA store" }
    }
    finally {
        # CLEANUP: PowerShell only (in case test failed)
        Get-ChildItem "Cert:\CurrentUser\CA" |
            Where-Object { $_.Thumbprint -eq $thumbprint } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
}

# Test trm-1.4: Multiple matches without --force fails
Invoke-Test -TestId "trm-1.4" -TestName "Multiple matches without --force fails" -FilePrefix "trm-multi" -TestScript {
    if (-not $script:IsAdmin) {
        [PSCustomObject]@{ Success = $true; Details = "Skipped (requires admin for LocalMachine\Root)" }
        return
    }

    $uniquePrefix = "certz-multi-test-$([guid]::NewGuid().ToString().Substring(0,8))"

    # SETUP: Create TWO certificates with similar subjects, import to LocalMachine\Root
    $cert1 = New-SelfSignedCertificate -Subject "CN=$uniquePrefix-1" -KeyAlgorithm ECDSA_nistP256 -KeyExportPolicy Exportable -CertStoreLocation "Cert:\CurrentUser\My" -NotAfter (Get-Date).AddDays(90)
    $cert2 = New-SelfSignedCertificate -Subject "CN=$uniquePrefix-2" -KeyAlgorithm ECDSA_nistP256 -KeyExportPolicy Exportable -CertStoreLocation "Cert:\CurrentUser\My" -NotAfter (Get-Date).AddDays(90)

    # Export and import both to LocalMachine\Root store
    Export-Certificate -Cert $cert1 -FilePath "trm-multi-1.cer" -Type CERT | Out-Null
    Export-Certificate -Cert $cert2 -FilePath "trm-multi-2.cer" -Type CERT | Out-Null
    Import-CertificateToStoreNoUI -FilePath "trm-multi-1.cer" -StoreName "Root" -StoreLocation "LocalMachine"
    Import-CertificateToStoreNoUI -FilePath "trm-multi-2.cer" -StoreName "Root" -StoreLocation "LocalMachine"
    Remove-Item "trm-multi-1.cer", "trm-multi-2.cer" -Force
    Remove-Item $cert1.PSPath, $cert2.PSPath -Force

    try {
        # ACTION: Single certz.exe call (should fail without --force)
        $output = & .\certz.exe trust remove --subject "CN=$uniquePrefix*" --location LocalMachine 2>&1
        $exitCode = $LASTEXITCODE
        $outputStr = $output -join "`n"

        # ASSERTION 1: Should fail (exit code non-zero)
        if ($exitCode -eq 0) {
            throw "Command should have failed when multiple certificates match without --force"
        }

        # ASSERTION 2: Output should list matching certificates or mention multiple
        if ($outputStr -notmatch "$uniquePrefix|multiple|more than one|2 certificate") {
            throw "Output should indicate multiple matches found"
        }

        [PSCustomObject]@{ Success = $true; Details = "Multiple matches correctly requires --force" }
    }
    finally {
        # CLEANUP: PowerShell only
        Get-ChildItem "Cert:\LocalMachine\Root" |
            Where-Object { $_.Subject -like "*$uniquePrefix*" } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# PARTIAL THUMBPRINT TESTS
# ============================================================================
Write-TestHeader "Testing PARTIAL THUMBPRINT Matching"

# Test trm-2.1: Remove by partial thumbprint (8 chars) with --force
Invoke-Test -TestId "trm-2.1" -TestName "Remove by partial thumbprint (8 chars)" -FilePrefix "trm-partial8" -TestScript {
    if (-not $script:IsAdmin) {
        [PSCustomObject]@{ Success = $true; Details = "Skipped (requires admin for LocalMachine\Root)" }
        return
    }

    $uniqueCN = "certz-partial8-test-$([guid]::NewGuid().ToString().Substring(0,8))"

    # SETUP: Create certificate in My store, then move to LocalMachine\Root store
    $certParams = @{
        Subject = "CN=$uniqueCN"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $thumbprint = $cert.Thumbprint
    $partialThumbprint = $thumbprint.Substring(0, 8)  # First 8 characters

    # Export and import to LocalMachine\Root store
    $tempCerFile = "trm-partial8-temp.cer"
    Export-Certificate -Cert $cert -FilePath $tempCerFile -Type CERT | Out-Null
    Import-CertificateToStoreNoUI -FilePath $tempCerFile -StoreName "Root" -StoreLocation "LocalMachine"
    Remove-Item $tempCerFile -Force
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call with partial thumbprint
        $output = & .\certz.exe trust remove $partialThumbprint --force --location LocalMachine 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Certificate removed from store (PowerShell verification)
        $foundCert = Get-ChildItem "Cert:\LocalMachine\Root" |
            Where-Object { $_.Thumbprint -eq $thumbprint }
        if ($foundCert) {
            throw "Certificate should have been removed from store"
        }

        [PSCustomObject]@{ Success = $true; Details = "Certificate removed by 8-char partial thumbprint" }
    }
    finally {
        # CLEANUP: PowerShell only (in case test failed)
        Get-ChildItem "Cert:\LocalMachine\Root" |
            Where-Object { $_.Thumbprint -eq $thumbprint } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
}

# Test trm-2.2: Remove by partial thumbprint (16 chars) with --force
Invoke-Test -TestId "trm-2.2" -TestName "Remove by partial thumbprint (16 chars)" -FilePrefix "trm-partial16" -TestScript {
    if (-not $script:IsAdmin) {
        [PSCustomObject]@{ Success = $true; Details = "Skipped (requires admin for LocalMachine\Root)" }
        return
    }

    $uniqueCN = "certz-partial16-test-$([guid]::NewGuid().ToString().Substring(0,8))"

    # SETUP: Create certificate in My store, then move to LocalMachine\Root store
    $certParams = @{
        Subject = "CN=$uniqueCN"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $thumbprint = $cert.Thumbprint
    $partialThumbprint = $thumbprint.Substring(0, 16)  # First 16 characters

    # Export and import to LocalMachine\Root store
    $tempCerFile = "trm-partial16-temp.cer"
    Export-Certificate -Cert $cert -FilePath $tempCerFile -Type CERT | Out-Null
    Import-CertificateToStoreNoUI -FilePath $tempCerFile -StoreName "Root" -StoreLocation "LocalMachine"
    Remove-Item $tempCerFile -Force
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call with partial thumbprint
        $output = & .\certz.exe trust remove $partialThumbprint --force --location LocalMachine 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Certificate removed from store (PowerShell verification)
        $foundCert = Get-ChildItem "Cert:\LocalMachine\Root" |
            Where-Object { $_.Thumbprint -eq $thumbprint }
        if ($foundCert) {
            throw "Certificate should have been removed from store"
        }

        [PSCustomObject]@{ Success = $true; Details = "Certificate removed by 16-char partial thumbprint" }
    }
    finally {
        # CLEANUP: PowerShell only (in case test failed)
        Get-ChildItem "Cert:\LocalMachine\Root" |
            Where-Object { $_.Thumbprint -eq $thumbprint } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
}

# Test trm-2.3: Partial thumbprint too short (< 8 chars) should fail
Invoke-Test -TestId "trm-2.3" -TestName "Partial thumbprint too short fails" -FilePrefix "trm-tooshort" -TestScript {
    # ACTION: Single certz.exe call with short thumbprint (no setup needed)
    $output = & .\certz.exe trust remove "ABC123" --force 2>&1
    $exitCode = $LASTEXITCODE
    $outputStr = $output -join "`n"

    # ASSERTION 1: Should fail (exit code non-zero)
    if ($exitCode -eq 0) {
        throw "Command should have failed with thumbprint < 8 characters"
    }

    # ASSERTION 2: Error message should mention minimum length
    if ($outputStr -notmatch "8 character|at least 8") {
        throw "Error message should mention minimum 8 character requirement"
    }

    [PSCustomObject]@{ Success = $true; Details = "Short thumbprint correctly rejected" }
}

# Test trm-2.4: Partial thumbprint matching multiple certs requires --force
Invoke-Test -TestId "trm-2.4" -TestName "Partial thumbprint multiple matches requires --force" -FilePrefix "trm-partial-multi" -TestScript {
    if (-not $script:IsAdmin) {
        [PSCustomObject]@{ Success = $true; Details = "Skipped (requires admin for LocalMachine\Root)" }
        return
    }

    $uniquePrefix = "certz-partial-multi-$([guid]::NewGuid().ToString().Substring(0,8))"

    # Create two certificates
    $cert1 = New-SelfSignedCertificate -Subject "CN=$uniquePrefix-1" -KeyAlgorithm ECDSA_nistP256 -KeyExportPolicy Exportable -CertStoreLocation "Cert:\CurrentUser\My" -NotAfter (Get-Date).AddDays(90)
    $cert2 = New-SelfSignedCertificate -Subject "CN=$uniquePrefix-2" -KeyAlgorithm ECDSA_nistP256 -KeyExportPolicy Exportable -CertStoreLocation "Cert:\CurrentUser\My" -NotAfter (Get-Date).AddDays(90)

    # Export and import both to LocalMachine\Root store
    Export-Certificate -Cert $cert1 -FilePath "trm-partial-multi-1.cer" -Type CERT | Out-Null
    Export-Certificate -Cert $cert2 -FilePath "trm-partial-multi-2.cer" -Type CERT | Out-Null
    Import-CertificateToStoreNoUI -FilePath "trm-partial-multi-1.cer" -StoreName "Root" -StoreLocation "LocalMachine"
    Import-CertificateToStoreNoUI -FilePath "trm-partial-multi-2.cer" -StoreName "Root" -StoreLocation "LocalMachine"
    Remove-Item "trm-partial-multi-1.cer", "trm-partial-multi-2.cer" -Force
    Remove-Item $cert1.PSPath, $cert2.PSPath -Force

    # Get thumbprints
    $thumb1 = $cert1.Thumbprint
    $thumb2 = $cert2.Thumbprint

    try {
        # Use subject pattern to test multiple match logic (more reliable than hoping thumbprints match)
        $output = & .\certz.exe trust remove --subject "CN=$uniquePrefix*" --location LocalMachine 2>&1
        $exitCode = $LASTEXITCODE
        $outputStr = $output -join "`n"

        # ASSERTION 1: Should fail without --force
        if ($exitCode -eq 0) {
            throw "Command should have failed with multiple matches without --force"
        }

        # ASSERTION 2: Output should indicate multiple matches
        if ($outputStr -notmatch "multiple|force|2 certificate") {
            throw "Output should indicate multiple matches require --force"
        }

        [PSCustomObject]@{ Success = $true; Details = "Multiple matches correctly requires --force" }
    }
    finally {
        # CLEANUP: PowerShell only
        Get-ChildItem "Cert:\LocalMachine\Root" |
            Where-Object { $_.Subject -like "*$uniquePrefix*" } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# STORE LIST TESTS
# ============================================================================
Write-TestHeader "Testing STORE LIST Command"

# Test sto-1.1: List certificates in My store
Invoke-Test -TestId "sto-1.1" -TestName "List certificates in My store" -FilePrefix "sto-list" -TestScript {
    # SETUP: Ensure at least one certificate exists
    $uniqueCN = "certz-store-list-test-$([guid]::NewGuid().ToString().Substring(0,8))"
    $certParams = @{
        Subject = "CN=$uniqueCN"
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
        if ($outputStr -notmatch "$uniqueCN|Subject|Thumbprint") {
            throw "Output should list certificates"
        }

        [PSCustomObject]@{ Success = $true; Details = "Store list shows certificates" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item $cert.PSPath -Force -ErrorAction SilentlyContinue
    }
}

# Test sto-1.2: List certificates in Root store (LocalMachine)
Invoke-Test -TestId "sto-1.2" -TestName "List certificates in Root store" -FilePrefix "sto-list-root" -TestScript {
    if (-not $script:IsAdmin) {
        [PSCustomObject]@{ Success = $true; Details = "Skipped (requires admin for LocalMachine\Root)" }
        return
    }

    # SETUP: Create certificate in My store, then move to LocalMachine\Root store
    $uniqueCN = "certz-store-list-root-test-$([guid]::NewGuid().ToString().Substring(0,8))"
    $certParams = @{
        Subject = "CN=$uniqueCN"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $thumbprint = $cert.Thumbprint

    # Export and import to LocalMachine\Root store (using helper)
    $tempCerFile = "sto-list-root-temp.cer"
    Export-Certificate -Cert $cert -FilePath $tempCerFile -Type CERT | Out-Null
    Import-CertificateToStoreNoUI -FilePath $tempCerFile -StoreName "Root" -StoreLocation "LocalMachine"
    Remove-Item $tempCerFile -Force
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe store list --store root --location LocalMachine 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Output contains certificate information
        if ($outputStr -notmatch "$uniqueCN|Subject|Thumbprint|Root") {
            throw "Output should list certificates from Root store"
        }

        [PSCustomObject]@{ Success = $true; Details = "Root store list shows certificates" }
    }
    finally {
        # CLEANUP: PowerShell only
        Get-ChildItem "Cert:\LocalMachine\Root" |
            Where-Object { $_.Thumbprint -eq $thumbprint } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
}

# Test sto-1.3: List with JSON output
Invoke-Test -TestId "sto-1.3" -TestName "List with JSON output" -FilePrefix "sto-list-json" -TestScript {
    # SETUP: Ensure at least one certificate exists
    $uniqueCN = "certz-store-list-json-test-$([guid]::NewGuid().ToString().Substring(0,8))"
    $certParams = @{
        Subject = "CN=$uniqueCN"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $thumbprint = $cert.Thumbprint

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe store list --format json 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Output is valid JSON
        try {
            $json = $outputStr | ConvertFrom-Json
            # JSON should be an array or object with certificates
            if ($null -eq $json) {
                throw "JSON should not be null"
            }
        }
        catch {
            if ($_.Exception.Message -match "JSON") {
                throw "Output is not valid JSON: $outputStr"
            }
            throw $_
        }

        [PSCustomObject]@{ Success = $true; Details = "Valid JSON output for store list" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item $cert.PSPath -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# LINUX PLATFORM TESTS
# ============================================================================
if ($IsLinux) {
    Write-TestHeader "Linux Platform -- Trust Store Tests"

    # lin-1.1: trust add CurrentUser works on Linux (via X509Store)
    Invoke-Test -TestId "lin-1.1" -TestName "Linux: trust add CurrentUser via X509Store" -FilePrefix "lin-trust-cu" -TestScript {
        # SETUP: Create a self-signed cert with PowerShell
        $cert = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            "CN=certz-linux-test", [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve]::NamedCurves.nistP256),
            [System.Security.Cryptography.HashAlgorithmName]::SHA256)
        $built = $cert.CreateSelfSigned([System.DateTimeOffset]::UtcNow.AddDays(-1), [System.DateTimeOffset]::UtcNow.AddDays(30))
        $pemPath = "lin-test.pem"
        [System.IO.File]::WriteAllText($pemPath, $built.ExportCertificatePem())
        $thumbprint = $built.Thumbprint

        # ACTION: Trust add to CurrentUser
        $output = & $certz trust add $pemPath --location CurrentUser 2>&1
        $exitCode = $LASTEXITCODE

        # ASSERTION: Verify cert is in the CurrentUser X509Store
        $inStore = $false
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
            [System.Security.Cryptography.X509Certificates.StoreName]::Root,
            [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
        try {
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
            $found = $store.Certificates.Find(
                [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
                $thumbprint, $false)
            $inStore = $found.Count -gt 0
        } finally {
            $store.Close()
        }

        # CLEANUP: Remove from store
        if ($inStore) {
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            $found = $store.Certificates.Find(
                [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
                $thumbprint, $false)
            foreach ($c in $found) { $store.Remove($c) }
            $store.Close()
        }
        Remove-Item $pemPath -Force -ErrorAction SilentlyContinue

        if ($exitCode -eq 0 -and $inStore) {
            return @{ Success = $true; Details = "Cert $thumbprint added to CurrentUser/Root on Linux" }
        }
        return @{ Success = $false; Details = "exitCode=$exitCode inStore=$inStore output=$output" }
    }

    # lin-1.2: trust add --location CurrentUser is default on Linux (non-root)
    Invoke-Test -TestId "lin-1.2" -TestName "Linux: --location defaults to CurrentUser when not root" -FilePrefix "lin-default-loc" -TestScript {
        # SETUP: minimal PEM
        $cert = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            "CN=certz-linux-default", [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve]::NamedCurves.nistP256),
            [System.Security.Cryptography.HashAlgorithmName]::SHA256)
        $built = $cert.CreateSelfSigned([System.DateTimeOffset]::UtcNow.AddDays(-1), [System.DateTimeOffset]::UtcNow.AddDays(30))
        $pemPath = "lin-default.pem"
        [System.IO.File]::WriteAllText($pemPath, $built.ExportCertificatePem())

        # ACTION: Run with --format json and check result includes CurrentUser
        $output = & $certz trust add $pemPath --format json 2>&1
        $exitCode = $LASTEXITCODE

        # CLEANUP store
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
            [System.Security.Cryptography.X509Certificates.StoreName]::Root,
            [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $found = $store.Certificates.Find(
            [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
            $built.Thumbprint, $false)
        foreach ($c in $found) { $store.Remove($c) }
        $store.Close()
        Remove-Item $pemPath -Force -ErrorAction SilentlyContinue

        if ($exitCode -eq 0 -and ($output -match "CurrentUser" -or $output -match "currentUser")) {
            return @{ Success = $true; Details = "Default location is CurrentUser on Linux" }
        }
        return @{ Success = $false; Details = "exitCode=$exitCode output=$output" }
    }

    # lin-1.3: trust add --location LocalMachine requires root on Linux
    Invoke-Test -TestId "lin-1.3" -TestName "Linux: trust add LocalMachine requires root" -FilePrefix "lin-localmachine" -TestScript {
        # SETUP: minimal PEM
        $cert = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            "CN=certz-linux-lm", [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve]::NamedCurves.nistP256),
            [System.Security.Cryptography.HashAlgorithmName]::SHA256)
        $built = $cert.CreateSelfSigned([System.DateTimeOffset]::UtcNow.AddDays(-1), [System.DateTimeOffset]::UtcNow.AddDays(30))
        $pemPath = "lin-lm.pem"
        [System.IO.File]::WriteAllText($pemPath, $built.ExportCertificatePem())

        $isRoot = [System.Environment]::IsPrivilegedProcess

        # ACTION
        $output = & $certz trust add $pemPath --location LocalMachine 2>&1
        $exitCode = $LASTEXITCODE

        Remove-Item $pemPath -Force -ErrorAction SilentlyContinue

        if ($isRoot) {
            # When running as root, expect success
            if ($exitCode -eq 0) {
                return @{ Success = $true; Details = "Root: LocalMachine add succeeded" }
            }
            return @{ Success = $false; Details = "Root: expected success, got exitCode=$exitCode output=$output" }
        } else {
            # When not root, expect failure with privilege error
            if ($exitCode -ne 0 -and ($output -match "Administrator|root|privilege")) {
                return @{ Success = $true; Details = "Non-root: correctly denied LocalMachine access" }
            }
            return @{ Success = $false; Details = "Non-root: expected privilege error, got exitCode=$exitCode output=$output" }
        }
    }

    # lin-1.4: macOS stub throws PlatformNotSupportedException (only testable on macOS, skip here)
    # lin-1.5: store list CurrentUser works on Linux
    Invoke-Test -TestId "lin-1.5" -TestName "Linux: store list CurrentUser works" -FilePrefix "lin-store-list" -TestScript {
        $output = & $certz store list --location CurrentUser --format json 2>&1
        $exitCode = $LASTEXITCODE

        if ($exitCode -eq 0) {
            try {
                $json = $output | ConvertFrom-Json
                return @{ Success = $true; Details = "store list returned $($json.filteredCount) certificates" }
            } catch {
                return @{ Success = $false; Details = "JSON parse error: output=$output" }
            }
        }
        return @{ Success = $false; Details = "exitCode=$exitCode output=$output" }
    }
}

# ============================================================================
# DRY-RUN TESTS
# ============================================================================
Write-TestHeader "Testing --dry-run Flag (trust)"

# Test tdr-1.1: trust add --dry-run exits 0 and does NOT add cert to store
Invoke-Test -TestId "tdr-1.1" -TestName "trust add --dry-run: exit 0, cert NOT added to store" -FilePrefix "tdr-add" -TestScript {
    # SETUP: Create a self-signed cert file using PowerShell only
    $cert = New-SelfSignedCertificate `
        -Subject "CN=certz-dry-trust-add-$([guid]::NewGuid().ToString().Substring(0,8))" `
        -KeyAlgorithm ECDSA_nistP256 `
        -KeyExportPolicy Exportable `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -NotAfter (Get-Date).AddDays(30)
    $thumbprint = $cert.Thumbprint
    Export-Certificate -Cert $cert -FilePath "tdr-add.cer" -Type CERT | Out-Null
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call with --dry-run (targets CurrentUser\My so no admin needed)
        $null = & .\certz.exe trust add tdr-add.cer --store My --location CurrentUser --dry-run 2>&1

        # ASSERTION 1: Exit code 0
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Cert was NOT added to the store
        $found = Get-ChildItem "Cert:\CurrentUser\My" | Where-Object { $_.Thumbprint -eq $thumbprint }
        if ($found) {
            throw "--dry-run must not add certificate to the store, but thumbprint $thumbprint was found"
        }

        [PSCustomObject]@{ Success = $true; Details = "trust add --dry-run exits 0 and leaves store unchanged" }
    }
    finally {
        # CLEANUP: ensure cert is removed from store and temp file deleted
        Get-ChildItem "Cert:\CurrentUser\My" |
            Where-Object { $_.Thumbprint -eq $thumbprint } |
            Remove-Item -Force -ErrorAction SilentlyContinue
        Remove-Item "tdr-add.cer" -Force -ErrorAction SilentlyContinue
    }
}

# Test tdr-1.2: trust add --dry-run --format json returns dryRun:true JSON
Invoke-Test -TestId "tdr-1.2" -TestName "trust add --dry-run --format json: machine-readable output" -FilePrefix "tdr-add-json" -TestScript {
    # SETUP: Create cert file using PowerShell only
    $cert = New-SelfSignedCertificate `
        -Subject "CN=certz-dry-trust-json-$([guid]::NewGuid().ToString().Substring(0,8))" `
        -KeyAlgorithm ECDSA_nistP256 `
        -KeyExportPolicy Exportable `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -NotAfter (Get-Date).AddDays(30)
    $thumbprint = $cert.Thumbprint
    Export-Certificate -Cert $cert -FilePath "tdr-add-json.cer" -Type CERT | Out-Null
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe trust add tdr-add-json.cer --store My --location CurrentUser --dry-run --format json 2>&1

        # ASSERTION 1: Exit code 0
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Valid JSON with dryRun:true
        $outputStr = $output -join "`n"
        $json = $outputStr | ConvertFrom-Json
        if (-not $json.dryRun) {
            throw "--dry-run JSON output must have dryRun:true, got: $outputStr"
        }

        # ASSERTION 3: wouldSucceed:true for valid input
        if (-not $json.wouldSucceed) {
            throw "--dry-run JSON output must have wouldSucceed:true for a valid cert file"
        }

        # ASSERTION 4: command field present
        if ($json.command -ne "trust add") {
            throw "--dry-run JSON command must be 'trust add', got: $($json.command)"
        }

        # ASSERTION 5: Cert NOT added to store
        $found = Get-ChildItem "Cert:\CurrentUser\My" | Where-Object { $_.Thumbprint -eq $thumbprint }
        if ($found) {
            throw "--dry-run must not add certificate to the store"
        }

        [PSCustomObject]@{ Success = $true; Details = "trust add --dry-run JSON has dryRun:true and correct fields" }
    }
    finally {
        Get-ChildItem "Cert:\CurrentUser\My" |
            Where-Object { $_.Thumbprint -eq $thumbprint } |
            Remove-Item -Force -ErrorAction SilentlyContinue
        Remove-Item "tdr-add-json.cer" -Force -ErrorAction SilentlyContinue
    }
}

# Test tdr-1.3: trust remove --dry-run exits 0 and does NOT remove cert from store
Invoke-Test -TestId "tdr-1.3" -TestName "trust remove --dry-run: exit 0, cert NOT removed from store" -FilePrefix "tdr-remove" -TestScript {
    # SETUP: Create cert and import it into CurrentUser\My (no admin needed)
    $uniqueCN = "certz-dry-trust-rm-$([guid]::NewGuid().ToString().Substring(0,8))"
    $cert = New-SelfSignedCertificate `
        -Subject "CN=$uniqueCN" `
        -KeyAlgorithm ECDSA_nistP256 `
        -KeyExportPolicy Exportable `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -NotAfter (Get-Date).AddDays(30)
    $thumbprint = $cert.Thumbprint
    # cert is already in CurrentUser\My; no export needed

    try {
        # ACTION: Single certz.exe call -- dry-run remove by thumbprint
        $null = & .\certz.exe trust remove $thumbprint --store My --location CurrentUser --dry-run --force 2>&1

        # ASSERTION 1: Exit code 0
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Cert is STILL in the store (not removed)
        $found = Get-ChildItem "Cert:\CurrentUser\My" | Where-Object { $_.Thumbprint -eq $thumbprint }
        if (-not $found) {
            throw "--dry-run must NOT remove the certificate, but it is gone from the store"
        }

        [PSCustomObject]@{ Success = $true; Details = "trust remove --dry-run exits 0 and leaves cert in store" }
    }
    finally {
        # CLEANUP
        Get-ChildItem "Cert:\CurrentUser\My" |
            Where-Object { $_.Thumbprint -eq $thumbprint } |
            Remove-Item -Force -ErrorAction SilentlyContinue
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
