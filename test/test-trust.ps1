#Requires -Version 7.5

<#
.SYNOPSIS
    Test suite for certz trust and store commands.

.DESCRIPTION
    This script tests the trust add, trust remove, and store list commands.
    It follows test isolation principles from test-isolation-plan.md:
    - Each test invokes certz.exe exactly ONCE
    - Setup and teardown use pure PowerShell (no certz calls)
    - Assert against system state (files, cert store), NOT console output

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
    "store-list" = @("sto-1.1", "sto-1.2", "sto-1.3")
}

# Initialize test environment
Initialize-TestEnvironment -TestId $TestId -Category $Category -TestCategories $TestCategories
Set-VerboseOutput -Enabled $Verbose

# Display banner
Write-Host "`nCertz Trust and Store Command Test Suite" -ForegroundColor Magenta
Write-Host "=========================================`n" -ForegroundColor Magenta

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

# Change to tools directory
Push-Location -Path (Join-Path -Path $PSScriptRoot -ChildPath "..\docker\tools")

# Initial cleanup
Write-Host "Initializing test environment..." -ForegroundColor Yellow
Remove-TestFiles

# ============================================================================
# TRUST ADD TESTS
# ============================================================================
Write-TestHeader "Testing TRUST ADD Command"

# Test tru-1.1: Add certificate to Root store
Invoke-Test -TestId "tru-1.1" -TestName "Add certificate to Root store" -FilePrefix "tru-add" -TestScript {
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

        [PSCustomObject]@{ Success = $true; Details = "Certificate added to Root store" }
    }
    finally {
        # CLEANUP: PowerShell only
        $matchingCerts = Get-ChildItem "Cert:\CurrentUser\Root" |
            Where-Object { $_.Thumbprint -eq $thumbprint }
        foreach ($c in $matchingCerts) {
            Remove-Item "HKCU:\Software\Microsoft\SystemCertificates\Root\Certificates\$($c.Thumbprint)" -Force
        }
        Remove-Item "tru-add.cer" -Force -ErrorAction SilentlyContinue
    }
}

# Test tru-1.2: Add PFX to Root store
Invoke-Test -TestId "tru-1.2" -TestName "Add PFX to Root store" -FilePrefix "tru-add-pfx" -TestScript {
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
        $output = & .\certz.exe trust add tru-add-pfx.pfx --password TrustPfxPass123 --store root 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Certificate in store (PowerShell verification)
        $foundCert = Get-ChildItem "Cert:\CurrentUser\Root" |
            Where-Object { $_.Thumbprint -eq $thumbprint }
        if (-not $foundCert) {
            throw "Certificate should be in CurrentUser\Root store"
        }

        [PSCustomObject]@{ Success = $true; Details = "PFX certificate added to Root store" }
    }
    finally {
        # CLEANUP: PowerShell only
        $matchingCerts = Get-ChildItem "Cert:\CurrentUser\Root" |
            Where-Object { $_.Thumbprint -eq $thumbprint }
        foreach ($c in $matchingCerts) {
            Remove-Item "HKCU:\Software\Microsoft\SystemCertificates\Root\Certificates\$($c.Thumbprint)" -Force
        }
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
        $output = & .\certz.exe trust add tru-add-ca.cer --store ca 2>&1

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

# Test tru-1.4: LocalMachine without admin fails
Invoke-Test -TestId "tru-1.4" -TestName "LocalMachine without admin fails" -FilePrefix "tru-noadmin" -TestScript {
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
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

        if (-not $isAdmin) {
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
    $uniqueCN = "certz-trust-remove-test-$([guid]::NewGuid().ToString().Substring(0,8))"

    # SETUP: Create certificate in My store, then move to Root store
    $certParams = @{
        Subject = "CN=$uniqueCN"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $thumbprint = $cert.Thumbprint

    # Export and import to Root store (using helper to avoid UI prompt)
    $tempCerFile = "trm-thumb-temp.cer"
    Export-Certificate -Cert $cert -FilePath $tempCerFile -Type CERT | Out-Null
    Import-CertificateToStoreNoUI -FilePath $tempCerFile -StoreName "Root"
    Remove-Item $tempCerFile -Force
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe trust remove $thumbprint --force 2>&1
        Write-Host $output
        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Certificate removed from store (PowerShell verification)
        $foundCert = Get-ChildItem "Cert:\CurrentUser\Root" |
            Where-Object { $_.Thumbprint -eq $thumbprint }
        if ($foundCert) {
            throw "Certificate should have been removed from store"
        }

        [PSCustomObject]@{ Success = $true; Details = "Certificate removed by thumbprint" }
    }
    finally {
        # CLEANUP: PowerShell only (in case test failed)
        $matchingCerts = Get-ChildItem "Cert:\CurrentUser\Root" |
            Where-Object { $_.Thumbprint -eq $thumbprint }
        foreach ($c in $matchingCerts) {
            Write-Host "Cleaning up certificate with thumbprint $($c.Thumbprint)" -ForegroundColor Yellow
            Remove-Item "HKCU:\Software\Microsoft\SystemCertificates\Root\Certificates\$($c.Thumbprint)" -Force
        }
    }
}

# Test trm-1.2: Remove by subject pattern with --force
Invoke-Test -TestId "trm-1.2" -TestName "Remove by subject pattern with --force" -FilePrefix "trm-subject" -TestScript {
    $uniquePrefix = "certz-remove-subj-$([guid]::NewGuid().ToString().Substring(0,8))"

    # SETUP: Create certificate in My store, then move to Root store
    $certParams = @{
        Subject = "CN=$uniquePrefix-test"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $thumbprint = $cert.Thumbprint

    # Export and import to Root store (using helper to avoid UI prompt)
    $tempCerFile = "trm-subject-temp.cer"
    Export-Certificate -Cert $cert -FilePath $tempCerFile -Type CERT | Out-Null
    Import-CertificateToStoreNoUI -FilePath $tempCerFile -StoreName "Root"
    Remove-Item $tempCerFile -Force
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call with subject pattern
        $output = & .\certz.exe trust remove --subject "CN=$uniquePrefix*" --force 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Certificate removed from store (PowerShell verification)
        $foundCert = Get-ChildItem "Cert:\CurrentUser\Root" |
            Where-Object { $_.Thumbprint -eq $thumbprint }
        if ($foundCert) {
            throw "Certificate should have been removed from store"
        }

        [PSCustomObject]@{ Success = $true; Details = "Certificate removed by subject pattern" }
    }
    finally {
        # CLEANUP: PowerShell only (in case test failed)
        Get-ChildItem "Cert:\CurrentUser\Root" |
            Where-Object { $_.Subject -like "*$uniquePrefix*" } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
}

# Test trm-1.3: Remove from specific store
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

    # Export and import to CA store (using helper to avoid UI prompt)
    $tempCerFile = "trm-store-temp.cer"
    Export-Certificate -Cert $cert -FilePath $tempCerFile -Type CERT | Out-Null
    Import-CertificateToStoreNoUI -FilePath $tempCerFile -StoreName "CA"
    Remove-Item $tempCerFile -Force
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe trust remove $thumbprint --store ca --force 2>&1

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
    $uniquePrefix = "certz-multi-test-$([guid]::NewGuid().ToString().Substring(0,8))"

    # SETUP: Create TWO certificates with similar subjects in My store, then move to Root store
    $cert1 = New-SelfSignedCertificate -Subject "CN=$uniquePrefix-1" -KeyAlgorithm ECDSA_nistP256 -KeyExportPolicy Exportable -CertStoreLocation "Cert:\CurrentUser\My" -NotAfter (Get-Date).AddDays(90)
    $cert2 = New-SelfSignedCertificate -Subject "CN=$uniquePrefix-2" -KeyAlgorithm ECDSA_nistP256 -KeyExportPolicy Exportable -CertStoreLocation "Cert:\CurrentUser\My" -NotAfter (Get-Date).AddDays(90)

    # Export and import both to Root store (using helper to avoid UI prompt)
    Export-Certificate -Cert $cert1 -FilePath "trm-multi-1.cer" -Type CERT | Out-Null
    Export-Certificate -Cert $cert2 -FilePath "trm-multi-2.cer" -Type CERT | Out-Null
    Import-CertificateToStoreNoUI -FilePath "trm-multi-1.cer" -StoreName "Root"
    Import-CertificateToStoreNoUI -FilePath "trm-multi-2.cer" -StoreName "Root"
    Remove-Item "trm-multi-1.cer", "trm-multi-2.cer" -Force
    Remove-Item $cert1.PSPath, $cert2.PSPath -Force

    try {
        # ACTION: Single certz.exe call (should fail without --force)
        $output = & .\certz.exe trust remove --subject "CN=$uniquePrefix*" 2>&1
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
        $matchingCerts = Get-ChildItem "Cert:\CurrentUser\Root" |
            Where-Object { $_.Subject -like "*$uniquePrefix*" }
        foreach ($c in $matchingCerts) {
            Remove-Item "HKCU:\Software\Microsoft\SystemCertificates\Root\Certificates\$($c.Thumbprint)" -Force
        }
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

# Test sto-1.2: List certificates in Root store
Invoke-Test -TestId "sto-1.2" -TestName "List certificates in Root store" -FilePrefix "sto-list-root" -TestScript {
    # SETUP: Create certificate in My store, then move to Root store
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

    # Export and import to Root store (using helper to avoid UI prompt)
    $tempCerFile = "sto-list-root-temp.cer"
    Export-Certificate -Cert $cert -FilePath $tempCerFile -Type CERT | Out-Null
    Import-CertificateToStoreNoUI -FilePath $tempCerFile -StoreName "Root"
    Remove-Item $tempCerFile -Force
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe store list --store root 2>&1
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
        $matchingCerts = Get-ChildItem "Cert:\CurrentUser\Root" |
            Where-Object { $_.Thumbprint -eq $thumbprint }
        foreach ($c in $matchingCerts) {
            Remove-Item "HKCU:\Software\Microsoft\SystemCertificates\Root\Certificates\$($c.Thumbprint)" -Force
        }
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
Pop-Location

# Display summary and exit
$exitCode = Write-TestSummary -SkipCleanup:$SkipCleanup
exit $exitCode
