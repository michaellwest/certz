#Requires -Version 7.5

<#
.SYNOPSIS
    Test suite for certz convert command.

.DESCRIPTION
    This script tests the convert command: PEM to PFX and PFX to PEM conversions.
    It follows test isolation principles from test-isolation-plan.md:
    - Each test invokes certz.exe exactly ONCE
    - Setup and teardown use pure PowerShell (no certz calls)
    - Assert against system state (files), NOT console output

.PARAMETER TestId
    Run specific tests by ID. Example: -TestId "cnv-1.1", "cnv-2.1"

.PARAMETER Category
    Run tests by category: pem-to-pfx, pfx-to-pem, encryption, format

.PARAMETER SkipCleanup
    Keep test files after running.

.PARAMETER Verbose
    Show detailed output.

.EXAMPLE
    .\test-convert.ps1
    Runs all tests with default settings.

.EXAMPLE
    .\test-convert.ps1 -Category pem-to-pfx
    Runs only PEM to PFX conversion tests.

.EXAMPLE
    .\test-convert.ps1 -TestId "cnv-1.1", "cnv-2.1" -Verbose
    Runs specific tests with verbose output.
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

# Store parameters in script-scoped variables for use in functions
$script:FilterTestId = $TestId
$script:FilterCategory = $Category

# Test categories
$script:TestCategories = @{
    "pem-to-pfx" = @("cnv-1.1", "cnv-1.2", "cnv-1.3")
    "pfx-to-pem" = @("cnv-2.1", "cnv-2.2", "cnv-2.3")
    "encryption" = @("cnv-3.1", "cnv-3.2")
    "format" = @("fmt-1.1")
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Test-ShouldRun {
    param([string]$Id)

    # If no filters specified, run all tests
    if (-not $script:FilterTestId -and -not $script:FilterCategory) {
        return $true
    }

    # Check if test ID matches
    if ($script:FilterTestId -and $script:FilterTestId -contains $Id) {
        return $true
    }

    # Check if test belongs to any selected category
    if ($script:FilterCategory) {
        foreach ($cat in $script:FilterCategory) {
            if ($script:TestCategories.ContainsKey($cat) -and $script:TestCategories[$cat] -contains $Id) {
                return $true
            }
        }
    }

    return $false
}

function Write-TestHeader {
    param([string]$Message)
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host " $Message" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Write-TestResult {
    param(
        [string]$TestId,
        [string]$TestName,
        [bool]$Success,
        [string]$Details = ""
    )

    $script:TestCount++

    if ($Success) {
        Write-Host "[PASS] $TestName" -ForegroundColor Green
        $script:PassedTests += $TestName
        if ($Details -and $Verbose) {
            Write-Host "       $Details" -ForegroundColor Gray
        }
    } else {
        Write-Host "[FAIL] $TestName" -ForegroundColor Red
        $script:FailedTests += "$TestId : $TestName"
        if ($Details) {
            Write-Host "       ERROR: $Details" -ForegroundColor Yellow
        }
    }
}

function Remove-TestFiles {
    param([string]$Pattern = "*")

    Get-ChildItem -Path . -File -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -like "$Pattern*.pfx" -or
        $_.Name -like "$Pattern*.cer" -or
        $_.Name -like "$Pattern*.crt" -or
        $_.Name -like "$Pattern*.key" -or
        $_.Name -like "$Pattern*.pem" -or
        $_.Name -like "$Pattern*.der" -or
        $_.Name -like "$Pattern*.password.txt"
    } | Remove-Item -Force -ErrorAction SilentlyContinue
}

# ============================================================================
# ASSERTION FUNCTIONS
# ============================================================================

function Assert-FileExists {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [string]$Message = "File should exist"
    )
    $exists = Test-Path -Path $Path -PathType Leaf
    if (-not $exists) {
        throw "Assertion failed: $Message - File not found: $Path"
    }
    return $true
}

function Assert-FileNotExists {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [string]$Message = "File should not exist"
    )
    $exists = Test-Path -Path $Path -PathType Leaf
    if ($exists) {
        throw "Assertion failed: $Message - File exists: $Path"
    }
    return $true
}

function Assert-ExitCode {
    param(
        [int]$Expected = 0,
        [string]$Message = "Exit code should match"
    )
    if ($LASTEXITCODE -ne $Expected) {
        throw "Assertion failed: $Message - Expected exit code $Expected but got $LASTEXITCODE"
    }
    return $true
}

function Assert-Match {
    param(
        [Parameter(Mandatory)]
        [string]$Actual,
        [Parameter(Mandatory)]
        [string]$Pattern,
        [string]$Message = "Output should match pattern"
    )
    if ($Actual -notmatch $Pattern) {
        throw "Assertion failed: $Message - Pattern '$Pattern' not found in output"
    }
    return $true
}

function Invoke-Test {
    param(
        [Parameter(Mandatory)]
        [string]$TestId,
        [Parameter(Mandatory)]
        [string]$TestName,
        [Parameter(Mandatory)]
        [scriptblock]$TestScript,
        [string]$FilePrefix = ""
    )

    # Check if this test should run based on filters
    if (-not (Test-ShouldRun -Id $TestId)) {
        return $null
    }

    # Clean up files if prefix specified
    if ($FilePrefix) {
        Remove-TestFiles $FilePrefix
    }

    Write-Host "[TEST $TestId] $TestName" -ForegroundColor Cyan

    try {
        $result = & $TestScript
        if ($result -is [hashtable] -and $result.ContainsKey("Success")) {
            Write-TestResult $TestId $TestName $result.Success $result.Details
            return $result
        } else {
            Write-TestResult $TestId $TestName $true ""
            return [PSCustomObject]@{ Success = $true; Result = $result } | Out-String
        }
    } catch {
        Write-TestResult $TestId $TestName $false $_.Exception.Message
        return [PSCustomObject]@{ Success = $false; Error = $_.Exception.Message } | Out-String
    }
}

# ============================================================================
# BUILD AND SETUP
# ============================================================================

function Build-Certz {
    param([bool]$Verbose = $false)

    Write-Host "Building and publishing certz..." -ForegroundColor Cyan

    $buildOutput = dotnet publish -c Debug -o docker\tools 2>&1

    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Build failed" -ForegroundColor Red
        if ($Verbose) {
            $buildOutput | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
        }
        exit 1
    }

    if ($Verbose) {
        $buildOutput | ForEach-Object { Write-Host $_ -ForegroundColor Gray }
    }

    Write-Host "Build completed successfully" -ForegroundColor Green
    Write-Host ""
}

# Initialize test environment
Write-Host "`nCertz Convert Command Test Suite" -ForegroundColor Magenta
Write-Host "=================================`n" -ForegroundColor Magenta

# Display active filters
if ($script:FilterTestId -or $script:FilterCategory) {
    Write-Host "Test Filters Active:" -ForegroundColor Yellow
    if ($script:FilterTestId) {
        Write-Host "  Test IDs: $($script:FilterTestId -join ', ')" -ForegroundColor Gray
    }
    if ($script:FilterCategory) {
        Write-Host "  Categories: $($script:FilterCategory -join ', ')" -ForegroundColor Gray
    }
    Write-Host ""
}

# Build certz
Build-Certz -Verbose:$Verbose

# Change to tools directory
Push-Location -Path (Join-Path -Path $PSScriptRoot -ChildPath "docker\tools")

# Initial cleanup
Write-Host "Initializing test environment..." -ForegroundColor Yellow
Remove-TestFiles

# ============================================================================
# PEM TO PFX CONVERSION TESTS
# ============================================================================
Write-TestHeader "Testing PEM to PFX Conversion"

# Test cnv-1.1: Convert PEM cert+key to PFX
Invoke-Test -TestId "cnv-1.1" -TestName "Convert PEM cert+key to PFX" -FilePrefix "cnv-basic" -TestScript {
    $guid = [guid]::NewGuid().ToString().Substring(0,8)

    # SETUP: Create a test certificate and export to PEM using PowerShell
    $certParams = @{
        Subject = "CN=certz-convert-test-$guid"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams

    # Export certificate to PEM format
    $certPem = [Convert]::ToBase64String($cert.RawData, [Base64FormattingOptions]::InsertLineBreaks)
    $certPemContent = "-----BEGIN CERTIFICATE-----`n$certPem`n-----END CERTIFICATE-----"
    Set-Content -Path "cnv-basic.cer" -Value $certPemContent

    # Export private key to PEM
    $ecdsaKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert)
    $pkcs8Bytes = $ecdsaKey.ExportPkcs8PrivateKey()
    $base64Key = [System.Convert]::ToBase64String($pkcs8Bytes, [System.Base64FormattingOptions]::InsertLineBreaks)
    $keyPem = "-----BEGIN PRIVATE KEY-----`n$base64Key`n-----END PRIVATE KEY-----"
    Set-Content -Path "cnv-basic.key" -Value $keyPem

    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call (password will be auto-generated)
        $output = & .\certz.exe convert --cert cnv-basic.cer --key cnv-basic.key --pfx cnv-basic.pfx --password TestPass123 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: PFX file exists
        Assert-FileExists "cnv-basic.pfx"

        # ASSERTION 3: PFX can be loaded (PowerShell verification)
        $loadedCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            (Resolve-Path "cnv-basic.pfx").Path, "TestPass123")
        if ($loadedCert.Subject -notmatch "certz-convert-test-$guid") {
            throw "Loaded certificate subject mismatch"
        }
        if (-not $loadedCert.HasPrivateKey) {
            throw "Loaded certificate should have private key"
        }
        $loadedCert.Dispose()

        [PSCustomObject]@{ Success = $true; Details = "PEM to PFX conversion successful" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item "cnv-basic.cer" -Force -ErrorAction SilentlyContinue
        Remove-Item "cnv-basic.key" -Force -ErrorAction SilentlyContinue
        Remove-Item "cnv-basic.pfx" -Force -ErrorAction SilentlyContinue
    }
}

# Test cnv-1.2: Convert with explicit password
Invoke-Test -TestId "cnv-1.2" -TestName "Convert PEM to PFX with explicit password" -FilePrefix "cnv-passwd" -TestScript {
    $guid = [guid]::NewGuid().ToString().Substring(0,8)

    # SETUP: Create a test certificate and export to PEM using PowerShell
    $certParams = @{
        Subject = "CN=certz-convert-passwd-$guid"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams

    # Export certificate to PEM format
    $certPem = [Convert]::ToBase64String($cert.RawData, [Base64FormattingOptions]::InsertLineBreaks)
    $certPemContent = "-----BEGIN CERTIFICATE-----`n$certPem`n-----END CERTIFICATE-----"
    Set-Content -Path "cnv-passwd.cer" -Value $certPemContent

    # Export private key to PEM
    $ecdsaKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert)
    $pkcs8Bytes = $ecdsaKey.ExportPkcs8PrivateKey()
    $base64Key = [System.Convert]::ToBase64String($pkcs8Bytes, [System.Base64FormattingOptions]::InsertLineBreaks)
    $keyPem = "-----BEGIN PRIVATE KEY-----`n$base64Key`n-----END PRIVATE KEY-----"
    Set-Content -Path "cnv-passwd.key" -Value $keyPem

    Remove-Item $cert.PSPath -Force

    $explicitPassword = "MyExplicitPassword123!"

    try {
        # ACTION: Single certz.exe call with explicit password
        $output = & .\certz.exe convert --cert cnv-passwd.cer --key cnv-passwd.key --pfx cnv-passwd.pfx --password $explicitPassword 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: PFX file exists
        Assert-FileExists "cnv-passwd.pfx"

        # ASSERTION 3: PFX can be loaded with the explicit password
        $loadedCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            (Resolve-Path "cnv-passwd.pfx").Path, $explicitPassword)
        if (-not $loadedCert.HasPrivateKey) {
            throw "Loaded certificate should have private key"
        }
        $loadedCert.Dispose()

        [PSCustomObject]@{ Success = $true; Details = "Explicit password conversion successful" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item "cnv-passwd.cer" -Force -ErrorAction SilentlyContinue
        Remove-Item "cnv-passwd.key" -Force -ErrorAction SilentlyContinue
        Remove-Item "cnv-passwd.pfx" -Force -ErrorAction SilentlyContinue
    }
}

# Test cnv-1.3: Convert with password file
Invoke-Test -TestId "cnv-1.3" -TestName "Convert PEM to PFX with password file" -FilePrefix "cnv-pwdfile" -TestScript {
    $guid = [guid]::NewGuid().ToString().Substring(0,8)

    # SETUP: Create a test certificate and export to PEM using PowerShell
    $certParams = @{
        Subject = "CN=certz-convert-pwdfile-$guid"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams

    # Export certificate to PEM format
    $certPem = [Convert]::ToBase64String($cert.RawData, [Base64FormattingOptions]::InsertLineBreaks)
    $certPemContent = "-----BEGIN CERTIFICATE-----`n$certPem`n-----END CERTIFICATE-----"
    Set-Content -Path "cnv-pwdfile.cer" -Value $certPemContent

    # Export private key to PEM
    $ecdsaKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert)
    $pkcs8Bytes = $ecdsaKey.ExportPkcs8PrivateKey()
    $base64Key = [System.Convert]::ToBase64String($pkcs8Bytes, [System.Base64FormattingOptions]::InsertLineBreaks)
    $keyPem = "-----BEGIN PRIVATE KEY-----`n$base64Key`n-----END PRIVATE KEY-----"
    Set-Content -Path "cnv-pwdfile.key" -Value $keyPem

    Remove-Item $cert.PSPath -Force

    # Create password file
    $passwordFromFile = "PasswordFromFile456!"
    Set-Content -Path "cnv-pwdfile.password.txt" -Value $passwordFromFile

    try {
        # ACTION: Single certz.exe call with password file
        $output = & .\certz.exe convert --cert cnv-pwdfile.cer --key cnv-pwdfile.key --pfx cnv-pwdfile.pfx --password-file cnv-pwdfile.password.txt 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: PFX file exists
        Assert-FileExists "cnv-pwdfile.pfx"

        # ASSERTION 3: PFX can be loaded with password from file
        $loadedCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            (Resolve-Path "cnv-pwdfile.pfx").Path, $passwordFromFile)
        if (-not $loadedCert.HasPrivateKey) {
            throw "Loaded certificate should have private key"
        }
        $loadedCert.Dispose()

        [PSCustomObject]@{ Success = $true; Details = "Password file conversion successful" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item "cnv-pwdfile.cer" -Force -ErrorAction SilentlyContinue
        Remove-Item "cnv-pwdfile.key" -Force -ErrorAction SilentlyContinue
        Remove-Item "cnv-pwdfile.pfx" -Force -ErrorAction SilentlyContinue
        Remove-Item "cnv-pwdfile.password.txt" -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# PFX TO PEM CONVERSION TESTS
# ============================================================================
Write-TestHeader "Testing PFX to PEM Conversion"

# Test cnv-2.1: Convert PFX to PEM (cert only)
Invoke-Test -TestId "cnv-2.1" -TestName "Convert PFX to PEM (cert only)" -FilePrefix "cnv-topem-cert" -TestScript {
    $guid = [guid]::NewGuid().ToString().Substring(0,8)

    # SETUP: Create a test certificate and export to PFX using PowerShell
    $certParams = @{
        Subject = "CN=certz-topem-cert-$guid"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $password = ConvertTo-SecureString "PfxPass123" -AsPlainText -Force
    Export-PfxCertificate -Cert $cert -FilePath "cnv-topem-cert.pfx" -Password $password | Out-Null
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe convert --pfx cnv-topem-cert.pfx --password PfxPass123 --out-cert cnv-topem-cert.cer 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Certificate PEM file exists
        Assert-FileExists "cnv-topem-cert.cer"

        # ASSERTION 3: PEM file contains valid certificate
        $content = Get-Content "cnv-topem-cert.cer" -Raw
        if ($content -notmatch "-----BEGIN CERTIFICATE-----") {
            throw "Output should contain PEM-encoded certificate"
        }

        [PSCustomObject]@{ Success = $true; Details = "PFX to PEM (cert only) successful" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item "cnv-topem-cert.pfx" -Force -ErrorAction SilentlyContinue
        Remove-Item "cnv-topem-cert.cer" -Force -ErrorAction SilentlyContinue
    }
}

# Test cnv-2.2: Convert PFX to PEM (cert+key)
Invoke-Test -TestId "cnv-2.2" -TestName "Convert PFX to PEM (cert+key)" -FilePrefix "cnv-topem-both" -TestScript {
    $guid = [guid]::NewGuid().ToString().Substring(0,8)

    # SETUP: Create a test certificate and export to PFX using PowerShell
    $certParams = @{
        Subject = "CN=certz-topem-both-$guid"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $password = ConvertTo-SecureString "PfxBothPass123" -AsPlainText -Force
    Export-PfxCertificate -Cert $cert -FilePath "cnv-topem-both.pfx" -Password $password | Out-Null
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe convert --pfx cnv-topem-both.pfx --password PfxBothPass123 --out-cert cnv-topem-both.cer --out-key cnv-topem-both.key 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Both files exist
        Assert-FileExists "cnv-topem-both.cer"
        Assert-FileExists "cnv-topem-both.key"

        # ASSERTION 3: Files contain correct PEM content
        $certContent = Get-Content "cnv-topem-both.cer" -Raw
        $keyContent = Get-Content "cnv-topem-both.key" -Raw
        if ($certContent -notmatch "-----BEGIN CERTIFICATE-----") {
            throw "Certificate file should contain PEM-encoded certificate"
        }
        if ($keyContent -notmatch "-----BEGIN.*PRIVATE KEY-----") {
            throw "Key file should contain PEM-encoded private key"
        }

        [PSCustomObject]@{ Success = $true; Details = "PFX to PEM (cert+key) successful" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item "cnv-topem-both.pfx" -Force -ErrorAction SilentlyContinue
        Remove-Item "cnv-topem-both.cer" -Force -ErrorAction SilentlyContinue
        Remove-Item "cnv-topem-both.key" -Force -ErrorAction SilentlyContinue
    }
}

# Test cnv-2.3: PFX to PEM without password fails
Invoke-Test -TestId "cnv-2.3" -TestName "PFX to PEM without password fails" -FilePrefix "cnv-nopwd" -TestScript {
    $guid = [guid]::NewGuid().ToString().Substring(0,8)

    # SETUP: Create a password-protected PFX using PowerShell
    $certParams = @{
        Subject = "CN=certz-nopwd-test-$guid"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $password = ConvertTo-SecureString "SecretPass123" -AsPlainText -Force
    Export-PfxCertificate -Cert $cert -FilePath "cnv-nopwd.pfx" -Password $password | Out-Null
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call WITHOUT password (should fail)
        $output = & .\certz.exe convert --pfx cnv-nopwd.pfx --out-cert cnv-nopwd.cer 2>&1
        $exitCode = $LASTEXITCODE
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code should be non-zero
        if ($exitCode -eq 0) {
            throw "Command should have failed without password"
        }

        # ASSERTION 2: Output should mention password requirement
        if ($outputStr -notmatch "password|Password") {
            throw "Error message should mention password requirement"
        }

        # ASSERTION 3: Output file should NOT exist
        Assert-FileNotExists "cnv-nopwd.cer"

        [PSCustomObject]@{ Success = $true; Details = "Password requirement enforced correctly" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item "cnv-nopwd.pfx" -Force -ErrorAction SilentlyContinue
        Remove-Item "cnv-nopwd.cer" -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# PFX ENCRYPTION TESTS
# ============================================================================
Write-TestHeader "Testing PFX Encryption Options"

# Test cnv-3.1: PFX encryption modern (AES-256)
Invoke-Test -TestId "cnv-3.1" -TestName "PFX with modern encryption (AES-256)" -FilePrefix "cnv-modern" -TestScript {
    $guid = [guid]::NewGuid().ToString().Substring(0,8)

    # SETUP: Create a test certificate and export to PEM using PowerShell
    $certParams = @{
        Subject = "CN=certz-modern-$guid"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams

    # Export certificate to PEM format
    $certPem = [Convert]::ToBase64String($cert.RawData, [Base64FormattingOptions]::InsertLineBreaks)
    $certPemContent = "-----BEGIN CERTIFICATE-----`n$certPem`n-----END CERTIFICATE-----"
    Set-Content -Path "cnv-modern.cer" -Value $certPemContent

    # Export private key to PEM
    $ecdsaKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert)
    $pkcs8Bytes = $ecdsaKey.ExportPkcs8PrivateKey()
    $base64Key = [System.Convert]::ToBase64String($pkcs8Bytes, [System.Base64FormattingOptions]::InsertLineBreaks)
    $keyPem = "-----BEGIN PRIVATE KEY-----`n$base64Key`n-----END PRIVATE KEY-----"
    Set-Content -Path "cnv-modern.key" -Value $keyPem

    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call with modern encryption
        $output = & .\certz.exe convert --cert cnv-modern.cer --key cnv-modern.key --pfx cnv-modern.pfx --password ModernPass123 --pfx-encryption modern 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: PFX file exists
        Assert-FileExists "cnv-modern.pfx"

        # ASSERTION 3: PFX can be loaded
        $loadedCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            (Resolve-Path "cnv-modern.pfx").Path, "ModernPass123")
        if (-not $loadedCert.HasPrivateKey) {
            throw "Loaded certificate should have private key"
        }
        $loadedCert.Dispose()

        [PSCustomObject]@{ Success = $true; Details = "Modern encryption PFX created successfully" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item "cnv-modern.cer" -Force -ErrorAction SilentlyContinue
        Remove-Item "cnv-modern.key" -Force -ErrorAction SilentlyContinue
        Remove-Item "cnv-modern.pfx" -Force -ErrorAction SilentlyContinue
    }
}

# Test cnv-3.2: PFX encryption legacy (3DES)
Invoke-Test -TestId "cnv-3.2" -TestName "PFX with legacy encryption (3DES)" -FilePrefix "cnv-legacy" -TestScript {
    $guid = [guid]::NewGuid().ToString().Substring(0,8)

    # SETUP: Create a test certificate and export to PEM using PowerShell
    $certParams = @{
        Subject = "CN=certz-legacy-$guid"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams

    # Export certificate to PEM format
    $certPem = [Convert]::ToBase64String($cert.RawData, [Base64FormattingOptions]::InsertLineBreaks)
    $certPemContent = "-----BEGIN CERTIFICATE-----`n$certPem`n-----END CERTIFICATE-----"
    Set-Content -Path "cnv-legacy.cer" -Value $certPemContent

    # Export private key to PEM
    $ecdsaKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert)
    $pkcs8Bytes = $ecdsaKey.ExportPkcs8PrivateKey()
    $base64Key = [System.Convert]::ToBase64String($pkcs8Bytes, [System.Base64FormattingOptions]::InsertLineBreaks)
    $keyPem = "-----BEGIN PRIVATE KEY-----`n$base64Key`n-----END PRIVATE KEY-----"
    Set-Content -Path "cnv-legacy.key" -Value $keyPem

    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call with legacy encryption
        $output = & .\certz.exe convert --cert cnv-legacy.cer --key cnv-legacy.key --pfx cnv-legacy.pfx --password LegacyPass123 --pfx-encryption legacy 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: PFX file exists
        Assert-FileExists "cnv-legacy.pfx"

        # ASSERTION 3: PFX can be loaded
        $loadedCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            (Resolve-Path "cnv-legacy.pfx").Path, "LegacyPass123")
        if (-not $loadedCert.HasPrivateKey) {
            throw "Loaded certificate should have private key"
        }
        $loadedCert.Dispose()

        [PSCustomObject]@{ Success = $true; Details = "Legacy encryption PFX created successfully" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item "cnv-legacy.cer" -Force -ErrorAction SilentlyContinue
        Remove-Item "cnv-legacy.key" -Force -ErrorAction SilentlyContinue
        Remove-Item "cnv-legacy.pfx" -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# FORMAT OUTPUT TESTS
# ============================================================================
Write-TestHeader "Testing FORMAT Output"

# Test fmt-1.1: JSON output format
Invoke-Test -TestId "fmt-1.1" -TestName "Convert with JSON output" -FilePrefix "fmt-json" -TestScript {
    $guid = [guid]::NewGuid().ToString().Substring(0,8)

    # SETUP: Create a test certificate and export to PEM using PowerShell
    $certParams = @{
        Subject = "CN=certz-fmt-json-$guid"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams

    # Export certificate to PEM format
    $certPem = [Convert]::ToBase64String($cert.RawData, [Base64FormattingOptions]::InsertLineBreaks)
    $certPemContent = "-----BEGIN CERTIFICATE-----`n$certPem`n-----END CERTIFICATE-----"
    Set-Content -Path "fmt-json.cer" -Value $certPemContent

    # Export private key to PEM
    $ecdsaKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert)
    $pkcs8Bytes = $ecdsaKey.ExportPkcs8PrivateKey()
    $base64Key = [System.Convert]::ToBase64String($pkcs8Bytes, [System.Base64FormattingOptions]::InsertLineBreaks)
    $keyPem = "-----BEGIN PRIVATE KEY-----`n$base64Key`n-----END PRIVATE KEY-----"
    Set-Content -Path "fmt-json.key" -Value $keyPem

    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call with JSON output
        $output = & .\certz.exe convert --cert fmt-json.cer --key fmt-json.key --pfx fmt-json.pfx --password JsonPass123 --format json 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: PFX file exists
        Assert-FileExists "fmt-json.pfx"

        # ASSERTION 3: Valid JSON output
        try {
            $json = $outputStr | ConvertFrom-Json
            if (-not $json.success) { throw "JSON 'success' field should be true" }
            if (-not $json.outputFile) { throw "JSON should contain outputFile" }
        }
        catch {
            if ($_.Exception.Message -match "JSON") {
                throw "Output is not valid JSON: $outputStr"
            }
            throw $_
        }

        [PSCustomObject]@{ Success = $true; Details = "Valid JSON output with conversion info" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item "fmt-json.cer" -Force -ErrorAction SilentlyContinue
        Remove-Item "fmt-json.key" -Force -ErrorAction SilentlyContinue
        Remove-Item "fmt-json.pfx" -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# CLEANUP
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

# ============================================================================
# SUMMARY
# ============================================================================
Write-Host "`n" -NoNewline
Write-TestHeader "Test Summary"

$totalTests = $script:TestCount
$passedCount = $script:PassedTests.Count
$failedCount = $script:FailedTests.Count
$passRate = if ($totalTests -gt 0) { [math]::Round(($passedCount / $totalTests) * 100, 2) } else { 0 }

Write-Host "`nTotal Tests:  $totalTests" -ForegroundColor White
Write-Host "Passed:       $passedCount ($passRate%)" -ForegroundColor Green
Write-Host "Failed:       $failedCount" -ForegroundColor $(if ($failedCount -eq 0) { "Green" } else { "Red" })

if ($failedCount -gt 0) {
    Write-Host "`nFailed Tests:" -ForegroundColor Red
    foreach ($test in $script:FailedTests) {
        Write-Host "  - $test" -ForegroundColor Yellow
    }
}

# Exit with appropriate code
if ($failedCount -eq 0) {
    Write-Host "`nAll tests passed!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`nSome tests failed!" -ForegroundColor Red
    exit 1
}
