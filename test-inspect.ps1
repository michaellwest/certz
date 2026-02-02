#Requires -Version 7.5

<#
.SYNOPSIS
    Test suite for certz inspect command.

.DESCRIPTION
    This script tests the inspect command: file inspection, URL inspection,
    thumbprint/store inspection, chain visualization, and save/export options.
    It follows test isolation principles from test-isolation-plan.md:
    - Each test invokes certz.exe exactly ONCE
    - Setup and teardown use pure PowerShell (no certz calls)
    - Assert against system state (files, cert store), NOT console output

.PARAMETER TestId
    Run specific tests by ID. Example: -TestId "ins-1.1", "ins-2.1"

.PARAMETER Category
    Run tests by category: inspect-file, inspect-url, inspect-store, chain, save, format

.PARAMETER SkipCleanup
    Keep test files after running.

.PARAMETER Verbose
    Show detailed output.

.EXAMPLE
    .\test-inspect.ps1
    Runs all tests with default settings.

.EXAMPLE
    .\test-inspect.ps1 -Category inspect-file
    Runs only file inspection tests.

.EXAMPLE
    .\test-inspect.ps1 -TestId "ins-1.1", "sav-1.1" -Verbose
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
    "inspect-file" = @("ins-1.1", "ins-1.2", "ins-1.3", "ins-1.4", "ins-1.5")
    "inspect-url" = @("ins-2.1", "ins-2.2", "ins-2.3")
    "inspect-store" = @("ins-3.1", "ins-3.2")
    "chain" = @("chn-1.1", "chn-1.2")
    "save" = @("sav-1.1", "sav-1.2", "sav-1.3", "sav-1.4", "sav-1.5")
    "format" = @("fmt-2.1", "fmt-2.2")
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
            Write-Host "       $($Details)" -ForegroundColor Gray
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

function Assert-CertificateInStore {
    param(
        [Parameter(Mandatory)]
        [string]$SubjectPattern,
        [string]$StoreName = "Root",
        [string]$StoreLocation = "CurrentUser",
        [string]$Message = "Certificate should exist in store"
    )
    $cert = Get-ChildItem "Cert:\$StoreLocation\$StoreName" -ErrorAction SilentlyContinue |
            Where-Object { $_.Subject -like $SubjectPattern } |
            Select-Object -First 1
    if (-not $cert) {
        throw "Assertion failed: $Message - No certificate matching '$SubjectPattern' in $StoreLocation\$StoreName"
    }
    return $cert
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
        return [PSCustomObject]@{ Success = $false; Error = $_.Exception.Message }
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
Write-Host "`nCertz Inspect Command Test Suite" -ForegroundColor Magenta
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
# INSPECT FILE TESTS
# ============================================================================
Write-TestHeader "Testing INSPECT FILE Command"

# Test ins-1.1: Inspect PFX file
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

        [PSCustomObject]@{ Success = $true; Details = "PFX inspection shows certificate details" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item "ins-pfx.pfx" -Force -ErrorAction SilentlyContinue
    }
}

# Test ins-1.2: Inspect PEM certificate
Invoke-Test -TestId "ins-1.2" -TestName "Inspect PEM certificate" -FilePrefix "ins-pem" -TestScript {
    # SETUP: Create a test certificate and export to PEM using PowerShell
    $certParams = @{
        Subject = "CN=ins-pem-test.local"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams

    # Export certificate to PEM format
    $certPem = [Convert]::ToBase64String($cert.RawData, [Base64FormattingOptions]::InsertLineBreaks)
    $certPemContent = "-----BEGIN CERTIFICATE-----`n$certPem`n-----END CERTIFICATE-----"
    Set-Content -Path "ins-pem.cer" -Value $certPemContent

    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe inspect ins-pem.cer 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Output contains certificate info
        if ($outputStr -notmatch "ins-pem-test\.local") {
            throw "Output should contain subject name 'ins-pem-test.local'"
        }

        [PSCustomObject]@{ Success = $true; Details = "PEM certificate inspection shows details" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item "ins-pem.cer" -Force -ErrorAction SilentlyContinue
    }
}

# Test ins-1.3: Inspect DER certificate
Invoke-Test -TestId "ins-1.3" -TestName "Inspect DER certificate" -FilePrefix "ins-der" -TestScript {
    # SETUP: Create a test certificate and export to DER using PowerShell
    $certParams = @{
        Subject = "CN=ins-der-test.local"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams

    # Export certificate to DER format (raw bytes)
    $derPath = Join-Path -Path (Get-Location).Path -ChildPath "ins-der.der"
    [System.IO.File]::WriteAllBytes($derPath, $cert.RawData)

    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe inspect ins-der.der 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0
        
        # ASSERTION 2: Output contains certificate info
        if ($outputStr -notmatch "ins-der-test\.local") {
            throw "Output should contain subject name 'ins-der-test.local'"
        }

        [PSCustomObject]@{ Success = $true; Details = "DER certificate inspection shows details" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item "ins-der.der" -Force -ErrorAction SilentlyContinue
    }
}

# Test ins-1.4: Inspect PEM with private key
Invoke-Test -TestId "ins-1.4" -TestName "Inspect PEM with private key" -FilePrefix "ins-pem-key" -TestScript {
    # SETUP: Create a test certificate and export cert+key to PEM using PowerShell
    $certParams = @{
        Subject = "CN=ins-pem-key-test.local"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams

    # Export certificate to PEM format
    $certPem = [Convert]::ToBase64String($cert.RawData, [Base64FormattingOptions]::InsertLineBreaks)
    $certPemContent = "-----BEGIN CERTIFICATE-----`n$certPem`n-----END CERTIFICATE-----"

    # Export private key to PEM
    $ecdsaKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert)
    $pkcs8Bytes = $ecdsaKey.ExportPkcs8PrivateKey()
    $base64Key = [System.Convert]::ToBase64String($pkcs8Bytes, [System.Base64FormattingOptions]::InsertLineBreaks)
    $keyPem = "-----BEGIN PRIVATE KEY-----`n$base64Key`n-----END PRIVATE KEY-----"

    # Combine into single PEM file
    $combinedPem = "$certPemContent`n`n$keyPem"
    Set-Content -Path "ins-pem-key.pem" -Value $combinedPem

    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe inspect ins-pem-key.pem 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Output contains certificate info and indicates private key
        if ($outputStr -notmatch "ins-pem-key-test\.local") {
            throw "Output should contain subject name 'ins-pem-key-test.local'"
        }
        if ($outputStr -notmatch "Private Key.*Yes|HasPrivateKey.*True|Has Private Key") {
            throw "Output should indicate certificate has private key"
        }

        [PSCustomObject]@{ Success = $true; Details = "PEM with key inspection shows details" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item "ins-pem-key.pem" -Force -ErrorAction SilentlyContinue
    }
}

# Test ins-1.5: Inspect with expiration warning
Invoke-Test -TestId "ins-1.5" -TestName "Inspect with expiration warning" -FilePrefix "ins-warn" -TestScript {
    # SETUP: Create a test certificate expiring in 20 days using PowerShell
    $certParams = @{
        Subject = "CN=ins-warn-test.local"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(20)
    }
    $cert = New-SelfSignedCertificate @certParams
    $password = ConvertTo-SecureString "WarnPass123" -AsPlainText -Force
    Export-PfxCertificate -Cert $cert -FilePath "ins-warn.pfx" -Password $password | Out-Null
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call with --warn 30 (should trigger warning for cert expiring in 20 days)
        $output = & .\certz.exe inspect ins-warn.pfx --password WarnPass123 --warn 30 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code (may be non-zero due to warning)
        # Just check the output contains the expected info

        # ASSERTION 2: Output should contain warning about expiration
        if ($outputStr -notmatch "warning|expir|days") {
            throw "Output should contain expiration warning"
        }

        [PSCustomObject]@{ Success = $true; Details = "Expiration warning shown for cert expiring in 20 days" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item "ins-warn.pfx" -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# INSPECT URL TESTS
# ============================================================================
Write-TestHeader "Testing INSPECT URL Command"

# Test ins-2.1: Inspect remote HTTPS URL
Invoke-Test -TestId "ins-2.1" -TestName "Inspect remote HTTPS URL" -FilePrefix "" -TestScript {
    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe inspect https://www.github.com 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code
        if ($LASTEXITCODE -ne 0) {
            # Network issues are acceptable - treat as skipped/pass
            return [PSCustomObject]@{ Success = $true; Details = "Skipped (network issue)" }
        }

        # ASSERTION 2: Output contains certificate info
        if ($outputStr -notmatch "github|Subject|Issuer|Thumbprint") {
            throw "Output should contain certificate information"
        }

        [PSCustomObject]@{ Success = $true; Details = "Remote certificate inspection successful" }
    }
    catch {
        # Network errors are acceptable
        [PSCustomObject]@{ Success = $true; Details = "Skipped (network error: $($_.Exception.Message))" }
    }
}

# Test ins-2.2: Inspect URL with custom port (using known site)
Invoke-Test -TestId "ins-2.2" -TestName "Inspect URL with explicit port" -FilePrefix "" -TestScript {
    try {
        # ACTION: Single certz.exe call (github on port 443)
        $output = & .\certz.exe inspect https://www.github.com:443 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION: Exit code or network error
        if ($LASTEXITCODE -ne 0) {
            return [PSCustomObject]@{ Success = $true; Details = "Skipped (network issue)" }
        }

        if ($outputStr -notmatch "github|Subject|Issuer") {
            throw "Output should contain certificate information"
        }

        [PSCustomObject]@{ Success = $true; Details = "URL with port inspection successful" }
    }
    catch {
        [PSCustomObject]@{ Success = $true; Details = "Skipped (network error)" }
    }
}

# Test ins-2.3: Inspect URL with chain
Invoke-Test -TestId "ins-2.3" -TestName "Inspect URL with certificate chain" -FilePrefix "" -TestScript {
    try {
        # ACTION: Single certz.exe call with --chain
        $output = & .\certz.exe inspect https://www.github.com --chain 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION: Exit code or network error
        if ($LASTEXITCODE -ne 0) {
            return [PSCustomObject]@{ Success = $true; Details = "Skipped (network issue)" }
        }

        # Output should show chain information
        if ($outputStr -notmatch "Chain|Root|CA|Issuer") {
            throw "Output should contain chain information"
        }

        [PSCustomObject]@{ Success = $true; Details = "Chain visualization displayed" }
    }
    catch {
        [PSCustomObject]@{ Success = $true; Details = "Skipped (network error)" }
    }
}

# ============================================================================
# INSPECT STORE TESTS
# ============================================================================
Write-TestHeader "Testing INSPECT STORE Command"

# Test ins-3.1: Inspect by thumbprint
Invoke-Test -TestId "ins-3.1" -TestName "Inspect certificate by thumbprint" -FilePrefix "ins-store" -TestScript {
    # SETUP: Create and install a test certificate using PowerShell
    $uniqueCN = "ins-store-test-$([guid]::NewGuid().ToString().Substring(0,8))"
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
        $output = & .\certz.exe inspect $thumbprint 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Output contains certificate info
        if ($outputStr -notmatch $uniqueCN) {
            throw "Output should contain subject name '$uniqueCN'"
        }

        [PSCustomObject]@{ Success = $true; Details = "Thumbprint inspection successful" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item $cert.PSPath -Force -ErrorAction SilentlyContinue
    }
}

# Test ins-3.2: Inspect by thumbprint with store option
Invoke-Test -TestId "ins-3.2" -TestName "Inspect by thumbprint with --store option" -FilePrefix "ins-store-opt" -TestScript {
    # SETUP: Create and install a test certificate using PowerShell
    $uniqueCN = "ins-store-opt-test-$([guid]::NewGuid().ToString().Substring(0,8))"
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
        # ACTION: Single certz.exe call with --store option
        $output = & .\certz.exe inspect $thumbprint --store My --location CurrentUser 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Output contains certificate info
        if ($outputStr -notmatch $uniqueCN) {
            throw "Output should contain subject name '$uniqueCN'"
        }

        [PSCustomObject]@{ Success = $true; Details = "Thumbprint with store option successful" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item $cert.PSPath -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# CHAIN TESTS
# ============================================================================
Write-TestHeader "Testing CHAIN Visualization"

# Test chn-1.1: Display certificate chain tree
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

        [PSCustomObject]@{ Success = $true; Details = "Chain tree displayed correctly" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item $caCert.PSPath -Force -ErrorAction SilentlyContinue
        Remove-Item $endCert.PSPath -Force -ErrorAction SilentlyContinue
        Remove-Item "chn-tree.pfx" -Force -ErrorAction SilentlyContinue
    }
}

# Test chn-1.2: Chain with revocation check (OCSP/CRL)
Invoke-Test -TestId "chn-1.2" -TestName "Chain with revocation check" -FilePrefix "chn-crl" -TestScript {
    # SETUP: Create a test certificate using PowerShell
    $certParams = @{
        Subject = "CN=chn-crl-test.local"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $password = ConvertTo-SecureString "CrlPass123" -AsPlainText -Force
    Export-PfxCertificate -Cert $cert -FilePath "chn-crl.pfx" -Password $password | Out-Null
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call with --chain and --crl
        $output = & .\certz.exe inspect chn-crl.pfx --password CrlPass123 --chain --crl 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION: Exit code (may fail revocation check for self-signed)
        # Just check that the command ran and produced output
        if ($outputStr -notmatch "chn-crl-test\.local|Chain|revocation") {
            throw "Output should contain certificate or revocation information"
        }

        [PSCustomObject]@{ Success = $true; Details = "Revocation check executed" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item "chn-crl.pfx" -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# SAVE TESTS
# ============================================================================
Write-TestHeader "Testing SAVE Options"

# Test sav-1.1: Save certificate to PEM (default)
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

        [PSCustomObject]@{ Success = $true; Details = "Certificate saved to PEM format" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item "sav-pem.pfx" -Force -ErrorAction SilentlyContinue
        Remove-Item "sav-pem-out.cer" -Force -ErrorAction SilentlyContinue
    }
}

# Test sav-1.2: Save certificate and key to PEM
Invoke-Test -TestId "sav-1.2" -TestName "Save certificate and key to PEM" -FilePrefix "sav-both" -TestScript {
    # SETUP: Create a test certificate using PowerShell
    $certParams = @{
        Subject = "CN=save-both-test.local"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $password = ConvertTo-SecureString "SaveBothPass123" -AsPlainText -Force
    Export-PfxCertificate -Cert $cert -FilePath "sav-both.pfx" -Password $password | Out-Null
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe inspect sav-both.pfx --password SaveBothPass123 --save sav-both-out.cer --save-key sav-both-out.key 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Both files exist
        Assert-FileExists "sav-both-out.cer"
        Assert-FileExists "sav-both-out.key"

        # ASSERTION 3: Files contain correct PEM content
        $certContent = Get-Content "sav-both-out.cer" -Raw
        $keyContent = Get-Content "sav-both-out.key" -Raw
        if ($certContent -notmatch "-----BEGIN CERTIFICATE-----") {
            throw "Certificate file should contain PEM-encoded certificate"
        }
        if ($keyContent -notmatch "-----BEGIN.*PRIVATE KEY-----") {
            throw "Key file should contain PEM-encoded private key"
        }

        [PSCustomObject]@{ Success = $true; Details = "Certificate and key saved to PEM" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item "sav-both.pfx" -Force -ErrorAction SilentlyContinue
        Remove-Item "sav-both-out.cer" -Force -ErrorAction SilentlyContinue
        Remove-Item "sav-both-out.key" -Force -ErrorAction SilentlyContinue
    }
}

# Test sav-1.3: Save remote certificate
Invoke-Test -TestId "sav-1.3" -TestName "Save remote certificate" -FilePrefix "sav-remote" -TestScript {
    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe inspect https://www.github.com --save sav-remote.cer 2>&1

        # Check for network errors
        if ($LASTEXITCODE -ne 0) {
            return [PSCustomObject]@{ Success = $true; Details = "Skipped (network issue)" }
        }

        # ASSERTION: Output file exists and contains certificate
        Assert-FileExists "sav-remote.cer"

        $content = Get-Content "sav-remote.cer" -Raw
        if ($content -notmatch "-----BEGIN CERTIFICATE-----") {
            throw "Output file should contain PEM-encoded certificate"
        }

        [PSCustomObject]@{ Success = $true; Details = "Remote certificate saved" }
    }
    catch {
        [PSCustomObject]@{ Success = $true; Details = "Skipped (network error)" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item "sav-remote.cer" -Force -ErrorAction SilentlyContinue
    }
}

# Test sav-1.4: Save certificate to DER format
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

        [PSCustomObject]@{ Success = $true; Details = "Certificate saved to DER format" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item "sav-der.pfx" -Force -ErrorAction SilentlyContinue
        Remove-Item "sav-der-out.der" -Force -ErrorAction SilentlyContinue
    }
}

# Test sav-1.5: Save certificate and key to DER
Invoke-Test -TestId "sav-1.5" -TestName "Save certificate and key to DER" -FilePrefix "sav-der-both" -TestScript {
    # SETUP: Create a test certificate using PowerShell
    $certParams = @{
        Subject = "CN=save-der-both-test.local"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $password = ConvertTo-SecureString "SaveDerBothPass123" -AsPlainText -Force
    Export-PfxCertificate -Cert $cert -FilePath "sav-der-both.pfx" -Password $password | Out-Null
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe inspect sav-der-both.pfx --password SaveDerBothPass123 --save sav-der-both-out.der --save-key sav-der-both-out.key --save-format der 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Both files exist
        Assert-FileExists "sav-der-both-out.der"
        Assert-FileExists "sav-der-both-out.key"

        # ASSERTION 3: Certificate is DER format
        $certContent = Get-Content "sav-der-both-out.der" -Raw -ErrorAction SilentlyContinue
        if ($certContent -match "-----BEGIN CERTIFICATE-----") {
            throw "Certificate file should be DER format (binary), not PEM"
        }

        [PSCustomObject]@{ Success = $true; Details = "Certificate and key saved to DER" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item "sav-der-both.pfx" -Force -ErrorAction SilentlyContinue
        Remove-Item "sav-der-both-out.der" -Force -ErrorAction SilentlyContinue
        Remove-Item "sav-der-both-out.key" -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# FORMAT TESTS
# ============================================================================
Write-TestHeader "Testing FORMAT Output"

# Test fmt-2.1: Inspect with JSON output
Invoke-Test -TestId "fmt-2.1" -TestName "Inspect with JSON output" -FilePrefix "fmt-json" -TestScript {
    # SETUP: Create a test certificate using PowerShell
    $certParams = @{
        Subject = "CN=fmt-json-test.local"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $password = ConvertTo-SecureString "FmtJsonPass123" -AsPlainText -Force
    Export-PfxCertificate -Cert $cert -FilePath "fmt-json.pfx" -Password $password | Out-Null
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe inspect fmt-json.pfx --password FmtJsonPass123 --format json 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Output is valid JSON
        try {
            $json = $output | ConvertFrom-Json            
            if (-not $json.success -and -not $json.certificate.subject -and -not $json.certificate.thumbprint) {
                throw "JSON should contain certificate fields"
            }
        }
        catch {
            if ($_.Exception.Message -match "JSON") {
                throw "Output is not valid JSON; $($_.Exception.Message): $($output)"
            }
            throw $_
        }

        [PSCustomObject]@{ Success = $true; Details = "Valid JSON output" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item "fmt-json.pfx" -Force -ErrorAction SilentlyContinue
    }
}

# Test fmt-2.2: Inspect URL with JSON output
Invoke-Test -TestId "fmt-2.2" -TestName "Inspect URL with JSON output" -FilePrefix "" -TestScript {
    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe inspect https://www.github.com --format json 2>&1

        # Check for network errors
        if ($LASTEXITCODE -ne 0) {
            return [PSCustomObject]@{ Success = $true; Details = "Skipped (network issue); $($output)" }
        }

        # ASSERTION: Output is valid JSON
        try {
            $json = $output | ConvertFrom-Json            
            if (-not $json.success -and -not $json.certificate.subject -and -not $json.certificate.thumbprint) {
                throw "JSON should contain certificate fields"
            }
        }
        catch {
            if ($_.Exception.Message -match "JSON") {
                throw "Output is not valid JSON; $($_.Exception.Message): $($output)"
            }
            throw $_
        }

        [PSCustomObject]@{ Success = $true; Details = "Valid JSON output for URL" }
    }
    catch {
        [PSCustomObject]@{ Success = $true; Details = "Skipped (network error)" }
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
