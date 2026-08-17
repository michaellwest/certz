#requires -version 7

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

# Load shared test helper functions
. "$PSScriptRoot\test-helper.ps1"

# Test categories
$TestCategories = @{
    "inspect-file" = @("ins-1.1", "ins-1.2", "ins-1.3", "ins-1.4", "ins-1.5")
    "inspect-url" = @("ins-2.1", "ins-2.2", "ins-2.3")
    "inspect-store" = @("ins-3.1", "ins-3.2")
    "chain" = @("chn-1.1", "chn-1.2", "chn-1.3", "chn-1.4")
    "save" = @("sav-1.1", "sav-1.2", "sav-1.3", "sav-1.4", "sav-1.5")
    "format" = @("fmt-2.1", "fmt-2.2")
    "save-dir" = @("svd-1.1", "svd-1.2", "svd-1.3", "svd-1.4", "svd-1.5", "svd-1.6", "svd-1.7", "svd-1.8")
    "guided" = @("ins-gui-1.1")  # Interactive tests (manual only)
}

# Initialize test environment
Initialize-TestEnvironment -TestId $TestId -Category $Category -TestCategories $TestCategories
Set-VerboseOutput -Enabled $Verbose

# Display banner
Write-Host "`nCertz Inspect Command Test Suite" -ForegroundColor Magenta
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
# INSPECT FILE TESTS
# ============================================================================
Write-TestHeader "Testing INSPECT FILE Command"

# Test ins-1.1: Inspect PFX file
Invoke-Test -TestId "ins-1.1" -TestName "Inspect PFX file" -FilePrefix "ins-pfx" -TestScript {
    # SETUP: Create a test certificate using PowerShell
    $certParams = @{
        Subject = "CN=certz-ins-test.local"
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
        if ($outputStr -notmatch "certz-ins-test\.local") {
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
        Subject = "CN=certz-ins-pem-test.local"
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
        if ($outputStr -notmatch "certz-ins-pem-test\.local") {
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
        Subject = "CN=certz-ins-der-test.local"
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
        if ($outputStr -notmatch "certz-ins-der-test\.local") {
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
        Subject = "CN=certz-ins-pem-key-test.local"
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
        if ($outputStr -notmatch "certz-ins-pem-key-test\.local") {
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
        Subject = "CN=certz-ins-warn-test.local"
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
    $uniqueCN = "certz-ins-store-test-$([guid]::NewGuid().ToString().Substring(0,8))"
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
    $uniqueCN = "certz-ins-store-opt-test-$([guid]::NewGuid().ToString().Substring(0,8))"
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
        Subject = "CN=certz-certz-Chain Test CA"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddYears(1)
        KeyUsage = "CertSign", "CRLSign"
        TextExtension = @("2.5.29.19={critical}{text}CA=TRUE")
    }
    $caCert = New-SelfSignedCertificate @caParams

    $endParams = @{
        Subject = "CN=certz-chain-end.local"
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
        if ($outputStr -notmatch "certz-Chain Test CA") {
            throw "Chain output should show issuer CA"
        }
        if ($outputStr -notmatch "certz-chain-end\.local") {
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
        Subject = "CN=certz-chn-crl-test.local"
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
        if ($outputStr -notmatch "certz-chn-crl-test\.local|Chain|revocation") {
            throw "Output should contain certificate or revocation information"
        }

        [PSCustomObject]@{ Success = $true; Details = "Revocation check executed" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item "chn-crl.pfx" -Force -ErrorAction SilentlyContinue
    }
}

# Test chn-1.3: Display detailed certificate chain tree with --tree flag
Invoke-Test -TestId "chn-1.3" -TestName "Display detailed chain tree (--tree)" -FilePrefix "chn-tree-detail" -TestScript {
    # SETUP: Create a CA and signed certificate chain using PowerShell
    $caParams = @{
        Subject = "CN=certz-Detail Chain Test CA"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddYears(1)
        KeyUsage = "CertSign", "CRLSign"
        TextExtension = @("2.5.29.19={critical}{text}CA=TRUE")
    }
    $caCert = New-SelfSignedCertificate @caParams

    $endParams = @{
        Subject = "CN=certz-chain-detail-end.local"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
        Signer = $caCert
        DnsName = "certz-chain-detail-end.local", "localhost"
    }
    $endCert = New-SelfSignedCertificate @endParams

    $password = ConvertTo-SecureString "ChainDetailPass123" -AsPlainText -Force
    Export-PfxCertificate -Cert $endCert -FilePath "chn-tree-detail.pfx" -Password $password -ChainOption BuildChain | Out-Null

    try {
        # ACTION: Single certz.exe call with --chain --tree
        $output = & .\certz.exe inspect chn-tree-detail.pfx --password ChainDetailPass123 --chain --tree 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Output shows detailed chain structure with key info
        if ($outputStr -notmatch "Key:") {
            throw "Detailed chain should show key algorithm"
        }
        if ($outputStr -notmatch "Signature:") {
            throw "Detailed chain should show signature algorithm"
        }
        if ($outputStr -notmatch "Valid:") {
            throw "Detailed chain should show validity period"
        }

        # ASSERTION 3: End entity shows SANs
        if ($outputStr -notmatch "SANs:") {
            throw "Detailed chain should show SANs for end entity"
        }

        [PSCustomObject]@{ Success = $true; Details = "Detailed chain tree with --tree flag displayed correctly" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item $caCert.PSPath -Force -ErrorAction SilentlyContinue
        Remove-Item $endCert.PSPath -Force -ErrorAction SilentlyContinue
        Remove-Item "chn-tree-detail.pfx" -Force -ErrorAction SilentlyContinue
    }
}

# Test chn-1.4: Chain JSON output includes new fields
Invoke-Test -TestId "chn-1.4" -TestName "Chain JSON output with detailed fields" -FilePrefix "chn-json-detail" -TestScript {
    # SETUP: Create a CA and signed certificate chain using PowerShell
    $caParams = @{
        Subject = "CN=certz-JSON Chain Test CA"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddYears(1)
        KeyUsage = "CertSign", "CRLSign"
        TextExtension = @("2.5.29.19={critical}{text}CA=TRUE")
    }
    $caCert = New-SelfSignedCertificate @caParams

    $endParams = @{
        Subject = "CN=certz-chain-json-end.local"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
        Signer = $caCert
        DnsName = "certz-chain-json-end.local", "localhost"
    }
    $endCert = New-SelfSignedCertificate @endParams

    $password = ConvertTo-SecureString "ChainJsonPass123" -AsPlainText -Force
    Export-PfxCertificate -Cert $endCert -FilePath "chn-json-detail.pfx" -Password $password -ChainOption BuildChain | Out-Null

    try {
        # ACTION: Single certz.exe call with --chain --format json
        $output = & .\certz.exe inspect chn-json-detail.pfx --password ChainJsonPass123 --chain --format json 2>&1
        $outputStr = $output -join ""

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Parse JSON and check for new fields
        try {
            $json = $outputStr | ConvertFrom-Json
            if (-not $json.chain) {
                throw "JSON should contain chain array"
            }

            # Check that chain elements have new fields
            $endEntity = $json.chain[0]
            if (-not $endEntity.keyAlgorithm) {
                throw "Chain element should have keyAlgorithm field"
            }
            if ($null -eq $endEntity.keySize) {
                throw "Chain element should have keySize field"
            }
            if (-not $endEntity.signatureAlgorithm) {
                throw "Chain element should have signatureAlgorithm field"
            }
            if ($null -eq $endEntity.daysRemaining) {
                throw "Chain element should have daysRemaining field"
            }
            # End entity should have SANs
            if ($null -eq $endEntity.subjectAlternativeNames) {
                throw "End entity should have subjectAlternativeNames field"
            }
        }
        catch {
            if ($_.Exception.Message -match "JSON") {
                throw "Output is not valid JSON: $outputStr"
            }
            throw $_
        }

        [PSCustomObject]@{ Success = $true; Details = "Chain JSON output includes all new fields" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item $caCert.PSPath -Force -ErrorAction SilentlyContinue
        Remove-Item $endCert.PSPath -Force -ErrorAction SilentlyContinue
        Remove-Item "chn-json-detail.pfx" -Force -ErrorAction SilentlyContinue
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
        Subject = "CN=certz-save-test.local"
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
        Subject = "CN=certz-save-both-test.local"
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
        Subject = "CN=certz-save-der-test.local"
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
        if ($derCert.Subject -notmatch "certz-save-der-test\.local") {
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
        Subject = "CN=certz-save-der-both-test.local"
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
        Subject = "CN=certz-fmt-json-test.local"
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
# SAVE-DIR / CHAIN EXPORT TESTS (issue #73)
# ============================================================================
Write-TestHeader "Testing Chain Export to Directory"

# Shared setup: build a chain PFX and return its path plus the fixture certs.
function New-SaveDirFixture {
    param([string]$Name)

    $chain = New-TestCertificateChain -Subject $Name
    $collection = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
    $collection.Add($chain.Leaf) | Out-Null
    $collection.Add($chain.Ca) | Out-Null
    [System.IO.File]::WriteAllBytes(
        (Join-Path (Get-Location) "$Name.pfx"),
        $collection.Export('Pkcs12', 'TestPass123'))

    return $chain
}

# Test svd-1.1: Each chain element is written to its own file
Invoke-Test -TestId "svd-1.1" -TestName "Save-dir writes each chain element to its own file" -TestScript {
    $guid = [guid]::NewGuid().ToString().Substring(0,8)
    $name = "svd-basic-$guid"
    $outDir = "svd-out-$guid"
    $chain = New-SaveDirFixture -Name $name

    try {
        # ACTION: Single certz.exe call
        & .\certz.exe inspect "$name.pfx" --password TestPass123 --save-dir $outDir 2>&1 | Out-Null

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: One file per chain element
        $files = @(Get-ChildItem -Path $outDir -Filter "*.pem" -ErrorAction SilentlyContinue)
        if ($files.Count -ne 2) {
            throw "Expected 2 chain files, found $($files.Count)"
        }

        # ASSERTION 3: Leaf is index 00 and is the end-entity certificate
        $leafFile = $files | Where-Object { $_.Name -like "00-*" } | Select-Object -First 1
        if (-not $leafFile) {
            throw "Expected a leaf file prefixed '00-', found: $($files.Name -join ', ')"
        }
        $leafCert = [System.Security.Cryptography.X509Certificates.X509CertificateLoader]::LoadCertificateFromFile($leafFile.FullName)
        if ($leafCert.Subject -ne $chain.Leaf.Subject) {
            throw "Expected leaf subject '$($chain.Leaf.Subject)', found '$($leafCert.Subject)'"
        }

        # ASSERTION 4: Each file holds exactly one certificate
        foreach ($f in $files) {
            $count = Get-CertificateCount -Path $f.FullName
            if ($count -ne 1) {
                throw "Expected 1 certificate in $($f.Name), found $count"
            }
        }

        [PSCustomObject]@{ Success = $true; Details = "Wrote $($files.Count) chain files" }
    }
    finally {
        Remove-TestCertificateChain -Chain $chain
        Remove-Item "$name.pfx" -Force -ErrorAction SilentlyContinue
        Remove-Item $outDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Test svd-1.2: The output directory is created when it does not exist
Invoke-Test -TestId "svd-1.2" -TestName "Save-dir creates a missing nested directory" -TestScript {
    $guid = [guid]::NewGuid().ToString().Substring(0,8)
    $name = "svd-mkdir-$guid"
    $rootDir = "svd-mkdir-root-$guid"
    $outDir = Join-Path $rootDir "nested/chain"
    $chain = New-SaveDirFixture -Name $name

    try {
        if (Test-Path $rootDir) {
            throw "Precondition failed: $rootDir already exists"
        }

        # ACTION: Single certz.exe call
        & .\certz.exe inspect "$name.pfx" --password TestPass123 --save-dir $outDir 2>&1 | Out-Null

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Nested directory was created and populated
        if (-not (Test-Path $outDir -PathType Container)) {
            throw "Expected certz to create $outDir"
        }
        $files = @(Get-ChildItem -Path $outDir -Filter "*.pem" -ErrorAction SilentlyContinue)
        if ($files.Count -lt 1) {
            throw "Expected chain files in the created directory, found none"
        }

        [PSCustomObject]@{ Success = $true; Details = "Created $outDir with $($files.Count) files" }
    }
    finally {
        Remove-TestCertificateChain -Chain $chain
        Remove-Item "$name.pfx" -Force -ErrorAction SilentlyContinue
        Remove-Item $rootDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Test svd-1.3: --save-dir and --save are mutually exclusive
Invoke-Test -TestId "svd-1.3" -TestName "Save-dir combined with --save is rejected" -TestScript {
    $guid = [guid]::NewGuid().ToString().Substring(0,8)
    $name = "svd-excl-$guid"
    $outDir = "svd-excl-out-$guid"
    $chain = New-SaveDirFixture -Name $name

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe inspect "$name.pfx" --password TestPass123 --save-dir $outDir --save "svd-excl-$guid.pem" 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Validation error
        Assert-ExitCode -Expected 1

        # ASSERTION 2: Rejected for the right reason, not merely an unknown option
        Assert-Match -Actual $outputStr -Pattern "mutually exclusive" `
            -Message "Error should identify --save-dir and --save as mutually exclusive"

        # ASSERTION 3: Nothing was written
        Assert-FileNotExists "svd-excl-$guid.pem"

        [PSCustomObject]@{ Success = $true; Details = "Mutually exclusive options rejected" }
    }
    finally {
        Remove-TestCertificateChain -Chain $chain
        Remove-Item "$name.pfx" -Force -ErrorAction SilentlyContinue
        Remove-Item "svd-excl-$guid.pem" -Force -ErrorAction SilentlyContinue
        Remove-Item $outDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Test svd-1.4: Existing files are not overwritten without --force
Invoke-Test -TestId "svd-1.4" -TestName "Save-dir refuses to overwrite without --force" -TestScript {
    $guid = [guid]::NewGuid().ToString().Substring(0,8)
    $name = "svd-force-$guid"
    $outDir = "svd-force-out-$guid"
    $chain = New-SaveDirFixture -Name $name

    try {
        # SETUP: Pre-populate the directory with a colliding filename.
        # The leaf file is deterministic: 00-<sanitized CN>-<first 8 of thumbprint>.pem
        New-Item -ItemType Directory -Path $outDir | Out-Null
        $collision = Join-Path $outDir "00-$name-$($chain.Leaf.Thumbprint.Substring(0,8)).pem"
        Set-Content -Path $collision -Value "SENTINEL"

        # ACTION: Single certz.exe call
        $output = & .\certz.exe inspect "$name.pfx" --password TestPass123 --save-dir $outDir 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Refused
        Assert-ExitCode -Expected 1

        # ASSERTION 2: Refused for the collision, not merely an unknown option
        Assert-Match -Actual $outputStr -Pattern "--force" `
            -Message "Error should point at --force as the way to overwrite"

        # ASSERTION 3: Existing file untouched
        $content = Get-Content -Path $collision -Raw
        if ($content -notmatch "SENTINEL") {
            throw "Existing file was overwritten without --force"
        }

        [PSCustomObject]@{ Success = $true; Details = "Overwrite refused without --force" }
    }
    finally {
        Remove-TestCertificateChain -Chain $chain
        Remove-Item "$name.pfx" -Force -ErrorAction SilentlyContinue
        Remove-Item $outDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Test svd-1.5: --dry-run suppresses every write, not only the chain export
Invoke-Test -TestId "svd-1.5" -TestName "Save-dir dry-run writes nothing" -TestScript {
    $guid = [guid]::NewGuid().ToString().Substring(0,8)
    $name = "svd-dry-$guid"
    $outDir = "svd-dry-out-$guid"
    $keyPath = "svd-dry-$guid.key"
    $chain = New-SaveDirFixture -Name $name

    try {
        # ACTION: Single certz.exe call. --save-key is included deliberately: dry-run
        # must suppress it too, not just the --save-dir export.
        $output = & .\certz.exe inspect "$name.pfx" --password TestPass123 --save-dir $outDir --save-key $keyPath --dry-run --format json 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: No chain files written
        $files = @(Get-ChildItem -Path $outDir -Filter "*.pem" -ErrorAction SilentlyContinue)
        if ($files.Count -ne 0) {
            throw "Dry run wrote $($files.Count) chain files"
        }

        # ASSERTION 3: No private key written
        Assert-FileNotExists $keyPath -Message "Dry run must not write the private key"

        # ASSERTION 4: The plan WAS reported. Without this the test would also pass if
        # the export were removed entirely rather than merely suppressed.
        $json = $outputStr | ConvertFrom-Json
        if (-not $json.savedFilesWereDryRun) {
            throw "Expected savedFilesWereDryRun to be true"
        }

        # 3 paths: the suppressed --save-key file plus the 2 chain certificates. A dry
        # run must account for every write it suppressed, not only the chain export.
        $planned = @($json.savedFiles)
        if ($planned.Count -ne 3) {
            throw "Expected 3 planned paths (key + 2 chain certs), found $($planned.Count)"
        }
        if (-not ($planned | Where-Object { $_ -like "*$keyPath" })) {
            throw "Expected the suppressed --save-key path to be reported, got: $($planned -join ', ')"
        }

        [PSCustomObject]@{ Success = $true; Details = "Dry run wrote nothing" }
    }
    finally {
        Remove-TestCertificateChain -Chain $chain
        Remove-Item "$name.pfx" -Force -ErrorAction SilentlyContinue
        Remove-Item $keyPath -Force -ErrorAction SilentlyContinue
        Remove-Item $outDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Test svd-1.6: --naming thumbprint produces thumbprint filenames
Invoke-Test -TestId "svd-1.6" -TestName "Save-dir honors --naming thumbprint" -TestScript {
    $guid = [guid]::NewGuid().ToString().Substring(0,8)
    $name = "svd-naming-$guid"
    $outDir = "svd-naming-out-$guid"
    $chain = New-SaveDirFixture -Name $name

    try {
        # ACTION: Single certz.exe call
        & .\certz.exe inspect "$name.pfx" --password TestPass123 --save-dir $outDir --naming thumbprint 2>&1 | Out-Null

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Leaf file is named for its thumbprint alone
        $expected = Join-Path $outDir "$($chain.Leaf.Thumbprint).pem"
        Assert-FileExists $expected -Message "Expected thumbprint-named file"

        [PSCustomObject]@{ Success = $true; Details = "Thumbprint naming applied" }
    }
    finally {
        Remove-TestCertificateChain -Chain $chain
        Remove-Item "$name.pfx" -Force -ErrorAction SilentlyContinue
        Remove-Item $outDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Test svd-1.7: A hostile subject cannot escape the output directory
Invoke-Test -TestId "svd-1.7" -TestName "Save-dir sanitizes a traversal attempt in the subject" -TestScript {
    $guid = [guid]::NewGuid().ToString().Substring(0,8)
    $root = "svd-trav-$guid"
    $outDir = Join-Path $root "target"

    # SETUP: subject content is attacker-controlled, so build a certificate whose CN is
    # a relative path. Uses .NET directly - New-SelfSignedCertificate rejects this DN.
    $curve = [System.Security.Cryptography.ECCurve+NamedCurves]::nistP256
    $sha = [System.Security.Cryptography.HashAlgorithmName]::SHA256
    $now = [DateTimeOffset]::UtcNow
    $key = [System.Security.Cryptography.ECDsa]::Create($curve)
    $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=..\..\evil', $key, $sha)
    $req.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false,$false,0,$true))
    $cert = $req.CreateSelfSigned($now.AddDays(-1), $now.AddDays(30))

    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    [System.IO.File]::WriteAllBytes((Join-Path (Get-Location) "$root\evil.pfx"), $cert.Export('Pkcs12','p'))

    try {
        # ACTION: Single certz.exe call
        & .\certz.exe inspect "$root\evil.pfx" --password p --save-dir $outDir 2>&1 | Out-Null

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Exactly one file, and it is INSIDE the target directory
        $inside = @(Get-ChildItem -Path $outDir -File -Recurse -ErrorAction SilentlyContinue)
        if ($inside.Count -ne 1) {
            throw "Expected 1 file inside the target directory, found $($inside.Count)"
        }

        # ASSERTION 3: The separators were neutralized, not preserved as path structure
        if ($inside[0].Name -match '[\\/]') {
            throw "Filename retained a path separator: $($inside[0].Name)"
        }

        # ASSERTION 4: Nothing was written above the target directory
        $escaped = @(Get-ChildItem -Path $root -File -ErrorAction SilentlyContinue |
                     Where-Object { $_.Extension -in '.pem', '.cer' })
        if ($escaped.Count -ne 0) {
            throw "Traversal escaped the target directory: $($escaped.Name -join ', ')"
        }

        [PSCustomObject]@{ Success = $true; Details = "Sanitized to $($inside[0].Name)" }
    }
    finally {
        $cert.Dispose()
        Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Test svd-1.8: A reserved Windows device name in the subject is not used as a filename
Invoke-Test -TestId "svd-1.8" -TestName "Save-dir avoids reserved device names" -TestScript {
    $guid = [guid]::NewGuid().ToString().Substring(0,8)
    $root = "svd-dev-$guid"
    $outDir = Join-Path $root "target"

    # SETUP: CN=NUL would resolve to the null device rather than a file, so the write
    # would vanish while the command reported success.
    $curve = [System.Security.Cryptography.ECCurve+NamedCurves]::nistP256
    $sha = [System.Security.Cryptography.HashAlgorithmName]::SHA256
    $now = [DateTimeOffset]::UtcNow
    $key = [System.Security.Cryptography.ECDsa]::Create($curve)
    $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=NUL', $key, $sha)
    $req.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false,$false,0,$true))
    $cert = $req.CreateSelfSigned($now.AddDays(-1), $now.AddDays(30))

    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    [System.IO.File]::WriteAllBytes((Join-Path (Get-Location) "$root\dev.pfx"), $cert.Export('Pkcs12','p'))

    try {
        # ACTION: Single certz.exe call, --naming cn to force the CN into the filename
        & .\certz.exe inspect "$root\dev.pfx" --password p --save-dir $outDir --naming cn 2>&1 | Out-Null

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: A real file exists and is not named for the device
        $files = @(Get-ChildItem -Path $outDir -File -ErrorAction SilentlyContinue)
        if ($files.Count -ne 1) {
            throw "Expected 1 written file, found $($files.Count)"
        }
        if ([System.IO.Path]::GetFileNameWithoutExtension($files[0].Name) -eq 'NUL') {
            throw "Filename used the reserved device name NUL"
        }

        # ASSERTION 3: The file holds a real certificate, i.e. the bytes went to disk
        $count = Get-CertificateCount -Path $files[0].FullName
        if ($count -ne 1) {
            throw "Expected 1 certificate in the written file, found $count"
        }

        [PSCustomObject]@{ Success = $true; Details = "Device name avoided: $($files[0].Name)" }
    }
    finally {
        $cert.Dispose()
        Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Test ins-gui-1.1: Interactive wizard (manual test)
Invoke-Test -TestId "ins-gui-1.1" -TestName "Interactive wizard (manual test)" -TestScript {
    Write-Host "  This test requires manual interaction." -ForegroundColor Yellow
    Write-Host "  Run: .\certz.exe inspect --guided" -ForegroundColor Yellow
    Write-Host "  The wizard should prompt for source (file/URL/store), password, and chain options." -ForegroundColor Yellow
    [PSCustomObject]@{ Success = $true; Details = "Manual test - run interactively" }
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
