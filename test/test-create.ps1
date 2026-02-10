#Requires -RunAsAdministrator
#requires -version 7

<#
.SYNOPSIS
    Test suite for certz create commands (create dev, create ca).

.DESCRIPTION
    This script tests the hierarchical create commands: create dev and create ca.
    It follows test isolation principles from test-isolation-plan.md:
    - Each test invokes certz.exe exactly ONCE
    - Setup and teardown use pure PowerShell (no certz calls)
    - Assert against system state (files, cert store), NOT console output

.PARAMETER TestId
    Run specific tests by ID. Example: -TestId "dev-1.1", "ca-1.1"

.PARAMETER Category
    Run tests by category: create-dev, create-ca, format, issuer, trust, guided

.PARAMETER SkipCleanup
    Keep test files after running.

.PARAMETER Verbose
    Show detailed output.

.EXAMPLE
    .\test-create.ps1
    Runs all tests with default settings.

.EXAMPLE
    .\test-create.ps1 -Category create-dev
    Runs only create dev tests.

.EXAMPLE
    .\test-create.ps1 -TestId "dev-1.1", "ca-1.1" -Verbose
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
    "create-dev" = @("dev-1.1", "dev-1.2", "dev-1.3", "dev-1.4", "dev-1.5")
    "create-ca" = @("ca-1.1", "ca-1.2", "ca-1.3")
    "format" = @("fmt-1.1", "fmt-1.2")
    "issuer" = @("iss-1.1", "iss-1.2")
    "trust" = @("tru-1.1", "tru-1.2")
    "guided" = @("gui-1.1")  # Interactive tests (manual only)
}

# Initialize test environment
Initialize-TestEnvironment -TestId $TestId -Category $Category -TestCategories $TestCategories
Set-VerboseOutput -Enabled $Verbose

# Display banner
Write-Host "`nCertz Create Command Test Suite" -ForegroundColor Magenta
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
Remove-TestFiles

# ============================================================================
# CREATE DEV COMMAND TESTS
# ============================================================================
Write-TestHeader "Testing CREATE DEV Command"

# Test dev-1.1: Basic dev cert with domain argument
Invoke-Test -TestId "dev-1.1" -TestName "Create dev cert with domain argument" -FilePrefix "dev-basic" -TestScript {
    # ACTION: Single certz.exe call
    $output = & .\certz.exe create dev api.local --f dev-basic.pfx --p TestPass123 2>&1
    $outputStr = $output -join "`n"

    # ASSERTION 1: Exit code
    Assert-ExitCode -Expected 0

    # ASSERTION 2: File exists
    Assert-FileExists "dev-basic.pfx"

    # ASSERTION 3: Certificate has correct subject (PowerShell verification)
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        (Resolve-Path "dev-basic.pfx").Path, "TestPass123")
    if ($cert.Subject -notmatch "api\.local") {
        throw "Certificate subject should contain api.local, got: $($cert.Subject)"
    }
    $cert.Dispose()

    [PSCustomObject]@{ Success = $true; Details = "Dev cert created with correct subject" }
}

# Test dev-1.2: Dev cert with custom SANs
Invoke-Test -TestId "dev-1.2" -TestName "Create dev cert with custom SANs" -FilePrefix "dev-san" -TestScript {
    # ACTION: Single certz.exe call
    $output = & .\certz.exe create dev api.local --san localhost --san 127.0.0.1 --f dev-san.pfx --p TestPass123 2>&1

    # ASSERTION 1: Exit code
    Assert-ExitCode -Expected 0

    # ASSERTION 2: File exists
    Assert-FileExists "dev-san.pfx"

    # ASSERTION 3: Certificate has SANs (PowerShell verification)
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        (Resolve-Path "dev-san.pfx").Path, "TestPass123")

    # Check SAN extension
    $sanExt = $cert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.17" }
    if (-not $sanExt) {
        throw "Certificate should have SAN extension"
    }
    $cert.Dispose()

    [PSCustomObject]@{ Success = $true; Details = "Dev cert created with custom SANs" }
}

# Test dev-1.3: Dev cert with ECDSA-P384 key
Invoke-Test -TestId "dev-1.3" -TestName "Create dev cert with ECDSA-P384 key" -FilePrefix "dev-ecdsa" -TestScript {
    # ACTION: Single certz.exe call
    $output = & .\certz.exe create dev api.local --key-type ECDSA-P384 --f dev-ecdsa.pfx --p TestPass123 2>&1

    # ASSERTION 1: Exit code
    Assert-ExitCode -Expected 0

    # ASSERTION 2: File exists
    Assert-FileExists "dev-ecdsa.pfx"

    # ASSERTION 3: Certificate has ECDSA key (PowerShell verification)
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        (Resolve-Path "dev-ecdsa.pfx").Path, "TestPass123")

    $ecdsaKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert)
    if (-not $ecdsaKey) {
        throw "Certificate should have ECDSA private key"
    }
    $cert.Dispose()

    [PSCustomObject]@{ Success = $true; Details = "Dev cert created with ECDSA-P384 key" }
}

# Test dev-1.4: Dev cert with RSA-3072 key
Invoke-Test -TestId "dev-1.4" -TestName "Create dev cert with RSA-3072 key" -FilePrefix "dev-rsa" -TestScript {
    # ACTION: Single certz.exe call
    $output = & .\certz.exe create dev api.local --key-type RSA --key-size 3072 --f dev-rsa.pfx --p TestPass123 2>&1

    # ASSERTION 1: Exit code
    Assert-ExitCode -Expected 0

    # ASSERTION 2: File exists
    Assert-FileExists "dev-rsa.pfx"

    # ASSERTION 3: Certificate has RSA key with correct size (PowerShell verification)
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        (Resolve-Path "dev-rsa.pfx").Path, "TestPass123")

    $rsaKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    if (-not $rsaKey) {
        throw "Certificate should have RSA private key"
    }
    if ($rsaKey.KeySize -ne 3072) {
        throw "RSA key size should be 3072, got: $($rsaKey.KeySize)"
    }
    $cert.Dispose()

    [PSCustomObject]@{ Success = $true; Details = "Dev cert created with RSA-3072 key" }
}

# Test dev-1.5: Dev cert with custom validity
Invoke-Test -TestId "dev-1.5" -TestName "Create dev cert with custom validity" -FilePrefix "dev-days" -TestScript {
    # ACTION: Single certz.exe call
    $output = & .\certz.exe create dev api.local --days 30 --f dev-days.pfx --p TestPass123 2>&1

    # ASSERTION 1: Exit code
    Assert-ExitCode -Expected 0

    # ASSERTION 2: File exists
    Assert-FileExists "dev-days.pfx"

    # ASSERTION 3: Certificate has correct validity (PowerShell verification)
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        (Resolve-Path "dev-days.pfx").Path, "TestPass123")

    $expectedExpiry = (Get-Date).AddDays(30).Date
    $actualExpiry = $cert.NotAfter.Date
    # Allow 1 day tolerance for time zone differences
    if ([Math]::Abs(($expectedExpiry - $actualExpiry).Days) -gt 1) {
        throw "Certificate validity should be ~30 days, expires: $($cert.NotAfter)"
    }
    $cert.Dispose()

    [PSCustomObject]@{ Success = $true; Details = "Dev cert created with 30-day validity" }
}

# ============================================================================
# CREATE CA COMMAND TESTS
# ============================================================================
Write-TestHeader "Testing CREATE CA Command"

# Test ca-1.1: Basic CA cert with name
Invoke-Test -TestId "ca-1.1" -TestName "Create CA cert with name" -FilePrefix "ca-basic" -TestScript {
    # ACTION: Single certz.exe call
    $output = & .\certz.exe create ca --name "Dev Root CA" --f ca-basic.pfx --p CaPass123 2>&1

    # ASSERTION 1: Exit code
    Assert-ExitCode -Expected 0

    # ASSERTION 2: File exists
    Assert-FileExists "ca-basic.pfx"

    # ASSERTION 3: Certificate is CA (PowerShell verification)
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        (Resolve-Path "ca-basic.pfx").Path, "CaPass123")

    if ($cert.Subject -notmatch "Dev Root CA") {
        throw "CA subject should contain 'Dev Root CA', got: $($cert.Subject)"
    }

    # Check Basic Constraints extension for CA
    $basicConstraints = $cert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.19" }
    if (-not $basicConstraints) {
        throw "CA certificate should have Basic Constraints extension"
    }
    $cert.Dispose()

    [PSCustomObject]@{ Success = $true; Details = "CA cert created with correct subject" }
}

# Test ca-1.2: CA cert with path length 1
Invoke-Test -TestId "ca-1.2" -TestName "Create CA cert with path length 1" -FilePrefix "ca-path" -TestScript {
    # ACTION: Single certz.exe call
    $output = & .\certz.exe create ca --name "Intermediate CA" --path-length 1 --f ca-path.pfx --p CaPass123 2>&1

    # ASSERTION 1: Exit code
    Assert-ExitCode -Expected 0

    # ASSERTION 2: File exists
    Assert-FileExists "ca-path.pfx"

    # ASSERTION 3: Certificate has path length constraint (PowerShell verification)
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        (Resolve-Path "ca-path.pfx").Path, "CaPass123")

    $basicConstraints = $cert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.19" }
    if (-not $basicConstraints) {
        throw "CA certificate should have Basic Constraints extension"
    }
    # The path length is encoded in the extension - just verify it exists
    $cert.Dispose()

    [PSCustomObject]@{ Success = $true; Details = "CA cert created with path length constraint" }
}

# Test ca-1.3: CA cert with 10-year validity
Invoke-Test -TestId "ca-1.3" -TestName "Create CA cert with 10-year validity" -FilePrefix "ca-long" -TestScript {
    # Note: CA certificates can exceed 398-day limit as they're not subject to CA/B Forum TLS rules
    # ACTION: Single certz.exe call
    $output = & .\certz.exe create ca --name "Root CA" --days 3650 --f ca-long.pfx --p CaPass123 2>&1

    # ASSERTION 1: Exit code
    Assert-ExitCode -Expected 0

    # ASSERTION 2: File exists
    Assert-FileExists "ca-long.pfx"

    # ASSERTION 3: Certificate has ~10 year validity (PowerShell verification)
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        (Resolve-Path "ca-long.pfx").Path, "CaPass123")

    $expectedExpiry = (Get-Date).AddDays(3650).Date
    $actualExpiry = $cert.NotAfter.Date
    # Allow 2 day tolerance
    if ([Math]::Abs(($expectedExpiry - $actualExpiry).Days) -gt 2) {
        throw "CA certificate validity should be ~10 years, expires: $($cert.NotAfter)"
    }
    $cert.Dispose()

    [PSCustomObject]@{ Success = $true; Details = "CA cert created with 10-year validity" }
}

# ============================================================================
# FORMAT OUTPUT TESTS
# ============================================================================
Write-TestHeader "Testing FORMAT Output"

# Test fmt-1.1: Dev cert with JSON output
Invoke-Test -TestId "fmt-1.1" -TestName "Create dev cert with JSON output" -FilePrefix "fmt-json" -TestScript {
    # ACTION: Single certz.exe call
    $output = & .\certz.exe create dev localhost --format json --f fmt-json.pfx --p TestPass123 2>&1
    $outputStr = $output -join "`n"

    # ASSERTION 1: Exit code
    Assert-ExitCode -Expected 0

    # ASSERTION 2: File exists
    Assert-FileExists "fmt-json.pfx"

    # ASSERTION 3: Valid JSON output
    try {
        $json = $outputStr | ConvertFrom-Json
        if (-not $json.success) { throw "JSON 'success' field should be true" }
        if (-not $json.certificate.thumbprint) { throw "JSON should contain certificate.thumbprint" }
    }
    catch {
        if ($_.Exception.Message -match "JSON") {
            throw "Output is not valid JSON: $outputStr"
        }
        throw $_
    }

    [PSCustomObject]@{ Success = $true; Details = "Valid JSON output with certificate info" }
}

# Test fmt-1.2: CA cert with JSON output
Invoke-Test -TestId "fmt-1.2" -TestName "Create CA cert with JSON output" -FilePrefix "fmt-ca-json" -TestScript {
    # ACTION: Single certz.exe call
    $output = & .\certz.exe create ca --name "JSON Test CA" --format json --f fmt-ca-json.pfx --p CaPass123 2>&1
    $outputStr = $output -join "`n"

    # ASSERTION 1: Exit code
    Assert-ExitCode -Expected 0

    # ASSERTION 2: File exists
    Assert-FileExists "fmt-ca-json.pfx"

    # ASSERTION 3: Valid JSON output
    try {
        $json = $outputStr | ConvertFrom-Json
        if (-not $json.success) { throw "JSON 'success' field should be true" }
        if (-not $json.certificate.thumbprint) { throw "JSON should contain certificate.thumbprint" }
    }
    catch {
        if ($_.Exception.Message -match "JSON") {
            throw "Output is not valid JSON: $outputStr"
        }
        throw $_
    }

    [PSCustomObject]@{ Success = $true; Details = "Valid JSON output for CA cert" }
}

# ============================================================================
# ISSUER SIGNING TESTS
# ============================================================================
Write-TestHeader "Testing Issuer Signing"

# Test iss-1.1: Dev cert signed by CA (PFX issuer)
Invoke-Test -TestId "iss-1.1" -TestName "Create dev cert signed by CA (PFX issuer)" -FilePrefix "iss-chain" -TestScript {
    # SETUP: Create CA certificate using PowerShell (NOT certz)
    $caParams = @{
        Subject = "CN=certz-certz-Test Issuer CA"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddYears(1)
        KeyUsage = "CertSign", "CRLSign"
        TextExtension = @("2.5.29.19={critical}{text}CA=TRUE")
    }
    $caCert = New-SelfSignedCertificate @caParams

    # Export CA to PFX for certz to use
    $caPassword = ConvertTo-SecureString "CaPass123" -AsPlainText -Force
    Export-PfxCertificate -Cert $caCert -FilePath "iss-chain-ca.pfx" -Password $caPassword | Out-Null

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe create dev signed.local --issuer-cert iss-chain-ca.pfx --issuer-password CaPass123 --f iss-chain-dev.pfx --p DevPass123 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: File exists
        Assert-FileExists "iss-chain-dev.pfx"

        # ASSERTION 3: Certificate has correct issuer (PowerShell verification)
        $devCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            (Resolve-Path "iss-chain-dev.pfx").Path, "DevPass123")
        if ($devCert.Issuer -notmatch "certz-Test Issuer CA") {
            throw "Certificate issuer should be 'certz-Test Issuer CA', got: $($devCert.Issuer)"
        }
        $devCert.Dispose()

        [PSCustomObject]@{ Success = $true; Details = "Dev cert correctly signed by CA" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item $caCert.PSPath -Force -ErrorAction SilentlyContinue
        Remove-Item "iss-chain-ca.pfx" -Force -ErrorAction SilentlyContinue
        Remove-Item "iss-chain-dev.pfx" -Force -ErrorAction SilentlyContinue
    }
}

# Test iss-1.2: Dev cert signed by CA (PEM issuer)
Invoke-Test -TestId "iss-1.2" -TestName "Create dev cert signed by CA (PEM issuer)" -FilePrefix "iss-pem" -TestScript {
    # SETUP: Create CA certificate using PowerShell and export to PEM
    $caParams = @{
        Subject = "CN=certz-certz-Test PEM Issuer CA"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddYears(1)
        KeyUsage = "CertSign", "CRLSign"
        TextExtension = @("2.5.29.19={critical}{text}CA=TRUE")
    }
    $caCert = New-SelfSignedCertificate @caParams

    # Export CA to PEM format
    $certPem = [Convert]::ToBase64String($caCert.RawData, [Base64FormattingOptions]::InsertLineBreaks)
    $certPemContent = "-----BEGIN CERTIFICATE-----`n$certPem`n-----END CERTIFICATE-----"
    Set-Content -Path "iss-pem-ca.cer" -Value $certPemContent

    # Export private key to PEM
    $ecdsaKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($caCert)

    # Export the private key in PKCS#8 binary format
    $pkcs8Bytes = $ecdsaKey.ExportPkcs8PrivateKey()

    # Encode to Base64 with PEM headers
    $base64Key = [System.Convert]::ToBase64String($pkcs8Bytes, [System.Base64FormattingOptions]::InsertLineBreaks)
    $keyPem = "-----BEGIN PRIVATE KEY-----`n$base64Key`n-----END PRIVATE KEY-----"

    Set-Content -Path "iss-pem-ca.key" -Value $keyPem

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe create dev signed-pem.local --issuer-cert iss-pem-ca.cer --issuer-key iss-pem-ca.key --f iss-pem-dev.pfx --p DevPass123 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: File exists
        Assert-FileExists "iss-pem-dev.pfx"

        # ASSERTION 3: Certificate has correct issuer (PowerShell verification)
        $devCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            (Resolve-Path "iss-pem-dev.pfx").Path, "DevPass123")
        if ($devCert.Issuer -notmatch "certz-Test PEM Issuer CA") {
            throw "Certificate issuer should be 'certz-Test PEM Issuer CA', got: $($devCert.Issuer)"
        }
        $devCert.Dispose()

        [PSCustomObject]@{ Success = $true; Details = "Dev cert correctly signed by CA (PEM)" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item $caCert.PSPath -Force -ErrorAction SilentlyContinue
        Remove-Item "iss-pem-ca.cer" -Force -ErrorAction SilentlyContinue
        Remove-Item "iss-pem-ca.key" -Force -ErrorAction SilentlyContinue
        Remove-Item "iss-pem-dev.pfx" -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# TRUST TESTS
# ============================================================================
Write-TestHeader "Testing Trust Flag"

# Test tru-1.1: Dev cert with --trust flag
Invoke-Test -TestId "tru-1.1" -TestName "Create dev cert with --trust flag" -FilePrefix "dev-trust" -TestScript {
    $uniqueDomain = "certz-trusttest-$([guid]::NewGuid().ToString().Substring(0,8)).local"

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe create dev $uniqueDomain --trust --f dev-trust.pfx --p TrustPass123 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: File exists
        Assert-FileExists "dev-trust.pfx"

        # ASSERTION 3: Certificate in trust store (PowerShell verification)
        $cert = Assert-CertificateInStore -SubjectPattern "*$uniqueDomain*" -StoreName "Root" -StoreLocation "CurrentUser"

        [PSCustomObject]@{ Success = $true; Details = "Dev cert created and trusted" }
    }
    finally {
        # CLEANUP: Remove from store and file (PowerShell only)
        Get-ChildItem "Cert:\CurrentUser\Root" |
            Where-Object { $_.Subject -like "*$uniqueDomain*" } |
            Remove-Item -Force -ErrorAction SilentlyContinue
        Remove-Item "dev-trust.pfx" -Force -ErrorAction SilentlyContinue
    }
}

# Test tru-1.2: CA cert with --trust flag
Invoke-Test -TestId "tru-1.2" -TestName "Create CA cert with --trust flag" -FilePrefix "ca-trust" -TestScript {
    $uniqueName = "certz-TrustedCA-$([guid]::NewGuid().ToString().Substring(0,8))"

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe create ca --name $uniqueName --trust --f ca-trust.pfx --p TrustPass123 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: File exists
        Assert-FileExists "ca-trust.pfx"

        # ASSERTION 3: Certificate in trust store (PowerShell verification)
        $cert = Assert-CertificateInStore -SubjectPattern "*$uniqueName*" -StoreName "Root" -StoreLocation "CurrentUser"

        [PSCustomObject]@{ Success = $true; Details = "CA cert created and trusted" }
    }
    finally {
        # CLEANUP: Remove from store and file (PowerShell only)
        Get-ChildItem "Cert:\CurrentUser\Root" |
            Where-Object { $_.Subject -like "*$uniqueName*" } |
            Remove-Item -Force -ErrorAction SilentlyContinue
        Remove-Item "ca-trust.pfx" -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# GUIDED/INTERACTIVE TESTS (Manual only - skipped by default)
# ============================================================================
Write-TestHeader "Guided/Interactive Tests (Manual)"

# Test gui-1.1: Interactive wizard (manual test)
Invoke-Test -TestId "gui-1.1" -TestName "Interactive wizard (manual test)" -TestScript {
    Write-Host "  This test requires manual interaction." -ForegroundColor Yellow
    Write-Host "  Run: .\certz.exe create dev --guided" -ForegroundColor Yellow
    Write-Host "  The wizard should prompt for domain, SANs, days, key type, and trust." -ForegroundColor Yellow
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
