#requires -version 7

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

# Load shared test helper functions
. "$PSScriptRoot\test-helper.ps1"

# Test categories
$TestCategories = @{
    "pem-to-pfx" = @("cnv-1.1", "cnv-1.2", "cnv-1.3")
    "pfx-to-pem" = @("cnv-2.1", "cnv-2.2", "cnv-2.3")
    "encryption" = @("cnv-3.1", "cnv-3.2")
    "format" = @("fmt-1.1")
    "simplified-pem-der" = @("cnv-4.1", "cnv-4.2")
    "simplified-der-pem" = @("cnv-5.1", "cnv-5.2")
    "simplified-pem-pfx" = @("cnv-6.1", "cnv-6.2")
    "simplified-pfx-pem" = @("cnv-7.1", "cnv-7.2")
    "simplified-pfx-der" = @("cnv-8.1")
    "simplified-der-pfx" = @("cnv-9.1")
    "simplified-errors" = @("cnv-10.1", "cnv-10.2", "cnv-10.3")
}

# Initialize test environment
Initialize-TestEnvironment -TestId $TestId -Category $Category -TestCategories $TestCategories
Set-VerboseOutput -Enabled $Verbose

# Display banner
Write-Host "`nCertz Convert Command Test Suite" -ForegroundColor Magenta
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
        # ACTION: Single certz.exe call
        $output = & .\certz.exe convert cnv-basic.cer --to pfx --key cnv-basic.key --output cnv-basic.pfx --password TestPass123 2>&1
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
        $output = & .\certz.exe convert cnv-passwd.cer --to pfx --key cnv-passwd.key --output cnv-passwd.pfx --password $explicitPassword 2>&1

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
        $output = & .\certz.exe convert cnv-pwdfile.cer --to pfx --key cnv-pwdfile.key --output cnv-pwdfile.pfx --password-file cnv-pwdfile.password.txt 2>&1

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
        $output = & .\certz.exe convert cnv-topem-cert.pfx --to pem --password PfxPass123 --output cnv-topem-cert.pem 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Certificate PEM file exists
        Assert-FileExists "cnv-topem-cert.pem"

        # ASSERTION 3: PEM file contains valid certificate
        $content = Get-Content "cnv-topem-cert.pem" -Raw
        if ($content -notmatch "-----BEGIN CERTIFICATE-----") {
            throw "Output should contain PEM-encoded certificate"
        }

        [PSCustomObject]@{ Success = $true; Details = "PFX to PEM (cert only) successful" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item "cnv-topem-cert.pfx" -Force -ErrorAction SilentlyContinue
        Remove-Item "cnv-topem-cert.pem" -Force -ErrorAction SilentlyContinue
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
        # ACTION: Single certz.exe call (cert and key combined in one PEM output)
        $output = & .\certz.exe convert cnv-topem-both.pfx --to pem --password PfxBothPass123 --output cnv-topem-both.pem 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Combined PEM file exists
        Assert-FileExists "cnv-topem-both.pem"

        # ASSERTION 3: PEM file contains cert and key
        $content = Get-Content "cnv-topem-both.pem" -Raw
        if ($content -notmatch "-----BEGIN CERTIFICATE-----") {
            throw "PEM file should contain PEM-encoded certificate"
        }
        if ($content -notmatch "-----BEGIN.*PRIVATE KEY-----") {
            throw "PEM file should contain PEM-encoded private key (--include-key is true by default)"
        }

        [PSCustomObject]@{ Success = $true; Details = "PFX to PEM (cert+key combined) successful" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item "cnv-topem-both.pfx" -Force -ErrorAction SilentlyContinue
        Remove-Item "cnv-topem-both.pem" -Force -ErrorAction SilentlyContinue
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
        $output = & .\certz.exe convert cnv-nopwd.pfx --to pem --output cnv-nopwd.pem 2>&1
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
        Assert-FileNotExists "cnv-nopwd.pem"

        [PSCustomObject]@{ Success = $true; Details = "Password requirement enforced correctly" }
    }
    finally {
        # CLEANUP: PowerShell only
        Remove-Item "cnv-nopwd.pfx" -Force -ErrorAction SilentlyContinue
        Remove-Item "cnv-nopwd.pem" -Force -ErrorAction SilentlyContinue
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
        $output = & .\certz.exe convert cnv-modern.cer --to pfx --key cnv-modern.key --output cnv-modern.pfx --password ModernPass123 --pfx-encryption modern 2>&1

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
        $output = & .\certz.exe convert cnv-legacy.cer --to pfx --key cnv-legacy.key --output cnv-legacy.pfx --password LegacyPass123 --pfx-encryption legacy 2>&1

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
        $output = & .\certz.exe convert fmt-json.cer --to pfx --key fmt-json.key --output fmt-json.pfx --password JsonPass123 --format json 2>&1
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
# SIMPLIFIED INTERFACE: PEM TO DER
# ============================================================================
Write-TestHeader "Testing Simplified Interface: PEM to DER"

# Test cnv-4.1: PEM to DER conversion
Invoke-Test -TestId "cnv-4.1" -TestName "Convert PEM to DER (simplified)" -FilePrefix "cnv-pem-der" -TestScript {
    $guid = [guid]::NewGuid().ToString().Substring(0,8)

    # SETUP: Create a test certificate and export to PEM using PowerShell
    $certParams = @{
        Subject = "CN=certz-pem-der-$guid"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams

    # Export certificate to PEM format
    $certPem = [Convert]::ToBase64String($cert.RawData, [Base64FormattingOptions]::InsertLineBreaks)
    $certPemContent = "-----BEGIN CERTIFICATE-----`n$certPem`n-----END CERTIFICATE-----"
    Set-Content -Path "cnv-pem-der.pem" -Value $certPemContent

    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call using simplified interface
        $output = & .\certz.exe convert cnv-pem-der.pem --to der 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: DER file exists
        Assert-FileExists "cnv-pem-der.der"

        # ASSERTION 3: DER file is binary (starts with ASN.1 SEQUENCE tag 0x30)
        $bytes = [System.IO.File]::ReadAllBytes("cnv-pem-der.der")
        if ($bytes[0] -ne 0x30) {
            throw "Output is not valid DER format (expected ASN.1 SEQUENCE tag)"
        }

        [PSCustomObject]@{ Success = $true; Details = "PEM to DER conversion successful" }
    }
    finally {
        Remove-Item "cnv-pem-der.pem" -Force -ErrorAction SilentlyContinue
        Remove-Item "cnv-pem-der.der" -Force -ErrorAction SilentlyContinue
    }
}

# Test cnv-4.2: PEM to DER with custom output path
Invoke-Test -TestId "cnv-4.2" -TestName "Convert PEM to DER with custom output path" -FilePrefix "cnv-pem-der-out" -TestScript {
    $guid = [guid]::NewGuid().ToString().Substring(0,8)

    # SETUP
    $certParams = @{
        Subject = "CN=certz-pem-der-out-$guid"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams

    $certPem = [Convert]::ToBase64String($cert.RawData, [Base64FormattingOptions]::InsertLineBreaks)
    $certPemContent = "-----BEGIN CERTIFICATE-----`n$certPem`n-----END CERTIFICATE-----"
    Set-Content -Path "cnv-pem-der-out.pem" -Value $certPemContent

    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Custom output path
        $output = & .\certz.exe convert cnv-pem-der-out.pem --to der --output custom-output.der 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Custom output file exists
        Assert-FileExists "custom-output.der"

        [PSCustomObject]@{ Success = $true; Details = "Custom output path works" }
    }
    finally {
        Remove-Item "cnv-pem-der-out.pem" -Force -ErrorAction SilentlyContinue
        Remove-Item "custom-output.der" -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# SIMPLIFIED INTERFACE: DER TO PEM
# ============================================================================
Write-TestHeader "Testing Simplified Interface: DER to PEM"

# Test cnv-5.1: DER to PEM conversion
Invoke-Test -TestId "cnv-5.1" -TestName "Convert DER to PEM (simplified)" -FilePrefix "cnv-der-pem" -TestScript {
    $guid = [guid]::NewGuid().ToString().Substring(0,8)

    # SETUP: Create a DER file
    $certParams = @{
        Subject = "CN=certz-der-pem-$guid"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    [System.IO.File]::WriteAllBytes("cnv-der-pem.der", $cert.RawData)
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe convert cnv-der-pem.der --to pem 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: PEM file exists
        Assert-FileExists "cnv-der-pem.pem"

        # ASSERTION 3: PEM file contains correct headers
        $content = Get-Content "cnv-der-pem.pem" -Raw
        if ($content -notmatch "-----BEGIN CERTIFICATE-----") {
            throw "Output should contain PEM headers"
        }

        [PSCustomObject]@{ Success = $true; Details = "DER to PEM conversion successful" }
    }
    finally {
        Remove-Item "cnv-der-pem.der" -Force -ErrorAction SilentlyContinue
        Remove-Item "cnv-der-pem.pem" -Force -ErrorAction SilentlyContinue
    }
}

# Test cnv-5.2: DER to PEM with JSON output
Invoke-Test -TestId "cnv-5.2" -TestName "Convert DER to PEM with JSON output" -FilePrefix "cnv-der-pem-json" -TestScript {
    $guid = [guid]::NewGuid().ToString().Substring(0,8)

    # SETUP
    $certParams = @{
        Subject = "CN=certz-der-pem-json-$guid"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    [System.IO.File]::WriteAllBytes("cnv-der-pem-json.der", $cert.RawData)
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION
        $output = & .\certz.exe convert cnv-der-pem-json.der --to pem --format json 2>&1
        $outputStr = $output -join "`n"

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: Valid JSON
        $json = $outputStr | ConvertFrom-Json
        if (-not $json.success) { throw "JSON success should be true" }
        if ($json.outputFormat -ne "PEM") { throw "outputFormat should be PEM" }

        [PSCustomObject]@{ Success = $true; Details = "JSON output correct with outputFormat=PEM" }
    }
    finally {
        Remove-Item "cnv-der-pem-json.der" -Force -ErrorAction SilentlyContinue
        Remove-Item "cnv-der-pem-json.pem" -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# SIMPLIFIED INTERFACE: PEM TO PFX
# ============================================================================
Write-TestHeader "Testing Simplified Interface: PEM to PFX"

# Test cnv-6.1: PEM to PFX with explicit key
Invoke-Test -TestId "cnv-6.1" -TestName "Convert PEM to PFX with explicit key (simplified)" -FilePrefix "cnv-pem-pfx" -TestScript {
    $guid = [guid]::NewGuid().ToString().Substring(0,8)

    # SETUP
    $certParams = @{
        Subject = "CN=certz-pem-pfx-$guid"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams

    $certPem = [Convert]::ToBase64String($cert.RawData, [Base64FormattingOptions]::InsertLineBreaks)
    Set-Content -Path "cnv-pem-pfx.pem" -Value "-----BEGIN CERTIFICATE-----`n$certPem`n-----END CERTIFICATE-----"

    $ecdsaKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert)
    $pkcs8Bytes = $ecdsaKey.ExportPkcs8PrivateKey()
    $base64Key = [System.Convert]::ToBase64String($pkcs8Bytes, [System.Base64FormattingOptions]::InsertLineBreaks)
    Set-Content -Path "cnv-pem-pfx.key" -Value "-----BEGIN PRIVATE KEY-----`n$base64Key`n-----END PRIVATE KEY-----"

    Remove-Item $cert.PSPath -Force

    try {
        # ACTION
        $output = & .\certz.exe convert cnv-pem-pfx.pem --to pfx --key cnv-pem-pfx.key --password TestSimple123 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: PFX file exists
        Assert-FileExists "cnv-pem-pfx.pfx"

        # ASSERTION 3: PFX can be loaded
        $loadedCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            (Resolve-Path "cnv-pem-pfx.pfx").Path, "TestSimple123")
        if (-not $loadedCert.HasPrivateKey) {
            throw "PFX should have private key"
        }
        $loadedCert.Dispose()

        [PSCustomObject]@{ Success = $true; Details = "Simplified PEM to PFX with explicit key" }
    }
    finally {
        Remove-Item "cnv-pem-pfx.pem" -Force -ErrorAction SilentlyContinue
        Remove-Item "cnv-pem-pfx.key" -Force -ErrorAction SilentlyContinue
        Remove-Item "cnv-pem-pfx.pfx" -Force -ErrorAction SilentlyContinue
    }
}

# Test cnv-6.2: PEM to PFX with auto-discovered key
Invoke-Test -TestId "cnv-6.2" -TestName "Convert PEM to PFX with auto-discovered key" -FilePrefix "cnv-pem-pfx-auto" -TestScript {
    $guid = [guid]::NewGuid().ToString().Substring(0,8)

    # SETUP
    $certParams = @{
        Subject = "CN=certz-pem-pfx-auto-$guid"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams

    $certPem = [Convert]::ToBase64String($cert.RawData, [Base64FormattingOptions]::InsertLineBreaks)
    Set-Content -Path "cnv-pem-pfx-auto.pem" -Value "-----BEGIN CERTIFICATE-----`n$certPem`n-----END CERTIFICATE-----"

    $ecdsaKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert)
    $pkcs8Bytes = $ecdsaKey.ExportPkcs8PrivateKey()
    $base64Key = [System.Convert]::ToBase64String($pkcs8Bytes, [System.Base64FormattingOptions]::InsertLineBreaks)
    # Use .key extension for auto-discovery
    Set-Content -Path "cnv-pem-pfx-auto.key" -Value "-----BEGIN PRIVATE KEY-----`n$base64Key`n-----END PRIVATE KEY-----"

    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: No --key specified, should auto-discover cnv-pem-pfx-auto.key
        $output = & .\certz.exe convert cnv-pem-pfx-auto.pem --to pfx --password AutoPass123 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: PFX file exists
        Assert-FileExists "cnv-pem-pfx-auto.pfx"

        [PSCustomObject]@{ Success = $true; Details = "Key auto-discovery works" }
    }
    finally {
        Remove-Item "cnv-pem-pfx-auto.pem" -Force -ErrorAction SilentlyContinue
        Remove-Item "cnv-pem-pfx-auto.key" -Force -ErrorAction SilentlyContinue
        Remove-Item "cnv-pem-pfx-auto.pfx" -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# SIMPLIFIED INTERFACE: PFX TO PEM
# ============================================================================
Write-TestHeader "Testing Simplified Interface: PFX to PEM"

# Test cnv-7.1: PFX to PEM (simplified)
Invoke-Test -TestId "cnv-7.1" -TestName "Convert PFX to PEM (simplified)" -FilePrefix "cnv-pfx-pem" -TestScript {
    $guid = [guid]::NewGuid().ToString().Substring(0,8)

    # SETUP
    $certParams = @{
        Subject = "CN=certz-pfx-pem-$guid"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $password = ConvertTo-SecureString "SimplePfx123" -AsPlainText -Force
    Export-PfxCertificate -Cert $cert -FilePath "cnv-pfx-pem.pfx" -Password $password | Out-Null
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION
        $output = & .\certz.exe convert cnv-pfx-pem.pfx --to pem --password SimplePfx123 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: PEM file exists
        Assert-FileExists "cnv-pfx-pem.pem"

        # ASSERTION 3: Key file also created (PFX has private key)
        Assert-FileExists "cnv-pfx-pem.key"

        [PSCustomObject]@{ Success = $true; Details = "Simplified PFX to PEM conversion" }
    }
    finally {
        Remove-Item "cnv-pfx-pem.pfx" -Force -ErrorAction SilentlyContinue
        Remove-Item "cnv-pfx-pem.pem" -Force -ErrorAction SilentlyContinue
        Remove-Item "cnv-pfx-pem.key" -Force -ErrorAction SilentlyContinue
    }
}

# Test cnv-7.2: PFX to PEM without including key
Invoke-Test -TestId "cnv-7.2" -TestName "Convert PFX to PEM without key" -FilePrefix "cnv-pfx-pem-nokey" -TestScript {
    $guid = [guid]::NewGuid().ToString().Substring(0,8)

    # SETUP
    $certParams = @{
        Subject = "CN=certz-pfx-pem-nokey-$guid"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $password = ConvertTo-SecureString "NoKeyPfx123" -AsPlainText -Force
    Export-PfxCertificate -Cert $cert -FilePath "cnv-pfx-pem-nokey.pfx" -Password $password | Out-Null
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: --include-key false
        $output = & .\certz.exe convert cnv-pfx-pem-nokey.pfx --to pem --password NoKeyPfx123 --include-key:$false 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: PEM file exists
        Assert-FileExists "cnv-pfx-pem-nokey.pem"

        # ASSERTION 3: Key file NOT created
        Assert-FileNotExists "cnv-pfx-pem-nokey.key"

        [PSCustomObject]@{ Success = $true; Details = "Key excluded from output" }
    }
    finally {
        Remove-Item "cnv-pfx-pem-nokey.pfx" -Force -ErrorAction SilentlyContinue
        Remove-Item "cnv-pfx-pem-nokey.pem" -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# SIMPLIFIED INTERFACE: PFX TO DER
# ============================================================================
Write-TestHeader "Testing Simplified Interface: PFX to DER"

# Test cnv-8.1: PFX to DER
Invoke-Test -TestId "cnv-8.1" -TestName "Convert PFX to DER (simplified)" -FilePrefix "cnv-pfx-der" -TestScript {
    $guid = [guid]::NewGuid().ToString().Substring(0,8)

    # SETUP
    $certParams = @{
        Subject = "CN=certz-pfx-der-$guid"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $password = ConvertTo-SecureString "PfxDer123" -AsPlainText -Force
    Export-PfxCertificate -Cert $cert -FilePath "cnv-pfx-der.pfx" -Password $password | Out-Null
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION
        $output = & .\certz.exe convert cnv-pfx-der.pfx --to der --password PfxDer123 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: DER file exists
        Assert-FileExists "cnv-pfx-der.der"

        # ASSERTION 3: DER file is valid binary
        $bytes = [System.IO.File]::ReadAllBytes("cnv-pfx-der.der")
        if ($bytes[0] -ne 0x30) {
            throw "Output is not valid DER format"
        }

        [PSCustomObject]@{ Success = $true; Details = "PFX to DER conversion" }
    }
    finally {
        Remove-Item "cnv-pfx-der.pfx" -Force -ErrorAction SilentlyContinue
        Remove-Item "cnv-pfx-der.der" -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# SIMPLIFIED INTERFACE: DER TO PFX
# ============================================================================
Write-TestHeader "Testing Simplified Interface: DER to PFX"

# Test cnv-9.1: DER to PFX with key file
Invoke-Test -TestId "cnv-9.1" -TestName "Convert DER to PFX with key file" -FilePrefix "cnv-der-pfx" -TestScript {
    $guid = [guid]::NewGuid().ToString().Substring(0,8)

    # SETUP
    $certParams = @{
        Subject = "CN=certz-der-pfx-$guid"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams

    # Export certificate to DER
    [System.IO.File]::WriteAllBytes("cnv-der-pfx.der", $cert.RawData)

    # Export private key to PEM
    $ecdsaKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert)
    $pkcs8Bytes = $ecdsaKey.ExportPkcs8PrivateKey()
    $base64Key = [System.Convert]::ToBase64String($pkcs8Bytes, [System.Base64FormattingOptions]::InsertLineBreaks)
    Set-Content -Path "cnv-der-pfx.key" -Value "-----BEGIN PRIVATE KEY-----`n$base64Key`n-----END PRIVATE KEY-----"

    Remove-Item $cert.PSPath -Force

    try {
        # ACTION
        $output = & .\certz.exe convert cnv-der-pfx.der --to pfx --key cnv-der-pfx.key --password DerPfx123 2>&1

        # ASSERTION 1: Exit code
        Assert-ExitCode -Expected 0

        # ASSERTION 2: PFX file exists
        Assert-FileExists "cnv-der-pfx.pfx"

        # ASSERTION 3: PFX can be loaded
        $loadedCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            (Resolve-Path "cnv-der-pfx.pfx").Path, "DerPfx123")
        if (-not $loadedCert.HasPrivateKey) {
            throw "PFX should have private key"
        }
        $loadedCert.Dispose()

        [PSCustomObject]@{ Success = $true; Details = "DER to PFX with key" }
    }
    finally {
        Remove-Item "cnv-der-pfx.der" -Force -ErrorAction SilentlyContinue
        Remove-Item "cnv-der-pfx.key" -Force -ErrorAction SilentlyContinue
        Remove-Item "cnv-der-pfx.pfx" -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# SIMPLIFIED INTERFACE: ERROR HANDLING
# ============================================================================
Write-TestHeader "Testing Simplified Interface: Error Handling"

# Test cnv-10.1: Same format conversion error
Invoke-Test -TestId "cnv-10.1" -TestName "Error when input and output formats are same" -FilePrefix "cnv-same-format" -TestScript {
    $guid = [guid]::NewGuid().ToString().Substring(0,8)

    # SETUP
    $certParams = @{
        Subject = "CN=certz-same-format-$guid"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $certPem = [Convert]::ToBase64String($cert.RawData, [Base64FormattingOptions]::InsertLineBreaks)
    Set-Content -Path "cnv-same-format.pem" -Value "-----BEGIN CERTIFICATE-----`n$certPem`n-----END CERTIFICATE-----"
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: PEM to PEM should fail
        $output = & .\certz.exe convert cnv-same-format.pem --to pem 2>&1
        $exitCode = $LASTEXITCODE
        $outputStr = $output -join "`n"

        # ASSERTION: Should fail
        if ($exitCode -eq 0) {
            throw "Should have failed for same format"
        }
        if ($outputStr -notmatch "same") {
            throw "Error should mention same format"
        }

        [PSCustomObject]@{ Success = $true; Details = "Same format conversion rejected" }
    }
    finally {
        Remove-Item "cnv-same-format.pem" -Force -ErrorAction SilentlyContinue
    }
}

# Test cnv-10.2: PFX without password error
Invoke-Test -TestId "cnv-10.2" -TestName "Error when PFX password missing" -FilePrefix "cnv-pfx-nopwd" -TestScript {
    $guid = [guid]::NewGuid().ToString().Substring(0,8)

    # SETUP
    $certParams = @{
        Subject = "CN=certz-pfx-nopwd-$guid"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $password = ConvertTo-SecureString "NoPwdTest123" -AsPlainText -Force
    Export-PfxCertificate -Cert $cert -FilePath "cnv-pfx-nopwd.pfx" -Password $password | Out-Null
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: No password
        $output = & .\certz.exe convert cnv-pfx-nopwd.pfx --to pem 2>&1
        $exitCode = $LASTEXITCODE
        $outputStr = $output -join "`n"

        # ASSERTION: Should fail
        if ($exitCode -eq 0) {
            throw "Should have failed without password"
        }
        if ($outputStr -notmatch "password|Password") {
            throw "Error should mention password"
        }

        [PSCustomObject]@{ Success = $true; Details = "Password requirement enforced" }
    }
    finally {
        Remove-Item "cnv-pfx-nopwd.pfx" -Force -ErrorAction SilentlyContinue
    }
}

# Test cnv-10.3: Missing key for PFX output error
Invoke-Test -TestId "cnv-10.3" -TestName "Error when key missing for PFX output" -FilePrefix "cnv-nokey" -TestScript {
    $guid = [guid]::NewGuid().ToString().Substring(0,8)

    # SETUP: Create a PEM cert with no matching key file
    $certParams = @{
        Subject = "CN=certz-nokey-$guid"
        KeyAlgorithm = "ECDSA_nistP256"
        KeyExportPolicy = "Exportable"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $certPem = [Convert]::ToBase64String($cert.RawData, [Base64FormattingOptions]::InsertLineBreaks)
    Set-Content -Path "cnv-nokey-orphan.pem" -Value "-----BEGIN CERTIFICATE-----`n$certPem`n-----END CERTIFICATE-----"
    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: No key file available
        $output = & .\certz.exe convert cnv-nokey-orphan.pem --to pfx 2>&1
        $exitCode = $LASTEXITCODE
        $outputStr = $output -join "`n"

        # ASSERTION: Should fail
        if ($exitCode -eq 0) {
            throw "Should have failed without key"
        }
        if ($outputStr -notmatch "key|Key") {
            throw "Error should mention key"
        }

        [PSCustomObject]@{ Success = $true; Details = "Key requirement enforced" }
    }
    finally {
        Remove-Item "cnv-nokey-orphan.pem" -Force -ErrorAction SilentlyContinue
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
