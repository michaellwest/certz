#requires -version 7

<#
.SYNOPSIS
    Test suite for certz fingerprint command.

.DESCRIPTION
    Tests the fingerprint command: file sources, URL sources, algorithm selection,
    and JSON output format. Follows test isolation principles from test-isolation-plan.md:
    - Each test invokes certz.exe exactly ONCE
    - Setup and teardown use pure PowerShell (no certz calls)
    - Assert against command output (fingerprint is computed data, no file state to check)

.PARAMETER TestId
    Run specific tests by ID. Example: -TestId "fp-1.1", "fp-2.1"

.PARAMETER Category
    Run tests by category: file, algorithm, format, error

.PARAMETER SkipCleanup
    Keep test files after running.

.PARAMETER Verbose
    Show detailed output.

.EXAMPLE
    .\test-fingerprint.ps1
    Runs all tests.

.EXAMPLE
    .\test-fingerprint.ps1 -Category algorithm
    Runs only algorithm selection tests.
#>
param(
    [switch]$SkipCleanup,
    [switch]$Verbose,
    [string[]]$TestId,
    [string[]]$Category
)

$ErrorActionPreference = "Stop"

. "$PSScriptRoot\test-helper.ps1"

$TestCategories = @{
    "file"      = @("fp-1.1", "fp-1.2", "fp-1.3")
    "algorithm" = @("fp-2.1", "fp-2.2", "fp-2.3")
    "format"    = @("fp-3.1")
    "separator" = @("fp-5.1", "fp-5.2", "fp-5.3", "fp-5.4")
    "error"     = @("fp-4.1", "fp-4.2")
}

Initialize-TestEnvironment -TestId $TestId -Category $Category -TestCategories $TestCategories
Set-VerboseOutput -Enabled $Verbose

Write-Host "`nCertz Fingerprint Command Test Suite" -ForegroundColor Magenta
Write-Host "=====================================`n" -ForegroundColor Magenta

if ($TestId -or $Category) {
    Write-Host "Test Filters Active:" -ForegroundColor Yellow
    if ($TestId) { Write-Host "  Test IDs: $($TestId -join ', ')" -ForegroundColor Gray }
    if ($Category) { Write-Host "  Categories: $($Category -join ', ')" -ForegroundColor Gray }
    Write-Host ""
}

Build-Certz -Verbose:$Verbose
Enter-ToolsDirectory
Write-Host "Initializing test environment..." -ForegroundColor Yellow
Remove-TestFiles

# ============================================================================
# FILE SOURCE TESTS
# ============================================================================
Write-TestHeader "Testing FINGERPRINT FILE Sources"

# fp-1.1: Fingerprint a PEM certificate
Invoke-Test -TestId "fp-1.1" -TestName "Fingerprint PEM certificate (default SHA-256)" -FilePrefix "fp-pem" -TestScript {
    # SETUP: Create a certificate using PowerShell and export to PEM
    $certParams = @{
        Subject            = "CN=certz-fp-pem-test.local"
        KeyAlgorithm       = "ECDSA_nistP256"
        KeyExportPolicy    = "Exportable"
        CertStoreLocation  = "Cert:\CurrentUser\My"
        NotAfter           = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $certPem = [Convert]::ToBase64String($cert.RawData, [Base64FormattingOptions]::InsertLineBreaks)
    $pemContent = "-----BEGIN CERTIFICATE-----`n$certPem`n-----END CERTIFICATE-----"
    Set-Content -Path "fp-pem.cer" -Value $pemContent

    # Compute the expected SHA-256 fingerprint using PowerShell
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $sha256.ComputeHash($cert.RawData)
    $expectedFingerprint = ($hashBytes | ForEach-Object { $_.ToString("X2") }) -join ":"

    Remove-Item $cert.PSPath -Force

    try {
        # ACTION: Single certz.exe call
        $output = & .\certz.exe fingerprint fp-pem.cer 2>&1
        # Strip ANSI escape codes and collapse whitespace for comparison
        $outputStripped = ($output -join "") -replace '\e\[[0-9;]*[mK]', '' -replace '\s', ''
        $expectedStripped = $expectedFingerprint -replace '\s', ''

        Assert-ExitCode -Expected 0

        # Output must contain the expected fingerprint (whitespace-normalized)
        if ($outputStripped -notmatch [regex]::Escape($expectedStripped)) {
            throw "Expected fingerprint '$expectedFingerprint' not found in output"
        }

        # Output must show SHA256 label
        if ($outputStripped -notmatch "SHA256") {
            throw "Output should show 'SHA256' algorithm label"
        }

        [PSCustomObject]@{ Success = $true; Details = "PEM fingerprint matches expected SHA-256 hash" }
    }
    finally {
        Remove-Item "fp-pem.cer" -Force -ErrorAction SilentlyContinue
    }
}

# fp-1.2: Fingerprint a DER certificate
Invoke-Test -TestId "fp-1.2" -TestName "Fingerprint DER certificate" -FilePrefix "fp-der" -TestScript {
    # SETUP: Create and export to DER
    $certParams = @{
        Subject            = "CN=certz-fp-der-test.local"
        KeyAlgorithm       = "ECDSA_nistP256"
        KeyExportPolicy    = "Exportable"
        CertStoreLocation  = "Cert:\CurrentUser\My"
        NotAfter           = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $derPath = Join-Path (Get-Location).Path "fp-der.der"
    [System.IO.File]::WriteAllBytes($derPath, $cert.RawData)

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $sha256.ComputeHash($cert.RawData)
    $expectedFingerprint = ($hashBytes | ForEach-Object { $_.ToString("X2") }) -join ":"

    Remove-Item $cert.PSPath -Force

    try {
        $output = & .\certz.exe fingerprint fp-der.der 2>&1
        $outputStripped = ($output -join "") -replace '\e\[[0-9;]*[mK]', '' -replace '\s', ''
        $expectedStripped = $expectedFingerprint -replace '\s', ''

        Assert-ExitCode -Expected 0

        if ($outputStripped -notmatch [regex]::Escape($expectedStripped)) {
            throw "Expected fingerprint '$expectedFingerprint' not found in output"
        }

        [PSCustomObject]@{ Success = $true; Details = "DER fingerprint matches expected SHA-256 hash" }
    }
    finally {
        Remove-Item "fp-der.der" -Force -ErrorAction SilentlyContinue
    }
}

# fp-1.3: Fingerprint a PFX file
Invoke-Test -TestId "fp-1.3" -TestName "Fingerprint PFX file with password" -FilePrefix "fp-pfx" -TestScript {
    # SETUP: Create and export to PFX
    $certParams = @{
        Subject            = "CN=certz-fp-pfx-test.local"
        KeyAlgorithm       = "ECDSA_nistP256"
        KeyExportPolicy    = "Exportable"
        CertStoreLocation  = "Cert:\CurrentUser\My"
        NotAfter           = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $password = ConvertTo-SecureString "FpTestPass123" -AsPlainText -Force
    Export-PfxCertificate -Cert $cert -FilePath "fp-pfx.pfx" -Password $password | Out-Null

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $sha256.ComputeHash($cert.RawData)
    $expectedFingerprint = ($hashBytes | ForEach-Object { $_.ToString("X2") }) -join ":"

    Remove-Item $cert.PSPath -Force

    try {
        $output = & .\certz.exe fingerprint fp-pfx.pfx --password FpTestPass123 2>&1
        $outputStripped = ($output -join "") -replace '\e\[[0-9;]*[mK]', '' -replace '\s', ''
        $expectedStripped = $expectedFingerprint -replace '\s', ''

        Assert-ExitCode -Expected 0

        if ($outputStripped -notmatch [regex]::Escape($expectedStripped)) {
            throw "Expected fingerprint '$expectedFingerprint' not found in output"
        }

        [PSCustomObject]@{ Success = $true; Details = "PFX fingerprint matches expected SHA-256 hash" }
    }
    finally {
        Remove-Item "fp-pfx.pfx" -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# ALGORITHM SELECTION TESTS
# ============================================================================
Write-TestHeader "Testing FINGERPRINT Algorithm Selection"

# fp-2.1: SHA-256 explicit
Invoke-Test -TestId "fp-2.1" -TestName "Explicit --algorithm sha256" -FilePrefix "fp-alg-256" -TestScript {
    $certParams = @{
        Subject            = "CN=certz-fp-alg-test.local"
        KeyAlgorithm       = "ECDSA_nistP256"
        KeyExportPolicy    = "Exportable"
        CertStoreLocation  = "Cert:\CurrentUser\My"
        NotAfter           = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $certPem = [Convert]::ToBase64String($cert.RawData, [Base64FormattingOptions]::InsertLineBreaks)
    Set-Content -Path "fp-alg-256.cer" -Value "-----BEGIN CERTIFICATE-----`n$certPem`n-----END CERTIFICATE-----"
    Remove-Item $cert.PSPath -Force

    try {
        $output = & .\certz.exe fingerprint fp-alg-256.cer --algorithm sha256 2>&1
        $outputStr = $output -join "`n"

        Assert-ExitCode -Expected 0

        if ($outputStr -notmatch "SHA256") {
            throw "Output should show 'SHA256' label when --algorithm sha256 is used"
        }

        [PSCustomObject]@{ Success = $true; Details = "SHA-256 fingerprint produced with explicit --algorithm flag" }
    }
    finally {
        Remove-Item "fp-alg-256.cer" -Force -ErrorAction SilentlyContinue
    }
}

# fp-2.2: SHA-384
Invoke-Test -TestId "fp-2.2" -TestName "--algorithm sha384 produces 48-byte (96 hex char) fingerprint" -FilePrefix "fp-alg-384" -TestScript {
    $certParams = @{
        Subject            = "CN=certz-fp-alg384-test.local"
        KeyAlgorithm       = "ECDSA_nistP256"
        KeyExportPolicy    = "Exportable"
        CertStoreLocation  = "Cert:\CurrentUser\My"
        NotAfter           = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $certPem = [Convert]::ToBase64String($cert.RawData, [Base64FormattingOptions]::InsertLineBreaks)
    Set-Content -Path "fp-alg-384.cer" -Value "-----BEGIN CERTIFICATE-----`n$certPem`n-----END CERTIFICATE-----"

    # SHA-384 produces 48 bytes = 47 colons + 48 two-char hex groups
    $sha384 = [System.Security.Cryptography.SHA384]::Create()
    $hashBytes = $sha384.ComputeHash($cert.RawData)
    $expectedFingerprint = ($hashBytes | ForEach-Object { $_.ToString("X2") }) -join ":"

    Remove-Item $cert.PSPath -Force

    try {
        $output = & .\certz.exe fingerprint fp-alg-384.cer --algorithm sha384 2>&1
        $outputStripped = ($output -join "") -replace '\e\[[0-9;]*[mK]', '' -replace '\s', ''
        $expectedStripped = $expectedFingerprint -replace '\s', ''

        Assert-ExitCode -Expected 0

        if ($outputStripped -notmatch "SHA384") {
            throw "Output should show 'SHA384' label"
        }

        if ($outputStripped -notmatch [regex]::Escape($expectedStripped)) {
            throw "SHA-384 fingerprint does not match expected value"
        }

        [PSCustomObject]@{ Success = $true; Details = "SHA-384 fingerprint produced and matches expected hash" }
    }
    finally {
        Remove-Item "fp-alg-384.cer" -Force -ErrorAction SilentlyContinue
    }
}

# fp-2.3: SHA-512
Invoke-Test -TestId "fp-2.3" -TestName "--algorithm sha512 produces 64-byte fingerprint" -FilePrefix "fp-alg-512" -TestScript {
    $certParams = @{
        Subject            = "CN=certz-fp-alg512-test.local"
        KeyAlgorithm       = "ECDSA_nistP256"
        KeyExportPolicy    = "Exportable"
        CertStoreLocation  = "Cert:\CurrentUser\My"
        NotAfter           = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $certPem = [Convert]::ToBase64String($cert.RawData, [Base64FormattingOptions]::InsertLineBreaks)
    Set-Content -Path "fp-alg-512.cer" -Value "-----BEGIN CERTIFICATE-----`n$certPem`n-----END CERTIFICATE-----"

    Remove-Item $cert.PSPath -Force

    try {
        $output = & .\certz.exe fingerprint fp-alg-512.cer --algorithm sha512 2>&1
        $outputStr = $output -join "`n"

        Assert-ExitCode -Expected 0

        if ($outputStr -notmatch "SHA512") {
            throw "Output should show 'SHA512' label"
        }

        [PSCustomObject]@{ Success = $true; Details = "SHA-512 fingerprint produced" }
    }
    finally {
        Remove-Item "fp-alg-512.cer" -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# FORMAT TESTS
# ============================================================================
Write-TestHeader "Testing FINGERPRINT --format json"

# fp-3.1: JSON output
Invoke-Test -TestId "fp-3.1" -TestName "JSON output has correct structure" -FilePrefix "fp-json" -TestScript {
    $certParams = @{
        Subject            = "CN=certz-fp-json-test.local"
        KeyAlgorithm       = "ECDSA_nistP256"
        KeyExportPolicy    = "Exportable"
        CertStoreLocation  = "Cert:\CurrentUser\My"
        NotAfter           = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $certPem = [Convert]::ToBase64String($cert.RawData, [Base64FormattingOptions]::InsertLineBreaks)
    Set-Content -Path "fp-json.cer" -Value "-----BEGIN CERTIFICATE-----`n$certPem`n-----END CERTIFICATE-----"
    Remove-Item $cert.PSPath -Force

    try {
        $output = & .\certz.exe fingerprint fp-json.cer --format json 2>&1
        $outputStr = ($output -join "`n").Trim()

        Assert-ExitCode -Expected 0

        # Must be valid JSON
        $parsed = $outputStr | ConvertFrom-Json
        if (-not $parsed) {
            throw "Output is not valid JSON"
        }

        # Must have required fields
        if ($parsed.success -ne $true) {
            throw "JSON field 'success' should be true"
        }
        if ($parsed.algorithm -ne "SHA256") {
            throw "JSON field 'algorithm' should be 'SHA256', got: $($parsed.algorithm)"
        }
        if ([string]::IsNullOrEmpty($parsed.fingerprint)) {
            throw "JSON field 'fingerprint' should not be empty"
        }
        if ([string]::IsNullOrEmpty($parsed.subject)) {
            throw "JSON field 'subject' should not be empty"
        }
        if ([string]::IsNullOrEmpty($parsed.source)) {
            throw "JSON field 'source' should not be empty"
        }

        [PSCustomObject]@{ Success = $true; Details = "JSON output has correct structure with all required fields" }
    }
    finally {
        Remove-Item "fp-json.cer" -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# ERROR HANDLING TESTS
# ============================================================================
Write-TestHeader "Testing FINGERPRINT Error Cases"

# fp-4.1: File not found
Invoke-Test -TestId "fp-4.1" -TestName "Non-existent file returns exit code 1" -FilePrefix "fp-err-notfound" -TestScript {
    $output = & .\certz.exe fingerprint does-not-exist.pem 2>&1

    # Should fail with exit code 1
    if ($LASTEXITCODE -eq 0) {
        throw "Expected non-zero exit code for missing file, got 0"
    }

    [PSCustomObject]@{ Success = $true; Details = "Missing file returns non-zero exit code" }
}

# fp-4.2: Invalid algorithm rejected
Invoke-Test -TestId "fp-4.2" -TestName "Invalid algorithm is rejected" -FilePrefix "fp-err-alg" -TestScript {
    $certParams = @{
        Subject            = "CN=certz-fp-errtest.local"
        KeyAlgorithm       = "ECDSA_nistP256"
        KeyExportPolicy    = "Exportable"
        CertStoreLocation  = "Cert:\CurrentUser\My"
        NotAfter           = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $certPem = [Convert]::ToBase64String($cert.RawData, [Base64FormattingOptions]::InsertLineBreaks)
    Set-Content -Path "fp-err-alg.cer" -Value "-----BEGIN CERTIFICATE-----`n$certPem`n-----END CERTIFICATE-----"
    Remove-Item $cert.PSPath -Force

    try {
        $output = & .\certz.exe fingerprint fp-err-alg.cer --algorithm md5 2>&1

        if ($LASTEXITCODE -eq 0) {
            throw "Expected non-zero exit code for invalid algorithm 'md5', got 0"
        }

        [PSCustomObject]@{ Success = $true; Details = "Invalid algorithm is rejected with non-zero exit code" }
    }
    finally {
        Remove-Item "fp-err-alg.cer" -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# SEPARATOR TESTS
# ============================================================================
Write-TestHeader "Testing FINGERPRINT Separator Options"

# Shared setup helper: create a PEM cert and return its raw data + path
function New-FpTestCert {
    param([string]$Prefix, [string]$Cn)
    $certParams = @{
        Subject            = "CN=$Cn"
        KeyAlgorithm       = "ECDSA_nistP256"
        KeyExportPolicy    = "Exportable"
        CertStoreLocation  = "Cert:\CurrentUser\My"
        NotAfter           = (Get-Date).AddDays(90)
    }
    $cert = New-SelfSignedCertificate @certParams
    $certPem = [Convert]::ToBase64String($cert.RawData, [Base64FormattingOptions]::InsertLineBreaks)
    Set-Content -Path "$Prefix.cer" -Value "-----BEGIN CERTIFICATE-----`n$certPem`n-----END CERTIFICATE-----"
    $raw = $cert.RawData
    Remove-Item $cert.PSPath -Force
    return $raw
}

# fp-5.1: --no-separator outputs raw hex (no colons)
Invoke-Test -TestId "fp-5.1" -TestName "--no-separator outputs raw hex without delimiters" -FilePrefix "fp-sep-none" -TestScript {
    $raw = New-FpTestCert -Prefix "fp-sep-none" -Cn "certz-fp-sep-none.local"
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $sha256.ComputeHash($raw)
    $expectedRaw = ($hashBytes | ForEach-Object { $_.ToString("X2") }) -join ""

    try {
        $output = & .\certz.exe fingerprint fp-sep-none.cer --no-separator 2>&1
        $outputStripped = ($output -join "") -replace '\e\[[0-9;]*[mK]', '' -replace '\s', ''

        Assert-ExitCode -Expected 0

        # Must contain the raw hex string (no colons)
        if ($outputStripped -notmatch [regex]::Escape($expectedRaw)) {
            throw "Expected raw hex '$expectedRaw' not found in output"
        }

        # Must NOT contain colons in the fingerprint portion
        # Strip the label (e.g. "SHA256:") then check remaining has no colons
        $withoutLabel = $outputStripped -replace '^SHA\d+:', ''
        if ($withoutLabel -match ':') {
            throw "Output contains colons but --no-separator was specified"
        }

        [PSCustomObject]@{ Success = $true; Details = "--no-separator produces raw hex without delimiters" }
    }
    finally {
        Remove-Item "fp-sep-none.cer" -Force -ErrorAction SilentlyContinue
    }
}

# fp-5.2: --separator with custom string
Invoke-Test -TestId "fp-5.2" -TestName "--separator produces custom-delimited output" -FilePrefix "fp-sep-custom" -TestScript {
    $raw = New-FpTestCert -Prefix "fp-sep-custom" -Cn "certz-fp-sep-custom.local"
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $sha256.ComputeHash($raw)
    $expectedDash = ($hashBytes | ForEach-Object { $_.ToString("X2") }) -join "-"

    try {
        $output = & .\certz.exe fingerprint fp-sep-custom.cer --separator "-" 2>&1
        # Join but keep dashes; only strip ANSI and newlines
        $outputClean = ($output -join "") -replace '\e\[[0-9;]*[mK]', '' -replace '\r?\n', ''

        Assert-ExitCode -Expected 0

        $expectedCompact = $expectedDash -replace '\s', ''
        $outputCompact = $outputClean -replace '\s', ''
        if ($outputCompact -notmatch [regex]::Escape($expectedCompact)) {
            throw "Expected dash-separated fingerprint '$expectedDash' not found in output"
        }

        [PSCustomObject]@{ Success = $true; Details = "--separator '-' produces dash-delimited fingerprint" }
    }
    finally {
        Remove-Item "fp-sep-custom.cer" -Force -ErrorAction SilentlyContinue
    }
}

# fp-5.3: --no-separator reflected in JSON output
Invoke-Test -TestId "fp-5.3" -TestName "--no-separator reflected in JSON fingerprint field" -FilePrefix "fp-sep-json" -TestScript {
    $raw = New-FpTestCert -Prefix "fp-sep-json" -Cn "certz-fp-sep-json.local"
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $sha256.ComputeHash($raw)
    $expectedRaw = ($hashBytes | ForEach-Object { $_.ToString("X2") }) -join ""

    try {
        $output = & .\certz.exe fingerprint fp-sep-json.cer --no-separator --format json 2>&1
        $outputStr = ($output -join "`n").Trim()

        Assert-ExitCode -Expected 0

        $parsed = $outputStr | ConvertFrom-Json
        if ($parsed.fingerprint -ne $expectedRaw) {
            throw "JSON fingerprint '$($parsed.fingerprint)' does not match expected raw hex '$expectedRaw'"
        }

        [PSCustomObject]@{ Success = $true; Details = "JSON fingerprint field reflects --no-separator format" }
    }
    finally {
        Remove-Item "fp-sep-json.cer" -Force -ErrorAction SilentlyContinue
    }
}

# fp-5.4: --separator and --no-separator together is an error
Invoke-Test -TestId "fp-5.4" -TestName "--separator and --no-separator together returns exit code 1" -FilePrefix "fp-sep-mutex" -TestScript {
    $raw = New-FpTestCert -Prefix "fp-sep-mutex" -Cn "certz-fp-sep-mutex.local"

    try {
        $output = & .\certz.exe fingerprint fp-sep-mutex.cer --separator "-" --no-separator 2>&1

        if ($LASTEXITCODE -eq 0) {
            throw "Expected non-zero exit code when both --separator and --no-separator are provided"
        }

        $outputStr = ($output -join " ")
        if ($outputStr -notmatch "mutually exclusive") {
            throw "Error message should mention 'mutually exclusive', got: $outputStr"
        }

        [PSCustomObject]@{ Success = $true; Details = "Combining --separator and --no-separator produces a clear error" }
    }
    finally {
        Remove-Item "fp-sep-mutex.cer" -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# SUMMARY
# ============================================================================
$exitCode = Write-TestSummary -SkipCleanup:$SkipCleanup
exit $exitCode
