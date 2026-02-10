#requires -version 7

<#
.SYNOPSIS
    Test suite for certz export command.

.DESCRIPTION
    Tests certificate export functionality from certificate stores and URLs.
    Follows test isolation principles from test-isolation-plan.md.

.PARAMETER TestId
    Run specific tests by ID. Example: -TestId "exp-1.1", "exp-2.1"

.PARAMETER Category
    Run tests by category: store, url, errors, format

.PARAMETER SkipCleanup
    Keep test files after running.

.PARAMETER Verbose
    Show detailed output.

.EXAMPLE
    .\test-export.ps1
    Runs all tests with default settings.

.EXAMPLE
    .\test-export.ps1 -Category store
    Runs only store export tests.

.EXAMPLE
    .\test-export.ps1 -TestId "exp-1.1" -Verbose
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
    "store"  = @("exp-1.1", "exp-1.2", "exp-1.3", "exp-1.4")
    "url"    = @("exp-2.1", "exp-2.2")
    "errors" = @("exp-3.1", "exp-3.2")
    "format" = @("exp-4.1")
}

# Initialize test environment
Initialize-TestEnvironment -TestId $TestId -Category $Category -TestCategories $TestCategories
Set-VerboseOutput -Enabled $Verbose

# Display banner
Write-Host "`nCertz Export Command Test Suite" -ForegroundColor Magenta
Write-Host "==============================`n" -ForegroundColor Magenta

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
Remove-TestFiles "exp-"

# ============================================================================
# STORE EXPORT TESTS
# ============================================================================
Write-TestHeader "Testing Store Export"

# Test exp-1.1: Export from store to PFX
Invoke-Test -TestId "exp-1.1" -TestName "Export from store to PFX" -FilePrefix "exp" -TestScript {
    # SETUP: Create certificate in store using PowerShell (NOT certz)
    $cert = New-SelfSignedCertificate `
        -Subject "CN=exp-store-test.local" `
        -DnsName "exp-store-test.local" `
        -KeyAlgorithm ECDSA_nistP256 `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -NotAfter (Get-Date).AddDays(365) `
        -KeyExportPolicy Exportable
    $thumbprint = $cert.Thumbprint

    try {
        # ACTION: Export from store to PFX (single certz.exe call)
        $output = & .\certz.exe export --thumbprint $thumbprint --file exp-store.pfx --password TestPass123 --storelocation CurrentUser 2>&1
        $exitCode = $LASTEXITCODE

        # ASSERTIONS
        if ($exitCode -ne 0) {
            throw "Expected exit code 0, got $exitCode. Output: $output"
        }

        Assert-FileExists "exp-store.pfx"

        # Verify PFX is loadable with the given password
        $exported = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            (Resolve-Path "exp-store.pfx").Path, "TestPass123")
        if ($exported.Subject -notmatch "exp-store-test\.local") {
            $exported.Dispose()
            throw "Exported cert subject should contain exp-store-test.local, got: $($exported.Subject)"
        }
        $exported.Dispose()

        [PSCustomObject]@{ Success = $true; Details = "Exported from store to PFX successfully" }
    }
    finally {
        # CLEANUP: Remove cert from store
        Remove-Item $cert.PSPath -Force -ErrorAction SilentlyContinue
    }
}

# Test exp-1.2: Export from store to PEM cert+key
Invoke-Test -TestId "exp-1.2" -TestName "Export from store to PEM cert+key" -FilePrefix "exp" -TestScript {
    # SETUP: Create certificate in store using PowerShell (NOT certz)
    $cert = New-SelfSignedCertificate `
        -Subject "CN=exp-pem-test.local" `
        -DnsName "exp-pem-test.local" `
        -KeyAlgorithm ECDSA_nistP256 `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -NotAfter (Get-Date).AddDays(365) `
        -KeyExportPolicy Exportable
    $thumbprint = $cert.Thumbprint

    try {
        # ACTION: Export from store to PEM cert and key (single certz.exe call)
        $output = & .\certz.exe export --thumbprint $thumbprint --cert exp-pem.crt --key exp-pem.key --storelocation CurrentUser 2>&1
        $exitCode = $LASTEXITCODE

        # ASSERTIONS
        if ($exitCode -ne 0) {
            throw "Expected exit code 0, got $exitCode. Output: $output"
        }

        Assert-FileExists "exp-pem.crt"
        Assert-FileExists "exp-pem.key"

        # Verify cert file contains PEM header
        $certContent = Get-Content "exp-pem.crt" -Raw
        if ($certContent -notmatch "BEGIN CERTIFICATE") {
            throw "Cert file should contain PEM header"
        }

        # Verify key file contains PEM header
        $keyContent = Get-Content "exp-pem.key" -Raw
        if ($keyContent -notmatch "BEGIN") {
            throw "Key file should contain PEM header"
        }

        [PSCustomObject]@{ Success = $true; Details = "Exported from store to PEM cert+key" }
    }
    finally {
        # CLEANUP: Remove cert from store
        Remove-Item $cert.PSPath -Force -ErrorAction SilentlyContinue
    }
}

# Test exp-1.3: Export from store with custom password
Invoke-Test -TestId "exp-1.3" -TestName "Export from store with custom password" -FilePrefix "exp" -TestScript {
    # SETUP: Create certificate in store using PowerShell (NOT certz)
    $cert = New-SelfSignedCertificate `
        -Subject "CN=exp-custom-pw.local" `
        -DnsName "exp-custom-pw.local" `
        -KeyAlgorithm ECDSA_nistP256 `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -NotAfter (Get-Date).AddDays(365) `
        -KeyExportPolicy Exportable
    $thumbprint = $cert.Thumbprint

    try {
        # ACTION: Export with custom password (single certz.exe call)
        $output = & .\certz.exe export --thumbprint $thumbprint --file exp-custom-pw.pfx --password CustomPW456 --storelocation CurrentUser 2>&1
        $exitCode = $LASTEXITCODE

        # ASSERTIONS
        if ($exitCode -ne 0) {
            throw "Expected exit code 0, got $exitCode. Output: $output"
        }

        Assert-FileExists "exp-custom-pw.pfx"

        # Verify PFX is loadable with the custom password
        $exported = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            (Resolve-Path "exp-custom-pw.pfx").Path, "CustomPW456")
        if ($exported.Subject -notmatch "exp-custom-pw\.local") {
            $exported.Dispose()
            throw "Subject mismatch"
        }
        $exported.Dispose()

        [PSCustomObject]@{ Success = $true; Details = "Exported with custom password" }
    }
    finally {
        # CLEANUP: Remove cert from store
        Remove-Item $cert.PSPath -Force -ErrorAction SilentlyContinue
    }
}

# Test exp-1.4: Export from store with generated password (JSON output)
Invoke-Test -TestId "exp-1.4" -TestName "Export from store with generated password" -FilePrefix "exp" -TestScript {
    # SETUP: Create certificate in store using PowerShell (NOT certz)
    $cert = New-SelfSignedCertificate `
        -Subject "CN=exp-gen-pw.local" `
        -DnsName "exp-gen-pw.local" `
        -KeyAlgorithm ECDSA_nistP256 `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -NotAfter (Get-Date).AddDays(365) `
        -KeyExportPolicy Exportable
    $thumbprint = $cert.Thumbprint

    try {
        # ACTION: Export without password (should auto-generate) with JSON output (single certz.exe call)
        $output = & .\certz.exe export --thumbprint $thumbprint --file exp-gen-pw.pfx --format json --storelocation CurrentUser 2>&1
        $exitCode = $LASTEXITCODE

        # ASSERTIONS
        if ($exitCode -ne 0) {
            throw "Expected exit code 0, got $exitCode. Output: $output"
        }

        Assert-FileExists "exp-gen-pw.pfx"

        # Parse JSON to verify generated password
        $json = $output | ConvertFrom-Json
        if (-not $json.passwordWasGenerated) {
            throw "Expected passwordWasGenerated=true in JSON output"
        }
        if (-not $json.generatedPassword) {
            throw "Expected generatedPassword in JSON output"
        }

        [PSCustomObject]@{ Success = $true; Details = "Password auto-generated for export" }
    }
    finally {
        # CLEANUP: Remove cert from store
        Remove-Item $cert.PSPath -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# URL EXPORT TESTS
# ============================================================================
Write-TestHeader "Testing URL Export"

# Test exp-2.1: Export from URL to PEM cert
Invoke-Test -TestId "exp-2.1" -TestName "Export from URL to PEM cert" -FilePrefix "exp" -TestScript {
    # ACTION: Export certificate from URL (single certz.exe call)
    $output = & .\certz.exe export --url https://www.google.com --cert exp-url-cert.crt 2>&1
    $exitCode = $LASTEXITCODE

    # ASSERTIONS
    if ($exitCode -ne 0) {
        throw "Expected exit code 0, got $exitCode. Output: $output"
    }

    Assert-FileExists "exp-url-cert.crt"

    # Verify cert file contains PEM header
    $certContent = Get-Content "exp-url-cert.crt" -Raw
    if ($certContent -notmatch "BEGIN CERTIFICATE") {
        throw "Exported cert file should contain PEM certificate header"
    }

    [PSCustomObject]@{ Success = $true; Details = "Exported URL certificate to PEM" }
}

# Test exp-2.2: Export from URL to PFX with JSON output
Invoke-Test -TestId "exp-2.2" -TestName "Export from URL to PFX (JSON)" -FilePrefix "exp" -TestScript {
    # ACTION: Export from URL to PFX (single certz.exe call)
    $output = & .\certz.exe export --url https://www.google.com --file exp-url.pfx --format json 2>&1
    $exitCode = $LASTEXITCODE

    # ASSERTIONS
    if ($exitCode -ne 0) {
        throw "Expected exit code 0, got $exitCode. Output: $output"
    }

    Assert-FileExists "exp-url.pfx"

    # Parse JSON to verify output structure
    $json = $output | ConvertFrom-Json
    if (-not $json.success) {
        throw "Expected success=true in JSON output"
    }
    if (-not $json.source -or $json.source -notmatch "URL") {
        throw "Expected source to contain 'URL' in JSON output"
    }

    [PSCustomObject]@{ Success = $true; Details = "Exported URL certificate to PFX with JSON output" }
}

# ============================================================================
# ERROR HANDLING TESTS
# ============================================================================
Write-TestHeader "Testing Error Handling"

# Test exp-3.1: Error when no source specified
Invoke-Test -TestId "exp-3.1" -TestName "Error: no source specified" -FilePrefix "exp" -TestScript {
    # ACTION: Export without thumbprint or URL (single certz.exe call)
    # Note: ExportCommand.cs uses formatter.WriteError() + return (no exception),
    # so exit code is 0. This documents current behavior.
    $output = & .\certz.exe export --file exp-no-source.pfx 2>&1
    $exitCode = $LASTEXITCODE

    # The error message should indicate thumbprint is required
    $outputText = $output -join "`n"
    if ($outputText -notmatch "[Tt]humbprint") {
        throw "Expected error message about thumbprint requirement. Got: $outputText"
    }

    [PSCustomObject]@{ Success = $true; Details = "Error message displayed for missing source" }
}

# Test exp-3.2: Error when thumbprint not found in store
Invoke-Test -TestId "exp-3.2" -TestName "Error: thumbprint not found" -FilePrefix "exp" -TestScript {
    # ACTION: Export with non-existent thumbprint (single certz.exe call)
    $output = & .\certz.exe export --thumbprint DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF --file exp-notfound.pfx 2>&1
    $exitCode = $LASTEXITCODE

    # ASSERTIONS: CertificateException thrown, caught by Program.cs -> exit code 1
    if ($exitCode -ne 1) {
        throw "Expected exit code 1 (not found), got $exitCode"
    }

    # Verify no file was created
    Assert-FileNotExists "exp-notfound.pfx"

    [PSCustomObject]@{ Success = $true; Details = "Correctly failed with exit code 1 for missing thumbprint" }
}

# ============================================================================
# FORMAT TESTS
# ============================================================================
Write-TestHeader "Testing Output Formats"

# Test exp-4.1: JSON output format
Invoke-Test -TestId "exp-4.1" -TestName "JSON output format" -FilePrefix "exp" -TestScript {
    # SETUP: Create certificate in store using PowerShell (NOT certz)
    $cert = New-SelfSignedCertificate `
        -Subject "CN=exp-json-test.local" `
        -DnsName "exp-json-test.local" `
        -KeyAlgorithm ECDSA_nistP256 `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -NotAfter (Get-Date).AddDays(365) `
        -KeyExportPolicy Exportable
    $thumbprint = $cert.Thumbprint

    try {
        # ACTION: Export with JSON format (single certz.exe call)
        $output = & .\certz.exe export --thumbprint $thumbprint --file exp-json.pfx --password TestPass123 --format json --storelocation CurrentUser 2>&1
        $exitCode = $LASTEXITCODE

        # ASSERTIONS
        if ($exitCode -ne 0) {
            throw "Expected exit code 0, got $exitCode. Output: $output"
        }

        # Parse JSON output and verify structure
        $json = $output | ConvertFrom-Json

        if (-not $json.success) {
            throw "Expected success=true in JSON"
        }
        if (-not $json.subject) {
            throw "Expected subject in JSON"
        }
        if (-not $json.thumbprint) {
            throw "Expected thumbprint in JSON"
        }
        if (-not $json.outputFiles -or $json.outputFiles.Count -eq 0) {
            throw "Expected outputFiles array in JSON"
        }

        [PSCustomObject]@{ Success = $true; Details = "Valid JSON output with expected fields" }
    }
    finally {
        # CLEANUP: Remove cert from store
        Remove-Item $cert.PSPath -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# CLEANUP AND SUMMARY
# ============================================================================
if (-not $SkipCleanup) {
    Write-TestHeader "Cleaning Up Test Environment"
    Remove-TestFiles "exp-"
    Write-Host "Test files removed" -ForegroundColor Gray
} else {
    Write-Host "`nSkipping cleanup (test files preserved for inspection)" -ForegroundColor Yellow
}

# Return to original directory
Exit-ToolsDirectory

# Display summary and exit
$exitCode = Write-TestSummary -SkipCleanup:$SkipCleanup
exit $exitCode
