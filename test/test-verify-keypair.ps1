#requires -version 7

<#
.SYNOPSIS
    Test suite for certz verify-keypair command.

.DESCRIPTION
    Tests the verify-keypair command: cert+key match, cert+key mismatch, PFX self-check,
    CSR+key, JSON output, and error paths. Follows test isolation principles:
    - Each test invokes certz.exe exactly ONCE
    - Setup and teardown use pure PowerShell / .NET (no certz calls)
    - Assert against command output and exit code

.PARAMETER TestId
    Run specific tests by ID. Example: -TestId "vk-1.1", "vk-2.1"

.PARAMETER Category
    Run tests by category: match, mismatch, pfx, csr, format, error

.PARAMETER SkipCleanup
    Keep test files after running.

.PARAMETER Verbose
    Show detailed output.

.EXAMPLE
    .\test-verify-keypair.ps1
    Runs all tests.
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
    "match"    = @("vk-1.1", "vk-1.2")
    "mismatch" = @("vk-1.3")
    "pfx"      = @("vk-2.1", "vk-2.2")
    "csr"      = @("vk-3.1", "vk-3.2")
    "format"   = @("vk-4.1", "vk-4.2")
    "error"    = @("vk-5.1", "vk-5.2", "vk-5.3")
}

Initialize-TestEnvironment -TestId $TestId -Category $Category -TestCategories $TestCategories
Set-VerboseOutput -Enabled $Verbose

Write-Host "`nCertz verify-keypair Command Test Suite" -ForegroundColor Magenta
Write-Host "========================================`n" -ForegroundColor Magenta

if ($TestId -or $Category) {
    Write-Host "Test Filters Active:" -ForegroundColor Yellow
    if ($TestId) { Write-Host "  Test IDs: $($TestId -join ', ')" -ForegroundColor Gray }
    if ($Category) { Write-Host "  Categories: $($Category -join ', ')" -ForegroundColor Gray }
    Write-Host ""
}

Build-Certz -Verbose:$Verbose
Enter-ToolsDirectory
Write-Host "Initializing test environment..." -ForegroundColor Yellow
Remove-TestFiles "vk-"

# ============================================================================
# HELPERS
# ============================================================================

function New-RsaTestPair {
    param(
        [Parameter(Mandatory)][string]$Prefix,
        [string]$Cn = "vk-test.local"
    )
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    try {
        # Self-signed cert via CertificateRequest
        $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            "CN=$Cn",
            $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

        $now = [System.DateTimeOffset]::UtcNow
        $cert = $req.CreateSelfSigned($now.AddDays(-1), $now.AddDays(90))

        # Write cert PEM
        $certPem = "-----BEGIN CERTIFICATE-----`n" +
                   ([Convert]::ToBase64String($cert.RawData, 'InsertLineBreaks')) +
                   "`n-----END CERTIFICATE-----"
        Set-Content -Path "$Prefix.pem" -Value $certPem -NoNewline

        # Write key PEM (PKCS#8)
        Set-Content -Path "$Prefix.key" -Value $rsa.ExportPkcs8PrivateKeyPem() -NoNewline

        $cert.Dispose()
    } finally {
        $rsa.Dispose()
    }
}

function New-EcdsaTestPair {
    param(
        [Parameter(Mandatory)][string]$Prefix,
        [string]$Cn = "vk-test.local"
    )
    $ecdsa = [System.Security.Cryptography.ECDsa]::Create(
        [System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    try {
        $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            "CN=$Cn",
            $ecdsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256)

        $now = [System.DateTimeOffset]::UtcNow
        $cert = $req.CreateSelfSigned($now.AddDays(-1), $now.AddDays(90))

        $certPem = "-----BEGIN CERTIFICATE-----`n" +
                   ([Convert]::ToBase64String($cert.RawData, 'InsertLineBreaks')) +
                   "`n-----END CERTIFICATE-----"
        Set-Content -Path "$Prefix.pem" -Value $certPem -NoNewline

        Set-Content -Path "$Prefix.key" -Value $ecdsa.ExportPkcs8PrivateKeyPem() -NoNewline

        $cert.Dispose()
    } finally {
        $ecdsa.Dispose()
    }
}

function New-RsaPfx {
    param(
        [Parameter(Mandatory)][string]$Prefix,
        [Parameter(Mandatory)][string]$Password
    )
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    try {
        $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            "CN=$Prefix",
            $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $now = [System.DateTimeOffset]::UtcNow
        $cert = $req.CreateSelfSigned($now.AddDays(-1), $now.AddDays(90))

        $pbe = [System.Security.Cryptography.PbeParameters]::new(
            [System.Security.Cryptography.PbeEncryptionAlgorithm]::Aes256Cbc,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            100000)

        $pfxBytes = $cert.ExportPkcs12($pbe, $Password)
        [System.IO.File]::WriteAllBytes((Join-Path (Get-Location).Path "$Prefix.pfx"), $pfxBytes)
        $cert.Dispose()
    } finally {
        $rsa.Dispose()
    }
}

function New-RsaCsr {
    param(
        [Parameter(Mandatory)][string]$Prefix,
        [string]$Cn = "vk-csr.local"
    )
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    try {
        $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            "CN=$Cn",
            $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

        $csrPem = $req.CreateSigningRequestPem()
        Set-Content -Path "$Prefix.csr" -Value $csrPem -NoNewline

        Set-Content -Path "$Prefix.key" -Value $rsa.ExportPkcs8PrivateKeyPem() -NoNewline
    } finally {
        $rsa.Dispose()
    }
}

# ============================================================================
# MATCH TESTS
# ============================================================================
Write-TestHeader "Testing verify-keypair MATCH cases"

# vk-1.1: RSA cert + matching RSA key
Invoke-Test -TestId "vk-1.1" -TestName "RSA cert and matching RSA key reports match" -FilePrefix "vk-rsa-match" -TestScript {
    New-RsaTestPair -Prefix "vk-rsa-match" -Cn "vk-rsa-match.local"
    try {
        $output = & .\certz.exe verify-keypair --cert vk-rsa-match.pem --key vk-rsa-match.key 2>&1
        Assert-ExitCode -Expected 0
        $outputStr = ($output -join "") -replace '\e\[[0-9;]*[mK]', ''
        if ($outputStr -notmatch "Match") { throw "Output should mention 'Match', got: $outputStr" }
        if ($outputStr -notmatch "YES")   { throw "Output should show 'YES' for matched pair, got: $outputStr" }
        if ($outputStr -notmatch "RSA")   { throw "Output should mention RSA algorithm, got: $outputStr" }
        return @{ Success = $true; Details = "RSA cert + matching key reports match (exit 0)" }
    } finally {
        Remove-Item "vk-rsa-match.pem","vk-rsa-match.key" -Force -ErrorAction SilentlyContinue
    }
}

# vk-1.2: ECDSA cert + matching ECDSA key
Invoke-Test -TestId "vk-1.2" -TestName "ECDSA cert and matching ECDSA key reports match" -FilePrefix "vk-ec-match" -TestScript {
    New-EcdsaTestPair -Prefix "vk-ec-match" -Cn "vk-ec-match.local"
    try {
        $output = & .\certz.exe verify-keypair --cert vk-ec-match.pem --key vk-ec-match.key 2>&1
        Assert-ExitCode -Expected 0
        $outputStr = ($output -join "") -replace '\e\[[0-9;]*[mK]', ''
        if ($outputStr -notmatch "YES")        { throw "Output should show 'YES', got: $outputStr" }
        if ($outputStr -notmatch "ECDSA")      { throw "Output should mention ECDSA, got: $outputStr" }
        if ($outputStr -notmatch "P-256")      { throw "Output should mention P-256 curve, got: $outputStr" }
        return @{ Success = $true; Details = "ECDSA cert + matching key reports match" }
    } finally {
        Remove-Item "vk-ec-match.pem","vk-ec-match.key" -Force -ErrorAction SilentlyContinue
    }
}

# vk-1.3: RSA cert + non-matching key -> exit 1, payload still printed
Invoke-Test -TestId "vk-1.3" -TestName "Mismatched RSA cert and key reports mismatch and exits 1" -FilePrefix "vk-mismatch" -TestScript {
    New-RsaTestPair -Prefix "vk-mismatch-a" -Cn "vk-mismatch-a.local"
    New-RsaTestPair -Prefix "vk-mismatch-b" -Cn "vk-mismatch-b.local"
    try {
        $output = & .\certz.exe verify-keypair --cert vk-mismatch-a.pem --key vk-mismatch-b.key 2>&1
        if ($LASTEXITCODE -ne 1) { throw "Expected exit code 1 for mismatch, got $LASTEXITCODE" }
        $outputStr = ($output -join "") -replace '\e\[[0-9;]*[mK]', ''
        if ($outputStr -notmatch "MISMATCH" -and $outputStr -notmatch "NO") {
            throw "Output should indicate mismatch, got: $outputStr"
        }
        return @{ Success = $true; Details = "Mismatch produces exit 1 with the result block still printed" }
    } finally {
        Remove-Item "vk-mismatch-a.pem","vk-mismatch-a.key","vk-mismatch-b.pem","vk-mismatch-b.key" -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# PFX SELF-CHECK TESTS
# ============================================================================
Write-TestHeader "Testing verify-keypair PFX self-check"

# vk-2.1: PFX self-check on a fresh PFX
Invoke-Test -TestId "vk-2.1" -TestName "PFX self-check on a valid bundle reports match" -FilePrefix "vk-pfx-self" -TestScript {
    New-RsaPfx -Prefix "vk-pfx-self" -Password "SelfCheckPass1"
    try {
        $output = & .\certz.exe verify-keypair --pfx vk-pfx-self.pfx --password SelfCheckPass1 2>&1
        Assert-ExitCode -Expected 0
        $outputStr = ($output -join "") -replace '\e\[[0-9;]*[mK]', ''
        if ($outputStr -notmatch "YES") { throw "PFX self-check should report YES, got: $outputStr" }
        return @{ Success = $true; Details = "Valid PFX self-checks as match" }
    } finally {
        Remove-Item "vk-pfx-self.pfx" -Force -ErrorAction SilentlyContinue
    }
}

# vk-2.2: --pfx without --password is rejected
Invoke-Test -TestId "vk-2.2" -TestName "PFX without password returns non-zero exit" -FilePrefix "vk-pfx-nopass" -TestScript {
    New-RsaPfx -Prefix "vk-pfx-nopass" -Password "AnyPass"
    try {
        $output = & .\certz.exe verify-keypair --pfx vk-pfx-nopass.pfx 2>&1
        if ($LASTEXITCODE -eq 0) { throw "Expected non-zero exit when --password is missing" }
        return @{ Success = $true; Details = "PFX without password produces error exit" }
    } finally {
        Remove-Item "vk-pfx-nopass.pfx" -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# CSR TESTS
# ============================================================================
Write-TestHeader "Testing verify-keypair CSR cases"

# vk-3.1: CSR + matching key
Invoke-Test -TestId "vk-3.1" -TestName "CSR and matching RSA key reports match" -FilePrefix "vk-csr-match" -TestScript {
    New-RsaCsr -Prefix "vk-csr-match" -Cn "vk-csr-match.local"
    try {
        $output = & .\certz.exe verify-keypair --csr vk-csr-match.csr --key vk-csr-match.key 2>&1
        Assert-ExitCode -Expected 0
        $outputStr = ($output -join "") -replace '\e\[[0-9;]*[mK]', ''
        if ($outputStr -notmatch "YES") { throw "CSR + matching key should report YES, got: $outputStr" }
        return @{ Success = $true; Details = "CSR + matching key reports match" }
    } finally {
        Remove-Item "vk-csr-match.csr","vk-csr-match.key" -Force -ErrorAction SilentlyContinue
    }
}

# vk-3.2: CSR + non-matching key
Invoke-Test -TestId "vk-3.2" -TestName "CSR and non-matching RSA key reports mismatch (exit 1)" -FilePrefix "vk-csr-mismatch" -TestScript {
    New-RsaCsr -Prefix "vk-csr-mm-a" -Cn "vk-csr-mm-a.local"
    New-RsaCsr -Prefix "vk-csr-mm-b" -Cn "vk-csr-mm-b.local"
    try {
        $output = & .\certz.exe verify-keypair --csr vk-csr-mm-a.csr --key vk-csr-mm-b.key 2>&1
        if ($LASTEXITCODE -ne 1) { throw "Expected exit 1 for CSR mismatch, got $LASTEXITCODE" }
        return @{ Success = $true; Details = "CSR mismatch produces exit 1" }
    } finally {
        Remove-Item "vk-csr-mm-a.csr","vk-csr-mm-a.key","vk-csr-mm-b.csr","vk-csr-mm-b.key" -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# JSON FORMAT TESTS
# ============================================================================
Write-TestHeader "Testing verify-keypair --format json"

# vk-4.1: JSON output structure on match
Invoke-Test -TestId "vk-4.1" -TestName "JSON output has correct structure on match" -FilePrefix "vk-json-match" -TestScript {
    New-RsaTestPair -Prefix "vk-json-match" -Cn "vk-json-match.local"
    try {
        $output = & .\certz.exe verify-keypair --cert vk-json-match.pem --key vk-json-match.key --format json 2>&1
        Assert-ExitCode -Expected 0
        $parsed = ($output -join "`n").Trim() | ConvertFrom-Json
        if ($parsed.success -ne $true)        { throw "JSON 'success' should be true" }
        if ($parsed.match -ne $true)          { throw "JSON 'match' should be true on match" }
        if ($parsed.algorithm -ne "RSA")      { throw "JSON 'algorithm' should be RSA, got: $($parsed.algorithm)" }
        if ($parsed.keySize -ne 2048)         { throw "JSON 'keySize' should be 2048, got: $($parsed.keySize)" }
        if (-not $parsed.certPublicKeyHash)   { throw "JSON 'certPublicKeyHash' should be set" }
        if (-not $parsed.keyPublicKeyHash)    { throw "JSON 'keyPublicKeyHash' should be set" }
        if ($parsed.certPublicKeyHash -ne $parsed.keyPublicKeyHash) {
            throw "On match the SPKI hashes should be identical"
        }
        return @{ Success = $true; Details = "JSON match payload has all expected fields" }
    } finally {
        Remove-Item "vk-json-match.pem","vk-json-match.key" -Force -ErrorAction SilentlyContinue
    }
}

# vk-4.2: JSON output on mismatch (exit 1, payload reflects the mismatch)
Invoke-Test -TestId "vk-4.2" -TestName "JSON output reflects mismatch and exits 1" -FilePrefix "vk-json-mm" -TestScript {
    New-RsaTestPair -Prefix "vk-json-mm-a" -Cn "vk-json-mm-a.local"
    New-RsaTestPair -Prefix "vk-json-mm-b" -Cn "vk-json-mm-b.local"
    try {
        $output = & .\certz.exe verify-keypair --cert vk-json-mm-a.pem --key vk-json-mm-b.key --format json 2>&1
        if ($LASTEXITCODE -ne 1) { throw "Expected exit 1 for JSON mismatch, got $LASTEXITCODE" }
        $parsed = ($output -join "`n").Trim() | ConvertFrom-Json
        if ($parsed.match -ne $false) { throw "JSON 'match' should be false on mismatch" }
        if ($parsed.certPublicKeyHash -eq $parsed.keyPublicKeyHash) {
            throw "On mismatch the SPKI hashes should differ"
        }
        return @{ Success = $true; Details = "JSON mismatch payload reports match=false, exit 1" }
    } finally {
        Remove-Item "vk-json-mm-a.pem","vk-json-mm-a.key","vk-json-mm-b.pem","vk-json-mm-b.key" -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# ERROR PATH TESTS
# ============================================================================
Write-TestHeader "Testing verify-keypair error paths"

# vk-5.1: missing cert file -> non-zero exit
Invoke-Test -TestId "vk-5.1" -TestName "Missing certificate file returns non-zero exit" -FilePrefix "vk-err-missing" -TestScript {
    $output = & .\certz.exe verify-keypair --cert does-not-exist.pem --key does-not-exist.key 2>&1
    if ($LASTEXITCODE -eq 0) { throw "Expected non-zero exit for missing file" }
    return @{ Success = $true; Details = "Missing file produces error exit" }
}

# vk-5.2: --cert without --key -> error
Invoke-Test -TestId "vk-5.2" -TestName "--cert without --key returns non-zero exit" -FilePrefix "vk-err-nokey" -TestScript {
    New-RsaTestPair -Prefix "vk-err-nokey" -Cn "vk-err-nokey.local"
    try {
        $output = & .\certz.exe verify-keypair --cert vk-err-nokey.pem 2>&1
        if ($LASTEXITCODE -eq 0) { throw "Expected non-zero exit when --key is missing" }
        $outputStr = ($output -join " ")
        if ($outputStr -notmatch "key") { throw "Error message should mention 'key', got: $outputStr" }
        return @{ Success = $true; Details = "Missing --key flag produces a clear error" }
    } finally {
        Remove-Item "vk-err-nokey.pem","vk-err-nokey.key" -Force -ErrorAction SilentlyContinue
    }
}

# vk-5.3: --pfx with --cert -> mutex error
Invoke-Test -TestId "vk-5.3" -TestName "--pfx and --cert together returns non-zero exit" -FilePrefix "vk-err-mutex" -TestScript {
    New-RsaPfx -Prefix "vk-err-mutex" -Password "MutexPass1"
    New-RsaTestPair -Prefix "vk-err-mutex-c" -Cn "vk-err-mutex.local"
    try {
        $output = & .\certz.exe verify-keypair --pfx vk-err-mutex.pfx --password MutexPass1 --cert vk-err-mutex-c.pem 2>&1
        if ($LASTEXITCODE -eq 0) { throw "Expected non-zero exit when --pfx and --cert are both set" }
        $outputStr = ($output -join " ")
        if ($outputStr -notmatch "mutually exclusive") {
            throw "Error message should mention 'mutually exclusive', got: $outputStr"
        }
        return @{ Success = $true; Details = "--pfx and --cert together produces a clear mutex error" }
    } finally {
        Remove-Item "vk-err-mutex.pfx","vk-err-mutex-c.pem","vk-err-mutex-c.key" -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# SUMMARY
# ============================================================================
$exitCode = Write-TestSummary -SkipCleanup:$SkipCleanup
exit $exitCode
