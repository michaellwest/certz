#Requires -Version 7.5

<#
.SYNOPSIS
    Tests for ephemeral and pipe certificate generation modes.
#>

param(
    [string[]]$TestId,
    [string[]]$Category
)

. "$PSScriptRoot\test-helper.ps1"

$TestCategories = @{
    "ephemeral" = @("eph-1.1", "eph-1.2", "eph-1.3", "eph-2.1", "eph-2.2")
    "pipe"      = @("eph-3.1", "eph-3.2", "eph-3.3", "eph-3.4", "eph-3.5")
    "errors"    = @("eph-4.1", "eph-4.2", "eph-4.3", "eph-4.4")
}

Initialize-TestEnvironment -TestId $TestId -Category $Category -TestCategories $TestCategories
Build-Certz

Write-TestHeader "Ephemeral Certificate Generation Tests"
Write-Host "========================================`n"

# ============================================================================
# EPHEMERAL MODE TESTS
# ============================================================================

Write-TestHeader "Testing Ephemeral Mode"

# eph-1.1: Basic ephemeral dev certificate
Invoke-Test -TestId "eph-1.1" -TestName "Ephemeral dev certificate" -TestScript {
    $output = & certz create dev ephemeral-test.local --ephemeral 2>&1
    $exitCode = $LASTEXITCODE

    # Should succeed
    Assert-ExitCode -Expected 0

    # Should show certificate details
    $hasSubject = $output -match "ephemeral-test.local"
    $hasThumbprint = $output -match "Thumbprint"

    # Should NOT create any files
    $pfxExists = Test-Path "ephemeral-test.local.pfx"
    $pemExists = Test-Path "ephemeral-test.local.pem"
    $anyFiles = Get-ChildItem -Path . -Filter "ephemeral-test*" -ErrorAction SilentlyContinue

    if ($hasSubject -and $hasThumbprint -and -not $pfxExists -and -not $pemExists -and $anyFiles.Count -eq 0) {
        return @{ Success = $true; Details = "Certificate displayed, no files created" }
    }
    return @{ Success = $false; Details = "Expected no files, got pfx=$pfxExists pem=$pemExists files=$($anyFiles.Count)" }
}

# eph-1.2: Ephemeral with custom options
Invoke-Test -TestId "eph-1.2" -TestName "Ephemeral with SANs and key type" -TestScript {
    $output = & certz create dev custom.local --ephemeral --san "alt.local,192.168.1.1" --key-type RSA 2>&1

    Assert-ExitCode -Expected 0

    $hasRSA = $output -match "RSA"
    $hasSAN = $output -match "alt.local"

    # No files should exist
    $anyFiles = Get-ChildItem -Path . -Filter "custom*" -ErrorAction SilentlyContinue

    if ($hasRSA -and $hasSAN -and $anyFiles.Count -eq 0) {
        return @{ Success = $true; Details = "RSA key and SANs displayed, no files" }
    }
    return @{ Success = $false; Details = "RSA=$hasRSA SAN=$hasSAN files=$($anyFiles.Count)" }
}

# eph-1.3: Ephemeral CA certificate
Invoke-Test -TestId "eph-1.3" -TestName "Ephemeral CA certificate" -TestScript {
    $output = & certz create ca --name "Ephemeral Test CA" --ephemeral 2>&1

    Assert-ExitCode -Expected 0

    $hasCA = $output -match "Ephemeral Test CA"
    $anyFiles = Get-ChildItem -Path . -Filter "*ephemeral*" -ErrorAction SilentlyContinue

    if ($hasCA -and $anyFiles.Count -eq 0) {
        return @{ Success = $true; Details = "CA cert displayed, no files" }
    }
    return @{ Success = $false; Details = "CA displayed=$hasCA files=$($anyFiles.Count)" }
}

# eph-2.1: Ephemeral with JSON output
Invoke-Test -TestId "eph-2.1" -TestName "Ephemeral with JSON format" -TestScript {
    $output = & certz create dev json-test.local --ephemeral --format json 2>&1

    Assert-ExitCode -Expected 0

    try {
        $json = $output | ConvertFrom-Json
        $isEphemeral = $json.isEphemeral -eq $true
        $noFiles = ($null -eq $json.files) -or ($json.files.Count -eq 0)

        if ($isEphemeral -and $noFiles) {
            return @{ Success = $true; Details = "JSON shows isEphemeral=true, no files" }
        }
        return @{ Success = $false; Details = "isEphemeral=$isEphemeral files=$($json.files)" }
    }
    catch {
        return @{ Success = $false; Details = "Invalid JSON output: $($_.Exception.Message)" }
    }
}

# eph-2.2: Ephemeral shows warning panel
Invoke-Test -TestId "eph-2.2" -TestName "Ephemeral shows warning message" -TestScript {
    $output = & certz create dev warn-test.local --ephemeral 2>&1

    Assert-ExitCode -Expected 0

    $hasWarning = $output -match "EPHEMERAL MODE"
    $hasMemory = $output -match "memory only"

    if ($hasWarning -and $hasMemory) {
        return @{ Success = $true; Details = "Ephemeral warning displayed" }
    }
    return @{ Success = $false; Details = "Warning=$hasWarning Memory=$hasMemory" }
}

# ============================================================================
# PIPE MODE TESTS
# ============================================================================

Write-TestHeader "Testing Pipe Mode"

# eph-3.1: Pipe PEM output
Invoke-Test -TestId "eph-3.1" -TestName "Pipe PEM format to stdout" -TestScript {
    $output = & certz create dev pipe-test.local --pipe 2>&1

    Assert-ExitCode -Expected 0

    $hasCertBegin = $output -match "-----BEGIN CERTIFICATE-----"
    $hasCertEnd = $output -match "-----END CERTIFICATE-----"
    $hasKeyBegin = $output -match "-----BEGIN PRIVATE KEY-----"
    $hasKeyEnd = $output -match "-----END PRIVATE KEY-----"

    # No files should exist
    $anyFiles = Get-ChildItem -Path . -Filter "pipe-test*" -ErrorAction SilentlyContinue

    if ($hasCertBegin -and $hasCertEnd -and $hasKeyBegin -and $hasKeyEnd -and $anyFiles.Count -eq 0) {
        return @{ Success = $true; Details = "Full PEM output to stdout, no files" }
    }
    return @{ Success = $false; Details = "CertBegin=$hasCertBegin CertEnd=$hasCertEnd KeyBegin=$hasKeyBegin KeyEnd=$hasKeyEnd files=$($anyFiles.Count)" }
}

# eph-3.2: Pipe cert-only format
Invoke-Test -TestId "eph-3.2" -TestName "Pipe cert-only format" -TestScript {
    $output = & certz create dev cert-only.local --pipe --pipe-format cert 2>&1

    Assert-ExitCode -Expected 0

    $hasCert = $output -match "-----BEGIN CERTIFICATE-----"
    $hasKey = $output -match "-----BEGIN PRIVATE KEY-----"

    if ($hasCert -and -not $hasKey) {
        return @{ Success = $true; Details = "Certificate only, no private key" }
    }
    return @{ Success = $false; Details = "Cert=$hasCert Key=$hasKey (expected Cert=true Key=false)" }
}

# eph-3.3: Pipe key-only format
Invoke-Test -TestId "eph-3.3" -TestName "Pipe key-only format" -TestScript {
    $output = & certz create dev key-only.local --pipe --pipe-format key 2>&1

    Assert-ExitCode -Expected 0

    $hasCert = $output -match "-----BEGIN CERTIFICATE-----"
    $hasKey = $output -match "-----BEGIN PRIVATE KEY-----"

    if (-not $hasCert -and $hasKey) {
        return @{ Success = $true; Details = "Private key only, no certificate" }
    }
    return @{ Success = $false; Details = "Cert=$hasCert Key=$hasKey (expected Cert=false Key=true)" }
}

# eph-3.4: Pipe PFX with password
Invoke-Test -TestId "eph-3.4" -TestName "Pipe PFX format with password" -TestScript {
    $output = & certz create dev pfx-pipe.local --pipe --pipe-format pfx --pipe-password "TestPass123" 2>&1

    Assert-ExitCode -Expected 0

    # Output should be base64 (no PEM markers)
    $noPemMarkers = -not ($output -match "-----BEGIN")
    # Check that we got some output (base64 content)
    $hasContent = $output.Length -gt 50

    if ($noPemMarkers -and $hasContent) {
        return @{ Success = $true; Details = "Base64 PFX output" }
    }
    return @{ Success = $false; Details = "noPemMarkers=$noPemMarkers hasContent=$hasContent" }
}

# eph-3.5: Pipe PFX generates password to stderr
Invoke-Test -TestId "eph-3.5" -TestName "Pipe PFX auto-generates password to stderr" -TestScript {
    # Run the command and capture both stdout and stderr
    $tempFile = [System.IO.Path]::GetTempFileName()
    try {
        $stdout = & certz create dev pfx-auto.local --pipe --pipe-format pfx 2>$tempFile
        $stderr = Get-Content $tempFile -Raw

        $hasPassword = $stderr -match "PASSWORD:"

        if ($hasPassword) {
            return @{ Success = $true; Details = "Auto-generated password written to stderr" }
        }
        return @{ Success = $false; Details = "Expected PASSWORD: on stderr, got: $stderr" }
    }
    finally {
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# ERROR HANDLING TESTS
# ============================================================================

Write-TestHeader "Testing Error Handling"

# eph-4.1: Ephemeral with file option
Invoke-Test -TestId "eph-4.1" -TestName "Error: ephemeral with --file" -TestScript {
    $output = & certz create dev conflict.local --ephemeral --file conflict.pfx 2>&1
    $exitCode = $LASTEXITCODE

    $hasError = $output -match "cannot be used with"

    if ($exitCode -ne 0 -and $hasError) {
        return @{ Success = $true; Details = "Correctly rejected conflicting options" }
    }
    return @{ Success = $false; Details = "exitCode=$exitCode hasError=$hasError" }
}

# eph-4.2: Ephemeral with --trust
Invoke-Test -TestId "eph-4.2" -TestName "Error: ephemeral with --trust" -TestScript {
    $output = & certz create dev trust-conflict.local --ephemeral --trust 2>&1
    $exitCode = $LASTEXITCODE

    $hasError = $output -match "cannot be used with"

    if ($exitCode -ne 0 -and $hasError) {
        return @{ Success = $true; Details = "Correctly rejected --trust with ephemeral" }
    }
    return @{ Success = $false; Details = "exitCode=$exitCode hasError=$hasError" }
}

# eph-4.3: Pipe with file option
Invoke-Test -TestId "eph-4.3" -TestName "Error: pipe with --file" -TestScript {
    $output = & certz create dev pipe-conflict.local --pipe --file pipe.pfx 2>&1
    $exitCode = $LASTEXITCODE

    $hasError = $output -match "cannot be used with"

    if ($exitCode -ne 0 -and $hasError) {
        return @{ Success = $true; Details = "Correctly rejected conflicting options" }
    }
    return @{ Success = $false; Details = "exitCode=$exitCode hasError=$hasError" }
}

# eph-4.4: Both ephemeral and pipe
Invoke-Test -TestId "eph-4.4" -TestName "Error: both ephemeral and pipe" -TestScript {
    $output = & certz create dev both.local --ephemeral --pipe 2>&1
    $exitCode = $LASTEXITCODE

    $hasError = $output -match "mutually exclusive"

    if ($exitCode -ne 0 -and $hasError) {
        return @{ Success = $true; Details = "Correctly rejected both flags" }
    }
    return @{ Success = $false; Details = "exitCode=$exitCode hasError=$hasError" }
}

# ============================================================================
# SUMMARY
# ============================================================================

$exitCode = Write-TestSummary
exit $exitCode
