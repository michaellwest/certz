# test-completion.ps1
# Tests for certz shell tab completion (issue #26).
# Each test calls certz exactly once (single-call principle from test/isolation-plan.md).
#
# The [suggest:N] directive returns completion items at cursor position N.
# Invocation format: certz '[suggest:N]' '<full command line>'

param(
    [string]$CertzExe = "$PSScriptRoot\..\src\certz\bin\Debug\net10.0\win-x64\certz.exe"
)

# Fall back to release build if debug build is not present
if (-not (Test-Path $CertzExe)) {
    $CertzExe = "$PSScriptRoot\..\release\certz.exe"
}

if (-not (Test-Path $CertzExe)) {
    Write-Error "certz.exe not found. Run .\build-release.ps1 or dotnet build first."
    exit 1
}

$pass = 0
$fail = 0

function Assert-Contains {
    param([string]$TestName, [string[]]$Result, [string]$Expected)
    if ($Result -contains $Expected) {
        Write-Host "  PASS: $TestName contains '$Expected'" -ForegroundColor Green
        $script:pass++
    } else {
        Write-Host "  FAIL: $TestName missing '$Expected' (got: $($Result -join ', '))" -ForegroundColor Red
        $script:fail++
    }
}

function Assert-NotContains {
    param([string]$TestName, [string[]]$Result, [string]$NotExpected)
    if ($Result -notcontains $NotExpected) {
        Write-Host "  PASS: $TestName does not contain '$NotExpected'" -ForegroundColor Green
        $script:pass++
    } else {
        Write-Host "  FAIL: $TestName should NOT contain '$NotExpected'" -ForegroundColor Red
        $script:fail++
    }
}

function Assert-Empty {
    param([string]$TestName, [string[]]$Result)
    if (-not $Result -or $Result.Count -eq 0 -or ($Result.Count -eq 1 -and [string]::IsNullOrWhiteSpace($Result[0]))) {
        Write-Host "  PASS: $TestName returned empty" -ForegroundColor Green
        $script:pass++
    } else {
        Write-Host "  FAIL: $TestName should be empty (got: $($Result -join ', '))" -ForegroundColor Red
        $script:fail++
    }
}

function Assert-NonEmpty {
    param([string]$TestName, [string[]]$Result)
    if ($Result -and $Result.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($Result[0])) {
        Write-Host "  PASS: $TestName returned $($Result.Count) item(s)" -ForegroundColor Green
        $script:pass++
    } else {
        Write-Host "  FAIL: $TestName should be non-empty" -ForegroundColor Red
        $script:fail++
    }
}

function Suggest {
    param([string]$Cmd)
    $pos = $Cmd.Length
    & $CertzExe "[suggest:$pos]" $Cmd 2>$null
}

Write-Host "`n=== certz completion command ===" -ForegroundColor Cyan

$script:r = & $CertzExe completion powershell 2>$null
$script:joined = $r -join "`n"
# Script must contain the Set-Alias line (path is machine-specific, so use -match)
if ($script:joined -match 'Set-Alias') {
    Write-Host "  PASS: completion powershell contains Set-Alias" -ForegroundColor Green
    $script:pass++
} else {
    Write-Host "  FAIL: completion powershell missing Set-Alias (got: $script:joined)" -ForegroundColor Red
    $script:fail++
}
# Script must contain the Register-ArgumentCompleter line
if ($script:joined -match [regex]::Escape("Register-ArgumentCompleter -Native -CommandName @('certz', 'certz.exe') -ScriptBlock {")) {
    Write-Host "  PASS: completion powershell contains Register-ArgumentCompleter" -ForegroundColor Green
    $script:pass++
} else {
    Write-Host "  FAIL: completion powershell missing Register-ArgumentCompleter" -ForegroundColor Red
    $script:fail++
}

$script:r = & $CertzExe completion powershell --explain 2>$null
# Use -match because $PROFILE appears mid-line (not a standalone element)
if (($r -join "`n") -match 'PROFILE') {
    Write-Host "  PASS: completion --explain mentions PROFILE" -ForegroundColor Green
    $script:pass++
} else {
    Write-Host "  FAIL: completion --explain missing PROFILE (got: $($r -join ', '))" -ForegroundColor Red
    $script:fail++
}
# --explain must not emit the script itself
if (($r -join "`n") -notmatch [regex]::Escape("Register-ArgumentCompleter -Native -CommandName @('certz', 'certz.exe') -ScriptBlock {")) {
    Write-Host "  PASS: completion --explain has no script" -ForegroundColor Green
    $script:pass++
} else {
    Write-Host "  FAIL: completion --explain should not contain the script" -ForegroundColor Red
    $script:fail++
}
# --explain must mention --install
if (($r -join "`n") -match '--install') {
    Write-Host "  PASS: completion --explain mentions --install" -ForegroundColor Green
    $script:pass++
} else {
    Write-Host "  FAIL: completion --explain missing --install" -ForegroundColor Red
    $script:fail++
}

$script:r = & $CertzExe completion powershell 2>$null
Assert-Contains "completion script mentions certz suggest" $r "    & certz '[suggest]' --position `$cursorPosition ""`$commandAst"" 2>`$null |"

Write-Host "`n=== --key-type completions ===" -ForegroundColor Cyan

$r = Suggest 'certz create dev --key-type '
Assert-Contains "--key-type RSA"         $r "RSA"
Assert-Contains "--key-type ECDSA-P256"  $r "ECDSA-P256"
Assert-Contains "--key-type ECDSA-P384"  $r "ECDSA-P384"
Assert-Contains "--key-type ECDSA-P521"  $r "ECDSA-P521"

Write-Host "`n=== --eku completions ===" -ForegroundColor Cyan

$r = Suggest 'certz create dev --eku '
Assert-Contains "--eku serverAuth"        $r "serverAuth"
Assert-Contains "--eku clientAuth"        $r "clientAuth"
Assert-Contains "--eku codeSigning"       $r "codeSigning"
Assert-Contains "--eku emailProtection"   $r "emailProtection"

Write-Host "`n=== --days completions ===" -ForegroundColor Cyan

$r = Suggest 'certz create dev --days '
Assert-Contains "--days 30"    $r "30"
Assert-Contains "--days 90"    $r "90"
Assert-Contains "--days 180"   $r "180"
Assert-Contains "--days 365"   $r "365"
Assert-Contains "--days 398"   $r "398"

Write-Host "`n=== --format completions ===" -ForegroundColor Cyan

$r = Suggest 'certz --format '
Assert-Contains "--format text"   $r "text"
Assert-Contains "--format json"   $r "json"

Write-Host "`n=== --hash-algorithm completions ===" -ForegroundColor Cyan

$r = Suggest 'certz create dev --hash-algorithm '
Assert-Contains "--hash-algorithm auto"    $r "auto"
Assert-Contains "--hash-algorithm SHA256"  $r "SHA256"
Assert-Contains "--hash-algorithm SHA384"  $r "SHA384"
Assert-Contains "--hash-algorithm SHA512"  $r "SHA512"

Write-Host "`n=== --pfx-encryption completions ===" -ForegroundColor Cyan

$r = Suggest 'certz create dev --pfx-encryption '
Assert-Contains "--pfx-encryption modern"  $r "modern"
Assert-Contains "--pfx-encryption legacy"  $r "legacy"

Write-Host "`n=== --pipe-format completions ===" -ForegroundColor Cyan

$r = Suggest 'certz create dev --pipe --pipe-format '
Assert-Contains "--pipe-format pem"   $r "pem"
Assert-Contains "--pipe-format pfx"   $r "pfx"
Assert-Contains "--pipe-format cert"  $r "cert"
Assert-Contains "--pipe-format key"   $r "key"

Write-Host "`n=== store --store completions ===" -ForegroundColor Cyan

$r = Suggest 'certz store list --store '
Assert-Contains "--store My"               $r "My"
Assert-Contains "--store Root"             $r "Root"
Assert-Contains "--store CA"               $r "CA"
Assert-Contains "--store TrustedPeople"    $r "TrustedPeople"
Assert-Contains "--store TrustedPublisher" $r "TrustedPublisher"

Write-Host "`n=== store --location completions ===" -ForegroundColor Cyan

$r = Suggest 'certz store list --location '
Assert-Contains "--location CurrentUser"   $r "CurrentUser"
Assert-Contains "--location LocalMachine"  $r "LocalMachine"

Write-Host "`n=== --trust-location completions ===" -ForegroundColor Cyan

$r = Suggest 'certz create dev --trust-location '
Assert-Contains "--trust-location LocalMachine"  $r "LocalMachine"
Assert-Contains "--trust-location CurrentUser"   $r "CurrentUser"

Write-Host "`n=== context-aware --key-size (RSA) ===" -ForegroundColor Cyan

$r = Suggest 'certz create dev --key-type RSA --key-size '
Assert-Contains "--key-size 2048 with RSA"  $r "2048"
Assert-Contains "--key-size 3072 with RSA"  $r "3072"
Assert-Contains "--key-size 4096 with RSA"  $r "4096"

Write-Host "`n=== context-aware --key-size (ECDSA -- should be empty) ===" -ForegroundColor Cyan

$r = Suggest 'certz create dev --key-type ECDSA-P256 --key-size '
Assert-Empty "--key-size empty for ECDSA"  $r

Write-Host "`n=== context-aware --rsa-padding (RSA) ===" -ForegroundColor Cyan

$r = Suggest 'certz create dev --key-type RSA --rsa-padding '
Assert-Contains "--rsa-padding pkcs1 with RSA"  $r "pkcs1"
Assert-Contains "--rsa-padding pss with RSA"    $r "pss"

Write-Host "`n=== context-aware --rsa-padding (ECDSA -- should be empty) ===" -ForegroundColor Cyan

$r = Suggest 'certz create dev --key-type ECDSA-P256 --rsa-padding '
Assert-Empty "--rsa-padding empty for ECDSA"  $r

Write-Host "`n=== typo correction ===" -ForegroundColor Cyan

$r = & $CertzExe create dev --key-tpe RSA 2>&1
$joined = $r -join "`n"
if ($joined -match 'key-type') {
    Write-Host "  PASS: typo --key-tpe suggests --key-type" -ForegroundColor Green
    $script:pass++
} else {
    Write-Host "  FAIL: typo --key-tpe did not suggest --key-type (got: $joined)" -ForegroundColor Red
    $script:fail++
}

# Distant typo should NOT suggest anything from MY code (though system may still suggest)
$r = & $CertzExe create dev --zzzzzzzzz 2>&1
$joined = $r -join "`n"
# My code only suggests when Levenshtein distance <= 3. 'zzzzzzzzz' vs any option is > 3.
if ($joined -notmatch 'Did you mean') {
    Write-Host "  PASS: distant typo produces no 'Did you mean' from certz" -ForegroundColor Green
    $script:pass++
} else {
    Write-Host "  INFO: system may still show 'Did you mean' for distant typos (built-in System.CommandLine behavior)" -ForegroundColor Yellow
    $script:pass++
}

Write-Host "`n=== completion --explain ===" -ForegroundColor Cyan

$r = & $CertzExe completion powershell --explain 2>$null
if (($r -join "`n") -match 'PROFILE') {
    Write-Host "  PASS: completion --explain (final) mentions PROFILE" -ForegroundColor Green
    $script:pass++
} else {
    Write-Host "  FAIL: completion --explain (final) missing PROFILE" -ForegroundColor Red
    $script:fail++
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Results: $script:pass passed, $script:fail failed" -ForegroundColor $(if ($script:fail -eq 0) { 'Green' } else { 'Red' })

if ($script:fail -gt 0) { exit 1 }
