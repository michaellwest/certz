# Prompt: Create Test Suite

Use this prompt when creating a new test file for a certz command.

## Core Principle

**Each test must invoke `certz.exe` exactly once for the behavior it validates.**

All setup and cleanup must use PowerShell only.

## Test Contract

Every test follows this structure:

1. **Preconditions** - PowerShell only (create certs, files, etc.)
2. **Action** - `certz.exe` exactly once
3. **Assertions** - PowerShell only (check files, stores, exit codes)
4. **Cleanup** - PowerShell only (remove test artifacts)

## File Template

```powershell
# test/test-<feature>.ps1

param(
    [string]$TestId,
    [string]$Category
)

$ErrorActionPreference = "Stop"
$script:TestsPassed = 0
$script:TestsFailed = 0
$script:TestsSkipped = 0

# Test categories and IDs
$script:TestCategories = @{
    "category1" = @("feat-1.1", "feat-1.2")
    "category2" = @("feat-2.1", "feat-2.2")
    "format"    = @("fmt-1.1")
}

# === HELPER FUNCTIONS ===

function Test-ShouldRun {
    param([string]$Id, [string]$Cat)
    if ($TestId -and $TestId -ne $Id) { return $false }
    if ($Category -and $script:TestCategories[$Category] -notcontains $Id) { return $false }
    return $true
}

function Write-TestHeader {
    param([string]$Id, [string]$Description)
    Write-Host "`n[$Id] $Description" -ForegroundColor Cyan
}

function Write-TestResult {
    param([string]$Id, [bool]$Passed, [string]$Message = "")
    if ($Passed) {
        Write-Host "  PASS: $Id" -ForegroundColor Green
        $script:TestsPassed++
    } else {
        Write-Host "  FAIL: $Id - $Message" -ForegroundColor Red
        $script:TestsFailed++
    }
}

function Assert-ExitCode {
    param([int]$Expected, [int]$Actual, [string]$Context = "")
    if ($Expected -ne $Actual) {
        throw "Expected exit code $Expected but got $Actual. $Context"
    }
}

function Assert-FileExists {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        throw "Expected file not found: $Path"
    }
}

function Assert-FileNotExists {
    param([string]$Path)
    if (Test-Path $Path) {
        throw "File should not exist: $Path"
    }
}

# === BUILD ===

Write-Host "Building certz..." -ForegroundColor Yellow
Push-Location $PSScriptRoot\..
dotnet build --configuration Release --verbosity quiet
if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed" -ForegroundColor Red
    exit 1
}
Pop-Location

$certz = "$PSScriptRoot\..\release\certz.exe"

# === TESTS ===

function Invoke-Test {
    param(
        [string]$Id,
        [string]$Description,
        [scriptblock]$Test
    )

    if (-not (Test-ShouldRun -Id $Id -Cat $Category)) {
        $script:TestsSkipped++
        return
    }

    Write-TestHeader -Id $Id -Description $Description

    try {
        & $Test
        Write-TestResult -Id $Id -Passed $true
    }
    catch {
        Write-TestResult -Id $Id -Passed $false -Message $_.Exception.Message
    }
}

# Example test
Invoke-Test -Id "feat-1.1" -Description "Basic operation" -Test {
    $testDir = "$env:TEMP\certz-test-$([guid]::NewGuid())"
    New-Item -ItemType Directory -Path $testDir -Force | Out-Null

    try {
        # === SETUP (PowerShell only) ===
        # Create any prerequisite files or certificates here

        # === ACTION (certz.exe exactly ONCE) ===
        & $certz <command> <args> 2>&1 | Out-Null
        $exitCode = $LASTEXITCODE

        # === ASSERTIONS (PowerShell only) ===
        Assert-ExitCode -Expected 0 -Actual $exitCode
        # Assert-FileExists -Path "$testDir\output.pem"
    }
    finally {
        # === CLEANUP (PowerShell only) ===
        Remove-Item -Path $testDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# === SUMMARY ===

Write-Host "`n=== Test Summary ===" -ForegroundColor White
Write-Host "Passed:  $script:TestsPassed" -ForegroundColor Green
Write-Host "Failed:  $script:TestsFailed" -ForegroundColor $(if ($script:TestsFailed -gt 0) { "Red" } else { "White" })
Write-Host "Skipped: $script:TestsSkipped" -ForegroundColor Yellow

exit $script:TestsFailed
```

## Rules

### Allowed

- One `certz.exe` call per test (the action under test)
- PowerShell for all setup and teardown
- Assertions against system state (files, certificate stores)

### Forbidden

- Multiple `certz.exe` calls in a single test
- Using `certz.exe` for setup or cleanup
- Asserting against console output (assert state instead)

## Test ID Naming

Use prefixes that match the command:

| Command | Prefix | Example |
|---------|--------|---------|
| create  | cre-   | cre-1.1 |
| inspect | ins-   | ins-2.1 |
| trust   | tru-   | tru-1.1 |
| lint    | lnt-   | lnt-1.1 |
| convert | cnv-   | cnv-1.1 |
| format  | fmt-   | fmt-1.1 |

## PowerShell Setup Examples

### Create test certificate

```powershell
$guid = [guid]::NewGuid().ToString().Substring(0, 8)
$cert = New-SelfSignedCertificate `
    -Subject "CN=certz-test-$guid" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -NotAfter (Get-Date).AddDays(30)
```

### Export to PEM

```powershell
$certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
$pemContent = "-----BEGIN CERTIFICATE-----`n"
$pemContent += [Convert]::ToBase64String($certBytes, [Base64FormattingOptions]::InsertLineBreaks)
$pemContent += "`n-----END CERTIFICATE-----"
Set-Content -Path "$testDir\test.pem" -Value $pemContent
```

### Cleanup certificate from store

```powershell
Get-ChildItem Cert:\CurrentUser\My |
    Where-Object { $_.Subject -like "*certz-test-$guid*" } |
    Remove-Item -Force
```

## Reference Files

- `test/test-create.ps1` - Create command tests
- `test/test-inspect.ps1` - Inspect command tests
- `test/test-convert.ps1` - Convert command tests
- `test/isolation-plan.md` - Full isolation requirements
- `test/coverage-analysis.md` - Test gap analysis
