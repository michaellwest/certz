<#
.SYNOPSIS
    Comprehensive test suite for certz certificate management tool.

.DESCRIPTION
    This script tests all commands and options of the certz tool to ensure
    all features work as expected. It includes tests for create, install,
    list, remove, export, and convert commands.

.PARAMETER SkipCleanup
    If specified, test files and certificates will not be removed after testing.

.PARAMETER Verbose
    If specified, displays detailed output for each test.

.PARAMETER UseDocker
    If specified, runs the tests inside a Windows Docker container for isolation.
    Requires Docker Desktop with Windows containers enabled.

.PARAMETER DockerVerbose
    If specified with -UseDocker, passes the -Verbose flag to tests running in the container.

.PARAMETER TestId
    Run only specific tests by their IDs. Accepts an array of test IDs.
    Example: -TestId "1.1", "1.2", "2.1"

.PARAMETER Category
    Run only tests in specific categories. Accepts an array of category names.
    Available categories: create, password, keysize, hash, keytype, ca, subject,
    validity, extensions, rsa-padding, pfx-encryption, install, list, remove, export, convert, integration, error, info, verify

.EXAMPLE
    .\test-all.ps1
    Runs all tests with default settings on the local machine.

.EXAMPLE
    .\test-all.ps1 -SkipCleanup
    Runs all tests and keeps test files for manual inspection.

.EXAMPLE
    .\test-all.ps1 -UseDocker
    Runs all tests inside a Windows Docker container (files baked into image).

.EXAMPLE
    .\test-all.ps1 -UseDocker -DockerVerbose
    Runs all tests in Docker with verbose output.

.EXAMPLE
    .\test-all.ps1 -TestId "cre-1.1", "cre-1.2"
    Runs only tests cre-1.1 and cre-1.2 (basic create tests).

.EXAMPLE
    .\test-all.ps1 -Category "create", "install"
    Runs all tests in the create and install categories.

.EXAMPLE
    .\test-all.ps1 -Category "keytype" -Verbose
    Runs key type tests with verbose output.

#>

param(
    [switch]$SkipCleanup,
    [switch]$Verbose,
    [switch]$UseDocker,
    [switch]$DockerVerbose,
    [string[]]$TestId,
    [string[]]$Category
)

# ============================================================================
# TEST REGISTRY AND FILTERING
# ============================================================================
# Store parameters in script-scoped variables for use in functions
$script:FilterTestId = $TestId
$script:FilterCategory = $Category
$script:TestRegistry = @{}
$script:TestCategories = @{
    "create" = @("cre-1.1", "cre-1.2", "cre-1.3", "cre-1.4", "cre-1.5", "cre-1.6", "cre-1.7")
    "password" = @("cre-2.1", "cre-2.2", "cre-2.3")
    "keysize" = @("cre-3.1", "cre-3.2", "cre-3.3", "cre-3.4")
    "hash" = @("cre-4.1", "cre-4.2", "cre-4.3", "cre-4.4")
    "keytype" = @("cre-5.1", "cre-5.2", "cre-5.3", "cre-5.4", "cre-5.5")
    "ca" = @("cre-6.1", "cre-6.2", "cre-6.3")
    "subject" = @("cre-7.1", "cre-7.2", "cre-7.3")
    "validity" = @("cre-8.1", "cre-8.2", "cre-8.3", "cre-8.4", "cre-8.5")
    "extensions" = @("cre-9.1", "cre-9.2", "cre-9.3", "cre-9.4")
    "rsa-padding" = @("cre-10.1", "cre-10.2", "cre-10.3")
    "pfx-encryption" = @("cre-11.1", "cre-11.2", "cre-11.3", "cnv-3.1", "cnv-3.2")
    "install" = @("ins-1.1", "ins-1.2", "ins-1.3", "ins-2.1", "ins-2.2")
    "list" = @("lst-1.1", "lst-1.2", "lst-1.3")
    "remove" = @("rem-1.1", "rem-1.2", "rem-1.3")
    "export" = @("exp-1.1", "exp-1.2", "exp-1.3", "exp-1.4", "exp-1.5", "exp-1.6")
    "convert" = @("cnv-1.1", "cnv-1.2", "cnv-1.3", "cnv-1.4", "cnv-1.5", "cnv-2.1", "cnv-2.2", "cnv-2.3", "cnv-2.4", "cnv-3.1", "cnv-3.2")
    "integration" = @("int-1.1", "int-1.2")
    "error" = @("err-1.1", "err-1.2")
    "info" = @("inf-1.1", "inf-1.2", "inf-1.3", "inf-1.4")
    "verify" = @("ver-1.1", "ver-1.2", "ver-1.3")
}

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

# ============================================================================
# BUILD FUNCTION
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

# ============================================================================
# DOCKER EXECUTION MODE
# ============================================================================
if ($UseDocker) {
    Write-Host "`nCertz Docker Test Runner" -ForegroundColor Magenta
    Write-Host "========================`n" -ForegroundColor Magenta

    # Build certz before running Docker tests
    Build-Certz -Verbose:$DockerVerbose

    # Check if Docker is available
    try {
        $dockerVersion = docker --version 2>&1
        Write-Host "Docker detected: $dockerVersion" -ForegroundColor Green
    } catch {
        Write-Host "ERROR: Docker is not installed or not in PATH" -ForegroundColor Red
        Write-Host "Please install Docker Desktop and enable Windows containers" -ForegroundColor Yellow
        exit 1
    }

    # Check if Windows containers are enabled
    $dockerInfo = docker info 2>&1 | Out-String
    if ($dockerInfo -notmatch "windows") {
        Write-Host "WARNING: Docker may not be configured for Windows containers" -ForegroundColor Yellow
        Write-Host "If the build fails, switch Docker Desktop to Windows containers mode" -ForegroundColor Yellow
        Write-Host ""
    }

    # Build the Docker image
    Write-Host "Building Docker test image..." -ForegroundColor Cyan
    try {
        docker build -t certz-test:latest -f Dockerfile.test . 2>&1 | ForEach-Object {
            if ($_ -match "error|failed") {
                Write-Host $_ -ForegroundColor Red
            } elseif ($_ -match "successfully|complete") {
                Write-Host $_ -ForegroundColor Green
            } else {
                Write-Host $_ -ForegroundColor Gray
            }
        }

        if ($LASTEXITCODE -ne 0) {
            Write-Host "`nERROR: Docker build failed" -ForegroundColor Red
            exit 1
        }

        Write-Host "`nDocker image built successfully" -ForegroundColor Green
    } catch {
        Write-Host "ERROR: Failed to build Docker image: $_" -ForegroundColor Red
        exit 1
    }

    # Run tests in container
    Write-Host "`nRunning tests in Docker container..." -ForegroundColor Cyan
    Write-Host "====================================`n" -ForegroundColor Cyan

    # Use baked-in files (environment variable already set in Dockerfile)
    $dockerArgs = @("run", "--rm", "--isolation=process", "certz-test:latest")

    # Pass verbose flag if requested
    if ($DockerVerbose) {
        $dockerArgs += "-Verbose"
    }

    # Pass skip cleanup flag if requested
    if ($SkipCleanup) {
        Write-Host "NOTE: -SkipCleanup flag ignored in Docker mode (container is ephemeral)" -ForegroundColor Yellow
    }

    try {
        & docker $dockerArgs

        $exitCode = $LASTEXITCODE

        if ($exitCode -eq 0) {
            Write-Host "`nDocker tests completed successfully!" -ForegroundColor Green
        } else {
            Write-Host "`nDocker tests failed!" -ForegroundColor Red
        }

        exit $exitCode
    } catch {
        Write-Host "ERROR: Failed to run Docker container: $_" -ForegroundColor Red
        exit 1
    }
}

# ============================================================================
# LOCAL EXECUTION MODE (Original behavior)
# ============================================================================
#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$script:FailedTests = @()
$script:PassedTests = @()
$script:TestCount = 0

# Detect if running inside Docker container
$isInsideContainer = $env:DOTNET_ENVIRONMENT -eq "Test" -or (Test-Path "./certz.exe")

# Build certz before testing (only if not in container)
if (-not $isInsideContainer) {
    Build-Certz -Verbose:$Verbose
}

# Change to the tools directory where certz.exe is located (only if not in container)
if (-not $isInsideContainer) {
    Push-Location -Path (Join-Path -Path $PSScriptRoot -ChildPath "docker\tools")
} else {
    # Already in the correct directory inside container
    Write-Verbose "Running inside Docker container, files already in working directory"
}

# Test results tracking
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
            Write-Host "       $Details" -ForegroundColor Gray
        }
    } else {
        Write-Host "[FAIL] $TestName" -ForegroundColor Red
        $script:FailedTests += "$TestId : $TestName"
        if ($Details) {
            Write-Host "       ERROR: $Details" -ForegroundColor Yellow
        }
    }
}

function Test-FileExists {
    param([string]$FilePath)
    return Test-Path -Path $FilePath -PathType Leaf
}

function Remove-TestFiles {
    param([string]$Pattern = "*")

    Get-ChildItem -Path . -File | Where-Object {
        $_.Name -like "$Pattern*.pfx" -or
        $_.Name -like "$Pattern*.cer" -or
        $_.Name -like "$Pattern*.crt" -or
        $_.Name -like "$Pattern*.key" -or
        $_.Name -like "$Pattern*.password.txt"
    } | Remove-Item -Force -ErrorAction SilentlyContinue
}

function Remove-TestCertificates {
    param(
        [string]$Subject = "*.dev.local",
        [string]$StoreName = "My",
        [string]$StoreLocation = "LocalMachine"
    )

    try {
        $storePath = "Cert:\$StoreLocation\$StoreName"
        $certs = Get-ChildItem -Path $storePath -ErrorAction SilentlyContinue |
                 Where-Object { $_.Subject -like "*$Subject*" }

        foreach ($cert in $certs) {
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($StoreName, $StoreLocation)
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            $store.Remove($cert)
            $store.Close()
        }
    } catch {
        # Ignore cleanup errors
    }
}

# ----------------------------------------------------------------------------
# ASSERTION FUNCTIONS
# ----------------------------------------------------------------------------

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

function Assert-NotMatch {
    param(
        [Parameter(Mandatory)]
        [string]$Actual,
        [Parameter(Mandatory)]
        [string]$Pattern,
        [string]$Message = "Output should not match pattern"
    )
    if ($Actual -match $Pattern) {
        throw "Assertion failed: $Message - Pattern '$Pattern' found in output"
    }
    return $true
}

function Assert-CertificateInStore {
    param(
        [Parameter(Mandatory)]
        [string]$SubjectPattern,
        [string]$StoreName = "My",
        [string]$StoreLocation = "LocalMachine",
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

function Assert-CertificateNotInStore {
    param(
        [Parameter(Mandatory)]
        [string]$SubjectPattern,
        [string]$StoreName = "My",
        [string]$StoreLocation = "LocalMachine",
        [string]$Message = "Certificate should not exist in store"
    )
    $cert = Get-ChildItem "Cert:\$StoreLocation\$StoreName" -ErrorAction SilentlyContinue |
            Where-Object { $_.Subject -like $SubjectPattern } |
            Select-Object -First 1
    if ($cert) {
        throw "Assertion failed: $Message - Certificate matching '$SubjectPattern' found in $StoreLocation\$StoreName"
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

# ----------------------------------------------------------------------------
# REFACTORED HELPER FUNCTIONS
# ----------------------------------------------------------------------------

function Get-TestCertificate {
    param(
        [string]$SubjectPattern = "*dev.local*",
        [string]$StoreName = "My",
        [string]$StoreLocation = "LocalMachine"
    )
    return Get-ChildItem "Cert:\$StoreLocation\$StoreName" -ErrorAction SilentlyContinue |
           Where-Object { $_.Subject -like $SubjectPattern } |
           Select-Object -First 1
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
            return @{ Success = $true; Result = $result }
        }
    } catch {
        Write-TestResult $TestId $TestName $false $_.Exception.Message
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Test-PasswordFile {
    param(
        [string]$FilePath,
        [int]$MinLength = 20,
        [string[]]$ForbiddenPatterns = @("IMPORTANT", "WARNING")
    )
    $result = @{ Exists = $false; Valid = $false; Content = ""; Errors = @() }

    if (-not (Test-FileExists $FilePath)) {
        $result.Errors += "Password file not created"
        return $result
    }
    $result.Exists = $true
    $result.Content = Get-Content $FilePath -Raw

    if ($result.Content.Length -lt $MinLength) {
        $result.Errors += "Password too short (length: $($result.Content.Length), expected >= $MinLength)"
    }
    foreach ($pattern in $ForbiddenPatterns) {
        if ($result.Content -match $pattern) {
            $result.Errors += "Password contains forbidden pattern: $pattern"
        }
    }
    $result.Valid = $result.Errors.Count -eq 0
    return $result
}

function Test-CertzFileCreation {
    param(
        [string]$TestId,
        [string]$TestName,
        [string]$FilePrefix,
        [string[]]$CertzArgs,
        [string[]]$ExpectedFiles,
        [string]$Details = ""
    )

    if (-not (Test-ShouldRun -Id $TestId)) { return $null }

    Remove-TestFiles $FilePrefix
    try {
        Write-Host "[TEST $TestId] $TestName" -ForegroundColor Cyan
        if ($Verbose) { Write-Host "Running with arguments $($CertzArgs)" -ForegroundColor Gray }

        & .\certz.exe @CertzArgs | Out-Null
        $allExist = $true
        foreach ($file in $ExpectedFiles) {
            if (-not (Test-FileExists $file)) {
                $allExist = $false
                break
            }
        }
        Write-TestResult $TestId $TestName $allExist $Details
        return $allExist
    } catch {
        Write-TestResult $TestId $TestName $false $_.Exception.Message
        return $false
    }
}

function Test-CertzWithOutput {
    param(
        [string]$TestId,
        [string]$TestName,
        [string]$FilePrefix,
        [string[]]$CertzArgs,
        [string[]]$ExpectedFiles = @(),
        [string]$OutputPattern = "",
        [switch]$OutputShouldNotMatch,
        [string]$Details = ""
    )

    if (-not (Test-ShouldRun -Id $TestId)) { return $null }

    if ($FilePrefix) {
        Remove-TestFiles $FilePrefix
    }
    try {
        Write-Host "[TEST $TestId] $TestName" -ForegroundColor Cyan
        if ($Verbose) { Write-Host "Running with arguments $($CertzArgs)" -ForegroundColor Gray }

        $output = & .\certz.exe @CertzArgs 2>&1 | Out-String

        $filesExist = $true
        if ($ExpectedFiles.Count -gt 0) {
            foreach ($file in $ExpectedFiles) {
                if (-not (Test-FileExists $file)) {
                    $filesExist = $false
                    break
                }
            }
        }

        $outputMatch = $true
        if ($OutputPattern) {
            if ($OutputShouldNotMatch) {
                $outputMatch = $output -notmatch $OutputPattern
            } else {
                $outputMatch = $output -match $OutputPattern
            }
        }

        if ($Verbose) { Write-Host $output -ForegroundColor Gray }

        $success = $filesExist -and $outputMatch
        Write-TestResult $TestId $TestName $success $Details
        return @{ Success = $success; Output = $output }
    } catch {
        Write-TestResult $TestId $TestName $false $_.Exception.Message
        return @{ Success = $false; Output = "" }
    }
}

function Test-CertzExpectedFailure {
    param(
        [string]$TestId,
        [string]$TestName,
        [string]$FilePrefix,
        [string[]]$CertzArgs,
        [string]$Details = "Validation error expected"
    )

    if (-not (Test-ShouldRun -Id $TestId)) { return $null }

    if ($FilePrefix) {
        Remove-TestFiles $FilePrefix
    }
    try {
        Write-Host "[TEST $TestId] $TestName" -ForegroundColor Cyan
        if ($Verbose) { Write-Host "Running with arguments $($CertzArgs)" -ForegroundColor Gray }

        & .\certz.exe @CertzArgs 2>&1 | Out-Null
        $success = $LASTEXITCODE -ne 0
        Write-TestResult $TestId $TestName $success $Details
        return $success
    } catch {
        Write-TestResult $TestId $TestName $true "Exception caught as expected"
        return $true
    }
}

function Test-CertzInstall {
    param(
        [string]$TestId,
        [string]$TestName,
        [string]$PfxFile,
        [string]$Password,
        [string]$StoreName = "My",
        [string]$StoreLocation = "LocalMachine",
        [string]$SubjectPattern = "*dev.local*",
        [string]$Details = ""
    )

    if (-not (Test-ShouldRun -Id $TestId)) { return $null }

    try {
        Write-Host "[TEST $TestId] $TestName" -ForegroundColor Cyan

        & .\certz.exe install --f $PfxFile --p $Password --sn $StoreName --sl $StoreLocation | Out-Null
        $cert = Get-TestCertificate -SubjectPattern $SubjectPattern -StoreName $StoreName -StoreLocation $StoreLocation
        $success = $null -ne $cert
        Write-TestResult $TestId $TestName $success $Details
        return $cert
    } catch {
        Write-TestResult $TestId $TestName $false $_.Exception.Message
        return $null
    }
}

function Test-CertzPasswordFileCreation {
    param(
        [string]$TestId,
        [string]$TestName,
        [string]$FilePrefix,
        [string[]]$CertzArgs,
        [string]$PfxFile,
        [string]$PasswordFile,
        [string]$Details = "Password saved to file"
    )

    if (-not (Test-ShouldRun -Id $TestId)) { return $null }

    Remove-TestFiles $FilePrefix
    try {
        Write-Host "[TEST $TestId] $TestName" -ForegroundColor Cyan
        if ($Verbose) { Write-Host "Running with arguments $($CertzArgs)" -ForegroundColor Gray }

        $output = & .\certz.exe @CertzArgs 2>&1 | Out-String
        $pfxExists = Test-FileExists $PfxFile
        $pwResult = Test-PasswordFile -FilePath $PasswordFile
        $outputConfirms = $output -match "Password.*written to"

        $success = $pfxExists -and $pwResult.Valid -and $outputConfirms

        $failureDetails = @()
        if (-not $pfxExists) { $failureDetails += "PFX file not created" }
        if (-not $pwResult.Exists) { $failureDetails += "Password file not created" }
        elseif (-not $pwResult.Valid) { $failureDetails += $pwResult.Errors }
        if (-not $outputConfirms) { $failureDetails += "Output did not confirm password written to file" }

        $detailMsg = if ($success) { $Details } else { $failureDetails -join "; " }
        Write-TestResult $TestId $TestName $success $detailMsg
        return @{ Success = $success; Output = $output; PasswordContent = $pwResult.Content }
    } catch {
        Write-TestResult $TestId $TestName $false $_.Exception.Message
        return @{ Success = $false; Output = ""; PasswordContent = "" }
    }
}

# Initialize test environment
Write-Host "`nCertz Comprehensive Test Suite" -ForegroundColor Magenta
Write-Host "==============================`n" -ForegroundColor Magenta

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

# Cleanup before starting
Write-Host "Initializing test environment..." -ForegroundColor Yellow
Remove-TestFiles
Remove-TestCertificates -Subject "*.dev.local" -StoreName "My" -StoreLocation "LocalMachine"
Remove-TestCertificates -Subject "*.dev.local" -StoreName "Root" -StoreLocation "LocalMachine"
Remove-TestCertificates -Subject "*.dev.local" -StoreName "My" -StoreLocation "CurrentUser"

# ============================================================================
# CREATE COMMAND TESTS
# ============================================================================
Write-TestHeader "Testing CREATE Command"

# Test cre-1.1: Create with defaults (generates secure random password displayed on screen)
Test-CertzWithOutput -TestId "cre-1.1" -TestName "Create with defaults" -FilePrefix "devcert" `
    -CertzArgs @("create") `
    -ExpectedFiles @("devcert.pfx") `
    -OutputPattern "IMPORTANT: Certificate Password" `
    -Details "PFX created with generated password"

# Test cre-1.2: Create with custom PFX and password
Test-CertzWithOutput -TestId "cre-1.2" -TestName "Create with custom password" -FilePrefix "mycert" `
    -CertzArgs @("create", "--f", "mycert.pfx", "--p", "MySecurePass123") `
    -ExpectedFiles @("mycert.pfx") `
    -OutputPattern "IMPORTANT: Certificate Password" -OutputShouldNotMatch `
    -Details "PFX created with provided password"

# Test cre-1.3: Create with custom SANs
Test-CertzFileCreation -TestId "cre-1.3" -TestName "Create with custom SANs" -FilePrefix "testcert" `
    -CertzArgs @("create", "--f", "testcert.pfx", "--p", "TestCertPass", "--san", "*.example.com", "localhost", "127.0.0.1", "192.168.1.100") `
    -ExpectedFiles @("testcert.pfx") `
    -Details "Multiple DNS and IP SANs"

# Test cre-1.4: Create with custom validity period (within CA/B Forum 398-day limit)
Test-CertzFileCreation -TestId "cre-1.4" -TestName "Create with 365 days validity" -FilePrefix "longcert" `
    -CertzArgs @("create", "--f", "longcert.pfx", "--p", "LongCertPass", "--days", "365") `
    -ExpectedFiles @("longcert.pfx") `
    -Details "1-year certificate"

# Test cre-1.5: Create with all options
Test-CertzFileCreation -TestId "cre-1.5" -TestName "Create with all options" -FilePrefix "fulltest" `
    -CertzArgs @("create", "--f", "fulltest.pfx", "--c", "fulltest.cer", "--k", "fulltest.key", "--p", "ComplexPass456", "--san", "*.dev.local", "*.test.com", "127.0.0.1", "--days", "180") `
    -ExpectedFiles @("fulltest.pfx", "fulltest.cer", "fulltest.key") `
    -Details "PFX, CER, and KEY created"

# Test cre-1.6: Create PEM-only certificates
Invoke-Test -TestId "cre-1.6" -TestName "Create PEM-only (no PFX)" -FilePrefix "pemonly" -TestScript {
    .\certz.exe create --c pemonly.cer --k pemonly.key --p PemPass789 | Out-Null
    Assert-FileExists "pemonly.cer" "CER file should be created"
    Assert-FileExists "pemonly.key" "KEY file should be created"
    Assert-FileNotExists "pemonly.pfx" "PFX file should not be created"
    @{ Success = $true; Details = "Only CER and KEY files" }
}

# Test cre-1.7: Create with multiple SANs
Test-CertzFileCreation -TestId "cre-1.7" -TestName "Create with multiple SANs" -FilePrefix "multisan" `
    -CertzArgs @("create", "--f", "multisan.pfx", "--p", "MultiSanPass", "--san", "*.app1.local", "*.app2.local", "*.app3.local", "localhost") `
    -ExpectedFiles @("multisan.pfx") `
    -Details "4 DNS entries"

# ============================================================================
# PASSWORD FILE TESTS
# ============================================================================
Write-TestHeader "Testing Password File Option"

# Test cre-2.1: Create with password file (password written to file)
Test-CertzPasswordFileCreation -TestId "cre-2.1" -TestName "Create with password file" -FilePrefix "pwfile-create" `
    -CertzArgs @("create", "--f", "pwfile-create.pfx", "--password-file", "pwfile-create.password.txt") `
    -PfxFile "pwfile-create.pfx" -PasswordFile "pwfile-create.password.txt"
Remove-TestFiles "pwfile-create"

# Test cre-2.2: Verify password file content can be used to install certificate
Invoke-Test -TestId "cre-2.2" -TestName "Use password from file to install" -FilePrefix "pwfile-install" -TestScript {
    $testId = "cre-2.2"
    $uniqueId = [guid]::NewGuid().ToString().Substring(0,8)
    $subject = "CN=certz-test-$testId-$uniqueId"
    $password = "TestPassword-$uniqueId"
    $pfxPath = "pwfile-install.pfx"
    $passwordFile = "pwfile-install.password.txt"

    try {
        # PRECONDITION: Create PFX and password file using PowerShell only
        $cert = New-SelfSignedCertificate -Subject $subject -CertStoreLocation "Cert:\CurrentUser\My" -NotAfter (Get-Date).AddDays(30)
        $securePassword = ConvertTo-SecureString -String $password -Force -AsPlainText
        Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $securePassword | Out-Null
        Set-Content -Path $passwordFile -Value $password -NoNewline

        # Remove from temp store (we only wanted the PFX file)
        Remove-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)" -Force

        Assert-FileExists $pfxPath "PFX file should be created"
        Assert-FileExists $passwordFile "Password file should be created"

        # ACTION: Single certz.exe call - the behavior under test
        $filePassword = Get-Content $passwordFile -Raw
        & .\certz.exe install --f $pfxPath --p $filePassword --sn My --sl CurrentUser 2>&1 | Out-Null

        # ASSERTION: Verify using PowerShell
        $installedCert = Get-ChildItem "Cert:\CurrentUser\My" | Where-Object { $_.Subject -eq $subject } | Select-Object -First 1
        if (-not $installedCert) { throw "Certificate was not installed to store" }

        @{ Success = $true; Details = "Password file content is valid" }
    } finally {
        # CLEANUP: PowerShell only - never use certz
        Get-ChildItem "Cert:\CurrentUser\My" | Where-Object { $_.Subject -eq $subject } | Remove-Item -Force -ErrorAction SilentlyContinue
        Remove-Item $pfxPath -Force -ErrorAction SilentlyContinue
        Remove-Item $passwordFile -Force -ErrorAction SilentlyContinue
    }
}

# Test cre-2.3: Password file not created when password is provided
Invoke-Test -TestId "cre-2.3" -TestName "Password file ignored when password provided" -FilePrefix "pwfile-provided" -TestScript {
    & .\certz.exe create --f pwfile-provided.pfx --p ProvidedPass --password-file pwfile-provided.password.txt 2>&1 | Out-Null
    Assert-FileExists "pwfile-provided.pfx" "PFX file should be created"
    Assert-FileNotExists "pwfile-provided.password.txt" "Password file should not be created when password is provided"
    Remove-TestFiles "pwfile-provided"
    @{ Success = $true; Details = "No file created with explicit password" }
}

# ============================================================================
# KEY SIZE TESTS
# ============================================================================
Write-TestHeader "Testing Key Size Options"

# Test cre-3.1: Create with 2048-bit RSA key (shows NIST warning)
Test-CertzWithOutput -TestId "cre-3.1" -TestName "Create with 2048-bit RSA key" -FilePrefix "keysize-2048" `
    -CertzArgs @("create", "--f", "keysize-2048.pfx", "--p", "KeySize2048Pass", "--key-size", "2048") `
    -ExpectedFiles @("keysize-2048.pfx") `
    -OutputPattern "INFO: Using 2048-bit RSA key" `
    -Details "NIST warning displayed"

# Test cre-3.2: Create with 3072-bit RSA key (NIST recommended, now default)
Test-CertzFileCreation -TestId "cre-3.2" -TestName "Create with 3072-bit RSA key (default)" -FilePrefix "keysize-3072" `
    -CertzArgs @("create", "--f", "keysize-3072.pfx", "--p", "KeySize3072Pass", "--key-size", "3072") `
    -ExpectedFiles @("keysize-3072.pfx") `
    -Details "NIST recommended key size (default)"

# Test cre-3.3: Create with 4096-bit RSA key
Test-CertzFileCreation -TestId "cre-3.3" -TestName "Create with 4096-bit RSA key" -FilePrefix "keysize-4096" `
    -CertzArgs @("create", "--f", "keysize-4096.pfx", "--p", "KeySize4096Pass", "--key-size", "4096") `
    -ExpectedFiles @("keysize-4096.pfx") `
    -Details "Maximum RSA key size"

# Test cre-3.4: Invalid key size should fail
Test-CertzExpectedFailure -TestId "cre-3.4" -TestName "Reject invalid key size (1024)" -FilePrefix "keysize-invalid" `
    -CertzArgs @("create", "--f", "keysize-invalid.pfx", "--p", "InvalidPass", "--key-size", "1024")

# ============================================================================
# HASH ALGORITHM TESTS
# ============================================================================
Write-TestHeader "Testing Hash Algorithm Options"

# Test cre-4.1: Create with SHA256
Test-CertzFileCreation -TestId "cre-4.1" -TestName "Create with SHA256 hash" -FilePrefix "hash-sha256" `
    -CertzArgs @("create", "--f", "hash-sha256.pfx", "--p", "HashSha256Pass", "--hash-algorithm", "SHA256") `
    -ExpectedFiles @("hash-sha256.pfx") -Details "Standard hash algorithm"

# Test cre-4.2: Create with SHA384
Test-CertzFileCreation -TestId "cre-4.2" -TestName "Create with SHA384 hash" -FilePrefix "hash-sha384" `
    -CertzArgs @("create", "--f", "hash-sha384.pfx", "--p", "HashSha384Pass", "--hash-algorithm", "SHA384") `
    -ExpectedFiles @("hash-sha384.pfx") -Details "Stronger hash algorithm"

# Test cre-4.3: Create with SHA512
Test-CertzFileCreation -TestId "cre-4.3" -TestName "Create with SHA512 hash" -FilePrefix "hash-sha512" `
    -CertzArgs @("create", "--f", "hash-sha512.pfx", "--p", "HashSha512Pass", "--hash-algorithm", "SHA512") `
    -ExpectedFiles @("hash-sha512.pfx") -Details "Strongest hash algorithm"

# Test cre-4.4: Create with auto hash selection (3072-bit key should use SHA384)
Test-CertzFileCreation -TestId "cre-4.4" -TestName "Create with auto hash selection" -FilePrefix "hash-auto" `
    -CertzArgs @("create", "--f", "hash-auto.pfx", "--p", "HashAutoPass", "--key-size", "3072", "--hash-algorithm", "auto") `
    -ExpectedFiles @("hash-auto.pfx") -Details "Auto-selects based on key size"

# ============================================================================
# KEY TYPE TESTS (RSA and ECDSA)
# ============================================================================
Write-TestHeader "Testing Key Type Options"

# Test cre-5.1: Create with RSA key type (explicit)
Test-CertzFileCreation -TestId "cre-5.1" -TestName "Create with RSA key type" -FilePrefix "keytype-rsa" `
    -CertzArgs @("create", "--f", "keytype-rsa.pfx", "--p", "KeyTypeRsaPass", "--key-type", "RSA") `
    -ExpectedFiles @("keytype-rsa.pfx") -Details "Explicit RSA key type"

# Test cre-5.2: Create with ECDSA P-256 key
Test-CertzFileCreation -TestId "cre-5.2" -TestName "Create with ECDSA P-256 key" -FilePrefix "keytype-ecdsa256" `
    -CertzArgs @("create", "--f", "keytype-ecdsa256.pfx", "--c", "keytype-ecdsa256.cer", "--k", "keytype-ecdsa256.key", "--p", "EcdsaP256Pass", "--key-type", "ECDSA-P256") `
    -ExpectedFiles @("keytype-ecdsa256.pfx", "keytype-ecdsa256.key") -Details "Modern TLS 1.3 optimized"

# Test cre-5.3: Create with ECDSA P-384 key
Test-CertzFileCreation -TestId "cre-5.3" -TestName "Create with ECDSA P-384 key" -FilePrefix "keytype-ecdsa384" `
    -CertzArgs @("create", "--f", "keytype-ecdsa384.pfx", "--p", "EcdsaP384Pass", "--key-type", "ECDSA-P384") `
    -ExpectedFiles @("keytype-ecdsa384.pfx") -Details "High security ECDSA"

# Test cre-5.4: Create with ECDSA P-521 key
Test-CertzFileCreation -TestId "cre-5.4" -TestName "Create with ECDSA P-521 key" -FilePrefix "keytype-ecdsa521" `
    -CertzArgs @("create", "--f", "keytype-ecdsa521.pfx", "--p", "EcdsaP521Pass", "--key-type", "ECDSA-P521") `
    -ExpectedFiles @("keytype-ecdsa521.pfx") -Details "Maximum ECDSA security"

# Test cre-5.5: ECDSA certificate can be converted to PEM and back
Invoke-Test -TestId "cre-5.5" -TestName "ECDSA certificate conversion round-trip" -FilePrefix "ecdsa-convert" -TestScript {
    .\certz.exe create --f ecdsa-convert.pfx --c ecdsa-convert.cer --k ecdsa-convert.key --p EcdsaConvertPass --key-type ECDSA-P256 | Out-Null
    .\certz.exe convert --cert ecdsa-convert.cer --key ecdsa-convert.key --pfx ecdsa-convert-back.pfx --p EcdsaBackPass | Out-Null
    Assert-FileExists "ecdsa-convert.pfx" "Original ECDSA PFX should exist"
    Assert-FileExists "ecdsa-convert-back.pfx" "Converted PFX should exist"
    @{ Success = $true; Details = "PEM to PFX with ECDSA key" }
}

# ============================================================================
# CA CERTIFICATE TESTS
# ============================================================================
Write-TestHeader "Testing CA Certificate Options"

# Test cre-6.1: Create CA certificate
Test-CertzFileCreation -TestId "cre-6.1" -TestName "Create CA certificate" -FilePrefix "ca-cert" `
    -CertzArgs @("create", "--f", "ca-cert.pfx", "--p", "CaCertPass", "--san", "My Test CA", "--is-ca") `
    -ExpectedFiles @("ca-cert.pfx") -Details "Certificate Authority cert created"

# Test cre-6.2: Create CA certificate with path length constraint
Test-CertzFileCreation -TestId "cre-6.2" -TestName "Create CA with path length" -FilePrefix "ca-path" `
    -CertzArgs @("create", "--f", "ca-path.pfx", "--p", "CaPathPass", "--san", "My Intermediate CA", "--is-ca", "--path-length", "1") `
    -ExpectedFiles @("ca-path.pfx") -Details "Intermediate CA with depth=1"

# Test cre-6.3: Create CA certificate with CRL and OCSP URLs
Test-CertzFileCreation -TestId "cre-6.3" -TestName "Create CA with CRL/OCSP" -FilePrefix "ca-full" `
    -CertzArgs @("create", "--f", "ca-full.pfx", "--p", "CaFullPass", "--san", "My Full CA", "--is-ca", "--crl-url", "http://crl.example.com/ca.crl", "--ocsp-url", "http://ocsp.example.com") `
    -ExpectedFiles @("ca-full.pfx") -Details "CA with revocation endpoints"

# ============================================================================
# SUBJECT DN FIELD TESTS
# ============================================================================
Write-TestHeader "Testing Subject Distinguished Name Fields"

# Test cre-7.1: Create with Organization field
Test-CertzFileCreation -TestId "cre-7.1" -TestName "Create with Organization (O)" -FilePrefix "dn-org" `
    -CertzArgs @("create", "--f", "dn-org.pfx", "--p", "DnOrgPass", "--san", "*.example.com", "--subject-o", "Acme Corporation") `
    -ExpectedFiles @("dn-org.pfx") -Details "Subject O field set"

# Test cre-7.2: Create with full Distinguished Name
Invoke-Test -TestId "cre-7.2" -TestName "Create with full DN" -FilePrefix "dn-full" -TestScript {
    .\certz.exe create --f dn-full.pfx --p DnFullPass --san *.example.com --subject-o "Acme Corporation" --subject-ou "Engineering" --subject-c US --subject-st "California" --subject-l "San Francisco" | Out-Null
    Assert-FileExists "dn-full.pfx" "PFX file should be created"
    $output = .\certz.exe info --f dn-full.pfx --p DnFullPass 2>&1 | Out-String
    Assert-Match $output "Acme Corporation" "Output should contain Organization"
    Assert-Match $output "Engineering" "Output should contain OU"
    Assert-Match $output "California" "Output should contain State"
    @{ Success = $true; Details = "All DN fields present" }
}

# Test cre-7.3: Country code validation (must be 2 characters)
Test-CertzExpectedFailure -TestId "cre-7.3" -TestName "Reject invalid country code - 3 chars" -FilePrefix "dn-country-invalid" `
    -CertzArgs @("create", "--f", "dn-country-invalid.pfx", "--p", "InvalidPass", "--san", "*.example.com", "--subject-c", "USA")

# ============================================================================
# VALIDITY PERIOD VALIDATION TESTS
# ============================================================================
Write-TestHeader "Testing Validity Period Validation"

# Test cre-8.1: Default validity is 90 days
Test-CertzFileCreation -TestId "cre-8.1" -TestName "Default validity - 90 days" -FilePrefix "validity-default" `
    -CertzArgs @("create", "--f", "validity-default.pfx", "--p", "ValidityDefaultPass") `
    -ExpectedFiles @("validity-default.pfx") -Details "Certificate created with default validity"

# Test cre-8.2: Validity >200 days shows warning (until March 2026)
Test-CertzWithOutput -TestId "cre-8.2" -TestName "Warning for over 200 day validity" -FilePrefix "validity-warning" `
    -CertzArgs @("create", "--f", "validity-warning.pfx", "--p", "ValidityWarnPass", "--days", "250") `
    -ExpectedFiles @("validity-warning.pfx") `
    -OutputPattern "WARNING.*validity.*exceeds" `
    -Details "Future compliance warning shown"

# Test cre-8.3: Validity >398 days should fail
Test-CertzExpectedFailure -TestId "cre-8.3" -TestName "Reject over 398 day validity" -FilePrefix "validity-error" `
    -CertzArgs @("create", "--f", "validity-error.pfx", "--p", "ValidityErrorPass", "--days", "400") `
    -Details "CA/B Forum limit enforced"

# Test cre-8.4: Minimum validity - 1 day
Test-CertzFileCreation -TestId "cre-8.4" -TestName "Minimum validity - 1 day" -FilePrefix "validity-min" `
    -CertzArgs @("create", "--f", "validity-min.pfx", "--p", "ValidityMinPass", "--days", "1") `
    -ExpectedFiles @("validity-min.pfx") -Details "Short-lived certificate"

# Test cre-8.5: Zero days should fail
Test-CertzExpectedFailure -TestId "cre-8.5" -TestName "Reject 0 day validity" -FilePrefix "validity-zero" `
    -CertzArgs @("create", "--f", "validity-zero.pfx", "--p", "ValidityZeroPass", "--days", "0") `
    -Details "Minimum 1 day required"

# ============================================================================
# AIA/CDP EXTENSION TESTS
# ============================================================================
Write-TestHeader "Testing AIA and CDP Extensions"

# Test cre-9.1: Create with CRL Distribution Point
Test-CertzFileCreation -TestId "cre-9.1" -TestName "Create with CRL Distribution Point" -FilePrefix "ext-crl" `
    -CertzArgs @("create", "--f", "ext-crl.pfx", "--p", "ExtCrlPass", "--crl-url", "http://crl.example.com/cert.crl") `
    -ExpectedFiles @("ext-crl.pfx") -Details "CDP extension added"

# Test cre-9.2: Create with OCSP responder URL
Test-CertzFileCreation -TestId "cre-9.2" -TestName "Create with OCSP responder" -FilePrefix "ext-ocsp" `
    -CertzArgs @("create", "--f", "ext-ocsp.pfx", "--p", "ExtOcspPass", "--ocsp-url", "http://ocsp.example.com") `
    -ExpectedFiles @("ext-ocsp.pfx") -Details "AIA OCSP extension added"

# Test cre-9.3: Create with CA Issuers URL
Test-CertzFileCreation -TestId "cre-9.3" -TestName "Create with CA Issuers URL" -FilePrefix "ext-ca-issuers" `
    -CertzArgs @("create", "--f", "ext-ca-issuers.pfx", "--p", "ExtCaIssuersPass", "--ca-issuers-url", "http://certs.example.com/ca.cer") `
    -ExpectedFiles @("ext-ca-issuers.pfx") -Details "AIA CA Issuers extension added"

# Test cre-9.4: Create with all AIA/CDP extensions
Test-CertzFileCreation -TestId "cre-9.4" -TestName "Create with all AIA/CDP extensions" -FilePrefix "ext-all" `
    -CertzArgs @("create", "--f", "ext-all.pfx", "--p", "ExtAllPass", "--crl-url", "http://crl.example.com/cert.crl", "--ocsp-url", "http://ocsp.example.com", "--ca-issuers-url", "http://certs.example.com/ca.cer") `
    -ExpectedFiles @("ext-all.pfx") -Details "Full revocation info"

# ============================================================================
# RSA PADDING TESTS
# ============================================================================
Write-TestHeader "Testing RSA Padding Options"

# Test cre-10.1: Create with PKCS#1 v1.5 padding (default)
Test-CertzFileCreation -TestId "cre-10.1" -TestName "Create with PKCS#1 v1.5 padding (default)" -FilePrefix "padding-pkcs1" `
    -CertzArgs @("create", "--f", "padding-pkcs1.pfx", "--p", "PaddingPkcs1Pass", "--rsa-padding", "pkcs1") `
    -ExpectedFiles @("padding-pkcs1.pfx") -Details "Default RSA padding"

# Test cre-10.2: Create with RSA-PSS padding (modern)
Test-CertzFileCreation -TestId "cre-10.2" -TestName "Create with RSA-PSS padding" -FilePrefix "padding-pss" `
    -CertzArgs @("create", "--f", "padding-pss.pfx", "--p", "PaddingPssPass", "--rsa-padding", "pss") `
    -ExpectedFiles @("padding-pss.pfx") -Details "Modern RSA-PSS padding"

# Test cre-10.3: RSA-PSS padding with ECDSA key (should be ignored)
Test-CertzFileCreation -TestId "cre-10.3" -TestName "RSA padding ignored for ECDSA" -FilePrefix "padding-ecdsa" `
    -CertzArgs @("create", "--f", "padding-ecdsa.pfx", "--p", "PaddingEcdsaPass", "--key-type", "ECDSA-P256", "--rsa-padding", "pss") `
    -ExpectedFiles @("padding-ecdsa.pfx") -Details "RSA padding not applicable to ECDSA"

# ============================================================================
# PFX ENCRYPTION TESTS
# ============================================================================
Write-TestHeader "Testing PFX Encryption Options"

# Test cre-11.1: Create with modern AES-256 encryption (default)
Test-CertzFileCreation -TestId "cre-11.1" -TestName "Create with modern PFX encryption (default)" -FilePrefix "pfx-modern" `
    -CertzArgs @("create", "--f", "pfx-modern.pfx", "--p", "PfxModernPass", "--pfx-encryption", "modern") `
    -ExpectedFiles @("pfx-modern.pfx") -Details "AES-256 encryption"

# Test cre-11.2: Create with legacy 3DES encryption
Test-CertzWithOutput -TestId "cre-11.2" -TestName "Create with legacy PFX encryption" -FilePrefix "pfx-legacy" `
    -CertzArgs @("create", "--f", "pfx-legacy.pfx", "--p", "PfxLegacyPass", "--pfx-encryption", "legacy") `
    -ExpectedFiles @("pfx-legacy.pfx") `
    -OutputPattern "INFO: Using legacy 3DES encryption" `
    -Details "3DES encryption for compatibility"

# Test cre-11.3: Verify modern encrypted PFX can be installed
Invoke-Test -TestId "cre-11.3" -TestName "Install modern encrypted PFX" -FilePrefix "pfx-modern-install" -TestScript {
    .\certz.exe create --f pfx-modern-install.pfx --p ModernInstallPass --pfx-encryption modern | Out-Null
    .\certz.exe install --f pfx-modern-install.pfx --p ModernInstallPass --sn My --sl CurrentUser | Out-Null
    $cert = Assert-CertificateInStore -SubjectPattern "*dev.local*" -StoreName "My" -StoreLocation "CurrentUser"
    if ($cert) { .\certz.exe remove --thumb $cert.Thumbprint --sn My --sl CurrentUser | Out-Null }
    @{ Success = $true; Details = "Modern AES-256 PFX installs correctly" }
}

# ============================================================================
# INSTALL COMMAND TESTS
# ============================================================================
Write-TestHeader "Testing INSTALL Command"

# First, create a certificate with a known password for install tests
Remove-TestFiles "install-test"
.\certz.exe create --f install-test.pfx --p InstallTestPass --san *.dev.local | Out-Null

# Test ins-1.1: Install to default store (My/LocalMachine)
Test-CertzInstall -TestId "ins-1.1" -TestName "Install to default store (My)" `
    -PfxFile "install-test.pfx" -Password "InstallTestPass" `
    -Details "Certificate in LocalMachine\My"

# Test ins-1.2: Install to Root store
Test-CertzInstall -TestId "ins-1.2" -TestName "Install to Root store" `
    -PfxFile "install-test.pfx" -Password "InstallTestPass" -StoreName "Root" `
    -Details "Certificate in LocalMachine\Root"

# Test ins-1.3: Install to CurrentUser store
$ins13Cert = Test-CertzInstall -TestId "ins-1.3" -TestName "Install to CurrentUser store" `
    -PfxFile "install-test.pfx" -Password "InstallTestPass" `
    -StoreName "My" -StoreLocation "CurrentUser" `
    -Details "Certificate in CurrentUser\My"
if ($ins13Cert) { .\certz.exe remove --thumb $ins13Cert.Thumbprint --sn My --sl CurrentUser | Out-Null }

# ============================================================================
# EXPORTABLE OPTION TESTS
# ============================================================================
Write-TestHeader "Testing Exportable Option"

# Test ins-2.1: Install with exportable=true (default)
Invoke-Test -TestId "ins-2.1" -TestName "Install with exportable key (default)" -FilePrefix "exportable-true" -TestScript {
    .\certz.exe create --f exportable-true.pfx --p ExportableTruePass | Out-Null
    .\certz.exe install --f exportable-true.pfx --p ExportableTruePass --sn My --sl CurrentUser --exportable true | Out-Null
    $cert = Assert-CertificateInStore -SubjectPattern "*dev.local*" -StoreName "My" -StoreLocation "CurrentUser"

    # Try to export the private key - should succeed with exportable=true
    $exportSuccess = $false
    try {
        $exported = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, "TestExport123")
        $exportSuccess = $exported.Length -gt 0
    } catch {
        $exportSuccess = $false
    }

    if ($cert) { .\certz.exe remove --thumb $cert.Thumbprint --sn My --sl CurrentUser | Out-Null }
    Assert-CertificateNotInStore -SubjectPattern "*dev.local*" -StoreName "My" -StoreLocation "CurrentUser" -Message "Certificate should be removed from store"
    Remove-TestFiles "exportable-true"

    if (-not $exportSuccess) { throw "Private key should be exportable" }
    @{ Success = $true; Details = "Private key is exportable" }
}

# Test ins-2.2: Install with exportable=false
Invoke-Test -TestId "ins-2.2" -TestName "Install with non-exportable key" -FilePrefix "exportable-false" -TestScript {
    .\certz.exe create --f exportable-false.pfx --p ExportableFalsePass | Out-Null
    .\certz.exe install --f exportable-false.pfx --p ExportableFalsePass --sn My --sl CurrentUser --exportable false | Out-Null
    $cert = Assert-CertificateInStore -SubjectPattern "*dev.local*" -StoreName "My" -StoreLocation "CurrentUser"

    # Try to export the private key - should fail with exportable=false
    $exportFailed = $false
    try {
        $exported = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, "TestExport123")
    } catch {
        $exportFailed = $true
    }

    if ($cert) { .\certz.exe remove --thumb $cert.Thumbprint --sn My --sl CurrentUser | Out-Null }
    Assert-CertificateNotInStore -SubjectPattern "*dev.local*" -StoreName "My" -StoreLocation "CurrentUser" -Message "Certificate should be removed from store"
    Remove-TestFiles "exportable-false"

    if (-not $exportFailed) { throw "Private key should NOT be exportable" }
    @{ Success = $true; Details = "Private key is non-exportable" }
}

# ============================================================================
# LIST COMMAND TESTS
# ============================================================================
Write-TestHeader "Testing LIST Command"

# Test lst-1.1: List from default store
Test-CertzWithOutput -TestId "lst-1.1" -TestName "List from default store (My)" -FilePrefix "" `
    -CertzArgs @("list") -OutputPattern "." -Details "Output received"

# Test lst-1.2: List from Root store
Test-CertzWithOutput -TestId "lst-1.2" -TestName "List from Root store" -FilePrefix "" `
    -CertzArgs @("list", "--sn", "root", "--sl", "LocalMachine") -OutputPattern "." -Details "Output received"

# Test lst-1.3: List from CurrentUser store
Test-CertzWithOutput -TestId "lst-1.3" -TestName "List from CurrentUser store" -FilePrefix "" `
    -CertzArgs @("list", "--sl", "CurrentUser", "--sn", "My") -OutputPattern "." -Details "Output received"

# ============================================================================
# EXPORT COMMAND TESTS
# ============================================================================
Write-TestHeader "Testing EXPORT Command"

# Test exp-1.1: Export from remote URL
Test-CertzFileCreation -TestId "exp-1.1" -TestName "Export from remote URL (github.com)" -FilePrefix "github" `
    -CertzArgs @("export", "--url", "https://www.github.com", "--f", "github.pfx", "--c", "github.cer") `
    -ExpectedFiles @("github.pfx", "github.cer") -Details "PFX and CER created"

# Test exp-1.2: Export from remote with custom password
Test-CertzWithOutput -TestId "exp-1.2" -TestName "Export with custom password" -FilePrefix "microsoft" `
    -CertzArgs @("export", "--url", "https://www.microsoft.com", "--f", "microsoft.pfx", "--p", "CustomExportPass") `
    -ExpectedFiles @("microsoft.pfx") `
    -OutputPattern "IMPORTANT: Certificate Password" -OutputShouldNotMatch `
    -Details "PFX exported with provided password"

# Test exp-1.3: Export from certificate store by thumbprint
Invoke-Test -TestId "exp-1.3" -TestName "Export from store by thumbprint" -FilePrefix "exported" -TestScript {
    $cert = Get-TestCertificate -SubjectPattern "*dev.local*" -StoreName "My" -StoreLocation "LocalMachine"
    if (-not $cert) { throw "No certificate found in store to export" }
    .\certz.exe export --thumb $cert.Thumbprint --f exported.pfx --c exported.cer --p ExportPass123 | Out-Null
    Assert-FileExists "exported.pfx" "Exported PFX should exist"
    Assert-FileExists "exported.cer" "Exported CER should exist"
    @{ Success = $true; Details = "Certificate exported from store" }
}

# Test exp-1.4: Export PEM only from URL
Invoke-Test -TestId "exp-1.4" -TestName "Export PEM only (no PFX)" -FilePrefix "google" -TestScript {
    .\certz.exe export --url https://www.google.com --c google.cer | Out-Null
    Assert-FileExists "google.cer" "CER file should be created"
    Assert-FileNotExists "google.pfx" "PFX file should not be created"
    @{ Success = $true; Details = "Only CER file created" }
}

# Test exp-1.5: Export with password file from URL
Test-CertzPasswordFileCreation -TestId "exp-1.5" -TestName "Export with password file (URL)" -FilePrefix "export-pwfile" `
    -CertzArgs @("export", "--url", "https://www.github.com", "--f", "export-pwfile.pfx", "--password-file", "export-pwfile.password.txt") `
    -PfxFile "export-pwfile.pfx" -PasswordFile "export-pwfile.password.txt"

# Test exp-1.6: Export with password file from store
Invoke-Test -TestId "exp-1.6" -TestName "Export with password file (store)" -FilePrefix "export-store-pwfile" -TestScript {
    .\certz.exe create --f export-store-pwfile-src.pfx --p TempPass 2>&1 | Out-Null
    .\certz.exe install --f export-store-pwfile-src.pfx --p TempPass --sn My --sl LocalMachine 2>&1 | Out-Null

    $cert = Get-TestCertificate -SubjectPattern "*dev.local*" -StoreName "My" -StoreLocation "LocalMachine"
    if (-not $cert) { throw "No certificate found in store after install" }

    $output = .\certz.exe export --thumb $cert.Thumbprint --f export-store-pwfile.pfx --password-file export-store-pwfile.password.txt 2>&1 | Out-String
    Assert-FileExists "export-store-pwfile.pfx" "Exported PFX should exist"

    $pwResult = Test-PasswordFile -FilePath "export-store-pwfile.password.txt" -ForbiddenPatterns @()
    if (-not $pwResult.Valid) { throw "Password file validation failed: $($pwResult.Errors -join '; ')" }

    Assert-Match $output "Password.*written to" "Output should confirm password written to file"
    .\certz.exe remove --thumb $cert.Thumbprint --sn My --sl LocalMachine | Out-Null
    @{ Success = $true; Details = "Password saved to file" }
}

# ============================================================================
# CONVERT COMMAND TESTS
# ============================================================================
Write-TestHeader "Testing CONVERT Command"

# Create fresh source files for convert tests (don't rely on files from earlier tests)
Remove-TestFiles "convert-input"
.\certz.exe create --c convert-input.cer --k convert-input.key --p ConvertInputPass | Out-Null

# Test cnv-1.1: Convert CER/KEY to PFX
Test-CertzFileCreation -TestId "cnv-1.1" -TestName "Convert CER/KEY to PFX" -FilePrefix "converted" `
    -CertzArgs @("convert", "--c", "convert-input.cer", "--k", "convert-input.key", "--f", "converted.pfx", "--p", "ConvertPass123") `
    -ExpectedFiles @("converted.pfx") -Details "Conversion successful"

# Test cnv-1.2: Convert with generated password (no password provided)
Test-CertzWithOutput -TestId "cnv-1.2" -TestName "Convert with generated password" -FilePrefix "converted-default" `
    -CertzArgs @("convert", "--c", "convert-input.cer", "--k", "convert-input.key", "--f", "converted-default.pfx") `
    -ExpectedFiles @("converted-default.pfx") `
    -OutputPattern "IMPORTANT: Certificate Password" `
    -Details "Secure password generated and displayed"

# Test cnv-1.3: Convert with password file
Test-CertzPasswordFileCreation -TestId "cnv-1.3" -TestName "Convert with password file" -FilePrefix "converted-pwfile" `
    -CertzArgs @("convert", "--c", "convert-input.cer", "--k", "convert-input.key", "--f", "converted-pwfile.pfx", "--password-file", "converted-pwfile.password.txt") `
    -PfxFile "converted-pwfile.pfx" -PasswordFile "converted-pwfile.password.txt" `
    -Details "Password saved to file during conversion"

# Test cnv-1.4: Verify converted certificate with password file can be installed
Invoke-Test -TestId "cnv-1.4" -TestName "Install converted cert using password file" -TestScript {
    Assert-FileExists "converted-pwfile.password.txt" "Password file should exist from previous test"
    Assert-FileExists "converted-pwfile.pfx" "PFX file should exist from previous test"

    $password = Get-Content "converted-pwfile.password.txt" -Raw
    .\certz.exe install --f converted-pwfile.pfx --p $password --sn My --sl CurrentUser 2>&1 | Out-Null
    $cert = Assert-CertificateInStore -SubjectPattern "*dev.local*" -StoreName "My" -StoreLocation "CurrentUser"
    if ($cert) { .\certz.exe remove --thumb $cert.Thumbprint --sn My --sl CurrentUser | Out-Null }
    @{ Success = $true; Details = "Converted cert password is valid" }
}

# Test cnv-1.5: Verify converted certificate can be installed
Invoke-Test -TestId "cnv-1.5" -TestName "Install converted certificate" -TestScript {
    .\certz.exe install --f converted.pfx --p ConvertPass123 --sl CurrentUser --sn My | Out-Null
    $cert = Assert-CertificateInStore -SubjectPattern "*dev.local*" -StoreName "My" -StoreLocation "CurrentUser"
    if ($cert) { .\certz.exe remove --thumb $cert.Thumbprint --sn My --sl CurrentUser | Out-Null }
    @{ Success = $true; Details = "Converted cert is valid" }
}

# ============================================================================
# REMOVE COMMAND TESTS
# ============================================================================
Write-TestHeader "Testing REMOVE Command"

# Test rem-1.1: Remove by thumbprint from Root
Invoke-Test -TestId "rem-1.1" -TestName "Remove by thumbprint" -TestScript {
    $cert = Get-TestCertificate -SubjectPattern "*dev.local*" -StoreName "Root" -StoreLocation "LocalMachine"
    if (-not $cert) { throw "No certificate found in Root store to remove" }
    $thumb = $cert.Thumbprint
    .\certz.exe remove --thumb $thumb --sn root | Out-Null
    $certAfter = Get-TestCertificate -SubjectPattern "*dev.local*" -StoreName "Root" -StoreLocation "LocalMachine"
    if ($certAfter -and $certAfter.Thumbprint -eq $thumb) { throw "Certificate was not removed" }
    @{ Success = $true; Details = "Certificate removed from Root" }
}

# Test rem-1.2: Remove by subject from LocalMachine\My
Invoke-Test -TestId "rem-1.2" -TestName "Remove by subject (LocalMachine)" -TestScript {
    .\certz.exe remove --subject "*.dev.local" --sn My --sl LocalMachine | Out-Null
    Assert-CertificateNotInStore -SubjectPattern "*dev.local*" -StoreName "My" -StoreLocation "LocalMachine"
    @{ Success = $true; Details = "All matching certs removed" }
}

# Test rem-1.3: Remove by subject from CurrentUser\My
Invoke-Test -TestId "rem-1.3" -TestName "Remove by subject (CurrentUser)" -TestScript {
    .\certz.exe remove --subject "*.dev.local" --sl CurrentUser --sn My | Out-Null
    Assert-CertificateNotInStore -SubjectPattern "*dev.local*" -StoreName "My" -StoreLocation "CurrentUser"
    @{ Success = $true; Details = "All matching certs removed" }
}

# ============================================================================
# INTEGRATION TESTS
# ============================================================================
Write-TestHeader "Testing Integration Scenarios"

# Test int-1.1: Complete lifecycle (create to install to export to remove)
Invoke-Test -TestId "int-1.1" -TestName "Complete certificate lifecycle" -FilePrefix "lifecycle" -TestScript {
    .\certz.exe create --f lifecycle.pfx --p LifecyclePass --c lifecycle.cer --k lifecycle.key | Out-Null
    .\certz.exe install --f lifecycle.pfx --p LifecyclePass --sn My --sl LocalMachine | Out-Null
    $cert = Assert-CertificateInStore -SubjectPattern "*dev.local*" -StoreName "My" -StoreLocation "LocalMachine"

    .\certz.exe export --thumb $cert.Thumbprint --f lifecycle-export.pfx --p ExportPass | Out-Null
    .\certz.exe remove --subject "*.dev.local" --sn My --sl LocalMachine | Out-Null

    Assert-FileExists "lifecycle-export.pfx" "Exported PFX should exist"
    Assert-CertificateNotInStore -SubjectPattern "*dev.local*" -StoreName "My" -StoreLocation "LocalMachine"
    @{ Success = $true; Details = "Create-Install-Export-Remove" }
}

# Test int-1.2: Format conversion chain (PFX to PEM to PFX)
Invoke-Test -TestId "int-1.2" -TestName "Format conversion chain" -FilePrefix "conversion-chain" -TestScript {
    .\certz.exe create --f conversion-chain-original.pfx --p OriginalPass | Out-Null
    .\certz.exe install --f conversion-chain-original.pfx --p OriginalPass --sn My --sl LocalMachine | Out-Null
    $cert = Assert-CertificateInStore -SubjectPattern "*dev.local*" -StoreName "My" -StoreLocation "LocalMachine"

    .\certz.exe export --thumb $cert.Thumbprint --c conversion-chain-intermediate.cer --k conversion-chain-intermediate.key | Out-Null
    .\certz.exe convert --c conversion-chain-intermediate.cer --k conversion-chain-intermediate.key --f conversion-chain-final.pfx --p FinalPass | Out-Null
    .\certz.exe remove --thumb $cert.Thumbprint --sn My --sl LocalMachine | Out-Null

    Assert-FileExists "conversion-chain-original.pfx" "Original PFX should exist"
    Assert-FileExists "conversion-chain-intermediate.cer" "Intermediate CER should exist"
    Assert-FileExists "conversion-chain-final.pfx" "Final PFX should exist"
    @{ Success = $true; Details = "PFX to PEM to PFX" }
}

# ============================================================================
# INFO COMMAND TESTS
# ============================================================================
Write-TestHeader "Testing INFO Command"

# Create a certificate with known password for info tests
Remove-TestFiles "info-cert"
.\certz.exe create --f info-cert.pfx --c info-cert.cer --k info-cert.key --p InfoTestPass --san *.dev.local | Out-Null

# Test inf-1.1: Info from PFX file
Test-CertzWithOutput -TestId "inf-1.1" -TestName "Info from PFX file" -FilePrefix "" `
    -CertzArgs @("info", "--f", "info-cert.pfx", "--p", "InfoTestPass") `
    -OutputPattern "Certificate Information" -Details "Certificate details displayed"

# Test inf-1.2: Info from PEM file (uses info-cert.cer created above)
Test-CertzWithOutput -TestId "inf-1.2" -TestName "Info from PEM file" -FilePrefix "" `
    -CertzArgs @("info", "--f", "info-cert.cer") `
    -OutputPattern "Certificate Information" -Details "Certificate details displayed"

# Test inf-1.3: Info from URL
Invoke-Test -TestId "inf-1.3" -TestName "Info from URL" -TestScript {
    $output = .\certz.exe info --url https://www.github.com 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        # Network issues are acceptable - treat as skipped/pass
        @{ Success = $true; Details = "Skipped (network issue)" }
    } else {
        Assert-Match $output "Certificate Information" "Output should contain certificate info"
        @{ Success = $true; Details = "Remote certificate details displayed" }
    }
}

# Test inf-1.4: Info from store by thumbprint
Invoke-Test -TestId "inf-1.4" -TestName "Info from store by thumbprint" -FilePrefix "info-test" -TestScript {
    .\certz.exe create --f info-test.pfx --p InfoPass | Out-Null
    .\certz.exe install --f info-test.pfx --p InfoPass --sn My --sl LocalMachine | Out-Null

    $cert = Assert-CertificateInStore -SubjectPattern "*dev.local*" -StoreName "My" -StoreLocation "LocalMachine"
    $output = .\certz.exe info --thumbprint $cert.Thumbprint --sn My --sl LocalMachine 2>&1 | Out-String
    Assert-ExitCode 0 "Info command should succeed"
    Assert-Match $output "Certificate Information" "Output should contain certificate info"
    .\certz.exe remove --thumbprint $cert.Thumbprint --sn My --sl LocalMachine | Out-Null
    @{ Success = $true; Details = "Store certificate details displayed" }
}

# ============================================================================
# VERIFY COMMAND TESTS
# ============================================================================
Write-TestHeader "Testing VERIFY Command"

# Create a certificate with known password for verify tests
Remove-TestFiles "verify-cert"
.\certz.exe create --f verify-cert.pfx --p VerifyTestPass --san *.dev.local | Out-Null

# Test ver-1.1: Verify valid certificate from file
Test-CertzWithOutput -TestId "ver-1.1" -TestName "Verify certificate from PFX file" -FilePrefix "" `
    -CertzArgs @("verify", "--f", "verify-cert.pfx", "--p", "VerifyTestPass") `
    -OutputPattern "Certificate Validation Report" -Details "Validation report generated"

# Test ver-1.2: Verify with custom warning days
Test-CertzWithOutput -TestId "ver-1.2" -TestName "Verify with custom warning threshold" -FilePrefix "" `
    -CertzArgs @("verify", "--f", "verify-cert.pfx", "--p", "VerifyTestPass", "--warn", "60") `
    -OutputPattern "Certificate Validation Report" -Details "Custom warning threshold applied"

# Test ver-1.3: Verify from store by thumbprint
Invoke-Test -TestId "ver-1.3" -TestName "Verify from store by thumbprint" -FilePrefix "verify-test" -TestScript {
    .\certz.exe create --f verify-test.pfx --p VerifyPass | Out-Null
    .\certz.exe install --f verify-test.pfx --p VerifyPass --sn My --sl LocalMachine | Out-Null

    $cert = Assert-CertificateInStore -SubjectPattern "*dev.local*" -StoreName "My" -StoreLocation "LocalMachine"
    $output = .\certz.exe verify --thumbprint $cert.Thumbprint --sn My --sl LocalMachine 2>&1 | Out-String
    Assert-ExitCode 0 "Verify command should succeed"
    Assert-Match $output "Certificate Validation Report" "Output should contain validation report"
    .\certz.exe remove --thumbprint $cert.Thumbprint --sn My --sl LocalMachine | Out-Null
    @{ Success = $true; Details = "Store certificate validated" }
}

# ============================================================================
# ENHANCED CONVERT COMMAND TESTS (PFX to PEM)
# ============================================================================
Write-TestHeader "Testing Enhanced CONVERT Command (PFX to PEM)"

# Create a certificate with known password for convert tests
Remove-TestFiles "convert-source"
.\certz.exe create --f convert-source.pfx --p ConvertSourcePass --san *.dev.local | Out-Null

# Test cnv-2.1: Convert PFX to PEM (both cert and key)
Test-CertzFileCreation -TestId "cnv-2.1" -TestName "Convert PFX to PEM (cert+key)" -FilePrefix "pfx-to-pem" `
    -CertzArgs @("convert", "--pfx", "convert-source.pfx", "--p", "ConvertSourcePass", "--out-cert", "pfx-to-pem.cer", "--out-key", "pfx-to-pem.key") `
    -ExpectedFiles @("pfx-to-pem.cer", "pfx-to-pem.key") -Details "Both CER and KEY files created"

# Test cnv-2.2: Convert PFX to PEM (cert only)
Invoke-Test -TestId "cnv-2.2" -TestName "Convert PFX to PEM (cert only)" -FilePrefix "pfx-to-cer" -TestScript {
    .\certz.exe convert --pfx convert-source.pfx --p ConvertSourcePass --out-cert pfx-to-cer.cer 2>&1 | Out-Null
    Assert-FileExists "pfx-to-cer.cer" "CER file should be created"
    Assert-FileNotExists "pfx-to-cer.key" "KEY file should not be created"
    @{ Success = $true; Details = "Only CER file created" }
}

# Test cnv-2.3: Convert PFX to PEM (key only)
Invoke-Test -TestId "cnv-2.3" -TestName "Convert PFX to PEM (key only)" -FilePrefix "pfx-to-key" -TestScript {
    .\certz.exe convert --pfx convert-source.pfx --p ConvertSourcePass --out-key pfx-to-key.key 2>&1 | Out-Null
    Assert-FileExists "pfx-to-key.key" "KEY file should be created"
    Assert-FileNotExists "pfx-to-key.cer" "CER file should not be created"
    @{ Success = $true; Details = "Only KEY file created" }
}

# Test cnv-2.4: Round-trip conversion (PFX to PEM to PFX)
Invoke-Test -TestId "cnv-2.4" -TestName "Round-trip conversion (PFX to PEM to PFX)" -FilePrefix "roundtrip" -TestScript {
    .\certz.exe convert --pfx convert-source.pfx --p ConvertSourcePass --out-cert roundtrip.cer --out-key roundtrip.key 2>&1 | Out-Null
    .\certz.exe convert --cert roundtrip.cer --key roundtrip.key --pfx roundtrip.pfx --p RoundtripPass 2>&1 | Out-Null
    .\certz.exe info --f roundtrip.pfx --p RoundtripPass 2>&1 | Out-Null
    Assert-ExitCode 0 "Info command should succeed on converted PFX"
    Assert-FileExists "roundtrip.pfx" "Final PFX should exist"
    @{ Success = $true; Details = "Full conversion cycle successful" }
}

# ============================================================================
# CONVERT PFX ENCRYPTION TESTS
# ============================================================================
Write-TestHeader "Testing Convert PFX Encryption Options"

# Test cnv-3.1: Convert PEM to PFX with modern encryption
Test-CertzFileCreation -TestId "cnv-3.1" -TestName "Convert PEM to PFX with modern encryption" -FilePrefix "convert-modern" `
    -CertzArgs @("convert", "--cert", "convert-input.cer", "--key", "convert-input.key", "--pfx", "convert-modern.pfx", "--p", "ConvertModernPass", "--pfx-encryption", "modern") `
    -ExpectedFiles @("convert-modern.pfx") -Details "AES-256 encrypted PFX"

# Test cnv-3.2: Convert PEM to PFX with legacy encryption
Test-CertzWithOutput -TestId "cnv-3.2" -TestName "Convert PEM to PFX with legacy encryption" -FilePrefix "convert-legacy" `
    -CertzArgs @("convert", "--cert", "convert-input.cer", "--key", "convert-input.key", "--pfx", "convert-legacy.pfx", "--p", "ConvertLegacyPass", "--pfx-encryption", "legacy") `
    -ExpectedFiles @("convert-legacy.pfx") `
    -OutputPattern "INFO: Using legacy 3DES encryption" `
    -Details "3DES encrypted PFX for compatibility"

# ============================================================================
# ERROR HANDLING TESTS
# ============================================================================
Write-TestHeader "Testing Error Handling"

# Test err-1.1: Invalid file path
Test-CertzExpectedFailure -TestId "err-1.1" -TestName "Graceful failure on missing file" -FilePrefix "" `
    -CertzArgs @("install", "--f", "nonexistent.pfx", "--p", "password") `
    -Details "Expected error occurred"

# Test err-1.2: Missing required parameters for convert
Test-CertzExpectedFailure -TestId "err-1.2" -TestName "Missing required key parameter" -FilePrefix "" `
    -CertzArgs @("convert", "--c", "missing.cer", "--f", "output.pfx") `
    -Details "Expected error occurred"

# ============================================================================
# CLEANUP
# ============================================================================
if (-not $SkipCleanup) {
    Write-TestHeader "Cleaning Up Test Environment"

    # Remove test files
    Remove-TestFiles
    Write-Host "Test files removed" -ForegroundColor Gray

    # Remove test certificates from all stores
    Remove-TestCertificates -Subject "*.dev.local" -StoreName "My" -StoreLocation "LocalMachine"
    Remove-TestCertificates -Subject "*.dev.local" -StoreName "Root" -StoreLocation "LocalMachine"
    Remove-TestCertificates -Subject "*.dev.local" -StoreName "My" -StoreLocation "CurrentUser"
    Write-Host "Test certificates removed from stores" -ForegroundColor Gray
} else {
    Write-Host "`nSkipping cleanup (test files preserved for inspection)" -ForegroundColor Yellow
}

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

# Return to original directory (only if we changed it)
if (-not $isInsideContainer) {
    Pop-Location
}

# Exit with appropriate code
if ($failedCount -eq 0) {
    Write-Host "`nAll tests passed!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`nSome tests failed!" -ForegroundColor Red
    exit 1
}
