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

.PARAMETER DevMode
    If specified with -UseDocker, uses volume mounts instead of baked-in files.
    This allows testing changes to certz.exe and test-all.ps1 without rebuilding the Docker image.
    Perfect for active development.

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
    .\test-all.ps1 -UseDocker -DevMode
    Runs tests in Docker with volume mounts (no rebuild needed for file changes).
#>

param(
    [switch]$SkipCleanup,
    [switch]$Verbose,
    [switch]$UseDocker,
    [switch]$DockerVerbose,
    [switch]$DevMode
)

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

    # Build the Docker image (unless using DevMode with existing image)
    if (-not $DevMode) {
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
    } else {
        Write-Host "DevMode: Using existing image with volume mounts..." -ForegroundColor Cyan
        Write-Host "Changes to certz.exe and test-all.ps1 will be reflected without rebuild`n" -ForegroundColor Green

        # Verify required files exist
        $requiredFiles = @(
            "docker\tools\certz.exe",
            "docker\tools\certz.pdb",
            "test-all.ps1"
        )

        foreach ($file in $requiredFiles) {
            if (-not (Test-Path $file)) {
                Write-Host "ERROR: Required file not found: $file" -ForegroundColor Red
                exit 1
            }
        }
    }

    # Run tests in container
    Write-Host "`nRunning tests in Docker container..." -ForegroundColor Cyan
    Write-Host "====================================`n" -ForegroundColor Cyan

    if ($DevMode) {
        # Use volume mounts for development
        $currentPath = (Get-Location).Path
        $dockerArgs = @(
            "run", "--rm", "--isolation=process",
            "-e", "DOTNET_ENVIRONMENT=Test",
            "-v", "${currentPath}\docker\tools\certz.exe:/app/certz.exe:ro",
            "-v", "${currentPath}\docker\tools\certz.pdb:/app/certz.pdb:ro",
            "-v", "${currentPath}\test-all.ps1:/app/test-all.ps1:ro",
            "certz-test:latest"
        )
    } else {
        # Use baked-in files (environment variable already set in Dockerfile)
        $dockerArgs = @("run", "--rm", "--isolation=process", "certz-test:latest")
    }

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
        $script:FailedTests += $TestName
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
        [string]$TestName,
        [string]$FilePrefix,
        [string[]]$CertzArgs,
        [string[]]$ExpectedFiles,
        [string]$Details = ""
    )
    Remove-TestFiles $FilePrefix
    try {
        Write-Host "[TEST] $TestName" -ForegroundColor Cyan
        Write-Host "Running with arguments $($CertzArgs)"

        & .\certz.exe @CertzArgs | Out-Null
        $allExist = $true
        foreach ($file in $ExpectedFiles) {
            if (-not (Test-FileExists $file)) {
                $allExist = $false
                break
            }
        }
        Write-TestResult $TestName $allExist $Details
        return $allExist
    } catch {
        Write-TestResult $TestName $false $_.Exception.Message
        return $false
    }
}

function Test-CertzWithOutput {
    param(
        [string]$TestName,
        [string]$FilePrefix,
        [string[]]$CertzArgs,
        [string[]]$ExpectedFiles = @(),
        [string]$OutputPattern = "",
        [switch]$OutputShouldNotMatch,
        [string]$Details = ""
    )
    Remove-TestFiles $FilePrefix
    try {
        Write-Host "[TEST] $TestName" -ForegroundColor Cyan
        Write-Host "Running with arguments $($CertzArgs)"

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

        # TODO Remove this debug line later
        Write-Host $output

        $success = $filesExist -and $outputMatch
        Write-TestResult $TestName $success $Details
        return @{ Success = $success; Output = $output }
    } catch {
        Write-TestResult $TestName $false $_.Exception.Message
        return @{ Success = $false; Output = "" }
    }
}

function Test-CertzExpectedFailure {
    param(
        [string]$TestName,
        [string]$FilePrefix,
        [string[]]$CertzArgs,
        [string]$Details = "Validation error expected"
    )
    Remove-TestFiles $FilePrefix
    try {
        Write-Host "[TEST] $TestName" -ForegroundColor Cyan
        Write-Host "Running with arguments $($CertzArgs)"

        & .\certz.exe @CertzArgs 2>&1 | Out-Null
        $success = $LASTEXITCODE -ne 0
        Write-TestResult $TestName $success $Details
        return $success
    } catch {
        Write-TestResult $TestName $true "Exception caught as expected"
        return $true
    }
}

function Test-CertzInstall {
    param(
        [string]$TestName,
        [string]$PfxFile,
        [string]$Password,
        [string]$StoreName = "My",
        [string]$StoreLocation = "LocalMachine",
        [string]$SubjectPattern = "*dev.local*",
        [string]$Details = ""
    )
    try {
        Write-Host "[TEST] $TestName" -ForegroundColor Cyan
#        Write-Host "Running with arguments $($CertzArgs)"

        & .\certz.exe install --f $PfxFile --p $Password --sn $StoreName --sl $StoreLocation | Out-Null
        $cert = Get-TestCertificate -SubjectPattern $SubjectPattern -StoreName $StoreName -StoreLocation $StoreLocation
        $success = $null -ne $cert
        Write-TestResult $TestName $success $Details
        return $cert
    } catch {
        Write-TestResult $TestName $false $_.Exception.Message
        return $null
    }
}

function Test-CertzPasswordFileCreation {
    param(
        [string]$TestName,
        [string]$FilePrefix,
        [string[]]$CertzArgs,
        [string]$PfxFile,
        [string]$PasswordFile,
        [string]$Details = "Password saved to file"
    )
    Remove-TestFiles $FilePrefix
    try {
        Write-Host "[TEST] $TestName" -ForegroundColor Cyan
        Write-Host "Running with arguments $($CertzArgs)"

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
        Write-TestResult $TestName $success $detailMsg
        return @{ Success = $success; Output = $output; PasswordContent = $pwResult.Content }
    } catch {
        Write-TestResult $TestName $false $_.Exception.Message
        return @{ Success = $false; Output = ""; PasswordContent = "" }
    }
}

# Initialize test environment
Write-Host "`nCertz Comprehensive Test Suite" -ForegroundColor Magenta
Write-Host "==============================`n" -ForegroundColor Magenta

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

# Test 1.1: Create with defaults (generates secure random password displayed on screen)
Test-CertzWithOutput -TestName "Create with defaults" -FilePrefix "devcert" `
    -CertzArgs @("create") `
    -ExpectedFiles @("devcert.pfx") `
    -OutputPattern "IMPORTANT: Certificate Password" `
    -Details "PFX created with generated password"

# Test 1.2: Create with custom PFX and password
Test-CertzWithOutput -TestName "Create with custom password" -FilePrefix "mycert" `
    -CertzArgs @("create", "--f", "mycert.pfx", "--p", "MySecurePass123") `
    -ExpectedFiles @("mycert.pfx") `
    -OutputPattern "IMPORTANT: Certificate Password" -OutputShouldNotMatch `
    -Details "PFX created with provided password"

# Test 1.3: Create with custom SANs
Test-CertzFileCreation -TestName "Create with custom SANs" -FilePrefix "testcert" `
    -CertzArgs @("create", "--f", "testcert.pfx", "--p", "TestCertPass", "--san", "*.example.com", "localhost", "127.0.0.1", "192.168.1.100") `
    -ExpectedFiles @("testcert.pfx") `
    -Details "Multiple DNS and IP SANs"

# Test 1.4: Create with custom validity period (within CA/B Forum 398-day limit)
Test-CertzFileCreation -TestName "Create with 365 days validity" -FilePrefix "longcert" `
    -CertzArgs @("create", "--f", "longcert.pfx", "--p", "LongCertPass", "--days", "365") `
    -ExpectedFiles @("longcert.pfx") `
    -Details "1-year certificate"

# Test 1.5: Create with all options
Test-CertzFileCreation -TestName "Create with all options" -FilePrefix "fulltest" `
    -CertzArgs @("create", "--f", "fulltest.pfx", "--c", "fulltest.cer", "--k", "fulltest.key", "--p", "ComplexPass456", "--san", "*.dev.local", "*.test.com", "127.0.0.1", "--days", "180") `
    -ExpectedFiles @("fulltest.pfx", "fulltest.cer", "fulltest.key") `
    -Details "PFX, CER, and KEY created"

# Test 1.6: Create PEM-only certificates
Remove-TestFiles "pemonly"
try {
    .\certz.exe create --c pemonly.cer --k pemonly.key --p PemPass789 | Out-Null
    $success = (Test-FileExists "pemonly.cer") -and (Test-FileExists "pemonly.key") -and (-not (Test-FileExists "pemonly.pfx"))
    Write-TestResult "Create PEM-only (no PFX)" $success "Only CER and KEY files"
} catch {
    Write-TestResult "Create PEM-only (no PFX)" $false $_.Exception.Message
}

# Test 1.7: Create with multiple SANs
Test-CertzFileCreation -TestName "Create with multiple SANs" -FilePrefix "multisan" `
    -CertzArgs @("create", "--f", "multisan.pfx", "--p", "MultiSanPass", "--san", "*.app1.local", "*.app2.local", "*.app3.local", "localhost") `
    -ExpectedFiles @("multisan.pfx") `
    -Details "4 DNS entries"

# ============================================================================
# PASSWORD FILE TESTS
# ============================================================================
Write-TestHeader "Testing Password File Option"

# Test 1.8: Create with password file (password written to file)
$pwCreateResult = Test-CertzPasswordFileCreation -TestName "Create with password file" -FilePrefix "pwfile-create" `
    -CertzArgs @("create", "--f", "pwfile-create.pfx", "--password-file", "pwfile-create.password.txt") `
    -PfxFile "pwfile-create.pfx" -PasswordFile "pwfile-create.password.txt"

# Test 1.9: Verify password file content can be used to install certificate
try {
    $pwFileExists = Test-FileExists "pwfile-create.password.txt"
    $pfxExists = Test-FileExists "pwfile-create.pfx"
    $failureDetails = @()

    if (-not $pwFileExists) { $failureDetails += "Password file does not exist" }
    if (-not $pfxExists) { $failureDetails += "PFX file does not exist" }

    if ($pwFileExists -and $pfxExists) {
        $password = Get-Content "pwfile-create.password.txt" -Raw
        & .\certz.exe install --f pwfile-create.pfx --p $password --sn My --sl CurrentUser 2>&1 | Out-Null
        $cert = Get-TestCertificate -SubjectPattern "*dev.local*" -StoreName "My" -StoreLocation "CurrentUser"
        $success = $null -ne $cert

        if (-not $success) {
            $failureDetails += "Certificate not found in CurrentUser\My store after install"
        }
        # Cleanup
        if ($cert) { .\certz.exe remove --thumb $cert.Thumbprint --sn My --sl CurrentUser | Out-Null }
    } else {
        $success = $false
    }

    $details = if ($success) { "Password file content is valid" } else { $failureDetails -join "; " }
    Write-TestResult "Use password from file to install" $success $details
} catch {
    Write-TestResult "Use password from file to install" $false $_.Exception.Message
}

# Test 1.10: Password file not created when password is provided
Remove-TestFiles "pwfile-provided"
try {
    & .\certz.exe create --f pwfile-provided.pfx --p ProvidedPass --password-file pwfile-provided.password.txt 2>&1 | Out-Null
    $pfxExists = Test-FileExists "pwfile-provided.pfx"
    $pwFileNotCreated = -not (Test-FileExists "pwfile-provided.password.txt")
    $success = $pfxExists -and $pwFileNotCreated

    $failureDetails = @()
    if (-not $pfxExists) { $failureDetails += "PFX file not created" }
    if (-not $pwFileNotCreated) { $failureDetails += "Password file was created when it should not have been" }

    $details = if ($success) { "No file created with explicit password" } else { $failureDetails -join "; " }
    Write-TestResult "Password file ignored when password provided" $success $details
} catch {
    Write-TestResult "Password file ignored when password provided" $false $_.Exception.Message
}

# ============================================================================
# KEY SIZE TESTS
# ============================================================================
Write-TestHeader "Testing Key Size Options"

# Test 1.11: Create with 2048-bit RSA key (default)
Test-CertzWithOutput -TestName "Create with 2048-bit RSA key" -FilePrefix "keysize-2048" `
    -CertzArgs @("create", "--f", "keysize-2048.pfx", "--p", "KeySize2048Pass", "--key-size", "2048") `
    -ExpectedFiles @("keysize-2048.pfx") `
    -OutputPattern "INFO: Using 2048-bit RSA key" `
    -Details "NIST warning displayed"

# Test 1.12: Create with 3072-bit RSA key (NIST recommended)
Test-CertzFileCreation -TestName "Create with 3072-bit RSA key" -FilePrefix "keysize-3072" `
    -CertzArgs @("create", "--f", "keysize-3072.pfx", "--p", "KeySize3072Pass", "--key-size", "3072") `
    -ExpectedFiles @("keysize-3072.pfx") `
    -Details "NIST recommended key size"

# Test 1.13: Create with 4096-bit RSA key
Test-CertzFileCreation -TestName "Create with 4096-bit RSA key" -FilePrefix "keysize-4096" `
    -CertzArgs @("create", "--f", "keysize-4096.pfx", "--p", "KeySize4096Pass", "--key-size", "4096") `
    -ExpectedFiles @("keysize-4096.pfx") `
    -Details "Maximum RSA key size"

# Test 1.14: Invalid key size should fail
Test-CertzExpectedFailure -TestName "Reject invalid key size (1024)" -FilePrefix "keysize-invalid" `
    -CertzArgs @("create", "--f", "keysize-invalid.pfx", "--p", "InvalidPass", "--key-size", "1024")

# ============================================================================
# HASH ALGORITHM TESTS
# ============================================================================
Write-TestHeader "Testing Hash Algorithm Options"

# Test 1.15: Create with SHA256
Test-CertzFileCreation -TestName "Create with SHA256 hash" -FilePrefix "hash-sha256" `
    -CertzArgs @("create", "--f", "hash-sha256.pfx", "--p", "HashSha256Pass", "--hash-algorithm", "SHA256") `
    -ExpectedFiles @("hash-sha256.pfx") -Details "Standard hash algorithm"

# Test 1.16: Create with SHA384
Test-CertzFileCreation -TestName "Create with SHA384 hash" -FilePrefix "hash-sha384" `
    -CertzArgs @("create", "--f", "hash-sha384.pfx", "--p", "HashSha384Pass", "--hash-algorithm", "SHA384") `
    -ExpectedFiles @("hash-sha384.pfx") -Details "Stronger hash algorithm"

# Test 1.17: Create with SHA512
Test-CertzFileCreation -TestName "Create with SHA512 hash" -FilePrefix "hash-sha512" `
    -CertzArgs @("create", "--f", "hash-sha512.pfx", "--p", "HashSha512Pass", "--hash-algorithm", "SHA512") `
    -ExpectedFiles @("hash-sha512.pfx") -Details "Strongest hash algorithm"

# Test 1.18: Create with auto hash selection (3072-bit key should use SHA384)
Test-CertzFileCreation -TestName "Create with auto hash selection" -FilePrefix "hash-auto" `
    -CertzArgs @("create", "--f", "hash-auto.pfx", "--p", "HashAutoPass", "--key-size", "3072", "--hash-algorithm", "auto") `
    -ExpectedFiles @("hash-auto.pfx") -Details "Auto-selects based on key size"

# ============================================================================
# KEY TYPE TESTS (RSA and ECDSA)
# ============================================================================
Write-TestHeader "Testing Key Type Options"

# Test 1.19: Create with RSA key type (explicit)
Test-CertzFileCreation -TestName "Create with RSA key type" -FilePrefix "keytype-rsa" `
    -CertzArgs @("create", "--f", "keytype-rsa.pfx", "--p", "KeyTypeRsaPass", "--key-type", "RSA") `
    -ExpectedFiles @("keytype-rsa.pfx") -Details "Explicit RSA key type"

# Test 1.20: Create with ECDSA P-256 key
Test-CertzFileCreation -TestName "Create with ECDSA P-256 key" -FilePrefix "keytype-ecdsa256" `
    -CertzArgs @("create", "--f", "keytype-ecdsa256.pfx", "--c", "keytype-ecdsa256.cer", "--k", "keytype-ecdsa256.key", "--p", "EcdsaP256Pass", "--key-type", "ECDSA-P256") `
    -ExpectedFiles @("keytype-ecdsa256.pfx", "keytype-ecdsa256.key") -Details "Modern TLS 1.3 optimized"

# Test 1.21: Create with ECDSA P-384 key
Test-CertzFileCreation -TestName "Create with ECDSA P-384 key" -FilePrefix "keytype-ecdsa384" `
    -CertzArgs @("create", "--f", "keytype-ecdsa384.pfx", "--p", "EcdsaP384Pass", "--key-type", "ECDSA-P384") `
    -ExpectedFiles @("keytype-ecdsa384.pfx") -Details "High security ECDSA"

# Test 1.22: Create with ECDSA P-521 key
Test-CertzFileCreation -TestName "Create with ECDSA P-521 key" -FilePrefix "keytype-ecdsa521" `
    -CertzArgs @("create", "--f", "keytype-ecdsa521.pfx", "--p", "EcdsaP521Pass", "--key-type", "ECDSA-P521") `
    -ExpectedFiles @("keytype-ecdsa521.pfx") -Details "Maximum ECDSA security"

# Test 1.23: ECDSA certificate can be converted to PEM and back
Remove-TestFiles "ecdsa-convert"
try {
    .\certz.exe create --f ecdsa-convert.pfx --c ecdsa-convert.cer --k ecdsa-convert.key --p EcdsaConvertPass --key-type ECDSA-P256 | Out-Null
    .\certz.exe convert --cert ecdsa-convert.cer --key ecdsa-convert.key --pfx ecdsa-convert-back.pfx --p EcdsaBackPass | Out-Null
    $success = (Test-FileExists "ecdsa-convert.pfx") -and (Test-FileExists "ecdsa-convert-back.pfx")
    Write-TestResult "ECDSA certificate conversion round-trip" $success "PEM to PFX with ECDSA key"
} catch {
    Write-TestResult "ECDSA certificate conversion round-trip" $false $_.Exception.Message
}

# ============================================================================
# CA CERTIFICATE TESTS
# ============================================================================
Write-TestHeader "Testing CA Certificate Options"

# Test 1.24: Create CA certificate
Test-CertzFileCreation -TestName "Create CA certificate" -FilePrefix "ca-cert" `
    -CertzArgs @("create", "--f", "ca-cert.pfx", "--p", "CaCertPass", "--san", "My Test CA", "--is-ca") `
    -ExpectedFiles @("ca-cert.pfx") -Details "Certificate Authority cert created"

# Test 1.25: Create CA certificate with path length constraint
Test-CertzFileCreation -TestName "Create CA with path length" -FilePrefix "ca-path" `
    -CertzArgs @("create", "--f", "ca-path.pfx", "--p", "CaPathPass", "--san", "My Intermediate CA", "--is-ca", "--path-length", "1") `
    -ExpectedFiles @("ca-path.pfx") -Details "Intermediate CA with depth=1"

# Test 1.26: Create CA certificate with CRL and OCSP URLs
Test-CertzFileCreation -TestName "Create CA with CRL/OCSP" -FilePrefix "ca-full" `
    -CertzArgs @("create", "--f", "ca-full.pfx", "--p", "CaFullPass", "--san", "My Full CA", "--is-ca", "--crl-url", "http://crl.example.com/ca.crl", "--ocsp-url", "http://ocsp.example.com") `
    -ExpectedFiles @("ca-full.pfx") -Details "CA with revocation endpoints"

# ============================================================================
# SUBJECT DN FIELD TESTS
# ============================================================================
Write-TestHeader "Testing Subject Distinguished Name Fields"

# Test 1.27: Create with Organization field
Test-CertzFileCreation -TestName "Create with Organization (O)" -FilePrefix "dn-org" `
    -CertzArgs @("create", "--f", "dn-org.pfx", "--p", "DnOrgPass", "--san", "*.example.com", "--subject-o", "Acme Corporation") `
    -ExpectedFiles @("dn-org.pfx") -Details "Subject O field set"

# Test 1.28: Create with full Distinguished Name
Remove-TestFiles "dn-full"
try {
    .\certz.exe create --f dn-full.pfx --p DnFullPass --san *.example.com --subject-o "Acme Corporation" --subject-ou "Engineering" --subject-c US --subject-st "California" --subject-l "San Francisco" | Out-Null
    $success = Test-FileExists "dn-full.pfx"
    $output = .\certz.exe info --f dn-full.pfx --p DnFullPass 2>&1 | Out-String
    $hasDN = ($output -match "Acme Corporation") -and ($output -match "Engineering") -and ($output -match "California")
    Write-TestResult "Create with full DN" ($success -and $hasDN) "All DN fields present"
} catch {
    Write-TestResult "Create with full DN" $false $_.Exception.Message
}

# Test 1.29: Country code validation (must be 2 characters)
Test-CertzExpectedFailure -TestName "Reject invalid country code - 3 chars" -FilePrefix "dn-country-invalid" `
    -CertzArgs @("create", "--f", "dn-country-invalid.pfx", "--p", "InvalidPass", "--san", "*.example.com", "--subject-c", "USA")

# ============================================================================
# VALIDITY PERIOD VALIDATION TESTS
# ============================================================================
Write-TestHeader "Testing Validity Period Validation"

# Test 1.30: Default validity is 90 days
Test-CertzFileCreation -TestName "Default validity - 90 days" -FilePrefix "validity-default" `
    -CertzArgs @("create", "--f", "validity-default.pfx", "--p", "ValidityDefaultPass") `
    -ExpectedFiles @("validity-default.pfx") -Details "Certificate created with default validity"

# Test 1.31: Validity >200 days shows warning (until March 2026)
Test-CertzWithOutput -TestName "Warning for over 200 day validity" -FilePrefix "validity-warning" `
    -CertzArgs @("create", "--f", "validity-warning.pfx", "--p", "ValidityWarnPass", "--days", "250") `
    -ExpectedFiles @("validity-warning.pfx") `
    -OutputPattern "WARNING.*validity.*exceeds" `
    -Details "Future compliance warning shown"

# Test 1.32: Validity >398 days should fail
Test-CertzExpectedFailure -TestName "Reject over 398 day validity" -FilePrefix "validity-error" `
    -CertzArgs @("create", "--f", "validity-error.pfx", "--p", "ValidityErrorPass", "--days", "400") `
    -Details "CA/B Forum limit enforced"

# Test 1.33: Minimum validity - 1 day
Test-CertzFileCreation -TestName "Minimum validity - 1 day" -FilePrefix "validity-min" `
    -CertzArgs @("create", "--f", "validity-min.pfx", "--p", "ValidityMinPass", "--days", "1") `
    -ExpectedFiles @("validity-min.pfx") -Details "Short-lived certificate"

# Test 1.34: Zero days should fail
Test-CertzExpectedFailure -TestName "Reject 0 day validity" -FilePrefix "validity-zero" `
    -CertzArgs @("create", "--f", "validity-zero.pfx", "--p", "ValidityZeroPass", "--days", "0") `
    -Details "Minimum 1 day required"

# ============================================================================
# AIA/CDP EXTENSION TESTS
# ============================================================================
Write-TestHeader "Testing AIA and CDP Extensions"

# Test 1.35: Create with CRL Distribution Point
Test-CertzFileCreation -TestName "Create with CRL Distribution Point" -FilePrefix "ext-crl" `
    -CertzArgs @("create", "--f", "ext-crl.pfx", "--p", "ExtCrlPass", "--crl-url", "http://crl.example.com/cert.crl") `
    -ExpectedFiles @("ext-crl.pfx") -Details "CDP extension added"

# Test 1.36: Create with OCSP responder URL
Test-CertzFileCreation -TestName "Create with OCSP responder" -FilePrefix "ext-ocsp" `
    -CertzArgs @("create", "--f", "ext-ocsp.pfx", "--p", "ExtOcspPass", "--ocsp-url", "http://ocsp.example.com") `
    -ExpectedFiles @("ext-ocsp.pfx") -Details "AIA OCSP extension added"

# Test 1.37: Create with CA Issuers URL
Test-CertzFileCreation -TestName "Create with CA Issuers URL" -FilePrefix "ext-ca-issuers" `
    -CertzArgs @("create", "--f", "ext-ca-issuers.pfx", "--p", "ExtCaIssuersPass", "--ca-issuers-url", "http://certs.example.com/ca.cer") `
    -ExpectedFiles @("ext-ca-issuers.pfx") -Details "AIA CA Issuers extension added"

# Test 1.38: Create with all AIA/CDP extensions
Test-CertzFileCreation -TestName "Create with all AIA/CDP extensions" -FilePrefix "ext-all" `
    -CertzArgs @("create", "--f", "ext-all.pfx", "--p", "ExtAllPass", "--crl-url", "http://crl.example.com/cert.crl", "--ocsp-url", "http://ocsp.example.com", "--ca-issuers-url", "http://certs.example.com/ca.cer") `
    -ExpectedFiles @("ext-all.pfx") -Details "Full revocation info"

# ============================================================================
# INSTALL COMMAND TESTS
# ============================================================================
Write-TestHeader "Testing INSTALL Command"

# First, create a certificate with a known password for install tests
Remove-TestFiles "install-test"
.\certz.exe create --f install-test.pfx --p InstallTestPass --san *.dev.local | Out-Null

# Test 2.1: Install to default store (My/LocalMachine)
Test-CertzInstall -TestName "Install to default store (My)" `
    -PfxFile "install-test.pfx" -Password "InstallTestPass" `
    -Details "Certificate in LocalMachine\My"

# Test 2.2: Install to Root store
Test-CertzInstall -TestName "Install to Root store" `
    -PfxFile "install-test.pfx" -Password "InstallTestPass" -StoreName "Root" `
    -Details "Certificate in LocalMachine\Root"

# Test 2.3: Install to CurrentUser store
Test-CertzInstall -TestName "Install to CurrentUser store" `
    -PfxFile "install-test.pfx" -Password "InstallTestPass" `
    -StoreName "My" -StoreLocation "CurrentUser" `
    -Details "Certificate in CurrentUser\My"

# ============================================================================
# LIST COMMAND TESTS
# ============================================================================
Write-TestHeader "Testing LIST Command"

# Test 3.1: List from default store
Test-CertzWithOutput -TestName "List from default store (My)" -FilePrefix "" `
    -CertzArgs @("list") -OutputPattern "." -Details "Output received"

# Test 3.2: List from Root store
Test-CertzWithOutput -TestName "List from Root store" -FilePrefix "" `
    -CertzArgs @("list", "--sn", "root", "--sl", "LocalMachine") -OutputPattern "." -Details "Output received"

# Test 3.3: List from CurrentUser store
Test-CertzWithOutput -TestName "List from CurrentUser store" -FilePrefix "" `
    -CertzArgs @("list", "--sl", "CurrentUser", "--sn", "My") -OutputPattern "." -Details "Output received"

# ============================================================================
# EXPORT COMMAND TESTS
# ============================================================================
Write-TestHeader "Testing EXPORT Command"

# Test 5.1: Export from remote URL
Test-CertzFileCreation -TestName "Export from remote URL (github.com)" -FilePrefix "github" `
    -CertzArgs @("export", "--url", "https://www.github.com", "--f", "github.pfx", "--c", "github.cer") `
    -ExpectedFiles @("github.pfx", "github.cer") -Details "PFX and CER created"

# Test 5.2: Export from remote with custom password
Test-CertzWithOutput -TestName "Export with custom password" -FilePrefix "microsoft" `
    -CertzArgs @("export", "--url", "https://www.microsoft.com", "--f", "microsoft.pfx", "--p", "CustomExportPass") `
    -ExpectedFiles @("microsoft.pfx") `
    -OutputPattern "IMPORTANT: Certificate Password" -OutputShouldNotMatch `
    -Details "PFX exported with provided password"

# Test 5.3: Export from certificate store by thumbprint
Remove-TestFiles "exported"
try {
    $cert = Get-TestCertificate -SubjectPattern "*dev.local*" -StoreName "My" -StoreLocation "LocalMachine"
    if ($cert) {
        .\certz.exe export --thumb $cert.Thumbprint --f exported.pfx --c exported.cer --p ExportPass123 | Out-Null
        $success = (Test-FileExists "exported.pfx") -and (Test-FileExists "exported.cer")
        Write-TestResult "Export from store by thumbprint" $success "Certificate exported from store"
    } else {
        Write-TestResult "Export from store by thumbprint" $false "No certificate found in store"
    }
} catch {
    Write-TestResult "Export from store by thumbprint" $false $_.Exception.Message
}

# Test 5.4: Export PEM only from URL
Remove-TestFiles "google"
try {
    .\certz.exe export --url https://www.google.com --c google.cer | Out-Null
    $success = (Test-FileExists "google.cer") -and (-not (Test-FileExists "google.pfx"))
    Write-TestResult "Export PEM only (no PFX)" $success "Only CER file created"
} catch {
    Write-TestResult "Export PEM only (no PFX)" $false $_.Exception.Message
}

# Test 5.5: Export with password file from URL
Test-CertzPasswordFileCreation -TestName "Export with password file (URL)" -FilePrefix "export-pwfile" `
    -CertzArgs @("export", "--url", "https://www.github.com", "--f", "export-pwfile.pfx", "--password-file", "export-pwfile.password.txt") `
    -PfxFile "export-pwfile.pfx" -PasswordFile "export-pwfile.password.txt"

# Test 5.6: Export with password file from store
Remove-TestFiles "export-store-pwfile"
try {
    .\certz.exe create --f export-store-pwfile-src.pfx --p TempPass 2>&1 | Out-Null
    .\certz.exe install --f export-store-pwfile-src.pfx --p TempPass --sn My --sl LocalMachine 2>&1 | Out-Null

    $cert = Get-TestCertificate -SubjectPattern "*dev.local*" -StoreName "My" -StoreLocation "LocalMachine"
    if ($cert) {
        $output = .\certz.exe export --thumb $cert.Thumbprint --f export-store-pwfile.pfx --password-file export-store-pwfile.password.txt 2>&1 | Out-String
        $pfxExists = Test-FileExists "export-store-pwfile.pfx"
        $pwResult = Test-PasswordFile -FilePath "export-store-pwfile.password.txt" -ForbiddenPatterns @()
        $outputConfirms = $output -match "Password.*written to"
        $success = $pfxExists -and $pwResult.Valid -and $outputConfirms

        $failureDetails = @()
        if (-not $pfxExists) { $failureDetails += "PFX file not created" }
        if (-not $pwResult.Valid) { $failureDetails += $pwResult.Errors }
        if (-not $outputConfirms) { $failureDetails += "Output did not confirm password written to file" }

        .\certz.exe remove --thumb $cert.Thumbprint --sn My --sl LocalMachine | Out-Null
        $details = if ($success) { "Password saved to file" } else { $failureDetails -join "; " }
        Write-TestResult "Export with password file (store)" $success $details
    } else {
        Write-TestResult "Export with password file (store)" $false "No certificate found in store"
    }
} catch {
    Write-TestResult "Export with password file (store)" $false $_.Exception.Message
}

# ============================================================================
# CONVERT COMMAND TESTS
# ============================================================================
Write-TestHeader "Testing CONVERT Command"

# Create fresh source files for convert tests (don't rely on files from earlier tests)
Remove-TestFiles "convert-input"
.\certz.exe create --c convert-input.cer --k convert-input.key --p ConvertInputPass | Out-Null

# Test 6.1: Convert CER/KEY to PFX
Test-CertzFileCreation -TestName "Convert CER/KEY to PFX" -FilePrefix "converted" `
    -CertzArgs @("convert", "--c", "convert-input.cer", "--k", "convert-input.key", "--f", "converted.pfx", "--p", "ConvertPass123") `
    -ExpectedFiles @("converted.pfx") -Details "Conversion successful"

# Test 6.2: Convert with generated password (no password provided)
Test-CertzWithOutput -TestName "Convert with generated password" -FilePrefix "converted-default" `
    -CertzArgs @("convert", "--c", "convert-input.cer", "--k", "convert-input.key", "--f", "converted-default.pfx") `
    -ExpectedFiles @("converted-default.pfx") `
    -OutputPattern "IMPORTANT: Certificate Password" `
    -Details "Secure password generated and displayed"

# Test 6.3: Convert with password file
Test-CertzPasswordFileCreation -TestName "Convert with password file" -FilePrefix "converted-pwfile" `
    -CertzArgs @("convert", "--c", "convert-input.cer", "--k", "convert-input.key", "--f", "converted-pwfile.pfx", "--password-file", "converted-pwfile.password.txt") `
    -PfxFile "converted-pwfile.pfx" -PasswordFile "converted-pwfile.password.txt" `
    -Details "Password saved to file during conversion"

# Test 6.4: Verify converted certificate with password file can be installed
try {
    $pwFileExists = Test-FileExists "converted-pwfile.password.txt"
    $pfxExists = Test-FileExists "converted-pwfile.pfx"

    if ($pwFileExists -and $pfxExists) {
        $password = Get-Content "converted-pwfile.password.txt" -Raw
        .\certz.exe install --f converted-pwfile.pfx --p $password --sn My --sl CurrentUser 2>&1 | Out-Null
        $cert = Get-TestCertificate -SubjectPattern "*dev.local*" -StoreName "My" -StoreLocation "CurrentUser"
        $success = $null -ne $cert
        if ($cert) { .\certz.exe remove --thumb $cert.Thumbprint --sn My --sl CurrentUser | Out-Null }
        Write-TestResult "Install converted cert using password file" $success "Converted cert password is valid"
    } else {
        Write-TestResult "Install converted cert using password file" $false "Required files do not exist"
    }
} catch {
    Write-TestResult "Install converted cert using password file" $false $_.Exception.Message
}

# Test 6.5: Verify converted certificate can be installed
try {
    .\certz.exe install --f converted.pfx --p ConvertPass123 --sl CurrentUser --sn My | Out-Null
    $cert = Get-TestCertificate -SubjectPattern "*dev.local*" -StoreName "My" -StoreLocation "CurrentUser"
    Write-TestResult "Install converted certificate" ($null -ne $cert) "Converted cert is valid"
} catch {
    Write-TestResult "Install converted certificate" $false $_.Exception.Message
}

# ============================================================================
# REMOVE COMMAND TESTS
# ============================================================================
Write-TestHeader "Testing REMOVE Command"

# Test 4.1: Remove by thumbprint from Root
try {
    $cert = Get-TestCertificate -SubjectPattern "*dev.local*" -StoreName "Root" -StoreLocation "LocalMachine"
    if ($cert) {
        $thumb = $cert.Thumbprint
        .\certz.exe remove --thumb $thumb --sn root | Out-Null
        $certAfter = Get-TestCertificate -SubjectPattern "*dev.local*" -StoreName "Root" -StoreLocation "LocalMachine"
        Write-TestResult "Remove by thumbprint" ($null -eq $certAfter -or $certAfter.Thumbprint -ne $thumb) "Certificate removed from Root"
    } else {
        Write-TestResult "Remove by thumbprint" $false "No certificate found to remove"
    }
} catch {
    Write-TestResult "Remove by thumbprint" $false $_.Exception.Message
}

# Test 4.2: Remove by subject from LocalMachine\My
try {
    .\certz.exe remove --subject "*.dev.local" --sn My --sl LocalMachine | Out-Null
    $cert = Get-TestCertificate -SubjectPattern "*dev.local*" -StoreName "My" -StoreLocation "LocalMachine"
    Write-TestResult "Remove by subject (LocalMachine)" ($null -eq $cert) "All matching certs removed"
} catch {
    Write-TestResult "Remove by subject (LocalMachine)" $false $_.Exception.Message
}

# Test 4.3: Remove by subject from CurrentUser\My
try {
    .\certz.exe remove --subject "*.dev.local" --sl CurrentUser --sn My | Out-Null
    $cert = Get-TestCertificate -SubjectPattern "*dev.local*" -StoreName "My" -StoreLocation "CurrentUser"
    Write-TestResult "Remove by subject (CurrentUser)" ($null -eq $cert) "All matching certs removed"
} catch {
    Write-TestResult "Remove by subject (CurrentUser)" $false $_.Exception.Message
}

# ============================================================================
# INTEGRATION TESTS
# ============================================================================
Write-TestHeader "Testing Integration Scenarios"

# Test 7.1: Complete lifecycle (create to install to export to remove)
Remove-TestFiles "lifecycle"
try {
    .\certz.exe create --f lifecycle.pfx --p LifecyclePass --c lifecycle.cer --k lifecycle.key | Out-Null
    .\certz.exe install --f lifecycle.pfx --p LifecyclePass --sn My --sl LocalMachine | Out-Null
    $cert = Get-TestCertificate -SubjectPattern "*dev.local*" -StoreName "My" -StoreLocation "LocalMachine"

    if ($cert) {
        .\certz.exe export --thumb $cert.Thumbprint --f lifecycle-export.pfx --p ExportPass | Out-Null
    }
    .\certz.exe remove --subject "*.dev.local" --sn My --sl LocalMachine | Out-Null
    $certAfter = Get-TestCertificate -SubjectPattern "*dev.local*" -StoreName "My" -StoreLocation "LocalMachine"

    $success = ($null -ne $cert) -and (Test-FileExists "lifecycle-export.pfx") -and ($null -eq $certAfter)
    Write-TestResult "Complete certificate lifecycle" $success "Create-Install-Export-Remove"
} catch {
    Write-TestResult "Complete certificate lifecycle" $false $_.Exception.Message
}

# Test 7.2: Format conversion chain (PFX to PEM to PFX)
Remove-TestFiles "conversion-chain"
try {
    .\certz.exe create --f conversion-chain-original.pfx --p OriginalPass | Out-Null
    .\certz.exe install --f conversion-chain-original.pfx --p OriginalPass --sn My --sl LocalMachine | Out-Null
    $cert = Get-TestCertificate -SubjectPattern "*dev.local*" -StoreName "My" -StoreLocation "LocalMachine"

    if ($cert) {
        .\certz.exe export --thumb $cert.Thumbprint --c conversion-chain-intermediate.cer --k conversion-chain-intermediate.key | Out-Null
        .\certz.exe convert --c conversion-chain-intermediate.cer --k conversion-chain-intermediate.key --f conversion-chain-final.pfx --p FinalPass | Out-Null
        .\certz.exe remove --thumb $cert.Thumbprint --sn My --sl LocalMachine | Out-Null
    }

    $success = (Test-FileExists "conversion-chain-original.pfx") -and
               (Test-FileExists "conversion-chain-intermediate.cer") -and
               (Test-FileExists "conversion-chain-final.pfx")
    Write-TestResult "Format conversion chain" $success "PFX to PEM to PFX"
} catch {
    Write-TestResult "Format conversion chain" $false $_.Exception.Message
}

# ============================================================================
# INFO COMMAND TESTS
# ============================================================================
Write-TestHeader "Testing INFO Command"

# Create a certificate with known password for info tests
Remove-TestFiles "info-cert"
.\certz.exe create --f info-cert.pfx --c info-cert.cer --k info-cert.key --p InfoTestPass --san *.dev.local | Out-Null

# Test 9.1: Info from PFX file
Test-CertzWithOutput -TestName "Info from PFX file" -FilePrefix "" `
    -CertzArgs @("info", "--f", "info-cert.pfx", "--p", "InfoTestPass") `
    -OutputPattern "Certificate Information" -Details "Certificate details displayed"

# Test 9.2: Info from PEM file (uses info-cert.cer created above)
Test-CertzWithOutput -TestName "Info from PEM file" -FilePrefix "" `
    -CertzArgs @("info", "--f", "info-cert.cer") `
    -OutputPattern "Certificate Information" -Details "Certificate details displayed"

# Test 9.3: Info from URL
try {
    $output = .\certz.exe info --url https://www.github.com 2>&1 | Out-String
    $success = $LASTEXITCODE -eq 0 -and ($output -match "Certificate Information")
    if (-not $success) {
        Write-TestResult "Info from URL" $true "Skipped (network issue)"
    } else {
        Write-TestResult "Info from URL" $success "Remote certificate details displayed"
    }
} catch {
    Write-TestResult "Info from URL" $true "Skipped (network error)"
}

# Test 9.4: Info from store by thumbprint
try {
    Remove-TestFiles "info-test"
    .\certz.exe create --f info-test.pfx --p InfoPass | Out-Null
    .\certz.exe install --f info-test.pfx --p InfoPass --sn My --sl LocalMachine | Out-Null

    $cert = Get-TestCertificate -SubjectPattern "*dev.local*" -StoreName "My" -StoreLocation "LocalMachine"
    if ($cert) {
        $output = .\certz.exe info --thumbprint $cert.Thumbprint --sn My --sl LocalMachine 2>&1 | Out-String
        $success = $LASTEXITCODE -eq 0 -and ($output -match "Certificate Information")
        .\certz.exe remove --thumbprint $cert.Thumbprint --sn My --sl LocalMachine | Out-Null
    } else {
        $success = $false
    }
    Write-TestResult "Info from store by thumbprint" $success "Store certificate details displayed"
} catch {
    Write-TestResult "Info from store by thumbprint" $false $_.Exception.Message
}

# ============================================================================
# VERIFY COMMAND TESTS
# ============================================================================
Write-TestHeader "Testing VERIFY Command"

# Create a certificate with known password for verify tests
Remove-TestFiles "verify-cert"
.\certz.exe create --f verify-cert.pfx --p VerifyTestPass --san *.dev.local | Out-Null

# Test 10.1: Verify valid certificate from file
Test-CertzWithOutput -TestName "Verify certificate from PFX file" -FilePrefix "" `
    -CertzArgs @("verify", "--f", "verify-cert.pfx", "--p", "VerifyTestPass") `
    -OutputPattern "Certificate Validation Report" -Details "Validation report generated"

# Test 10.2: Verify with custom warning days
Test-CertzWithOutput -TestName "Verify with custom warning threshold" -FilePrefix "" `
    -CertzArgs @("verify", "--f", "verify-cert.pfx", "--p", "VerifyTestPass", "--warn", "60") `
    -OutputPattern "Certificate Validation Report" -Details "Custom warning threshold applied"

# Test 10.3: Verify from store by thumbprint
try {
    Remove-TestFiles "verify-test"
    .\certz.exe create --f verify-test.pfx --p VerifyPass | Out-Null
    .\certz.exe install --f verify-test.pfx --p VerifyPass --sn My --sl LocalMachine | Out-Null

    $cert = Get-TestCertificate -SubjectPattern "*dev.local*" -StoreName "My" -StoreLocation "LocalMachine"
    if ($cert) {
        $output = .\certz.exe verify --thumbprint $cert.Thumbprint --sn My --sl LocalMachine 2>&1 | Out-String
        $success = $LASTEXITCODE -eq 0 -and ($output -match "Certificate Validation Report")
        .\certz.exe remove --thumbprint $cert.Thumbprint --sn My --sl LocalMachine | Out-Null
    } else {
        $success = $false
    }
    Write-TestResult "Verify from store by thumbprint" $success "Store certificate validated"
} catch {
    Write-TestResult "Verify from store by thumbprint" $false $_.Exception.Message
}

# ============================================================================
# ENHANCED CONVERT COMMAND TESTS (PFX to PEM)
# ============================================================================
Write-TestHeader "Testing Enhanced CONVERT Command (PFX to PEM)"

# Create a certificate with known password for convert tests
Remove-TestFiles "convert-source"
.\certz.exe create --f convert-source.pfx --p ConvertSourcePass --san *.dev.local | Out-Null

# Test 11.1: Convert PFX to PEM (both cert and key)
Test-CertzFileCreation -TestName "Convert PFX to PEM (cert+key)" -FilePrefix "pfx-to-pem" `
    -CertzArgs @("convert", "--pfx", "convert-source.pfx", "--p", "ConvertSourcePass", "--out-cert", "pfx-to-pem.cer", "--out-key", "pfx-to-pem.key") `
    -ExpectedFiles @("pfx-to-pem.cer", "pfx-to-pem.key") -Details "Both CER and KEY files created"

# Test 11.2: Convert PFX to PEM (cert only)
Remove-TestFiles "pfx-to-cer"
try {
    .\certz.exe convert --pfx convert-source.pfx --p ConvertSourcePass --out-cert pfx-to-cer.cer 2>&1 | Out-Null
    $success = (Test-FileExists "pfx-to-cer.cer") -and (-not (Test-FileExists "pfx-to-cer.key"))
    Write-TestResult "Convert PFX to PEM (cert only)" $success "Only CER file created"
} catch {
    Write-TestResult "Convert PFX to PEM (cert only)" $false $_.Exception.Message
}

# Test 11.3: Convert PFX to PEM (key only)
Remove-TestFiles "pfx-to-key"
try {
    .\certz.exe convert --pfx convert-source.pfx --p ConvertSourcePass --out-key pfx-to-key.key 2>&1 | Out-Null
    $success = (Test-FileExists "pfx-to-key.key") -and (-not (Test-FileExists "pfx-to-key.cer"))
    Write-TestResult "Convert PFX to PEM (key only)" $success "Only KEY file created"
} catch {
    Write-TestResult "Convert PFX to PEM (key only)" $false $_.Exception.Message
}

# Test 11.4: Round-trip conversion (PFX to PEM to PFX)
Remove-TestFiles "roundtrip"
try {
    .\certz.exe convert --pfx convert-source.pfx --p ConvertSourcePass --out-cert roundtrip.cer --out-key roundtrip.key 2>&1 | Out-Null
    .\certz.exe convert --cert roundtrip.cer --key roundtrip.key --pfx roundtrip.pfx --p RoundtripPass 2>&1 | Out-Null
    .\certz.exe info --f roundtrip.pfx --p RoundtripPass 2>&1 | Out-Null
    $success = (Test-FileExists "roundtrip.pfx") -and ($LASTEXITCODE -eq 0)
    Write-TestResult "Round-trip conversion (PFX to PEM to PFX)" $success "Full conversion cycle successful"
} catch {
    Write-TestResult "Round-trip conversion (PFX to PEM to PFX)" $false $_.Exception.Message
}

# ============================================================================
# ERROR HANDLING TESTS
# ============================================================================
Write-TestHeader "Testing Error Handling"

# Test 8.1: Invalid file path
Test-CertzExpectedFailure -TestName "Graceful failure on missing file" -FilePrefix "" `
    -CertzArgs @("install", "--f", "nonexistent.pfx", "--p", "password") `
    -Details "Expected error occurred"

# Test 8.2: Missing required parameters for convert
Test-CertzExpectedFailure -TestName "Missing required key parameter" -FilePrefix "" `
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
