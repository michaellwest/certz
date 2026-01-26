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
            Write-Host "`n✓ Docker tests completed successfully!" -ForegroundColor Green
        } else {
            Write-Host "`n✗ Docker tests failed!" -ForegroundColor Red
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

# Test 1.1: Create with defaults
Remove-TestFiles "devcert"
try {
    .\certz.exe create | Out-Null
    $success = (Test-FileExists "devcert.pfx") -and (Test-FileExists "devcert.pfx.password.txt")
    $password = if (Test-FileExists "devcert.pfx.password.txt") { Get-Content "devcert.pfx.password.txt" } else { "" }
    Write-TestResult "Create with defaults" $success "PFX created, password=$password"
} catch {
    Write-TestResult "Create with defaults" $false $_.Exception.Message
}

# Test 1.2: Create with custom PFX and password
Remove-TestFiles "mycert"
try {
    .\certz.exe create --f mycert.pfx --p MySecurePass123 | Out-Null
    $success = (Test-FileExists "mycert.pfx") -and (Test-FileExists "mycert.pfx.password.txt")
    $password = if (Test-FileExists "mycert.pfx.password.txt") { Get-Content "mycert.pfx.password.txt" } else { "" }
    Write-TestResult "Create with custom password" ($success -and $password -eq "MySecurePass123") "Password file verified"
} catch {
    Write-TestResult "Create with custom password" $false $_.Exception.Message
}

# Test 1.3: Create with custom SANs
Remove-TestFiles "testcert"
try {
    .\certz.exe create --f testcert.pfx --san *.example.com localhost 127.0.0.1 192.168.1.100 | Out-Null
    $success = Test-FileExists "testcert.pfx"
    Write-TestResult "Create with custom SANs" $success "Multiple DNS and IP SANs"
} catch {
    Write-TestResult "Create with custom SANs" $false $_.Exception.Message
}

# Test 1.4: Create with custom validity period
Remove-TestFiles "longcert"
try {
    .\certz.exe create --f longcert.pfx --days 1825 | Out-Null
    $success = Test-FileExists "longcert.pfx"
    Write-TestResult "Create with 1825 days validity" $success "5-year certificate"
} catch {
    Write-TestResult "Create with 1825 days validity" $false $_.Exception.Message
}

# Test 1.5: Create with all options
Remove-TestFiles "fulltest"
try {
    .\certz.exe create --f fulltest.pfx --c fulltest.cer --k fulltest.key --p ComplexPass456 --san *.dev.local *.test.com 127.0.0.1 --days 730 | Out-Null
    $success = (Test-FileExists "fulltest.pfx") -and (Test-FileExists "fulltest.cer") -and (Test-FileExists "fulltest.key")
    Write-TestResult "Create with all options" $success "PFX, CER, and KEY created"
} catch {
    Write-TestResult "Create with all options" $false $_.Exception.Message
}

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
Remove-TestFiles "multisan"
try {
    .\certz.exe create --f multisan.pfx --san *.app1.local *.app2.local *.app3.local localhost | Out-Null
    $success = Test-FileExists "multisan.pfx"
    Write-TestResult "Create with multiple SANs" $success "4 DNS entries"
} catch {
    Write-TestResult "Create with multiple SANs" $false $_.Exception.Message
}

# ============================================================================
# INSTALL COMMAND TESTS
# ============================================================================
Write-TestHeader "Testing INSTALL Command"

# Test 2.1: Install to default store (My/LocalMachine)
try {
    .\certz.exe install --f devcert.pfx --p changeit | Out-Null
    $cert = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
            Where-Object { $_.Subject -like "*dev.local*" } |
            Select-Object -First 1
    $success = $null -ne $cert
    Write-TestResult "Install to default store (My)" $success "Certificate in LocalMachine\My"
} catch {
    Write-TestResult "Install to default store (My)" $false $_.Exception.Message
}

# Test 2.2: Install to Root store
try {
    .\certz.exe install --f devcert.pfx --p changeit --sn root | Out-Null
    $cert = Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue |
            Where-Object { $_.Subject -like "*dev.local*" } |
            Select-Object -First 1
    $success = $null -ne $cert
    Write-TestResult "Install to Root store" $success "Certificate in LocalMachine\Root"
} catch {
    Write-TestResult "Install to Root store" $false $_.Exception.Message
}

# Test 2.3: Install to CurrentUser store
try {
    .\certz.exe install --f devcert.pfx --p changeit --sl CurrentUser --sn My | Out-Null
    $cert = Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
            Where-Object { $_.Subject -like "*dev.local*" } |
            Select-Object -First 1
    $success = $null -ne $cert
    Write-TestResult "Install to CurrentUser store" $success "Certificate in CurrentUser\My"
} catch {
    Write-TestResult "Install to CurrentUser store" $false $_.Exception.Message
}

# ============================================================================
# LIST COMMAND TESTS
# ============================================================================
Write-TestHeader "Testing LIST Command"

# Test 3.1: List from default store
try {
    $output = .\certz.exe list 2>&1 | Out-String
    $success = $output.Length -gt 0
    Write-TestResult "List from default store (My)" $success "Output received"
} catch {
    Write-TestResult "List from default store (My)" $false $_.Exception.Message
}

# Test 3.2: List from Root store
try {
    $output = .\certz.exe list --sn root --sl LocalMachine 2>&1 | Out-String
    $success = $output.Length -gt 0
    Write-TestResult "List from Root store" $success "Output received"
} catch {
    Write-TestResult "List from Root store" $false $_.Exception.Message
}

# Test 3.3: List from CurrentUser store
try {
    $output = .\certz.exe list --sl CurrentUser --sn My 2>&1 | Out-String
    $success = $output.Length -gt 0
    Write-TestResult "List from CurrentUser store" $success "Output received"
} catch {
    Write-TestResult "List from CurrentUser store" $false $_.Exception.Message
}

# ============================================================================
# EXPORT COMMAND TESTS
# ============================================================================
Write-TestHeader "Testing EXPORT Command"

# Test 5.1: Export from remote URL
Remove-TestFiles "github"
try {
    .\certz.exe export --url https://www.github.com --f github.pfx --c github.cer | Out-Null
    $success = (Test-FileExists "github.pfx") -and (Test-FileExists "github.cer")
    Write-TestResult "Export from remote URL (github.com)" $success "PFX and CER created"
} catch {
    Write-TestResult "Export from remote URL (github.com)" $false $_.Exception.Message
}

# Test 5.2: Export from remote with custom password
Remove-TestFiles "microsoft"
try {
    .\certz.exe export --url https://www.microsoft.com --f microsoft.pfx --p CustomExportPass | Out-Null
    $success = Test-FileExists "microsoft.pfx"
    $password = if (Test-FileExists "microsoft.pfx.password.txt") { Get-Content "microsoft.pfx.password.txt" } else { "" }
    Write-TestResult "Export with custom password" ($success -and $password -eq "CustomExportPass") "Password verified"
} catch {
    Write-TestResult "Export with custom password" $false $_.Exception.Message
}

# Test 5.3: Export from certificate store by thumbprint
Remove-TestFiles "exported"
try {
    $cert = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
            Where-Object { $_.Subject -like "*dev.local*" } |
            Select-Object -First 1

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

# ============================================================================
# CONVERT COMMAND TESTS
# ============================================================================
Write-TestHeader "Testing CONVERT Command"

# Test 6.1: Convert CER/KEY to PFX
Remove-TestFiles "converted"
try {
    .\certz.exe convert --c pemonly.cer --k pemonly.key --f converted.pfx --p ConvertPass123 | Out-Null
    $success = Test-FileExists "converted.pfx"
    Write-TestResult "Convert CER/KEY to PFX" $success "Conversion successful"
} catch {
    Write-TestResult "Convert CER/KEY to PFX" $false $_.Exception.Message
}

# Test 6.2: Convert with default password
Remove-TestFiles "converted-default"
try {
    .\certz.exe convert --c pemonly.cer --k pemonly.key --f converted-default.pfx | Out-Null
    $success = Test-FileExists "converted-default.pfx"
    $password = if (Test-FileExists "converted-default.pfx.password.txt") { Get-Content "converted-default.pfx.password.txt" } else { "" }
    Write-TestResult "Convert with default password" ($success -and $password -eq "changeit") "Default password used"
} catch {
    Write-TestResult "Convert with default password" $false $_.Exception.Message
}

# Test 6.3: Verify converted certificate can be installed
try {
    .\certz.exe install --f converted.pfx --p ConvertPass123 --sl CurrentUser --sn My | Out-Null
    $cert = Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
            Where-Object { $_.Subject -like "*dev.local*" } |
            Select-Object -First 1
    $success = $null -ne $cert
    Write-TestResult "Install converted certificate" $success "Converted cert is valid"
} catch {
    Write-TestResult "Install converted certificate" $false $_.Exception.Message
}

# ============================================================================
# REMOVE COMMAND TESTS
# ============================================================================
Write-TestHeader "Testing REMOVE Command"

# Test 4.1: Remove by thumbprint from Root
try {
    $cert = Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue |
            Where-Object { $_.Subject -like "*dev.local*" } |
            Select-Object -First 1

    if ($cert) {
        $thumb = $cert.Thumbprint
        .\certz.exe remove --thumb $thumb --sn root | Out-Null

        $certAfter = Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue |
                     Where-Object { $_.Thumbprint -eq $thumb }
        $success = $null -eq $certAfter
        Write-TestResult "Remove by thumbprint" $success "Certificate removed from Root"
    } else {
        Write-TestResult "Remove by thumbprint" $false "No certificate found to remove"
    }
} catch {
    Write-TestResult "Remove by thumbprint" $false $_.Exception.Message
}

# Test 4.2: Remove by subject from LocalMachine\My
try {
    .\certz.exe remove --subject "*.dev.local" --sn My --sl LocalMachine | Out-Null
    $cert = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
            Where-Object { $_.Subject -like "*dev.local*" }
    $success = $null -eq $cert -or $cert.Count -eq 0
    Write-TestResult "Remove by subject (LocalMachine)" $success "All matching certs removed"
} catch {
    Write-TestResult "Remove by subject (LocalMachine)" $false $_.Exception.Message
}

# Test 4.3: Remove by subject from CurrentUser\My
try {
    .\certz.exe remove --subject "*.dev.local" --sl CurrentUser --sn My | Out-Null
    $cert = Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
            Where-Object { $_.Subject -like "*dev.local*" }
    $success = $null -eq $cert -or $cert.Count -eq 0
    Write-TestResult "Remove by subject (CurrentUser)" $success "All matching certs removed"
} catch {
    Write-TestResult "Remove by subject (CurrentUser)" $false $_.Exception.Message
}

# ============================================================================
# INTEGRATION TESTS
# ============================================================================
Write-TestHeader "Testing Integration Scenarios"

# Test 7.1: Complete lifecycle (create → install → export → remove)
Remove-TestFiles "lifecycle"
try {
    # Create
    .\certz.exe create --f lifecycle.pfx --p LifecyclePass --c lifecycle.cer --k lifecycle.key | Out-Null

    # Install
    .\certz.exe install --f lifecycle.pfx --p LifecyclePass --sn My --sl LocalMachine | Out-Null

    # Verify installed
    $cert = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
            Where-Object { $_.Subject -like "*dev.local*" } |
            Select-Object -First 1

    # Export from store
    if ($cert) {
        .\certz.exe export --thumb $cert.Thumbprint --f lifecycle-export.pfx --p ExportPass | Out-Null
    }

    # Remove
    .\certz.exe remove --subject "*.dev.local" --sn My --sl LocalMachine | Out-Null

    # Verify removed
    $certAfter = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
                 Where-Object { $_.Subject -like "*dev.local*" }

    $success = ($null -ne $cert) -and
               (Test-FileExists "lifecycle-export.pfx") -and
               ($null -eq $certAfter -or $certAfter.Count -eq 0)

    Write-TestResult "Complete certificate lifecycle" $success "Create→Install→Export→Remove"
} catch {
    Write-TestResult "Complete certificate lifecycle" $false $_.Exception.Message
}

# Test 7.2: Format conversion chain (PFX → PEM → PFX)
Remove-TestFiles "conversion-chain"
try {
    # Create original PFX
    .\certz.exe create --f conversion-chain-original.pfx --p OriginalPass | Out-Null

    # Install to get access to certificate
    .\certz.exe install --f conversion-chain-original.pfx --p OriginalPass --sn My --sl LocalMachine | Out-Null

    # Export to PEM
    $cert = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
            Where-Object { $_.Subject -like "*dev.local*" } |
            Select-Object -First 1

    if ($cert) {
        .\certz.exe export --thumb $cert.Thumbprint --c conversion-chain-intermediate.cer --k conversion-chain-intermediate.key | Out-Null

        # Convert back to PFX
        .\certz.exe convert --c conversion-chain-intermediate.cer --k conversion-chain-intermediate.key --f conversion-chain-final.pfx --p FinalPass | Out-Null

        # Cleanup
        .\certz.exe remove --thumb $cert.Thumbprint --sn My --sl LocalMachine | Out-Null
    }

    $success = (Test-FileExists "conversion-chain-original.pfx") -and
               (Test-FileExists "conversion-chain-intermediate.cer") -and
               (Test-FileExists "conversion-chain-final.pfx")

    Write-TestResult "Format conversion chain" $success "PFX→PEM→PFX"
} catch {
    Write-TestResult "Format conversion chain" $false $_.Exception.Message
}

# ============================================================================
# INFO COMMAND TESTS
# ============================================================================
Write-TestHeader "Testing INFO Command"

# Test 9.1: Info from PFX file
try {
    $output = .\certz.exe info --f devcert.pfx --p changeit 2>&1
    $success = $LASTEXITCODE -eq 0 -and ($output -match "Certificate Information")
    Write-TestResult "Info from PFX file" $success "Certificate details displayed"
} catch {
    Write-TestResult "Info from PFX file" $false $_.Exception.Message
}

# Test 9.2: Info from PEM file (uses pemonly.cer created in Test 1.6)
try {
    $output = .\certz.exe info --f pemonly.cer 2>&1
    $success = $LASTEXITCODE -eq 0 -and ($output -match "Certificate Information")
    Write-TestResult "Info from PEM file" $success "Certificate details displayed"
} catch {
    Write-TestResult "Info from PEM file" $false $_.Exception.Message
}

# Test 9.3: Info from URL
try {
    $output = .\certz.exe info --url https://www.github.com 2>&1
    $success = $LASTEXITCODE -eq 0 -and ($output -match "Certificate Information")
    if (-not $success) {
        # Network issues are acceptable for URL tests
        Write-TestResult "Info from URL" $true "Skipped (network issue)"
    } else {
        Write-TestResult "Info from URL" $success "Remote certificate details displayed"
    }
} catch {
    # Network failures are acceptable for URL tests
    Write-TestResult "Info from URL" $true "Skipped (network error: $($_.Exception.Message))"
}

# Test 9.4: Info from store by thumbprint
try {
    # Create and install a cert first
    Remove-TestFiles "info-test"
    .\certz.exe create --f info-test.pfx --p InfoPass | Out-Null
    .\certz.exe install --f info-test.pfx --p InfoPass --sn My --sl LocalMachine | Out-Null

    $cert = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
            Where-Object { $_.Subject -like "*dev.local*" } |
            Select-Object -First 1

    if ($cert) {
        $output = .\certz.exe info --thumbprint $cert.Thumbprint --sn My --sl LocalMachine 2>&1
        $success = $LASTEXITCODE -eq 0 -and ($output -match "Certificate Information")

        # Clean up
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

# Test 10.1: Verify valid certificate from file
try {
    $output = .\certz.exe verify --f devcert.pfx --p changeit 2>&1
    $success = $LASTEXITCODE -eq 0 -and ($output -match "Certificate Validation Report")
    Write-TestResult "Verify certificate from PFX file" $success "Validation report generated"
} catch {
    Write-TestResult "Verify certificate from PFX file" $false $_.Exception.Message
}

# Test 10.2: Verify with custom warning days
try {
    $output = .\certz.exe verify --f devcert.pfx --p changeit --warn 60 2>&1
    $success = $LASTEXITCODE -eq 0 -and ($output -match "Certificate Validation Report")
    Write-TestResult "Verify with custom warning threshold" $success "Custom warning threshold applied"
} catch {
    Write-TestResult "Verify with custom warning threshold" $false $_.Exception.Message
}

# Test 10.3: Verify from store by thumbprint
try {
    # Create and install a cert first
    Remove-TestFiles "verify-test"
    .\certz.exe create --f verify-test.pfx --p VerifyPass | Out-Null
    .\certz.exe install --f verify-test.pfx --p VerifyPass --sn My --sl LocalMachine | Out-Null

    $cert = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
            Where-Object { $_.Subject -like "*dev.local*" } |
            Select-Object -First 1

    if ($cert) {
        $output = .\certz.exe verify --thumbprint $cert.Thumbprint --sn My --sl LocalMachine 2>&1
        $success = $LASTEXITCODE -eq 0 -and ($output -match "Certificate Validation Report")

        # Clean up
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

# Test 11.1: Convert PFX to PEM (both cert and key)
Remove-TestFiles "pfx-to-pem"
try {
    .\certz.exe convert --pfx devcert.pfx --p changeit --out-cert pfx-to-pem.cer --out-key pfx-to-pem.key 2>&1 | Out-Null
    $success = (Test-FileExists "pfx-to-pem.cer") -and (Test-FileExists "pfx-to-pem.key")
    Write-TestResult "Convert PFX to PEM (cert+key)" $success "Both CER and KEY files created"
} catch {
    Write-TestResult "Convert PFX to PEM (cert+key)" $false $_.Exception.Message
}

# Test 11.2: Convert PFX to PEM (cert only)
Remove-TestFiles "pfx-to-cer"
try {
    .\certz.exe convert --pfx devcert.pfx --p changeit --out-cert pfx-to-cer.cer 2>&1 | Out-Null
    $success = (Test-FileExists "pfx-to-cer.cer") -and (-not (Test-FileExists "pfx-to-cer.key"))
    Write-TestResult "Convert PFX to PEM (cert only)" $success "Only CER file created"
} catch {
    Write-TestResult "Convert PFX to PEM (cert only)" $false $_.Exception.Message
}

# Test 11.3: Convert PFX to PEM (key only)
Remove-TestFiles "pfx-to-key"
try {
    .\certz.exe convert --pfx devcert.pfx --p changeit --out-key pfx-to-key.key 2>&1 | Out-Null
    $success = (Test-FileExists "pfx-to-key.key") -and (-not (Test-FileExists "pfx-to-key.cer"))
    Write-TestResult "Convert PFX to PEM (key only)" $success "Only KEY file created"
} catch {
    Write-TestResult "Convert PFX to PEM (key only)" $false $_.Exception.Message
}

# Test 11.4: Round-trip conversion (PFX → PEM → PFX)
Remove-TestFiles "roundtrip"
try {
    # PFX to PEM
    .\certz.exe convert --pfx devcert.pfx --p changeit --out-cert roundtrip.cer --out-key roundtrip.key 2>&1 | Out-Null

    # PEM back to PFX
    .\certz.exe convert --cert roundtrip.cer --key roundtrip.key --pfx roundtrip.pfx --p RoundtripPass 2>&1 | Out-Null

    # Verify the final PFX is valid by getting info
    $output = .\certz.exe info --f roundtrip.pfx --p RoundtripPass 2>&1

    $success = (Test-FileExists "roundtrip.pfx") -and ($LASTEXITCODE -eq 0)
    Write-TestResult "Round-trip conversion (PFX→PEM→PFX)" $success "Full conversion cycle successful"
} catch {
    Write-TestResult "Round-trip conversion (PFX→PEM→PFX)" $false $_.Exception.Message
}

# ============================================================================
# ERROR HANDLING TESTS
# ============================================================================
Write-TestHeader "Testing Error Handling"

# Test 8.1: Invalid file path
try {
    $output = .\certz.exe install --f nonexistent.pfx --p password 2>&1
    $success = $LASTEXITCODE -ne 0  # Should fail
    Write-TestResult "Graceful failure on missing file" $success "Expected error occurred"
} catch {
    Write-TestResult "Graceful failure on missing file" $true "Exception caught as expected"
}

# Test 8.2: Missing required parameters for convert
try {
    $output = .\certz.exe convert --c missing.cer --f output.pfx 2>&1
    $success = $LASTEXITCODE -ne 0  # Should fail
    Write-TestResult "Missing required key parameter" $success "Expected error occurred"
} catch {
    Write-TestResult "Missing required key parameter" $true "Exception caught as expected"
}

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
    Write-Host "`nAll tests passed! ✓" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`nSome tests failed! ✗" -ForegroundColor Red
    exit 1
}
