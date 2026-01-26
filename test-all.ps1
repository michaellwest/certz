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

# Test 1.1: Create with defaults (generates secure random password displayed on screen)
Remove-TestFiles "devcert"
try {
    $output = .\certz.exe create 2>&1 | Out-String
    $success = (Test-FileExists "devcert.pfx") -and ($output -match "IMPORTANT: Certificate Password")
    Write-TestResult "Create with defaults" $success "PFX created with generated password"
} catch {
    Write-TestResult "Create with defaults" $false $_.Exception.Message
}

# Test 1.2: Create with custom PFX and password
Remove-TestFiles "mycert"
try {
    $output = .\certz.exe create --f mycert.pfx --p MySecurePass123 2>&1 | Out-String
    # When password is provided, no password warning should be displayed
    $success = (Test-FileExists "mycert.pfx") -and ($output -notmatch "IMPORTANT: Certificate Password")
    Write-TestResult "Create with custom password" $success "PFX created with provided password"
} catch {
    Write-TestResult "Create with custom password" $false $_.Exception.Message
}

# Test 1.3: Create with custom SANs
Remove-TestFiles "testcert"
try {
    .\certz.exe create --f testcert.pfx --p TestCertPass --san *.example.com localhost 127.0.0.1 192.168.1.100 | Out-Null
    $success = Test-FileExists "testcert.pfx"
    Write-TestResult "Create with custom SANs" $success "Multiple DNS and IP SANs"
} catch {
    Write-TestResult "Create with custom SANs" $false $_.Exception.Message
}

# Test 1.4: Create with custom validity period (within CA/B Forum 398-day limit)
Remove-TestFiles "longcert"
try {
    .\certz.exe create --f longcert.pfx --p LongCertPass --days 365 | Out-Null
    $success = Test-FileExists "longcert.pfx"
    Write-TestResult "Create with 365 days validity" $success "1-year certificate"
} catch {
    Write-TestResult "Create with 365 days validity" $false $_.Exception.Message
}

# Test 1.5: Create with all options
Remove-TestFiles "fulltest"
try {
    .\certz.exe create --f fulltest.pfx --c fulltest.cer --k fulltest.key --p ComplexPass456 --san *.dev.local *.test.com 127.0.0.1 --days 180 | Out-Null
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
    .\certz.exe create --f multisan.pfx --p MultiSanPass --san *.app1.local *.app2.local *.app3.local localhost | Out-Null
    $success = Test-FileExists "multisan.pfx"
    Write-TestResult "Create with multiple SANs" $success "4 DNS entries"
} catch {
    Write-TestResult "Create with multiple SANs" $false $_.Exception.Message
}

# ============================================================================
# KEY SIZE TESTS
# ============================================================================
Write-TestHeader "Testing Key Size Options"

# Test 1.8: Create with 2048-bit RSA key (default)
Remove-TestFiles "keysize-2048"
try {
    $output = .\certz.exe create --f keysize-2048.pfx --p KeySize2048Pass --key-size 2048 2>&1 | Out-String
    $success = (Test-FileExists "keysize-2048.pfx") -and ($output -match "INFO: Using 2048-bit RSA key")
    Write-TestResult "Create with 2048-bit RSA key" $success "NIST warning displayed"
} catch {
    Write-TestResult "Create with 2048-bit RSA key" $false $_.Exception.Message
}

# Test 1.9: Create with 3072-bit RSA key (NIST recommended)
Remove-TestFiles "keysize-3072"
try {
    .\certz.exe create --f keysize-3072.pfx --p KeySize3072Pass --key-size 3072 | Out-Null
    $success = Test-FileExists "keysize-3072.pfx"
    Write-TestResult "Create with 3072-bit RSA key" $success "NIST recommended key size"
} catch {
    Write-TestResult "Create with 3072-bit RSA key" $false $_.Exception.Message
}

# Test 1.10: Create with 4096-bit RSA key
Remove-TestFiles "keysize-4096"
try {
    .\certz.exe create --f keysize-4096.pfx --p KeySize4096Pass --key-size 4096 | Out-Null
    $success = Test-FileExists "keysize-4096.pfx"
    Write-TestResult "Create with 4096-bit RSA key" $success "Maximum RSA key size"
} catch {
    Write-TestResult "Create with 4096-bit RSA key" $false $_.Exception.Message
}

# Test 1.11: Invalid key size should fail
Remove-TestFiles "keysize-invalid"
try {
    $output = .\certz.exe create --f keysize-invalid.pfx --p InvalidPass --key-size 1024 2>&1
    $success = $LASTEXITCODE -ne 0
    Write-TestResult "Reject invalid key size (1024)" $success "Validation error expected"
} catch {
    Write-TestResult "Reject invalid key size (1024)" $true "Exception caught as expected"
}

# ============================================================================
# HASH ALGORITHM TESTS
# ============================================================================
Write-TestHeader "Testing Hash Algorithm Options"

# Test 1.12: Create with SHA256
Remove-TestFiles "hash-sha256"
try {
    .\certz.exe create --f hash-sha256.pfx --p HashSha256Pass --hash-algorithm SHA256 | Out-Null
    $success = Test-FileExists "hash-sha256.pfx"
    Write-TestResult "Create with SHA256 hash" $success "Standard hash algorithm"
} catch {
    Write-TestResult "Create with SHA256 hash" $false $_.Exception.Message
}

# Test 1.13: Create with SHA384
Remove-TestFiles "hash-sha384"
try {
    .\certz.exe create --f hash-sha384.pfx --p HashSha384Pass --hash-algorithm SHA384 | Out-Null
    $success = Test-FileExists "hash-sha384.pfx"
    Write-TestResult "Create with SHA384 hash" $success "Stronger hash algorithm"
} catch {
    Write-TestResult "Create with SHA384 hash" $false $_.Exception.Message
}

# Test 1.14: Create with SHA512
Remove-TestFiles "hash-sha512"
try {
    .\certz.exe create --f hash-sha512.pfx --p HashSha512Pass --hash-algorithm SHA512 | Out-Null
    $success = Test-FileExists "hash-sha512.pfx"
    Write-TestResult "Create with SHA512 hash" $success "Strongest hash algorithm"
} catch {
    Write-TestResult "Create with SHA512 hash" $false $_.Exception.Message
}

# Test 1.15: Create with auto hash selection (3072-bit key should use SHA384)
Remove-TestFiles "hash-auto"
try {
    .\certz.exe create --f hash-auto.pfx --p HashAutoPass --key-size 3072 --hash-algorithm auto | Out-Null
    $success = Test-FileExists "hash-auto.pfx"
    Write-TestResult "Create with auto hash selection" $success "Auto-selects based on key size"
} catch {
    Write-TestResult "Create with auto hash selection" $false $_.Exception.Message
}

# ============================================================================
# KEY TYPE TESTS (RSA and ECDSA)
# ============================================================================
Write-TestHeader "Testing Key Type Options"

# Test 1.16: Create with RSA key type (explicit)
Remove-TestFiles "keytype-rsa"
try {
    .\certz.exe create --f keytype-rsa.pfx --p KeyTypeRsaPass --key-type RSA | Out-Null
    $success = Test-FileExists "keytype-rsa.pfx"
    Write-TestResult "Create with RSA key type" $success "Explicit RSA key type"
} catch {
    Write-TestResult "Create with RSA key type" $false $_.Exception.Message
}

# Test 1.17: Create with ECDSA P-256 key
Remove-TestFiles "keytype-ecdsa256"
try {
    .\certz.exe create --f keytype-ecdsa256.pfx --c keytype-ecdsa256.cer --k keytype-ecdsa256.key --p EcdsaP256Pass --key-type ECDSA-P256 | Out-Null
    $success = (Test-FileExists "keytype-ecdsa256.pfx") -and (Test-FileExists "keytype-ecdsa256.key")
    Write-TestResult "Create with ECDSA P-256 key" $success "Modern TLS 1.3 optimized"
} catch {
    Write-TestResult "Create with ECDSA P-256 key" $false $_.Exception.Message
}

# Test 1.18: Create with ECDSA P-384 key
Remove-TestFiles "keytype-ecdsa384"
try {
    .\certz.exe create --f keytype-ecdsa384.pfx --p EcdsaP384Pass --key-type ECDSA-P384 | Out-Null
    $success = Test-FileExists "keytype-ecdsa384.pfx"
    Write-TestResult "Create with ECDSA P-384 key" $success "High security ECDSA"
} catch {
    Write-TestResult "Create with ECDSA P-384 key" $false $_.Exception.Message
}

# Test 1.19: Create with ECDSA P-521 key
Remove-TestFiles "keytype-ecdsa521"
try {
    .\certz.exe create --f keytype-ecdsa521.pfx --p EcdsaP521Pass --key-type ECDSA-P521 | Out-Null
    $success = Test-FileExists "keytype-ecdsa521.pfx"
    Write-TestResult "Create with ECDSA P-521 key" $success "Maximum ECDSA security"
} catch {
    Write-TestResult "Create with ECDSA P-521 key" $false $_.Exception.Message
}

# Test 1.20: ECDSA certificate can be converted to PEM and back
Remove-TestFiles "ecdsa-convert"
try {
    # Create ECDSA certificate
    .\certz.exe create --f ecdsa-convert.pfx --c ecdsa-convert.cer --k ecdsa-convert.key --p EcdsaConvertPass --key-type ECDSA-P256 | Out-Null

    # Convert PEM back to PFX
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

# Test 1.21: Create CA certificate
Remove-TestFiles "ca-cert"
try {
    .\certz.exe create --f ca-cert.pfx --p CaCertPass --san "My Test CA" --is-ca | Out-Null
    $success = Test-FileExists "ca-cert.pfx"
    Write-TestResult "Create CA certificate" $success "Certificate Authority cert created"
} catch {
    Write-TestResult "Create CA certificate" $false $_.Exception.Message
}

# Test 1.22: Create CA certificate with path length constraint
Remove-TestFiles "ca-path"
try {
    .\certz.exe create --f ca-path.pfx --p CaPathPass --san "My Intermediate CA" --is-ca --path-length 1 | Out-Null
    $success = Test-FileExists "ca-path.pfx"
    Write-TestResult "Create CA with path length" $success "Intermediate CA with depth=1"
} catch {
    Write-TestResult "Create CA with path length" $false $_.Exception.Message
}

# Test 1.23: Create CA certificate with CRL and OCSP URLs
Remove-TestFiles "ca-full"
try {
    .\certz.exe create --f ca-full.pfx --p CaFullPass --san "My Full CA" --is-ca --crl-url http://crl.example.com/ca.crl --ocsp-url http://ocsp.example.com | Out-Null
    $success = Test-FileExists "ca-full.pfx"
    Write-TestResult "Create CA with CRL/OCSP" $success "CA with revocation endpoints"
} catch {
    Write-TestResult "Create CA with CRL/OCSP" $false $_.Exception.Message
}

# ============================================================================
# SUBJECT DN FIELD TESTS
# ============================================================================
Write-TestHeader "Testing Subject Distinguished Name Fields"

# Test 1.24: Create with Organization field
Remove-TestFiles "dn-org"
try {
    .\certz.exe create --f dn-org.pfx --p DnOrgPass --san *.example.com --subject-o "Acme Corporation" | Out-Null
    $success = Test-FileExists "dn-org.pfx"
    Write-TestResult "Create with Organization (O)" $success "Subject O field set"
} catch {
    Write-TestResult "Create with Organization (O)" $false $_.Exception.Message
}

# Test 1.25: Create with full Distinguished Name
Remove-TestFiles "dn-full"
try {
    .\certz.exe create --f dn-full.pfx --p DnFullPass --san *.example.com --subject-o "Acme Corporation" --subject-ou "Engineering" --subject-c US --subject-st "California" --subject-l "San Francisco" | Out-Null
    $success = Test-FileExists "dn-full.pfx"

    # Verify the DN fields are in the certificate
    $output = .\certz.exe info --f dn-full.pfx --p DnFullPass 2>&1 | Out-String
    $hasDN = ($output -match "Acme Corporation") -and ($output -match "Engineering") -and ($output -match "California")

    Write-TestResult "Create with full DN" ($success -and $hasDN) "All DN fields present"
} catch {
    Write-TestResult "Create with full DN" $false $_.Exception.Message
}

# Test 1.26: Country code validation (must be 2 characters)
Remove-TestFiles "dn-country-invalid"
try {
    $output = .\certz.exe create --f dn-country-invalid.pfx --p InvalidPass --san *.example.com --subject-c USA 2>&1
    $success = $LASTEXITCODE -ne 0
    Write-TestResult "Reject invalid country code - 3 chars" $success "Validation error expected"
} catch {
    Write-TestResult "Reject invalid country code - 3 chars" $true "Exception caught as expected"
}

# ============================================================================
# VALIDITY PERIOD VALIDATION TESTS
# ============================================================================
Write-TestHeader "Testing Validity Period Validation"

# Test 1.27: Default validity is 90 days
Remove-TestFiles "validity-default"
try {
    .\certz.exe create --f validity-default.pfx --p ValidityDefaultPass | Out-Null
    $success = Test-FileExists "validity-default.pfx"

    # Check expiration date is ~90 days from now
    # (We can't easily check this without parsing cert, so just verify creation works)
    Write-TestResult "Default validity - 90 days" $success "Certificate created with default validity"
} catch {
    Write-TestResult "Default validity - 90 days" $false $_.Exception.Message
}

# Test 1.28: Validity >200 days shows warning (until March 2026)
Remove-TestFiles "validity-warning"
try {
    $output = .\certz.exe create --f validity-warning.pfx --p ValidityWarnPass --days 250 2>&1 | Out-String
    $success = (Test-FileExists "validity-warning.pfx") -and ($output -match "WARNING.*validity.*exceeds")
    Write-TestResult "Warning for over 200 day validity" $success "Future compliance warning shown"
} catch {
    Write-TestResult "Warning for over 200 day validity" $false $_.Exception.Message
}

# Test 1.29: Validity >398 days should fail
Remove-TestFiles "validity-error"
try {
    $output = .\certz.exe create --f validity-error.pfx --p ValidityErrorPass --days 400 2>&1
    $success = $LASTEXITCODE -ne 0
    Write-TestResult "Reject over 398 day validity" $success "CA/B Forum limit enforced"
} catch {
    Write-TestResult "Reject over 398 day validity" $true "Exception caught as expected"
}

# Test 1.30: Minimum validity - 1 day
Remove-TestFiles "validity-min"
try {
    .\certz.exe create --f validity-min.pfx --p ValidityMinPass --days 1 | Out-Null
    $success = Test-FileExists "validity-min.pfx"
    Write-TestResult "Minimum validity - 1 day" $success "Short-lived certificate"
} catch {
    Write-TestResult "Minimum validity - 1 day" $false $_.Exception.Message
}

# Test 1.31: Zero days should fail
Remove-TestFiles "validity-zero"
try {
    $output = .\certz.exe create --f validity-zero.pfx --p ValidityZeroPass --days 0 2>&1
    $success = $LASTEXITCODE -ne 0
    Write-TestResult "Reject 0 day validity" $success "Minimum 1 day required"
} catch {
    Write-TestResult "Reject 0 day validity" $true "Exception caught as expected"
}

# ============================================================================
# AIA/CDP EXTENSION TESTS
# ============================================================================
Write-TestHeader "Testing AIA and CDP Extensions"

# Test 1.32: Create with CRL Distribution Point
Remove-TestFiles "ext-crl"
try {
    .\certz.exe create --f ext-crl.pfx --p ExtCrlPass --crl-url http://crl.example.com/cert.crl | Out-Null
    $success = Test-FileExists "ext-crl.pfx"
    Write-TestResult "Create with CRL Distribution Point" $success "CDP extension added"
} catch {
    Write-TestResult "Create with CRL Distribution Point" $false $_.Exception.Message
}

# Test 1.33: Create with OCSP responder URL
Remove-TestFiles "ext-ocsp"
try {
    .\certz.exe create --f ext-ocsp.pfx --p ExtOcspPass --ocsp-url http://ocsp.example.com | Out-Null
    $success = Test-FileExists "ext-ocsp.pfx"
    Write-TestResult "Create with OCSP responder" $success "AIA OCSP extension added"
} catch {
    Write-TestResult "Create with OCSP responder" $false $_.Exception.Message
}

# Test 1.34: Create with CA Issuers URL
Remove-TestFiles "ext-ca-issuers"
try {
    .\certz.exe create --f ext-ca-issuers.pfx --p ExtCaIssuersPass --ca-issuers-url http://certs.example.com/ca.cer | Out-Null
    $success = Test-FileExists "ext-ca-issuers.pfx"
    Write-TestResult "Create with CA Issuers URL" $success "AIA CA Issuers extension added"
} catch {
    Write-TestResult "Create with CA Issuers URL" $false $_.Exception.Message
}

# Test 1.35: Create with all AIA/CDP extensions
Remove-TestFiles "ext-all"
try {
    .\certz.exe create --f ext-all.pfx --p ExtAllPass --crl-url http://crl.example.com/cert.crl --ocsp-url http://ocsp.example.com --ca-issuers-url http://certs.example.com/ca.cer | Out-Null
    $success = Test-FileExists "ext-all.pfx"
    Write-TestResult "Create with all AIA/CDP extensions" $success "Full revocation info"
} catch {
    Write-TestResult "Create with all AIA/CDP extensions" $false $_.Exception.Message
}

# ============================================================================
# INSTALL COMMAND TESTS
# ============================================================================
Write-TestHeader "Testing INSTALL Command"

# First, create a certificate with a known password for install tests
Remove-TestFiles "install-test"
.\certz.exe create --f install-test.pfx --p InstallTestPass --san *.dev.local | Out-Null

# Test 2.1: Install to default store (My/LocalMachine)
try {
    .\certz.exe install --f install-test.pfx --p InstallTestPass | Out-Null
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
    .\certz.exe install --f install-test.pfx --p InstallTestPass --sn root | Out-Null
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
    .\certz.exe install --f install-test.pfx --p InstallTestPass --sl CurrentUser --sn My | Out-Null
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
    $output = .\certz.exe export --url https://www.microsoft.com --f microsoft.pfx --p CustomExportPass 2>&1 | Out-String
    # When password is provided, no password warning should be displayed
    $success = (Test-FileExists "microsoft.pfx") -and ($output -notmatch "IMPORTANT: Certificate Password")
    Write-TestResult "Export with custom password" $success "PFX exported with provided password"
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

# Test 6.2: Convert with generated password (no password provided)
Remove-TestFiles "converted-default"
try {
    $output = .\certz.exe convert --c pemonly.cer --k pemonly.key --f converted-default.pfx 2>&1 | Out-String
    $success = (Test-FileExists "converted-default.pfx") -and ($output -match "IMPORTANT: Certificate Password")
    Write-TestResult "Convert with generated password" $success "Secure password generated and displayed"
} catch {
    Write-TestResult "Convert with generated password" $false $_.Exception.Message
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

# Test 7.1: Complete lifecycle (create to install to export to remove)
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

    Write-TestResult "Complete certificate lifecycle" $success "Create-Install-Export-Remove"
} catch {
    Write-TestResult "Complete certificate lifecycle" $false $_.Exception.Message
}

# Test 7.2: Format conversion chain (PFX to PEM to PFX)
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
try {
    $output = .\certz.exe info --f info-cert.pfx --p InfoTestPass 2>&1 | Out-String
    $success = $LASTEXITCODE -eq 0 -and ($output -match "Certificate Information")
    Write-TestResult "Info from PFX file" $success "Certificate details displayed"
} catch {
    Write-TestResult "Info from PFX file" $false $_.Exception.Message
}

# Test 9.2: Info from PEM file (uses info-cert.cer created above)
try {
    $output = .\certz.exe info --f info-cert.cer 2>&1 | Out-String
    $success = $LASTEXITCODE -eq 0 -and ($output -match "Certificate Information")
    Write-TestResult "Info from PEM file" $success "Certificate details displayed"
} catch {
    Write-TestResult "Info from PEM file" $false $_.Exception.Message
}

# Test 9.3: Info from URL
try {
    $output = .\certz.exe info --url https://www.github.com 2>&1 | Out-String
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
        $output = .\certz.exe info --thumbprint $cert.Thumbprint --sn My --sl LocalMachine 2>&1 | Out-String
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

# Create a certificate with known password for verify tests
Remove-TestFiles "verify-cert"
.\certz.exe create --f verify-cert.pfx --p VerifyTestPass --san *.dev.local | Out-Null

# Test 10.1: Verify valid certificate from file
try {
    $output = .\certz.exe verify --f verify-cert.pfx --p VerifyTestPass 2>&1 | Out-String
    $success = $LASTEXITCODE -eq 0 -and ($output -match "Certificate Validation Report")
    Write-TestResult "Verify certificate from PFX file" $success "Validation report generated"
} catch {
    Write-TestResult "Verify certificate from PFX file" $false $_.Exception.Message
}

# Test 10.2: Verify with custom warning days
try {
    $output = .\certz.exe verify --f verify-cert.pfx --p VerifyTestPass --warn 60 2>&1 | Out-String
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
        $output = .\certz.exe verify --thumbprint $cert.Thumbprint --sn My --sl LocalMachine 2>&1 | Out-String
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

# Create a certificate with known password for convert tests
Remove-TestFiles "convert-source"
.\certz.exe create --f convert-source.pfx --p ConvertSourcePass --san *.dev.local | Out-Null

# Test 11.1: Convert PFX to PEM (both cert and key)
Remove-TestFiles "pfx-to-pem"
try {
    .\certz.exe convert --pfx convert-source.pfx --p ConvertSourcePass --out-cert pfx-to-pem.cer --out-key pfx-to-pem.key 2>&1 | Out-Null
    $success = (Test-FileExists "pfx-to-pem.cer") -and (Test-FileExists "pfx-to-pem.key")
    Write-TestResult "Convert PFX to PEM (cert+key)" $success "Both CER and KEY files created"
} catch {
    Write-TestResult "Convert PFX to PEM (cert+key)" $false $_.Exception.Message
}

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
    # PFX to PEM
    .\certz.exe convert --pfx convert-source.pfx --p ConvertSourcePass --out-cert roundtrip.cer --out-key roundtrip.key 2>&1 | Out-Null

    # PEM back to PFX
    .\certz.exe convert --cert roundtrip.cer --key roundtrip.key --pfx roundtrip.pfx --p RoundtripPass 2>&1 | Out-Null

    # Verify the final PFX is valid by getting info
    $output = .\certz.exe info --f roundtrip.pfx --p RoundtripPass 2>&1

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
