#Requires -Version 7.5

<#
.SYNOPSIS
    Shared helper functions for certz test scripts.

.DESCRIPTION
    This file contains common functions used across all test scripts:
    - Test filtering (Test-ShouldRun)
    - Output formatting (Write-TestHeader, Write-TestResult)
    - Cleanup functions (Remove-TestFiles)
    - Assertion functions (Assert-*)
    - Test execution wrapper (Invoke-Test)
    - Build functions (Build-Certz)
    - Certificate store utilities (Import-CertificateToStoreNoUI)

    Each test script should dot-source this file:
        . "$PSScriptRoot\test-helper.ps1"

    And then call Initialize-TestEnvironment to set up shared state.
#>

# ============================================================================
# INITIALIZATION
# ============================================================================

function Initialize-TestEnvironment {
    <#
    .SYNOPSIS
        Initializes the test environment with shared state variables.
    .PARAMETER TestId
        Array of test IDs to filter on.
    .PARAMETER Category
        Array of categories to filter on.
    .PARAMETER TestCategories
        Hashtable mapping category names to arrays of test IDs.
    #>
    param(
        [string[]]$TestId,
        [string[]]$Category,
        [hashtable]$TestCategories
    )

    $script:FailedTests = @()
    $script:PassedTests = @()
    $script:TestCount = 0
    $script:FilterTestId = $TestId
    $script:FilterCategory = $Category
    $script:TestCategories = $TestCategories
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Test-ShouldRun {
    <#
    .SYNOPSIS
        Determines if a test should run based on active filters.
    .PARAMETER Id
        The test ID to check.
    .PARAMETER SkipByDefault
        If true, skip this test when no filters are specified (for manual/guided tests).
    #>
    param(
        [string]$Id,
        [switch]$SkipByDefault
    )

    # If no filters specified, run all tests (unless SkipByDefault)
    if (-not $script:FilterTestId -and -not $script:FilterCategory) {
        # Skip guided tests by default
        if ($SkipByDefault) {
            return $false
        }
        if ($script:TestCategories -and $script:TestCategories["guided"] -contains $Id) {
            return $false
        }
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

function Write-TestHeader {
    <#
    .SYNOPSIS
        Writes a formatted test section header.
    #>
    param([string]$Message)
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host " $Message" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Write-TestResult {
    <#
    .SYNOPSIS
        Writes the result of a test and updates tracking arrays.
    #>
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
        if ($Details -and $script:VerboseOutput) {
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

function Remove-TestFiles {
    <#
    .SYNOPSIS
        Removes test-generated certificate files matching a pattern.
    #>
    param([string]$Pattern = "*")

    Get-ChildItem -Path . -File -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -like "$Pattern*.pfx" -or
        $_.Name -like "$Pattern*.cer" -or
        $_.Name -like "$Pattern*.crt" -or
        $_.Name -like "$Pattern*.key" -or
        $_.Name -like "$Pattern*.pem" -or
        $_.Name -like "$Pattern*.der" -or
        $_.Name -like "$Pattern*.password.txt"
    } | Remove-Item -Force -ErrorAction SilentlyContinue
}

# ============================================================================
# ASSERTION FUNCTIONS
# ============================================================================

function Assert-FileExists {
    <#
    .SYNOPSIS
        Asserts that a file exists at the specified path.
    #>
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
    <#
    .SYNOPSIS
        Asserts that a file does not exist at the specified path.
    #>
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

function Assert-ExitCode {
    <#
    .SYNOPSIS
        Asserts that the last exit code matches the expected value.
    #>
    param(
        [int]$Expected = 0,
        [string]$Message = "Exit code should match"
    )
    if ($LASTEXITCODE -ne $Expected) {
        throw "Assertion failed: $Message - Expected exit code $Expected but got $LASTEXITCODE"
    }
    return $true
}

function Assert-Match {
    <#
    .SYNOPSIS
        Asserts that a string matches a regular expression pattern.
    #>
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

function Assert-CertificateInStore {
    <#
    .SYNOPSIS
        Asserts that a certificate exists in the specified store.
    .DESCRIPTION
        Searches for a certificate by subject pattern or thumbprint and returns it if found.
    #>
    param(
        [string]$SubjectPattern,
        [string]$Thumbprint,
        [string]$StoreName = "Root",
        [string]$StoreLocation = "CurrentUser",
        [string]$Message = "Certificate should exist in store"
    )

    if (-not $SubjectPattern -and -not $Thumbprint) {
        throw "Either SubjectPattern or Thumbprint must be specified"
    }

    $cert = $null
    if ($Thumbprint) {
        $cert = Get-ChildItem "Cert:\$StoreLocation\$StoreName" -ErrorAction SilentlyContinue |
                Where-Object { $_.Thumbprint -eq $Thumbprint } |
                Select-Object -First 1
        if (-not $cert) {
            throw "Assertion failed: $Message - No certificate with thumbprint '$Thumbprint' in $StoreLocation\$StoreName"
        }
    } else {
        $cert = Get-ChildItem "Cert:\$StoreLocation\$StoreName" -ErrorAction SilentlyContinue |
                Where-Object { $_.Subject -like $SubjectPattern } |
                Select-Object -First 1
        if (-not $cert) {
            throw "Assertion failed: $Message - No certificate matching '$SubjectPattern' in $StoreLocation\$StoreName"
        }
    }
    return $cert
}

function Assert-CertificateNotInStore {
    <#
    .SYNOPSIS
        Asserts that a certificate does not exist in the specified store.
    #>
    param(
        [string]$SubjectPattern,
        [string]$Thumbprint,
        [string]$StoreName = "Root",
        [string]$StoreLocation = "CurrentUser",
        [string]$Message = "Certificate should not exist in store"
    )

    if (-not $SubjectPattern -and -not $Thumbprint) {
        throw "Either SubjectPattern or Thumbprint must be specified"
    }

    $cert = $null
    if ($Thumbprint) {
        $cert = Get-ChildItem "Cert:\$StoreLocation\$StoreName" -ErrorAction SilentlyContinue |
                Where-Object { $_.Thumbprint -eq $Thumbprint } |
                Select-Object -First 1
        if ($cert) {
            throw "Assertion failed: $Message - Certificate with thumbprint '$Thumbprint' found in $StoreLocation\$StoreName"
        }
    } else {
        $cert = Get-ChildItem "Cert:\$StoreLocation\$StoreName" -ErrorAction SilentlyContinue |
                Where-Object { $_.Subject -like $SubjectPattern } |
                Select-Object -First 1
        if ($cert) {
            throw "Assertion failed: $Message - Certificate matching '$SubjectPattern' found in $StoreLocation\$StoreName"
        }
    }
    return $true
}

# ============================================================================
# TEST EXECUTION
# ============================================================================

function Invoke-Test {
    <#
    .SYNOPSIS
        Executes a test script block with proper error handling and result tracking.
    #>
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
            return [PSCustomObject]@{ Success = $true; Result = $result } | Out-String
        }
    } catch {
        Write-TestResult $TestId $TestName $false $_.Exception.Message
        return [PSCustomObject]@{ Success = $false; Error = $_.Exception.Message } | Out-String
    }
}

# ============================================================================
# BUILD AND SETUP
# ============================================================================

function Build-Certz {
    <#
    .SYNOPSIS
        Builds and publishes certz to the docker\tools directory.
    .PARAMETER Verbose
        Show detailed build output.
    .PARAMETER OutputPath
        The output path for the build. Defaults to "..\docker\tools" for test folder location.
    #>
    param(
        [bool]$Verbose = $false,
        [string]$OutputPath = "..\docker\tools"
    )

    Write-Host "Building and publishing certz..." -ForegroundColor Cyan

    # Resolve the output path relative to the script root
    $resolvedOutput = Join-Path -Path $PSScriptRoot -ChildPath $OutputPath

    # Get the project root (parent of test folder)
    $projectRoot = Split-Path -Parent $PSScriptRoot

    Push-Location -Path $projectRoot
    try {
        $buildOutput = dotnet publish -c Debug -o $resolvedOutput 2>&1

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
    } finally {
        Pop-Location
    }
}

# ============================================================================
# DIRECTORY UTILITIES
# ============================================================================

function Enter-ToolsDirectory {
    <#
    .SYNOPSIS
        Changes to the docker\tools directory, syncing both PowerShell and .NET directories.
    .DESCRIPTION
        When using Push-Location in PowerShell, the .NET Environment.CurrentDirectory is not
        updated. This causes issues with certz (and other .NET apps) that use System.IO.FileInfo
        to resolve relative paths. This function syncs both directories and saves the original
        state for restoration via Exit-ToolsDirectory.
    #>
    $script:OriginalNetDirectory = [System.IO.Directory]::GetCurrentDirectory()
    Push-Location -Path (Join-Path -Path $PSScriptRoot -ChildPath "..\docker\tools")
    [System.IO.Directory]::SetCurrentDirectory((Get-Location).Path)
}

function Exit-ToolsDirectory {
    <#
    .SYNOPSIS
        Returns to the original directory, restoring both PowerShell and .NET directories.
    #>
    Pop-Location
    if ($script:OriginalNetDirectory) {
        [System.IO.Directory]::SetCurrentDirectory($script:OriginalNetDirectory)
    }
}

# ============================================================================
# CERTIFICATE STORE UTILITIES
# ============================================================================

function Import-CertificateToStoreNoUI {
    <#
    .SYNOPSIS
        Imports a certificate to a store without UI prompts.
    .DESCRIPTION
        Uses certutil to import certificates silently, completely bypassing
        the Windows certificate UI that appears when importing to Root or
        other protected stores. Only works for CurrentUser stores.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,
        [Parameter(Mandatory)]
        [string]$StoreName,
        [string]$StoreLocation = "CurrentUser"
    )

    if ($StoreLocation -ne "CurrentUser") {
        throw "Import-CertificateToStoreNoUI only supports CurrentUser store location"
    }

    # Resolve to absolute path
    $absolutePath = (Resolve-Path $FilePath).Path

    # Use certutil to import without UI
    certutil.exe -user -addstore $StoreName $absolutePath | Out-Null
}

function Remove-CertificateFromStore {
    <#
    .SYNOPSIS
        Removes a certificate from a store by subject pattern.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$SubjectPattern,
        [string]$StoreName = "Root",
        [string]$StoreLocation = "CurrentUser"
    )

    $certs = Get-ChildItem "Cert:\$StoreLocation\$StoreName" -ErrorAction SilentlyContinue |
             Where-Object { $_.Subject -like $SubjectPattern }

    foreach ($cert in $certs) {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($StoreName, $StoreLocation)
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $store.Remove($cert)
        $store.Close()
    }
}

# ============================================================================
# SUMMARY OUTPUT
# ============================================================================

function Write-TestSummary {
    <#
    .SYNOPSIS
        Writes a summary of test results and returns the appropriate exit code.
    #>
    param([switch]$SkipCleanup)

    Write-Host "`n========================================" -ForegroundColor Magenta
    Write-Host " TEST SUMMARY" -ForegroundColor Magenta
    Write-Host "========================================" -ForegroundColor Magenta
    Write-Host "Total Tests: $script:TestCount" -ForegroundColor White
    Write-Host "Passed: $($script:PassedTests.Count)" -ForegroundColor Green
    Write-Host "Failed: $($script:FailedTests.Count)" -ForegroundColor $(if ($script:FailedTests.Count -gt 0) { "Red" } else { "Green" })

    if ($script:FailedTests.Count -gt 0) {
        Write-Host "`nFailed Tests:" -ForegroundColor Red
        $script:FailedTests | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    }

    if (-not $SkipCleanup) {
        Write-Host "`nCleaning up test files..." -ForegroundColor Yellow
        Remove-TestFiles
    }

    Write-Host ""

    # Return exit code
    if ($script:FailedTests.Count -gt 0) {
        return 1
    }
    return 0
}

# Export the verbose flag for use in Write-TestResult
function Set-VerboseOutput {
    param([bool]$Enabled)
    $script:VerboseOutput = $Enabled
}
