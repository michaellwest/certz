#Requires -RunAsAdministrator
#requires -version 7

<#
.SYNOPSIS
    Runs all certz test suites.

.DESCRIPTION
    Invokes each individual test-*.ps1 script in a separate process and reports
    aggregate results. Each test suite handles its own build, directory setup,
    and cleanup.

    Use -UseDocker to run the tests inside a Windows Docker container for
    isolation. This builds certz, builds the Docker image, and runs the
    container with all test suites baked in.

    In Docker containers (DOTNET_ENVIRONMENT=Test), individual suites skip
    building and use the pre-built certz.exe in the working directory.

.PARAMETER Verbose
    Show detailed output for each test suite.

.PARAMETER UseDocker
    Runs the tests inside a Windows Docker container for isolation.
    Requires Docker Desktop with Windows containers enabled.

.PARAMETER DockerVerbose
    When used with -UseDocker, passes the -Verbose flag to tests running
    in the container.

.PARAMETER Category
    Run only specific test suites by category name. Accepts an array.
    Available categories: create, inspect, trust, lint, monitor, renew,
    ephemeral, convert, examples

.EXAMPLE
    .\test-all.ps1
    Runs all test suites locally.

.EXAMPLE
    .\test-all.ps1 -Verbose
    Runs all test suites locally with verbose output.

.EXAMPLE
    .\test-all.ps1 -Category create, lint
    Runs only the create and lint test suites.

.EXAMPLE
    .\test-all.ps1 -UseDocker
    Runs all tests inside a Windows Docker container.

.EXAMPLE
    .\test-all.ps1 -UseDocker -DockerVerbose
    Runs all tests in Docker with verbose output.
#>
param(
    [switch]$Verbose,
    [switch]$UseDocker,
    [switch]$DockerVerbose,
    [ValidateSet("create", "inspect", "trust", "lint", "monitor", "renew",
                 "ephemeral", "convert", "examples")]
    [string[]]$Category
)

$ErrorActionPreference = "Stop"

# ============================================================================
# DOCKER EXECUTION MODE
# ============================================================================
if ($UseDocker) {
    Write-Host "`nCertz Docker Test Runner" -ForegroundColor Magenta
    Write-Host "========================`n" -ForegroundColor Magenta

    # Load shared test helper and build certz to debug/
    . "$PSScriptRoot\test-helper.ps1"
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

    # Resolve project root (parent of test/)
    $projectRoot = Split-Path -Parent $PSScriptRoot

    # Build the Docker image (Server Core for full PKI module support)
    Write-Host "Building Docker test image (Server Core)..." -ForegroundColor Cyan
    try {
        docker build -t certz-test:latest -f "$projectRoot\Dockerfile.test.servercore" $projectRoot 2>&1 | ForEach-Object {
            if ($_ -match "error|failed") {
                Write-Host $_ -ForegroundColor Red
            } elseif ($_ -match "successfully|complete") {
                Write-Host $_ -ForegroundColor Green
            } else {
                Write-Host $_ -ForegroundColor Gray
            }
        }
        # debug container using:
        # docker run -it --entrypoint pwsh certz-test:latest
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

    $dockerArgs = @("run", "--rm", "--isolation=process", "certz-test:latest")

    if ($DockerVerbose) {
        $dockerArgs += "-Verbose"
    }

    if ($Category) {
        $dockerArgs += "-Category"
        $dockerArgs += ($Category -join ",")
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
# LOCAL EXECUTION MODE
# ============================================================================

# All test suites in execution order (matches phase order)
$allSuites = @(
    "test-create.ps1"
    "test-inspect.ps1"
    "test-trust.ps1"
    "test-lint.ps1"
    "test-monitor.ps1"
    "test-renew.ps1"
    "test-ephemeral.ps1"
    "test-convert.ps1"
    "test-examples.ps1"
)

# Filter suites by category if specified
if ($Category) {
    $testSuites = $allSuites | Where-Object {
        $name = $_ -replace '^test-' -replace '\.ps1$'
        $Category -contains $name
    }
    if ($testSuites.Count -eq 0) {
        Write-Host "ERROR: No matching test suites for categories: $($Category -join ', ')" -ForegroundColor Red
        exit 1
    }
} else {
    $testSuites = $allSuites
}

$passedSuites = @()
$failedSuites = @()
$skippedSuites = @()

# Clear stale CTRF suite files from previous runs before starting
$testResultsDir = Join-Path $PSScriptRoot "test-results"
if (Test-Path $testResultsDir) {
    Remove-Item -Path (Join-Path $testResultsDir "*.json") -Force -ErrorAction SilentlyContinue
}

Write-Host "`nCertz Test Runner" -ForegroundColor Magenta
Write-Host "================================" -ForegroundColor Magenta

if ($Category) {
    Write-Host "Categories: $($Category -join ', ')" -ForegroundColor Yellow
}
Write-Host "Suites to run: $($testSuites.Count)`n" -ForegroundColor White

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

foreach ($suite in $testSuites) {
    $suitePath = Join-Path $PSScriptRoot $suite

    if (-not (Test-Path $suitePath)) {
        Write-Host "[SKIP] $suite - file not found" -ForegroundColor Yellow
        $skippedSuites += $suite
        continue
    }

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host " Running: $suite" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    $suiteArgs = @()
    if ($Verbose) { $suiteArgs += "-Verbose" }

    & pwsh -File $suitePath @suiteArgs

    if ($LASTEXITCODE -eq 0) {
        $passedSuites += $suite
        Write-Host "`n[SUITE PASS] $suite" -ForegroundColor Green
    } else {
        $failedSuites += $suite
        Write-Host "`n[SUITE FAIL] $suite (exit code: $LASTEXITCODE)" -ForegroundColor Red
    }
}

$stopwatch.Stop()

# Summary
Write-Host "`n========================================" -ForegroundColor Magenta
Write-Host " ALL SUITES SUMMARY" -ForegroundColor Magenta
Write-Host "========================================" -ForegroundColor Magenta
Write-Host "Total Suites: $($testSuites.Count)" -ForegroundColor White
Write-Host "Passed: $($passedSuites.Count)" -ForegroundColor Green
Write-Host "Failed: $($failedSuites.Count)" -ForegroundColor $(if ($failedSuites.Count -gt 0) { "Red" } else { "Green" })
if ($skippedSuites.Count -gt 0) {
    Write-Host "Skipped: $($skippedSuites.Count)" -ForegroundColor Yellow
}
Write-Host "Duration: $($stopwatch.Elapsed.ToString('mm\:ss'))" -ForegroundColor White

if ($failedSuites.Count -gt 0) {
    Write-Host "`nFailed Suites:" -ForegroundColor Red
    $failedSuites | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
}

# ============================================================================
# MERGE PER-SUITE CTRF FILES INTO results.json
# ============================================================================
$suiteFiles = Get-ChildItem -Path $testResultsDir -Filter "*.json" -ErrorAction SilentlyContinue |
              Where-Object { $_.Name -ne "results.json" }

if ($suiteFiles) {
    $allTests    = [System.Collections.Generic.List[object]]::new()
    $totalPassed  = 0
    $totalFailed  = 0
    $totalSkipped = 0
    $minStart     = [long]::MaxValue
    $maxStop      = [long]::MinValue

    foreach ($file in $suiteFiles) {
        $suite = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
        foreach ($t in $suite.results.tests) { $allTests.Add($t) }
        $totalPassed  += $suite.results.summary.passed
        $totalFailed  += $suite.results.summary.failed
        $totalSkipped += $suite.results.summary.skipped
        if ($suite.results.summary.start -lt $minStart) { $minStart = $suite.results.summary.start }
        if ($suite.results.summary.stop  -gt $maxStop)  { $maxStop  = $suite.results.summary.stop  }
    }

    $merged = @{
        results = @{
            tool    = @{ name = "certz" }
            summary = @{
                tests   = $totalPassed + $totalFailed + $totalSkipped
                passed  = $totalPassed
                failed  = $totalFailed
                skipped = $totalSkipped
                other   = 0
                start   = $minStart
                stop    = $maxStop
            }
            tests = @($allTests)
        }
    }

    $mergedPath = Join-Path $testResultsDir "results.json"
    $merged | ConvertTo-Json -Depth 10 | Set-Content -Path $mergedPath -Encoding UTF8
    Write-Host "`nCTRF report: $mergedPath" -ForegroundColor DarkGray
}

if ($failedSuites.Count -gt 0) {
    exit 1
}

exit 0
