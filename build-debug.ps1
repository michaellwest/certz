# Build Debug Script for certz
# Builds win-x64 and linux-x64 debug binaries into platform-specific subdirectories:
#   debug/win-x64/   - Windows executable and PDB
#   debug/linux-x64/ - Linux executable
#
# All Docker test services depend on this script. Run it once before starting any container:
#   pwsh -File build-debug.ps1

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot

$builds = @(
    @{ RuntimeIdentifier = "win-x64";   OutputDir = "debug/win-x64" }
    @{ RuntimeIdentifier = "linux-x64"; OutputDir = "debug/linux-x64" }
)

foreach ($build in $builds) {
    $rid = $build.RuntimeIdentifier
    $outputPath = Join-Path $ProjectRoot $build.OutputDir

    Write-Host "Building $rid (Debug)..." -ForegroundColor Cyan

    dotnet publish "$ProjectRoot/src/certz/certz.csproj" `
        -c Debug `
        -r $rid `
        -o $outputPath

    if ($LASTEXITCODE -ne 0) {
        Write-Error "Build failed for $rid with exit code $LASTEXITCODE"
        exit $LASTEXITCODE
    }

    Write-Host "  -> $($build.OutputDir)" -ForegroundColor Green
}

Write-Host ""
Write-Host "All debug builds complete!" -ForegroundColor Green
Write-Host "  debug/win-x64/   - Windows (win-x64)" -ForegroundColor Cyan
Write-Host "  debug/linux-x64/ - Linux   (linux-x64)" -ForegroundColor Cyan
