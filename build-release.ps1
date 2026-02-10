# Build Release Script for certz
# This script builds a release version of certz.exe and generates release notes

param(
    [string]$OutputDir = "release",
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot
$OutputPath = Join-Path $ProjectRoot $OutputDir

Write-Host "Building certz release..." -ForegroundColor Cyan

# Clean and create output directory
if (Test-Path $OutputPath) {
    Remove-Item $OutputPath -Recurse -Force
}
New-Item -ItemType Directory -Path $OutputPath | Out-Null

# Build the project
Write-Host "Publishing project..." -ForegroundColor Yellow
dotnet publish "$ProjectRoot\src\certz\certz.csproj" `
    -c $Configuration `
    -o $OutputPath `
    --self-contained true `
    -p:PublishSingleFile=true `
    -p:PublishReadyToRun=true `
    -p:PublishTrimmed=true

if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

$ExePath = Join-Path $OutputPath "certz.exe"
if (-not (Test-Path $ExePath)) {
    Write-Error "certz.exe was not found in output directory"
    exit 1
}

Write-Host "Build successful!" -ForegroundColor Green

# Get version from csproj
$CsprojPath = Join-Path $ProjectRoot "src\certz\certz.csproj"
[xml]$Csproj = Get-Content $CsprojPath
$Version = $Csproj.Project.PropertyGroup.AssemblyVersion
if (-not $Version) {
    $Version = "Unknown"
}

# Get the last tagged version
$LastTag = git describe --tags --abbrev=0 2>$null
if (-not $LastTag) {
    $LastTag = "initial"
    $Commits = git log --oneline --no-decorate
} else {
    $Commits = git log "$LastTag..HEAD" --oneline --no-decorate
}

# Calculate file hash
Write-Host "Calculating file hash..." -ForegroundColor Yellow
$FileHash = (Get-FileHash -Path $ExePath -Algorithm SHA256).Hash

# Generate release notes
Write-Host "Generating release notes..." -ForegroundColor Yellow
$ReleaseDate = Get-Date -Format "yyyy-MM-dd"
$ReleaseNotesPath = Join-Path $OutputPath "RELEASE_NOTES.md"

$ReleaseNotesContent = @"
# certz Release Notes

**Version:** $Version
**Release Date:** $ReleaseDate
**Previous Version:** $LastTag

## Changes Since $LastTag

"@

if ($Commits) {
    foreach ($Commit in $Commits) {
        # Extract commit message (skip the short hash)
        $Message = $Commit -replace "^[a-f0-9]+\s+", ""
        $ReleaseNotesContent += "- $Message`n"
    }
} else {
    $ReleaseNotesContent += "- No changes since last release`n"
}

$ReleaseNotesContent += @"

---

## File Verification

**File:** certz.exe
**SHA256 Hash:** ``$FileHash``
"@

$ReleaseNotesContent | Out-File -FilePath $ReleaseNotesPath -Encoding utf8

Write-Host ""
Write-Host "Release build complete!" -ForegroundColor Green
Write-Host "Output directory: $OutputPath" -ForegroundColor Cyan
Write-Host "Version: $Version" -ForegroundColor Cyan
Write-Host "SHA256: $FileHash" -ForegroundColor Cyan
Write-Host ""
Write-Host "Files created:" -ForegroundColor Yellow
Get-ChildItem $OutputPath | ForEach-Object { Write-Host "  - $($_.Name)" }
