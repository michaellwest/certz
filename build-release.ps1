# Build Release Script for certz
# Compiles a release binary and writes checksums.txt. Release notes are
# generated separately by scripts/release.ps1.

param(
    [string]$OutputDir = "",
    [string]$Configuration = "Release",
    [string]$RuntimeIdentifier = "win-x64"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot

# Default output directory is release/<RuntimeIdentifier> (e.g. release/win-x64, release/linux-x64)
if (-not $OutputDir) {
    $OutputDir = "release/$RuntimeIdentifier"
}

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
    -r $RuntimeIdentifier `
    -o $OutputPath `
    --self-contained true `
    -p:PublishSingleFile=true `
    -p:PublishReadyToRun=true `
    -p:PublishTrimmed=true

if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

if ($RuntimeIdentifier.StartsWith("win")) { $BuiltName = "certz.exe" } else { $BuiltName = "certz" }
$BuiltPath = Join-Path $OutputPath $BuiltName
if (-not (Test-Path $BuiltPath)) {
    Write-Error "$BuiltName was not found in output directory"
    exit 1
}

# Get version from csproj (needed for the output filename)
$CsprojPath = Join-Path $ProjectRoot "src\certz\certz.csproj"
[xml]$Csproj = Get-Content $CsprojPath
$Version = $Csproj.Project.PropertyGroup.Version
if (-not $Version) {
    $Version = "Unknown"
}

# Rename to certz-<version>-<rid>[.exe] so uploads are unambiguous
# e.g. certz-0.3.0-win-x64.exe, certz-0.3.0-linux-x64
if ($RuntimeIdentifier.StartsWith("win")) { $ExeName = "certz-$Version-$RuntimeIdentifier.exe" } else { $ExeName = "certz-$Version-$RuntimeIdentifier" }
$ExePath = Join-Path $OutputPath $ExeName
Rename-Item -Path $BuiltPath -NewName $ExeName

Write-Host "Build successful!" -ForegroundColor Green

# Calculate file hash
Write-Host "Calculating file hash..." -ForegroundColor Yellow
$FileHash = (Get-FileHash -Path $ExePath -Algorithm SHA256).Hash

# Write checksums.txt (sha256sum-compatible format)
$ChecksumsPath = Join-Path $OutputPath "checksums.txt"
"$($FileHash.ToLower())  $ExeName" | Out-File -FilePath $ChecksumsPath -Encoding utf8NoBOM -Append
Write-Host "Checksums written to: $ChecksumsPath" -ForegroundColor Yellow

Write-Host ""
Write-Host "Release build complete!" -ForegroundColor Green
Write-Host "Output directory: $OutputPath" -ForegroundColor Cyan
Write-Host "Version: $Version" -ForegroundColor Cyan
Write-Host "SHA256: $FileHash" -ForegroundColor Cyan
Write-Host "Checksums: $ChecksumsPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "Files created:" -ForegroundColor Yellow
Get-ChildItem $OutputPath | ForEach-Object { Write-Host "  - $($_.Name)" }
