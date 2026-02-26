# Verify that checksums.txt entries for a certz release match the GitHub API digest field.
#
# Usage:
#   pwsh -File scripts/verify-release.ps1 -Tag 0.3
#   pwsh -File scripts/verify-release.ps1 -Tag 0.3 -Repo owner/certz
#
# Exit codes:
#   0  All hashes in checksums.txt match the GitHub API digest
#   1  One or more mismatches, missing assets, or checksums.txt not found

param(
    [Parameter(Mandatory)]
    [string]$Tag,

    [string]$Repo = "michaellwest/certz"
)

$ErrorActionPreference = "Stop"
$gh = 'C:\Program Files\GitHub CLI\gh.exe'

Write-Host "Verifying release $Tag from $Repo..." -ForegroundColor Cyan

# Fetch release metadata from GitHub API
$release = & $gh api "repos/$Repo/releases/tags/$Tag" | ConvertFrom-Json
if (-not $release) {
    Write-Error "Release '$Tag' not found in $Repo"
    exit 1
}
$assets = $release.assets

# Locate checksums.txt asset
$cksAsset = $assets | Where-Object { $_.name -eq "checksums.txt" }
if (-not $cksAsset) {
    Write-Error "No checksums.txt asset found in release $Tag. Upload checksums.txt as a release asset and retry."
    exit 1
}

# Download checksums.txt to a temp file
$tmpFile = [System.IO.Path]::GetTempFileName()
try {
    Invoke-WebRequest -Uri $cksAsset.browser_download_url -OutFile $tmpFile -UseBasicParsing
    $lines = Get-Content $tmpFile | Where-Object { $_ -match '\S' }
} finally {
    Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
}

if (-not $lines) {
    Write-Error "checksums.txt is empty or could not be read."
    exit 1
}

$pass = $true

foreach ($line in $lines) {
    # sha256sum format: "<hash>  <filename>" (two spaces)
    $parts  = $line -split '\s+', 2
    if ($parts.Count -lt 2) {
        Write-Warning "Skipping malformed line: $line"
        continue
    }
    $ckHash = $parts[0].Trim().ToLower()
    $ckName = $parts[1].Trim()

    $apiAsset = $assets | Where-Object { $_.name -eq $ckName }
    if (-not $apiAsset) {
        Write-Host "MISS  $ckName  (not found in release assets)" -ForegroundColor Yellow
        $pass = $false
        continue
    }

    # GitHub API returns digest as "sha256:<lowercase-hex>"
    $apiHash = ($apiAsset.digest -replace '^sha256:', '').ToLower()

    if ($ckHash -eq $apiHash) {
        Write-Host "PASS  $ckName" -ForegroundColor Green
    } else {
        Write-Host "FAIL  $ckName" -ForegroundColor Red
        Write-Host "      checksums.txt : $ckHash"
        Write-Host "      GitHub API    : $apiHash"
        $pass = $false
    }
}

if ($pass) {
    Write-Host ""
    Write-Host "All hashes match." -ForegroundColor Green
    exit 0
} else {
    Write-Host ""
    Write-Host "One or more hashes did not match. Review output above." -ForegroundColor Red
    exit 1
}
