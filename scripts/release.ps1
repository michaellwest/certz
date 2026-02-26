<#
.SYNOPSIS
    Build and publish a new certz GitHub release.

.DESCRIPTION
    Bumps the version in certz.csproj, builds win-x64 and linux-x64 binaries
    (linux via .NET cross-compilation, no WSL required), merges checksums,
    commits the version bump, tags the commit, and creates a GitHub release
    with all assets attached.

    If the tag or GitHub release already exists, the script prompts to either
    overwrite (delete and recreate from scratch) or cancel.

.PARAMETER Version
    Semantic version to release in X.Y.Z format (e.g. 0.4.0). Required.

.PARAMETER Repo
    GitHub repository in owner/name format. Defaults to michaellwest/certz.

.PARAMETER SkipLinux
    Skip the linux-x64 cross-compile build. Only the win-x64 binary will be uploaded.

.EXAMPLE
    pwsh -File scripts/release.ps1 -Version 0.4.0
    pwsh -File scripts/release.ps1 -Version 0.4.0 -SkipLinux
#>
param(
    [Parameter(Mandatory)]
    [string]$Version,

    [string]$Repo = 'michaellwest/certz',

    [switch]$SkipLinux
)

$ErrorActionPreference = 'Stop'
$gh          = 'C:\Program Files\GitHub CLI\gh.exe'
$ProjectRoot = Split-Path $PSScriptRoot -Parent
$CsprojPath  = Join-Path $ProjectRoot 'src\certz\certz.csproj'

# ---------------------------------------------------------------------------
# Helpers

function Abort([string]$msg) {
    Write-Host ""
    Write-Host "Aborted: $msg" -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# 1. Validate version format

if ($Version -notmatch '^\d+\.\d+\.\d+$') {
    Abort "Version must be X.Y.Z format (e.g. 0.4.0). Got: $Version"
}

$Tag = $Version   # no 'v' prefix, consistent with existing 0.1 / 0.2 tags

Write-Host ""
Write-Host "certz release" -ForegroundColor Cyan
Write-Host "  Version : $Version"
Write-Host "  Tag     : $Tag"
Write-Host "  Repo    : $Repo"
Write-Host ""

# ---------------------------------------------------------------------------
# 2. Check gh CLI is reachable

if (-not (Test-Path $gh)) {
    Abort "GitHub CLI not found at: $gh`nInstall from https://cli.github.com/ and re-run."
}

# ---------------------------------------------------------------------------
# 3. Check current branch

$currentBranch = git rev-parse --abbrev-ref HEAD
if ($currentBranch -ne 'main') {
    Write-Host "WARNING: Current branch is '$currentBranch', not 'main'." -ForegroundColor Yellow
    $ans = Read-Host "Continue from '$currentBranch'? [y/N]"
    if ($ans -notmatch '^[Yy]') { Abort "Not on main branch." }
}

# ---------------------------------------------------------------------------
# 4. Check for uncommitted changes

$gitStatus = git status --porcelain
if ($gitStatus) {
    Write-Host "Uncommitted changes found:" -ForegroundColor Red
    $gitStatus | ForEach-Object { Write-Host "  $_" }
    Abort "Commit or stash your changes before releasing."
}

# ---------------------------------------------------------------------------
# 5. Check if tag / GitHub release already exists and handle overwrite

Write-Host "Checking for existing release '$Tag'..." -ForegroundColor Yellow

$localTagExists  = [bool](git tag -l $Tag | Where-Object { $_.Trim() -eq $Tag })
$remoteTagExists = [bool](git ls-remote --tags origin "refs/tags/$Tag" 2>$null)

$githubReleaseExists = $false
$releaseCheckOutput  = & $gh api "repos/$Repo/releases/tags/$Tag" 2>&1
if ($LASTEXITCODE -eq 0) { $githubReleaseExists = $true }

if ($localTagExists -or $remoteTagExists -or $githubReleaseExists) {
    Write-Host ""
    Write-Host "Release '$Tag' already exists:" -ForegroundColor Yellow
    if ($localTagExists)      { Write-Host "  [x] Local git tag '$Tag'" }
    if ($remoteTagExists)     { Write-Host "  [x] Remote git tag '$Tag' on origin" }
    if ($githubReleaseExists) { Write-Host "  [x] GitHub release '$Tag'" }
    Write-Host ""
    Write-Host "  [O] Overwrite  delete release + tags, then recreate from scratch"
    Write-Host "  [C] Cancel     abort, make no changes"
    Write-Host ""
    $choice = Read-Host "Choose [O/C]"
    if ($choice -notmatch '^[Oo]') { Abort "User cancelled." }

    Write-Host ""
    Write-Host "Removing existing release and tags..." -ForegroundColor Yellow

    if ($githubReleaseExists) {
        & $gh release delete $Tag --repo $Repo --yes
        Write-Host "  Deleted GitHub release '$Tag'" -ForegroundColor DarkYellow
    }
    if ($remoteTagExists) {
        git push origin ":refs/tags/$Tag"
        Write-Host "  Deleted remote tag '$Tag'" -ForegroundColor DarkYellow
    }
    if ($localTagExists) {
        git tag -d $Tag
        Write-Host "  Deleted local tag '$Tag'" -ForegroundColor DarkYellow
    }
}

# ---------------------------------------------------------------------------
# 6. Bump version in certz.csproj

Write-Host ""
Write-Host "Updating version in certz.csproj..." -ForegroundColor Cyan

$csprojContent = [System.IO.File]::ReadAllText($CsprojPath)

# Read current version before replacing (used later to decide whether to commit)
if ($csprojContent -match '<Version>([^<]+)</Version>') {
    $previousVersion = $Matches[1]
} else {
    $previousVersion = 'unknown'
}

$csprojContent = $csprojContent -replace '<Version>[^<]+</Version>',         "<Version>$Version</Version>"
$csprojContent = $csprojContent -replace '<AssemblyVersion>[^<]+</AssemblyVersion>', "<AssemblyVersion>$Version.0</AssemblyVersion>"
$csprojContent = $csprojContent -replace '<FileVersion>[^<]+</FileVersion>',   "<FileVersion>$Version.0</FileVersion>"

[System.IO.File]::WriteAllText($CsprojPath, $csprojContent, [System.Text.Encoding]::UTF8)
Write-Host "  $previousVersion -> $Version" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 7. Build win-x64

Write-Host ""
Write-Host "Building win-x64..." -ForegroundColor Cyan

& "$ProjectRoot\build-release.ps1" -RuntimeIdentifier win-x64
if ($LASTEXITCODE -ne 0) { Abort "win-x64 build failed." }

$WinExeName   = "certz-$Version-win-x64.exe"
$WinExePath   = Join-Path $ProjectRoot "release\win-x64\$WinExeName"
$WinNotesPath = Join-Path $ProjectRoot "release\win-x64\RELEASE_NOTES.md"

if (-not (Test-Path $WinExePath)) { Abort "Expected binary not found: $WinExePath" }

# ---------------------------------------------------------------------------
# 8. Build linux-x64 (cross-compile via .NET SDK - no WSL required)

$LinuxExeName = "certz-$Version-linux-x64"
$LinuxExePath = $null

if (-not $SkipLinux) {
    Write-Host ""
    Write-Host "Building linux-x64 (cross-compile)..." -ForegroundColor Cyan

    & "$ProjectRoot\build-release.ps1" -RuntimeIdentifier linux-x64
    if ($LASTEXITCODE -eq 0) {
        $candidate = Join-Path $ProjectRoot "release\linux-x64\$LinuxExeName"
        if (Test-Path $candidate) {
            $LinuxExePath = $candidate
            Write-Host "  linux-x64 build succeeded." -ForegroundColor Green
        } else {
            Write-Host "  WARNING: linux-x64 build reported success but binary not found. Skipping." -ForegroundColor Yellow
        }
    } else {
        Write-Host "  WARNING: linux-x64 build failed. Continuing with Windows-only release." -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# 9. Merge checksums into release/checksums.txt

Write-Host ""
Write-Host "Merging checksums..." -ForegroundColor Cyan

$MergedChecksumsPath = Join-Path $ProjectRoot "release\checksums.txt"
$allLines = [System.Collections.Generic.List[string]]::new()

$winCksPath = Join-Path $ProjectRoot "release\win-x64\checksums.txt"
Get-Content $winCksPath | Where-Object { $_ -match '\S' } | ForEach-Object { $allLines.Add($_) }

if ($LinuxExePath) {
    $linuxCksPath = Join-Path $ProjectRoot "release\linux-x64\checksums.txt"
    Get-Content $linuxCksPath | Where-Object { $_ -match '\S' } | ForEach-Object { $allLines.Add($_) }
}

[System.IO.File]::WriteAllLines($MergedChecksumsPath, $allLines, [System.Text.UTF8Encoding]::new($false))
Write-Host "  release/checksums.txt written ($($allLines.Count) $(if ($allLines.Count -eq 1) { 'entry' } else { 'entries' }))" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 10. Commit version bump (only if the version actually changed)

Write-Host ""
Write-Host "Committing version bump..." -ForegroundColor Cyan

git add $CsprojPath
git diff --cached --quiet
if ($LASTEXITCODE -ne 0) {
    # Staged changes exist - commit them
    git commit -m "chore: bump version to $Version"
    Write-Host "  Committed: chore: bump version to $Version" -ForegroundColor Green
} else {
    Write-Host "  No csproj changes to commit (version was already $Version)." -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# 11. Push commit, create tag, push tag

Write-Host ""
Write-Host "Pushing branch and creating tag '$Tag'..." -ForegroundColor Cyan

git push origin $currentBranch
git tag -a $Tag -m "Release $Tag"
git push origin $Tag

Write-Host "  Branch '$currentBranch' and tag '$Tag' pushed to origin." -ForegroundColor Green

# ---------------------------------------------------------------------------
# 12. Create GitHub release

Write-Host ""
Write-Host "Creating GitHub release '$Tag'..." -ForegroundColor Cyan

$releaseArgs = [System.Collections.Generic.List[string]]@(
    'release', 'create', $Tag,
    '--repo',       $Repo,
    '--title',      "certz $Tag",
    '--notes-file', $WinNotesPath,
    $WinExePath,
    $MergedChecksumsPath
)
if ($LinuxExePath) { $releaseArgs.Add($LinuxExePath) }

& $gh @releaseArgs
if ($LASTEXITCODE -ne 0) { Abort "GitHub release creation failed." }

# ---------------------------------------------------------------------------
# 13. Summary

Write-Host ""
Write-Host "Release $Tag published!" -ForegroundColor Green
Write-Host ""
Write-Host "  URL : https://github.com/$Repo/releases/tag/$Tag" -ForegroundColor Cyan
Write-Host ""
Write-Host "Assets uploaded:" -ForegroundColor Yellow
Write-Host "  - $WinExeName"
if ($LinuxExePath) { Write-Host "  - $LinuxExeName" }
Write-Host "  - checksums.txt"
Write-Host "  - release notes embedded in release body"
Write-Host ""
Write-Host "To verify hashes:" -ForegroundColor Yellow
Write-Host "  pwsh -File scripts/verify-release.ps1 -Tag $Tag"
Write-Host ""
