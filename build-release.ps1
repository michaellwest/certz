# Build Release Script for certz
# This script builds a release version of certz.exe and generates release notes

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

$releaseNotesPrompt = @"
Role: You are a Senior Release Engineer. Your task is to analyze the recent git history and generate a clean, user-facing changelog for a GitHub Release.

Task Instructions:

- Analyze Commits: Scan the commit messages since the last tag $LastTag.
- Filter & Deduplicate: >    * Ignore "stale" or "noise" commits (e.g., "typo fix," "update README," "merge branch," "linting").
  - Consolidate duplicate entries. If multiple commits refer to the same feature or bug fix, combine them into a single high-level bullet point.
- Categorize: Group the remaining commits into: 🚀 New Features, 🛠️ Improvements, and 🐛 Bug Fixes.
- Internal Documentation Linking: >    * For every major feature or change, search the repository for relevant .md files in the /docs folder (or similar).
  - Provide a relative link to the specific documentation file (e.g., [See Documentation](./docs/setup.md)) if it provides deeper context for that change.
- Formatting: Use clean Markdown with a professional, concise tone. Focus on the impact of the change for the user, not the technical implementation details.
- Prioritize commits starting with 'feat' and 'fix', and ignore 'chore' and 'test'.
Output Format:

# [Version/Date]

## [Category Name]

- [Feature/Fix Name]: Short description of the change. [Link to related doc if found]

Output Constraints:

NO CONVERSATIONAL FILLER: Do not include phrases like "Now I have everything I need," "Here is the changelog," or "I have analyzed the commits."

RAW MARKDOWN ONLY: Your entire response must start with the first header (e.g., ## [Version]) and end with the last bullet point.

DRY RUN: If you cannot find any relevant commits or docs, output exactly: NO NEW RELEASE DATA FOUND.

Text Sanitization Rules:

STRIP NON-ASCII: Remove any non-standard ASCII characters, including emojis, unless they are standard Markdown syntax.

NO ANSI CODES: Ensure no terminal color codes or escape sequences (e.g., \u001b) are included in the output.

LINE ENDINGS: Use standard LF (\n) line endings only.

ESCAPING: Escape any characters that might accidentally trigger GitHub Actions or unintended Markdown formatting (like underscores in the middle of words without backslashes).
"@

$ReleaseNotesContentPreamble = @"
# certz Release Notes

**Version:** $Version
**Release Date:** $ReleaseDate
**Changes Since:** $LastTag

"@

if ($Commits) {
    # Generate AI summary of commits using Claude Code
    $CommitText = ($Commits | ForEach-Object { $_ -replace "^[a-f0-9]+\s+", "" }) -join "`n"
    if (Get-Command claude -ErrorAction SilentlyContinue) {
        Write-Host "Generating AI summary of changes..." -ForegroundColor Yellow
        Add-Content -Path $ReleaseNotesPath -Value $ReleaseNotesContentPreamble
        $aiContent = $CommitText | claude -p $releaseNotesPrompt
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Claude summary failed, falling back to raw commits" -ForegroundColor DarkYellow
        } else {
            # Strip any conversational preamble before the first markdown header
            $aiLines = $aiContent -split "`n"
            $firstHeader = ($aiLines | Select-String -Pattern '^#' | Select-Object -First 1).LineNumber
            if ($firstHeader -gt 1) {
                $aiContent = ($aiLines[($firstHeader - 1)..($aiLines.Count - 1)]) -join "`n"
            }
            Add-Content -Path $ReleaseNotesPath -Value $aiContent
        }
    }
}

$ReleaseNotesContentEnding += @"

---

## File Verification

**File:** $ExeName
**Runtime:** $RuntimeIdentifier
**SHA256 Hash:** ``$FileHash``
"@

Add-Content -Path $ReleaseNotesPath -Value $ReleaseNotesContentEnding

Write-Host ""
Write-Host "Release build complete!" -ForegroundColor Green
Write-Host "Output directory: $OutputPath" -ForegroundColor Cyan
Write-Host "Version: $Version" -ForegroundColor Cyan
Write-Host "SHA256: $FileHash" -ForegroundColor Cyan
Write-Host ""
Write-Host "Files created:" -ForegroundColor Yellow
Get-ChildItem $OutputPath | ForEach-Object { Write-Host "  - $($_.Name)" }
