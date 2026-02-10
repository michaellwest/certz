# Prompt: Prepare Release

Use this prompt when preparing a new release of certz.

## Pre-Release Checklist

- [ ] All tests pass
- [ ] Build succeeds in release mode
- [ ] README.md is up to date
- [ ] CLAUDE.md Code Map is current
- [ ] Version number updated (if applicable)

## Release Steps

### 1. Run All Tests

```powershell
pwsh -File test/test-all.ps1
```

All tests must pass before proceeding.

### 2. Build Release

```powershell
.\build-release.ps1
```

This creates a single-file executable at `release/certz.exe`.

### 3. Verify Build

```powershell
.\release\certz.exe --version
.\release\certz.exe --help
.\release\certz.exe create dev --cn test.local --ephemeral
```

### 4. Generate SHA256 Hash

```powershell
$hash = (Get-FileHash -Algorithm SHA256 .\release\certz.exe).Hash
Write-Host "SHA256: $hash"
```

### 5. Update Release Notes

Edit `release/RELEASE_NOTES.md`:

```markdown
## v1.x.x (YYYY-MM-DD)

### New Features
- Feature description

### Bug Fixes
- Fix description

### SHA256
`<hash from step 4>`
```

### 6. Commit and Tag

```powershell
git add .
git commit -m "release: v1.x.x"
git tag v1.x.x
git push origin main --tags
```

## Quality Gates

### Single-File Verification

The executable must be self-contained with no external dependencies:

```powershell
# Copy to isolated location and verify it runs
$testDir = "$env:TEMP\certz-release-test"
New-Item -ItemType Directory -Path $testDir -Force | Out-Null
Copy-Item .\release\certz.exe $testDir\
& "$testDir\certz.exe" --version
Remove-Item $testDir -Recurse -Force
```

### Size Check

Typical release size is ~15-25 MB (single-file, self-contained, trimmed).

```powershell
$size = (Get-Item .\release\certz.exe).Length / 1MB
Write-Host "Release size: $([math]::Round($size, 2)) MB"
```

## Reference Files

- `release/RELEASE_NOTES.md` - Version history
- `build-release.ps1` - Build script
- `certz.csproj` - Project configuration
