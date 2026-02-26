# Verifying Downloads

Every certz release provides SHA-256 hashes in two places so you can confirm the binary you downloaded is the one that was built and published:

| Source | Location | Use case |
|--------|----------|----------|
| `checksums.txt` | Release asset | Standard file-based verification (sha256sum, Get-FileHash) |
| GitHub API `digest` field | Releases API JSON | Programmatic pre-download verification |

Both sources contain the same hash. The [consistency check](#c-verify-that-checksumstxt-matches-the-github-api-digest) script confirms they agree.

---

## A. Pre-download: verify via the GitHub API

The GitHub Releases API returns a `digest` field (`sha256:<hash>`) for every asset without requiring you to download the file first. The snippet below fetches the hash, downloads the binary, and refuses to proceed if they do not match.

```powershell
# Change these two values for each release
$Tag      = "0.3"
$AssetName = "certz-0.3.0-win-x64.exe"
$Repo     = "michaellwest/certz"

# 1. Fetch release metadata
$release = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/tags/$Tag"
$asset   = $release.assets | Where-Object { $_.name -eq $AssetName }

if (-not $asset) {
    throw "Asset '$AssetName' not found in release $Tag"
}

# 2. Extract expected hash from the API (format: "sha256:<lowercase-hex>")
$expectedHash = ($asset.digest -replace '^sha256:', '').ToUpper()

# 3. Download the binary
Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $AssetName -UseBasicParsing

# 4. Compute the actual hash and compare
$actualHash = (Get-FileHash $AssetName -Algorithm SHA256).Hash
if ($actualHash -ne $expectedHash) {
    throw "Hash mismatch! Expected: $expectedHash  Got: $actualHash"
}

Write-Host "Hash verified: $actualHash" -ForegroundColor Green
```

> **Note:** No authentication is required for public repositories. For private repositories, add `-Headers @{ Authorization = "Bearer $env:GITHUB_TOKEN" }` to each `Invoke-RestMethod` / `Invoke-WebRequest` call.

---

## B. Post-download: verify using checksums.txt

`checksums.txt` is attached as a release asset alongside each binary. It uses the standard `sha256sum` format:

```
68f80d2e26b93dd6f503d005b401e5bdfc5dd8d3c78cd77488786ab92b7480ad  certz-0.3.0-win-x64.exe
```

### Windows (PowerShell)

```powershell
# Download checksums.txt from the release assets page, then:
$lines    = Get-Content checksums.txt | Where-Object { $_ -match '\S' }
$entry    = $lines | Where-Object { $_ -match 'certz-.*-win-x64\.exe' }
$expected = ($entry -split '\s+')[0].ToUpper()
$actual   = (Get-FileHash certz-0.3.0-win-x64.exe -Algorithm SHA256).Hash

if ($actual -eq $expected) {
    Write-Host "Hash verified: $actual" -ForegroundColor Green
} else {
    Write-Host "MISMATCH  expected: $expected  got: $actual" -ForegroundColor Red
}
```

### Linux / macOS

```bash
# Download checksums.txt and the binary into the same directory, then:
sha256sum --check checksums.txt
```

`sha256sum --check` exits 0 if all listed files pass, non-zero on any failure.

---

## C. Verify that checksums.txt matches the GitHub API digest

Use `scripts/verify-release.ps1` to confirm that every hash in `checksums.txt` agrees with the `digest` field that GitHub computed when the asset was uploaded. This is a cross-source consistency check and does not require you to have downloaded the binary.

```powershell
pwsh -File scripts/verify-release.ps1 -Tag 0.3
```

Example output (all passing):

```
Verifying release 0.3 from michaellwest/certz...
PASS  certz-0.3.0-win-x64.exe
All hashes match.
```

Example output (mismatch):

```
Verifying release 0.3 from michaellwest/certz...
FAIL  certz-0.3.0-win-x64.exe
      checksums.txt : 68f80d2e...
      GitHub API    : a1b2c3d4...
One or more hashes did not match. Review output above.
```

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | All hashes in checksums.txt match the GitHub API digest |
| `1` | One or more mismatches, missing assets, or checksums.txt not found |

---

## See also

- [Exit Codes](exit-codes.md)
- [GitHub Releases](https://github.com/michaellwest/certz/releases)
