# Release Process

`scripts/release.ps1` automates the full certz release workflow: version bump, platform
builds, checksum generation, git tagging, and GitHub release creation in a single command.

---

## Prerequisites

| Requirement | Details |
|-------------|---------|
| PowerShell 7.5+ | Required to run the script |
| .NET 10 SDK | Required for `dotnet publish` (cross-compilation) |
| GitHub CLI | Must be installed at `C:\Program Files\GitHub CLI\gh.exe` |
| `gh` authentication | Run `& 'C:\Program Files\GitHub CLI\gh.exe' auth status` to verify |
| Clean working tree | No uncommitted changes (`git status` must be clean) |
| On `main` branch | Script warns and prompts if you are on another branch |
| All issues closed | Merge your feature branch and close related issues before releasing |

---

## Usage

```powershell
# Full release (Windows + Linux)
pwsh -File scripts/release.ps1 -Version 0.4.0

# Windows binary only (skip Linux cross-compile)
pwsh -File scripts/release.ps1 -Version 0.4.0 -SkipLinux
```

---

## Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-Version` | string | Yes | — | Semantic version to release. Must be `X.Y.Z` format (e.g. `0.4.0`). |
| `-Repo` | string | No | `michaellwest/certz` | GitHub repository in `owner/name` format. |
| `-SkipLinux` | switch | No | off | Skip the linux-x64 cross-compile build. Only the win-x64 binary is uploaded. |

---

## What the Script Does

1. **Validates** the version string against `X.Y.Z` format. Exits immediately on invalid input.
2. **Checks the current branch.** Warns and prompts for confirmation if you are not on `main`.
3. **Checks for uncommitted changes.** Aborts if the working tree is dirty.
4. **Detects an existing release** by checking for a local tag, remote tag, and GitHub release.
   If any exist, prompts to [O]verwrite or [C]ancel (see [Overwrite Behavior](#overwrite-behavior)).
5. **Bumps the version** in `src/certz/certz.csproj`:
   - `<Version>` — e.g. `0.4.0`
   - `<AssemblyVersion>` — e.g. `0.4.0.0`
   - `<FileVersion>` — e.g. `0.4.0.0`
6. **Builds win-x64** by calling `build-release.ps1 -RuntimeIdentifier win-x64`.
   This produces the binary, `checksums.txt`, and AI-generated `RELEASE_NOTES.md` in `release/win-x64/`.
7. **Cross-compiles linux-x64** by calling `build-release.ps1 -RuntimeIdentifier linux-x64`.
   Uses the .NET SDK's built-in cross-compilation — no WSL required. If the build fails,
   the script warns and continues with a Windows-only release. Use `-SkipLinux` to bypass entirely.
8. **Merges checksums** from both platform directories into `release/checksums.txt`
   (sha256sum-compatible format).
9. **Commits the version bump** (`chore: bump version to X.Y.Z`) if `certz.csproj` changed.
10. **Pushes the branch** to `origin`, then creates an annotated git tag and pushes it.
11. **Creates the GitHub release** via `gh release create` with:
    - Title: `certz X.Y.Z`
    - Body: the AI-generated `RELEASE_NOTES.md` from step 6
    - Attached assets: platform binaries + merged `checksums.txt`
12. **Prints a verification command** to run after the release is live.

---

## Assets Uploaded

| File | Description |
|------|-------------|
| `certz-X.Y.Z-win-x64.exe` | Windows x64 self-contained single-file executable |
| `certz-X.Y.Z-linux-x64` | Linux x64 self-contained single-file executable (if built) |
| `checksums.txt` | SHA-256 hashes for all binaries in sha256sum format |

Release notes are embedded in the GitHub release body (not a separate file attachment).

---

## Overwrite Behavior

If any of the following already exist for the target version, the script prompts
`[O]verwrite / [C]ancel`:

- Local git tag
- Remote git tag on `origin`
- GitHub release

Choosing **Overwrite** deletes all three (in that order) and then proceeds with a clean
rebuild and re-release. This is a destructive operation — the previous release, its assets,
and its tag are permanently removed before the new one is created.

Choosing **Cancel** exits with no changes made.

---

## Tag Naming Convention

Tags use bare semver with no `v` prefix, consistent with existing project tags `0.1` and `0.2`:

```
0.4.0      # correct
v0.4.0     # incorrect
```

GitHub release download URLs follow the same pattern:

```
https://github.com/michaellwest/certz/releases/download/0.4.0/certz-0.4.0-win-x64.exe
```

---

## Pre-Release Checklist

Before running the script:

- [ ] All feature branches for this release are merged to `main`
- [ ] All related GitHub issues are closed
- [ ] Tests pass: `pwsh -File test/test-all.ps1`
- [ ] Working tree is clean: `git status`
- [ ] `gh` is authenticated: `& 'C:\Program Files\GitHub CLI\gh.exe' auth status`

---

## Post-Release Verification

After the script completes, verify that all uploaded asset hashes match the GitHub API:

```powershell
pwsh -File scripts/verify-release.ps1 -Tag 0.4.0
```

Exit code 0 means all hashes match. Exit code 1 means a mismatch was detected.

See [Verifying Downloads](verify-download.md) for user-facing hash verification instructions.

---

## Linux Build Notes

The linux-x64 binary is cross-compiled on Windows using the .NET SDK's built-in
cross-compilation support (`dotnet publish -r linux-x64`). No WSL, no Docker, and no
Linux machine is required.

If cross-compilation fails (e.g. missing Linux runtime packs), run:

```powershell
pwsh -File scripts/release.ps1 -Version 0.4.0 -SkipLinux
```

and publish the Linux binary separately when a Linux environment is available.
