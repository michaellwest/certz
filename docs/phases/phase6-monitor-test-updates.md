# Phase 6 Addendum: Monitor Test Updates

**Status:** Planned
**Feature:** `--password-map` option and PFX warning behavior
**Related:** [phase6-monitor.md](phase6-monitor.md)

## Context

Two features were added to the monitor command that need test coverage:

1. **PFX warning behavior** — Password-protected PFX files encountered during directory scans are now reported as yellow warnings ("Skipped") instead of red errors. The `MonitorResult` model includes `Warnings` and `SkippedCount` fields.

2. **`--password-map` option** — A new `--password-map` / `--pm` option accepts a file mapping glob patterns to passwords for PFX files. Patterns are evaluated top-to-bottom (first match wins) using `FileSystemName.MatchesSimpleExpression`. The existing `--password` option serves as a fallback.

## Files to Modify

| File | Change |
|------|--------|
| `test/test-monitor.ps1` | Add `mon-6.1`–`6.3` (password-map) + `mon-7.1` (warnings) |
| `test/test-nanoserver.cmd` | Add 2 smoke tests with password map, renumber to 22 total |
| `test/coverage-analysis.md` | Update monitor gaps, add password-map coverage, update totals |
| `docs/phases/phase6-monitor.md` | Add steps 9–10 to progress tracker |

---

## New Tests: `test/test-monitor.ps1`

### Category: `password-map`

#### mon-6.1: Password map resolves correct password

```
SETUP:
  - Create 2 self-signed certs via PowerShell with different passwords
  - Export cert1 as alpha.pfx (password: AlphaPass)
  - Export cert2 as beta.pfx (password: BetaPass)
  - Write password map file:
      alpha.pfx=AlphaPass
      beta.pfx=BetaPass

ACTION:
  certz monitor <dir> --password-map map.txt --format json

ASSERTIONS:
  - Exit code 0
  - totalScanned = 2
  - validCount = 2
  - skippedCount = 0
  - warnings is null
  - errors is null
```

#### mon-6.2: Password map with fallback to `--password`

```
SETUP:
  - Create 2 self-signed certs via PowerShell
  - Export cert1 as mapped.pfx (password: MappedPass)
  - Export cert2 as fallback.pfx (password: FallbackPass)
  - Write password map file:
      mapped.pfx=MappedPass

ACTION:
  certz monitor <dir> --password-map map.txt --password FallbackPass --format json

ASSERTIONS:
  - Exit code 0
  - totalScanned = 2
  - validCount = 2
  - skippedCount = 0
  - warnings is null (fallback password worked for unmapped file)
```

#### mon-6.3: Unmatched PFX produces warning when using password map

```
SETUP:
  - Create 1 self-signed cert via PowerShell
  - Export as nomatch.pfx (password: SecretPass)
  - Write password map file with no matching pattern:
      other-*.pfx=WrongPass

ACTION:
  certz monitor <dir> --password-map map.txt --format json

ASSERTIONS:
  - Exit code 0
  - totalScanned = 0
  - skippedCount = 1
  - warnings array has 1 entry containing "nomatch.pfx"
```

### Category: `warnings`

#### mon-7.1: Password-protected PFX shows warning on directory scan

```
SETUP:
  - Create 1 self-signed cert via PowerShell
  - Export as protected.pfx (password: SecretPass)

ACTION:
  certz monitor <dir> --format json  (no --password, no --password-map)

ASSERTIONS:
  - Exit code 0
  - totalScanned = 0
  - skippedCount = 1
  - warnings array has 1 entry with reason containing "Skipped"
  - errors is null
```

---

## New Tests: `test/test-nanoserver.cmd`

Insert after test [17/22] (monitor --format json), before store commands. Bump total from 20 to 22.

### [18/22] monitor --password-map

```batch
echo.
echo [18/22] monitor --password-map
echo dev.pfx=TestPass123> passwords.txt
echo ca.pfx=CaPass123>> passwords.txt
echo converted.pfx=ConvertPass123>> passwords.txt
echo renewed.pfx=RenewPass123>> passwords.txt
%CERTZ% monitor . --password-map passwords.txt
if %errorlevel% neq 0 goto :fail
```

### [19/22] monitor --password-map --format json

```batch
echo.
echo [19/22] monitor --password-map --format json
%CERTZ% monitor . --password-map passwords.txt --format json >nul
if %errorlevel% neq 0 goto :fail
```

Remaining tests renumbered: install [20/22], list [21/22], verify [22/22].

---

## Documentation Updates

### `test/coverage-analysis.md`

Under `test-monitor.ps1 Gaps`, add:

| Gap | Priority | Status |
|-----|----------|--------|
| `--password-map` with multiple passwords | Medium | Planned (mon-6.1) |
| `--password-map` with `--password` fallback | Medium | Planned (mon-6.2) |
| `--password-map` unmatched PFX warning | Medium | Planned (mon-6.3) |
| PFX warning on directory scan (no password) | Medium | Planned (mon-7.1) |
| `--password-map` with invalid file | Low | Not covered |

Update total test count from 147 to 151.

### `docs/phases/phase6-monitor.md`

Add to progress tracker:

| # | Step | Status | Notes |
|---|------|--------|-------|
| 9 | Add --password-map option | [x] | OptionBuilders.cs, MonitorCommand.cs, MonitorService.cs |
| 10 | Add --password-map tests | [ ] | test/test-monitor.ps1 (mon-6.1–6.3, mon-7.1) |
| 11 | Add nanoserver smoke tests | [ ] | test/test-nanoserver.cmd (2 new tests) |

---

## Test Isolation Compliance

All proposed tests follow [isolation-plan.md](../../test/isolation-plan.md):

| Principle | Compliance |
|-----------|-----------|
| Each test invokes certz.exe exactly ONCE | Yes |
| Setup uses pure PowerShell (New-SelfSignedCertificate, Export-PfxCertificate, Set-Content) | Yes |
| Assert against system state (JSON output, exit codes), not console text | Yes |
| Cleanup in finally blocks using PowerShell | Yes |
