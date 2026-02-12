# Prompt: Implement Monitor Test Updates

Implement the test updates documented in `docs/phases/phase6-monitor-test-updates.md`. This covers two features added to the monitor command:

1. **PFX warning behavior** — Password-protected PFX files are reported as warnings ("Skipped") instead of errors during directory scans.
2. **`--password-map` option** — Maps glob patterns to PFX passwords via a file (`pattern=password` per line).

## What to Implement

### 1. Add tests to `test/test-monitor.ps1`

Add a `password-map` category (`mon-6.1`, `mon-6.2`, `mon-6.3`) and a `warnings` category (`mon-7.1`) to the existing test file. Follow the exact patterns used by the existing `mon-1.x` through `mon-5.x` tests.

**mon-6.1: Password map resolves correct password**
- Create 2 PFX files with different passwords (PowerShell `New-SelfSignedCertificate` + `Export-PfxCertificate`)
- Write a password map file with `Set-Content` mapping each filename to its password
- Run `certz monitor <dir> --password-map map.txt --format json`
- Assert: exit code 0, `totalScanned=2`, `validCount=2`, `skippedCount=0`

**mon-6.2: Password map with --password fallback**
- Create 2 PFX files — one matching a map pattern, one relying on `--password` fallback
- Run `certz monitor <dir> --password-map map.txt --password FallbackPass --format json`
- Assert: exit code 0, `totalScanned=2`, `skippedCount=0`

**mon-6.3: Unmatched PFX produces warning**
- Create 1 PFX file that doesn't match any pattern in the map
- Run `certz monitor <dir> --password-map map.txt --format json`
- Assert: exit code 0, `totalScanned=0`, `skippedCount=1`, warnings array has 1 entry

**mon-7.1: Password-protected PFX shows warning on directory scan**
- Create 1 PFX file with a password
- Run `certz monitor <dir> --format json` (no `--password`, no `--password-map`)
- Assert: exit code 0, `totalScanned=0`, `skippedCount=1`, warnings populated, errors null

Update the `$TestCategories` at the top of the file:
```powershell
$TestCategories = @{
    "file"         = @("mon-1.1", "mon-1.2", "mon-1.3", "mon-1.4")
    "url"          = @("mon-2.1")
    "store"        = @("mon-3.1", "mon-3.2")
    "threshold"    = @("mon-4.1", "mon-4.2", "mon-4.3")
    "format"       = @("mon-5.1", "mon-5.2")
    "password-map" = @("mon-6.1", "mon-6.2", "mon-6.3")
    "warnings"     = @("mon-7.1")
}
```

### 2. Add smoke tests to `test/test-nanoserver.cmd`

Insert 2 new tests after test [17/22] (monitor --format json), before store commands. Bump total from 20 to 22.

**[18/22] monitor --password-map** — Create a `passwords.txt` file using `echo` redirects with entries for the PFX files created earlier (dev.pfx, ca.pfx, converted.pfx, renewed.pfx), then run `certz monitor . --password-map passwords.txt`.

**[19/22] monitor --password-map --format json** — Same password map, JSON output redirected to nul.

Renumber remaining tests: install [20/22], list [21/22], verify [22/22]. Update the "All N smoke tests passed!" message.

### 3. Update `test/coverage-analysis.md`

Under `test-monitor.ps1 Gaps`, replace existing entries with the new coverage:

| Gap | Priority | Status |
|-----|----------|--------|
| `--password-map` with multiple passwords | Medium | Covered (mon-6.1) |
| `--password-map` with `--password` fallback | Medium | Covered (mon-6.2) |
| `--password-map` unmatched PFX warning | Medium | Covered (mon-6.3) |
| PFX warning on directory scan (no password) | Medium | Covered (mon-7.1) |
| `--password-map` with invalid file | Low | Not covered |

Update total test count from 147 to 151.

### 4. Update `docs/phases/phase6-monitor.md`

Add to the progress tracker table:

```
| 9  | Add --password-map option  | [x] | OptionBuilders.cs, MonitorCommand.cs, MonitorService.cs |
| 10 | Add --password-map tests   | [x] | test/test-monitor.ps1 (mon-6.1–6.3, mon-7.1) |
| 11 | Add nanoserver smoke tests | [x] | test/test-nanoserver.cmd (2 new tests) |
```

### 5. Update `docs/phases/phase6-monitor-test-updates.md`

Mark the plan status as **Complete** once all tests are implemented and passing.

## Key Files to Read First

| File | Why |
|------|-----|
| `docs/phases/phase6-monitor-test-updates.md` | Full plan with test specifications |
| `test/test-monitor.ps1` | Existing test patterns to follow |
| `test/test-nanoserver.cmd` | Current smoke test structure |
| `test/isolation-plan.md` | Test isolation rules |
| `test/coverage-analysis.md` | Current coverage gaps |

## Constraints

- Each test invokes `certz.exe` exactly ONCE
- Setup and cleanup use PowerShell only (no certz calls)
- Assert against system state (JSON output, exit codes), not console text
- Follow existing `Invoke-Test` pattern from `test/test-monitor.ps1`
- Password map file format: `pattern=password` per line, `#` comments, blank lines ignored
