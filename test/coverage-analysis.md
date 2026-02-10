# Test Coverage Analysis

**Date:** 2026-02-10
**Purpose:** Analyze test coverage gaps and provide recommendations for new tests

---

## Current Test Files

| Test File            | Commands Tested                            | Test Count | Status       |
| -------------------- | ------------------------------------------ | ---------- | ------------ |
| `test-create.ps1`    | `create dev`, `create ca`                  | 14 tests   | ✅ Modern v2 |
| `test-inspect.ps1`   | `inspect` (file, URL, store, chain, save)  | 17 tests   | ✅ Modern v2 |
| `test-trust.ps1`     | `trust add`, `trust remove`, `store list`  | 15 tests   | ✅ Modern v2 |
| `test-convert.ps1`   | `convert` (PEM, DER, PFX conversions)      | 23 tests   | ✅ Modern v2 |
| `test-lint.ps1`      | `lint` (CA/B Forum, Mozilla NSS)           | 10 tests   | ✅ Modern v2 |
| `test-monitor.ps1`   | `monitor` (expiration tracking)            | 12 tests   | ✅ Modern v2 |
| `test-renew.ps1`     | `renew` (certificate renewal)              | 11 tests   | ✅ Modern v2 |
| `test-ephemeral.ps1` | `--ephemeral`, `--pipe` modes              | 14 tests   | ✅ Modern v2 |
| `test-examples.ps1`  | `examples` (usage examples display)        | 9 tests    | ✅ Modern v2 |
| `test-export.ps1`    | `export` (from store, from URL)            | 9 tests    | ✅ Modern v2 |
| `test-verify.ps1`    | `verify` (file, store validation)          | 7 tests    | ✅ Modern v2 |
| `test-install.ps1`   | `install` (store install, exportable flag) | 6 tests    | ✅ Modern v2 |

**Total: 147 tests across 12 test files**

---

## Command Coverage Analysis

### V2 Commands (Hierarchical Structure)

| Command                  | Test File          | Coverage Status                              |
| ------------------------ | ------------------ | -------------------------------------------- |
| `create dev`             | test-create.ps1    | ✅ Covered (5 tests: dev-1.1–1.5)            |
| `create ca`              | test-create.ps1    | ✅ Covered (3 tests: ca-1.1–1.3)             |
| `create dev --guided`    | test-create.ps1    | ⚠️ Manual only (gui-1.1, skipped by default) |
| `inspect <file>`         | test-inspect.ps1   | ✅ Covered (5 tests: ins-1.1–1.5)            |
| `inspect <url>`          | test-inspect.ps1   | ✅ Covered (3 tests: ins-2.1–2.3)            |
| `inspect <thumbprint>`   | test-inspect.ps1   | ✅ Covered (2 tests: ins-3.1–3.2)            |
| `inspect --chain`        | test-inspect.ps1   | ✅ Covered (4 tests: chn-1.1–1.4)            |
| `inspect --save`         | test-inspect.ps1   | ✅ Covered (5 tests: sav-1.1–1.5)            |
| `inspect --format json`  | test-inspect.ps1   | ✅ Covered (2 tests: fmt-2.1–2.2)            |
| `trust add`              | test-trust.ps1     | ✅ Covered (4 tests: tru-1.1–1.4)            |
| `trust remove`           | test-trust.ps1     | ✅ Covered (4 tests: trm-1.1–1.4)            |
| `trust remove` (multi)   | test-trust.ps1     | ✅ Covered (4 tests: trm-2.1–2.4)            |
| `store list`             | test-trust.ps1     | ✅ Covered (3 tests: sto-1.1–1.3)            |
| `convert`                | test-convert.ps1   | ✅ Covered (23 tests)                        |
| `lint`                   | test-lint.ps1      | ✅ Covered (10 tests)                        |
| `monitor`                | test-monitor.ps1   | ✅ Covered (12 tests)                        |
| `renew`                  | test-renew.ps1     | ✅ Covered (11 tests: ren-1.1–6.1)           |
| `--ephemeral` / `--pipe` | test-ephemeral.ps1 | ✅ Covered (14 tests)                        |
| `examples`               | test-examples.ps1  | ✅ Covered (9 tests: ex-1.1–3.1)             |
| `export`                 | test-export.ps1    | ✅ Covered (9 tests: exp-1.1–4.1)            |
| `verify`                 | test-verify.ps1    | ✅ Covered (7 tests: ver-1.1–4.1)            |
| `install`                | test-install.ps1   | ✅ Covered (6 tests: ist-1.1–3.2)            |

### Legacy Commands

| Command           | Source File      | Notes                                 |
| ----------------- | ---------------- | ------------------------------------- |
| `remove` (legacy) | RemoveCommand.cs | Superseded by `trust remove` (tested) |
| `list` (legacy)   | ListCommand.cs   | Superseded by `store list` (tested)   |
| `info` (legacy)   | InfoCommand.cs   | Superseded by `inspect` (tested)      |

---

## Test Coverage Gaps in Existing Files

### test-create.ps1 Gaps

| Gap                                                | Priority | Status                           |
| -------------------------------------------------- | -------- | -------------------------------- |
| `create ca --guided` wizard                        | Low      | Not covered (manual/interactive) |
| `--issuer-password-file`                           | Low      | Not covered                      |
| `--hash-algorithm` (SHA-256/SHA-384/SHA-512)       | Medium   | Not covered                      |
| `--rsa-padding` (pss/pkcs1)                        | Low      | Not covered                      |
| `--cert` / `--key` PEM output                      | Medium   | Not covered                      |
| `--crl-url`, `--ocsp-url`, `--ca-issuers-url` (CA) | Medium   | Not covered                      |

### test-inspect.ps1 Gaps

| Gap                                    | Priority | Status      |
| -------------------------------------- | -------- | ----------- |
| `--warn` with `--format json` combined | Low      | Not covered |
| `--save --chain` (save chain to file)  | Low      | Not covered |

### test-trust.ps1 Gaps

| Gap                            | Priority | Status      |
| ------------------------------ | -------- | ----------- |
| `store list --expired` filter  | Low      | Not covered |
| `store list --expiring` filter | Low      | Not covered |

### test-monitor.ps1 Gaps

| Gap                                 | Priority | Status      |
| ----------------------------------- | -------- | ----------- |
| URL monitoring with `--format json` | Low      | Not covered |
| `--store` + `--expired` filter      | Low      | Not covered |

---

## Test Isolation Compliance

All test files follow [test-isolation-plan.md](isolation-plan.md):

| Principle                                       | Status                                              |
| ----------------------------------------------- | --------------------------------------------------- |
| Each test invokes certz.exe exactly ONCE        | ✅ All files compliant                              |
| Setup uses pure PowerShell                      | ✅ All files compliant                              |
| Cleanup uses pure PowerShell                    | ✅ All files compliant                              |
| Assert against system state, not console output | ✅ (ephemeral/pipe tests exempt -- no system state) |
| Unique test identifiers                         | ✅ All tests use unique IDs                         |

---

## Recommendations

### Medium Priority

1. **Add `--hash-algorithm` tests** to test-create.ps1
   - Test SHA-384 and SHA-512 hash algorithms
   - Test with both ECDSA and RSA key types

2. **Add PEM output tests** to test-create.ps1
   - Test `--cert` / `--key` output options for both dev and CA

### Low Priority

3. **Add remaining low-priority coverage**
   - `--issuer-password-file` test to test-create.ps1
   - `--warn` with JSON test to test-inspect.ps1
   - `--save --chain` test to test-inspect.ps1
   - `store list --expired` / `--expiring` filters to test-trust.ps1

### Future Work

4. **Phase 10: Cross-Platform Support**
   - Create `test-crossplatform.ps1` when Linux support is implemented
   - Test platform guards for trust store operations

---

## Template for New Test File

```powershell
#requires -version 7

<#
.SYNOPSIS
    Test suite for certz <command> command.

.DESCRIPTION
    This script tests the <command> command functionality.
    It follows test isolation principles from test-isolation-plan.md.

.PARAMETER TestId
    Run specific tests by ID. Example: -TestId "xxx-1.1", "xxx-1.2"

.PARAMETER Category
    Run tests by category.

.PARAMETER SkipCleanup
    Keep test files after running.

.PARAMETER Verbose
    Show detailed output.
#>
param(
    [switch]$SkipCleanup,
    [switch]$Verbose,
    [string[]]$TestId,
    [string[]]$Category
)

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\test-helper.ps1"

$TestCategories = @{
    "category-1" = @("xxx-1.1", "xxx-1.2")
    "category-2" = @("xxx-2.1", "xxx-2.2")
}

Initialize-TestEnvironment -TestId $TestId -Category $Category -TestCategories $TestCategories
Set-VerboseOutput -Enabled $Verbose
Build-Certz -Verbose:$Verbose
Enter-ToolsDirectory
Remove-TestFiles "xxx-"

# Tests follow the pattern:
# Invoke-Test -TestId "xxx-1.1" -TestName "Description" -FilePrefix "xxx" -TestScript {
#     # SETUP: PowerShell only (New-SelfSignedCertificate, Export-PfxCertificate, etc.)
#     # ACTION: Single certz.exe call
#     # ASSERTIONS: PowerShell verification (Assert-FileExists, cert properties, etc.)
#     # CLEANUP: In finally block if needed
# }

if (-not $SkipCleanup) {
    Remove-TestFiles "xxx-"
}
Exit-ToolsDirectory
$exitCode = Write-TestSummary -SkipCleanup:$SkipCleanup
exit $exitCode
```

---

## Summary

| Status     | Count    | Description                            |
| ---------- | -------- | -------------------------------------- |
| ✅ Covered | 12 files | All commands have dedicated test files |
| ⚠️ Gaps    | ~10      | Medium and low priority (see above)    |
| ⏳ Future  | 1        | `test-crossplatform.ps1` (Phase 10)    |

**Total tests: 147 across 12 files**
