# Test Coverage Analysis

**Date:** 2026-02-09
**Purpose:** Analyze test coverage gaps and provide recommendations for new tests

---

## Current Test Files

| Test File | Commands Tested | Test Count | Status |
|-----------|-----------------|------------|--------|
| `test-create.ps1` | `create dev`, `create ca` | 14 tests | ✅ Modern v2 |
| `test-inspect.ps1` | `inspect` (file, URL, store, chain, save) | 17 tests | ✅ Modern v2 |
| `test-trust.ps1` | `trust add`, `trust remove`, `store list` | 11 tests | ✅ Modern v2 |
| `test-convert.ps1` | `convert` (PEM, DER, PFX conversions) | 23 tests | ✅ Modern v2 |
| `test-lint.ps1` | `lint` (CA/B Forum, Mozilla NSS) | 12 tests | ✅ Modern v2 |
| `test-monitor.ps1` | `monitor` (expiration tracking) | 8 tests | ✅ Modern v2 |
| `test-renew.ps1` | `renew` (certificate renewal) | 6 tests | ✅ Modern v2 |
| `test-ephemeral.ps1` | `--ephemeral`, `--pipe` modes | 10 tests | ✅ Modern v2 |

---

## Command Coverage Analysis

### V2 Commands (Hierarchical Structure)

| Command | Test File | Coverage Status |
|---------|-----------|-----------------|
| `create dev` | test-create.ps1 | ✅ Covered (5 tests) |
| `create ca` | test-create.ps1 | ✅ Covered (3 tests) |
| `create dev --guided` | test-create.ps1 | ⚠️ Manual only (gui-1.1) |
| `create ca --guided` | test-create.ps1 | ❌ Not covered |
| `inspect <file>` | test-inspect.ps1 | ✅ Covered (5 tests) |
| `inspect <url>` | test-inspect.ps1 | ✅ Covered (3 tests) |
| `inspect <thumbprint>` | test-inspect.ps1 | ✅ Covered (2 tests) |
| `inspect --chain` | test-inspect.ps1 | ✅ Covered (2 tests) |
| `inspect --save` | test-inspect.ps1 | ✅ Covered (5 tests) |
| `inspect --format json` | test-inspect.ps1 | ✅ Covered (2 tests) |
| `trust add` | test-trust.ps1 | ✅ Covered (4 tests) |
| `trust remove` | test-trust.ps1 | ✅ Covered (4 tests) |
| `store list` | test-trust.ps1 | ✅ Covered (3 tests) |
| `convert` | test-convert.ps1 | ✅ Covered (23 tests) |
| `lint` | test-lint.ps1 | ✅ Covered (12 tests) |
| `monitor` | test-monitor.ps1 | ✅ Covered (8 tests) |
| `renew` | test-renew.ps1 | ✅ Covered (6 tests) |
| `--ephemeral` / `--pipe` | test-ephemeral.ps1 | ✅ Covered (10 tests) |

---

## Completed Test Files

All v2 commands now have dedicated test files:

| Test File | Categories | Test Count |
|-----------|------------|------------|
| `test-convert.ps1` | pem-to-pfx, pfx-to-pem, encryption, format, simplified conversions, errors | 23 tests |
| `test-lint.ps1` | CA/B Forum, Mozilla NSS, JSON output | 12 tests |
| `test-monitor.ps1` | directory scan, expiration tracking, JSON output | 8 tests |
| `test-renew.ps1` | auto-detect parameters, preserve SANs, custom validity | 6 tests |
| `test-ephemeral.ps1` | ephemeral mode, pipe mode, mutual exclusion | 10 tests |

---

## Test Coverage Gaps in Existing Files

### test-create.ps1 Gaps

| Gap | Priority | Status |
|-----|----------|--------|
| `--guided` for CA | Medium | ✅ Covered (gui-1.2) |
| `--issuer` with password file | Low | Add iss-1.3 for `--issuer-password-file` |

### test-inspect.ps1 Gaps

| Gap | Priority | Status |
|-----|----------|--------|
| `--crl` revocation check | Medium | ✅ Covered (crl-1.1) |
| `--warn` with JSON | Low | Add fmt-2.3 for warn + JSON combo |
| Save chain to file | Low | Add sav-1.6 for `--save --chain` |

### test-trust.ps1 Gaps

| Gap | Priority | Status |
|-----|----------|--------|
| `--expired` filter | Medium | ✅ Covered (sto-1.4) |
| `--expiring` filter | Medium | ✅ Covered (sto-1.5) |
| Browser trust stores | Phase 5 | Deferred until browser support added |

---

## Recommendations

### Low Priority

1. **Add remaining low-priority coverage**
   - Add `--issuer-password-file` test to test-create.ps1
   - Add `--warn` with JSON test to test-inspect.ps1
   - Add `--save --chain` test to test-inspect.ps1

### Future Work

2. **Phase 10: Cross-Platform Support**
   - Create `test-crossplatform.ps1` when Linux support is implemented
   - Test platform guards for trust store operations
   - Test file-based operations on Linux

---

## Test Isolation Principles (Reference)

All new tests must follow [test-isolation-plan.md](test-isolation-plan.md):

1. **Each test invokes certz.exe exactly ONCE**
2. **Setup uses pure PowerShell** (New-SelfSignedCertificate, etc.)
3. **Cleanup uses pure PowerShell** (Remove-Item, etc.)
4. **Assert against system state**, not console output
5. **Use unique test identifiers** (GUID suffixes for subjects)

---

## Template for New Test File

```powershell
#Requires -Version 7.5

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

# ... (copy helper functions from existing test files)

# Test categories
$script:TestCategories = @{
    "category-1" = @("xxx-1.1", "xxx-1.2")
    "category-2" = @("xxx-2.1", "xxx-2.2")
}

# Tests follow the pattern:
# Invoke-Test -TestId "xxx-1.1" -TestName "Description" -TestScript {
#     # SETUP: PowerShell only
#     # ACTION: Single certz.exe call
#     # ASSERTION: PowerShell verification
#     # CLEANUP: In finally block
# }
```

---

## Summary

| Status | Count | Description |
|--------|-------|-------------|
| ✅ Covered | 8 | test-create, test-inspect, test-trust, test-convert, test-lint, test-monitor, test-renew, test-ephemeral |
| ⚠️ Gaps | 3 | Low priority only (see above) |
| ⏳ Future | 1 | test-crossplatform.ps1 (Phase 10) |

**Next Action:** Begin Phase 10 cross-platform support, or fill remaining low-priority test gaps.
