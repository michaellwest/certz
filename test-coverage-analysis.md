# Test Coverage Analysis

**Date:** 2026-02-07
**Purpose:** Analyze test coverage gaps and provide recommendations for new tests

---

## Current Test Files

| Test File | Commands Tested | Test Count | Status |
|-----------|-----------------|------------|--------|
| `test-create.ps1` | `create dev`, `create ca` | 14 tests | ✅ Modern v2 |
| `test-inspect.ps1` | `inspect` (file, URL, store, chain, save) | 17 tests | ✅ Modern v2 |
| `test-trust.ps1` | `trust add`, `trust remove`, `store list` | 11 tests | ✅ Modern v2 |
| `test-all.ps1` | Legacy v1 commands (create, install, list, remove, export, convert, info, verify) | ~70+ tests | ⚠️ Legacy |

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
| `convert` | ❌ **MISSING** | ❌ No dedicated v2 test file |
| `lint` | N/A | Phase 4 - Not implemented |
| `renew` | N/A | Phase 4 - Not implemented |

### Legacy V1 Commands (Covered by test-all.ps1)

| Command | Category | Test IDs | Migration Status |
|---------|----------|----------|------------------|
| `create` | create, password, keysize, hash, keytype, ca, subject, validity, extensions, rsa-padding, pfx-encryption | cre-1.x through cre-11.x | → `create dev/ca` |
| `install` | install | ins-1.x, ins-2.x | → `trust add` |
| `list` | list | lst-1.x | → `store list` |
| `remove` | remove | rem-1.x | → `trust remove` |
| `export` | export | exp-1.x | → `inspect --save` |
| `convert` | convert | cnv-1.x through cnv-3.x | Kept as `convert` |
| `info` | info | inf-1.x | → `inspect` |
| `verify` | verify | ver-1.x | → `inspect --chain --crl` |

---

## Missing Test Files

### 1. `test-convert.ps1` - **CRITICAL**

The `convert` command is a standalone v2 command that needs a dedicated test file.

**Required Test Categories:**
- `convert-to-pfx` - Convert PEM/DER to PFX
- `convert-from-pfx` - Convert PFX to PEM/DER
- `format` - JSON output support

**Proposed Test IDs:**
| Test ID | Description |
|---------|-------------|
| cnv-1.1 | Convert PEM cert to PFX |
| cnv-1.2 | Convert PEM cert+key to PFX |
| cnv-1.3 | Convert DER cert to PFX |
| cnv-2.1 | Convert PFX to PEM (cert only) |
| cnv-2.2 | Convert PFX to PEM (cert+key) |
| cnv-2.3 | Convert PFX to DER |
| cnv-3.1 | Convert with password |
| cnv-3.2 | Convert with password file |
| fmt-1.1 | Convert with JSON output |

### 2. Phase 4 Test Files (Future)

When Phase 4 is implemented, these test files will be needed:

#### `test-lint.ps1`
- Lint against CA/B Forum Baseline Requirements
- Lint against Mozilla NSS Policy
- JSON output support

#### `test-renew.ps1`
- Auto-detect parameters from existing certificate
- Preserve SANs, key type, extensions
- Custom validity period

---

## Test Coverage Gaps in Existing Files

### test-create.ps1 Gaps

| Gap | Priority | Recommendation |
|-----|----------|----------------|
| `--guided` for CA | Medium | Add gui-1.2 test for CA wizard |
| `--issuer` with password file | Low | Add iss-1.3 for `--issuer-password-file` |
| PFX encryption options | Low | Covered in test-all.ps1, consider migrating |
| RSA padding options | Low | Covered in test-all.ps1, consider migrating |

### test-inspect.ps1 Gaps

| Gap | Priority | Recommendation |
|-----|----------|----------------|
| `--crl` revocation check | Medium | Add crl-1.1 for OCSP/CRL checking |
| `--warn` with JSON | Low | Add fmt-2.3 for warn + JSON combo |
| Save chain to file | Low | Add sav-1.6 for `--save --chain` |

### test-trust.ps1 Gaps

| Gap | Priority | Recommendation |
|-----|----------|----------------|
| `--expired` filter | Medium | Add sto-1.4 for expired cert filter |
| `--expiring` filter | Medium | Add sto-1.5 for expiring cert filter |
| Browser trust stores | Phase 5 | Deferred until browser support added |

---

## Recommendations

### Immediate Priority (Before Next Release)

1. **Create `test-convert.ps1`**
   - This is the only v2 command without a dedicated test file
   - Can adapt tests from test-all.ps1 convert category (cnv-1.x through cnv-3.x)
   - Follow test-isolation-plan.md principles

### Medium Priority

2. **Add missing coverage to existing test files**
   - Add `--crl` revocation tests to test-inspect.ps1
   - Add `--expired`/`--expiring` filter tests to test-trust.ps1
   - Add CA `--guided` wizard test to test-create.ps1

### Low Priority (Technical Debt)

3. **Migrate legacy tests from test-all.ps1**
   - Many tests in test-all.ps1 use legacy v1 command syntax
   - Consider migrating key tests to v2 syntax files
   - Keep test-all.ps1 for backwards compatibility testing

### Phase 4 (Future)

4. **Create Phase 4 test files when commands are implemented**
   - `test-lint.ps1` - For CA/B Forum and Mozilla NSS linting
   - `test-renew.ps1` - For certificate renewal

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
| ✅ Covered | 3 | test-create.ps1, test-inspect.ps1, test-trust.ps1 |
| ❌ Missing | 1 | test-convert.ps1 |
| ⏳ Future | 2 | test-lint.ps1, test-renew.ps1 (Phase 4) |
| ⚠️ Gaps | 7 | Various gaps in existing test files |

**Next Action:** Create `test-convert.ps1` following the established patterns.
