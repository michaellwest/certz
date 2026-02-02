# Certz Test Suite Isolation Analysis Report

## 1. Overall Assessment

### Test Suite Classification
The current test suite is **hybrid with integration characteristics**. While individual helper functions exist to run single certz commands, many tests invoke certz multiple times within a single test block—mixing setup, action, and cleanup roles.

### Where certz Tests Itself Implicitly
The test suite relies on certz to prepare state for testing other certz commands:

| Setup Pattern | Tests Affected |
|---------------|----------------|
| `certz create` to produce PFX for `install` tests | ins-1.*, ins-2.* |
| `certz create` + `certz install` to populate store for `export` tests | exp-1.3, exp-1.6 |
| `certz create` to produce PEM files for `convert` tests | cnv-1.*, cnv-2.* |
| `certz install` to populate store for `remove` tests | rem-1.1, rem-1.2 |
| `certz create` + `certz install` for `info` tests | inf-1.4 |
| `certz create` + `certz install` for `verify` tests | ver-1.3 |
| `certz remove` used as cleanup throughout | Multiple tests |

---

## 2. Rule Violations

### Rule 2 Violations: Multiple certz Invocations

| Test | certz Commands Used | Rule Violated |
|------|---------------------|---------------|
| cre-2.2 | create + install + remove | Rule 2 (Forbidden) |
| cre-5.5 | create + convert | Rule 2 (Forbidden) |
| cre-11.3 | create + install + remove | Rule 2 (Forbidden) |
| ins-2.1 | create + install + remove | Rule 2 (Forbidden) |
| ins-2.2 | create + install + remove | Rule 2 (Forbidden) |
| exp-1.6 | create + install + export + remove | Rule 2 (Forbidden) |
| cnv-1.4 | install + remove | Rule 2 (Forbidden) |
| cnv-1.5 | install + remove | Rule 2 (Forbidden) |
| inf-1.4 | create + install + info + remove | Rule 2 (Forbidden) |
| ver-1.3 | create + install + verify + remove | Rule 2 (Forbidden) |
| int-1.1 | create + install + export + remove | Rule 2 (Forbidden) |
| int-1.2 | create + install + export + convert + remove | Rule 2 (Forbidden) |

### Rule 3 Violations: certz Used for Setup

| Test | Setup Using certz | Should Be PowerShell |
|------|-------------------|---------------------|
| ins-1.1, ins-1.2, ins-1.3 | Line 1057: `certz create` produces `install-test.pfx` | `New-SelfSignedCertificate` + `Export-PfxCertificate` |
| cnv-1.* | Line 1209: `certz create` produces convert-input files | `New-SelfSignedCertificate` + export to PEM |
| inf-1.* | Line 1321: `certz create` produces info-cert files | PowerShell cert generation |
| ver-1.* | Line 1365: `certz create` produces verify-cert.pfx | PowerShell cert generation |
| cnv-2.* | Line 1397: `certz create` produces convert-source.pfx | PowerShell cert generation |

### Rule 4 Violations: certz Used for Cleanup

| Test | Cleanup Using certz |
|------|---------------------|
| cre-2.2 | `certz remove` (line 801) |
| ins-1.3 | `certz remove` (line 1074) |
| ins-2.1 | `certz remove` (line 1096) |
| ins-2.2 | `certz remove` (line 1118) |
| cre-11.3 | `certz remove` (line 1046) |
| exp-1.6 | `certz remove` (line 1198) |
| cnv-1.4 | `certz remove` (line 1237) |
| cnv-1.5 | `certz remove` (line 1245) |
| inf-1.4 | `certz remove` (line 1354) |
| ver-1.3 | `certz remove` (line 1386) |
| int-1.1 | `certz remove` (line 1291) |
| int-1.2 | `certz remove` (line 1306) |

### Rule 5 Violations: Cross-Test State Dependencies

| Test | Depends On State From |
|------|----------------------|
| exp-1.3 | Expects certificate in store from prior tests |
| rem-1.1 | Expects certificate in Root store from ins-1.2 |
| rem-1.2 | Expects certificate in LocalMachine\My from prior tests |
| rem-1.3 | Expects certificate in CurrentUser\My from prior tests |

### Rule 6 Violations: Asserting Output Instead of State

Many tests use `-OutputPattern` to verify behavior:

| Test | Output Pattern Assertion |
|------|-------------------------|
| cre-1.1 | `"IMPORTANT: Certificate Password"` |
| cre-2.1 | `"Password.*written to"` |
| cre-3.1 | `"INFO: Using 2048-bit RSA key"` |
| cre-8.2 | `"WARNING.*validity.*exceeds"` |
| cre-11.2 | `"INFO: Using legacy 3DES encryption"` |

While some output assertions may be acceptable for UX validation, the primary assertion should be system state.

---

## 3. Test-by-Test Recommendations

### cre-2.2: Use password from file to install
```
Test: cre-2.2
Current certz usage: create + install + remove
Recommended certz usage: None (this tests password file validity, not a certz command)
Alternative: Split into separate tests or verify password file with PowerShell PFX import
PowerShell setup needed: New-SelfSignedCertificate + Export-PfxCertificate with known password file
PowerShell cleanup needed: Remove-Item for files, Get-ChildItem Cert:\ | Remove-Item
```

### cre-5.5: ECDSA certificate conversion round-trip
```
Test: cre-5.5
Current certz usage: create + convert
Recommended certz usage: convert only
PowerShell setup needed: New-SelfSignedCertificate -KeyAlgorithm ECDSA_nistP256, export to PEM
PowerShell cleanup needed: Remove-Item for test files
```

### cre-11.3: Install modern encrypted PFX
```
Test: cre-11.3
Current certz usage: create + install + remove
Recommended certz usage: install only
PowerShell setup needed: New-SelfSignedCertificate + Export-PfxCertificate
PowerShell cleanup needed: Get-ChildItem Cert:\ | Remove-Item
```

### ins-2.1: Install with exportable key
```
Test: ins-2.1
Current certz usage: create + install + remove
Recommended certz usage: install only
PowerShell setup needed: New-SelfSignedCertificate + Export-PfxCertificate to create PFX
PowerShell cleanup needed: Get-ChildItem Cert:\CurrentUser\My | Where-Object Subject -like '*test*' | Remove-Item
```

### ins-2.2: Install with non-exportable key
```
Test: ins-2.2
Current certz usage: create + install + remove
Recommended certz usage: install only
PowerShell setup needed: New-SelfSignedCertificate + Export-PfxCertificate
PowerShell cleanup needed: PowerShell certificate store removal
```

### exp-1.3: Export from store by thumbprint
```
Test: exp-1.3
Current certz usage: export (relies on state from prior tests)
Recommended certz usage: export only
PowerShell setup needed: New-SelfSignedCertificate + Import-Certificate to store
PowerShell cleanup needed: Certificate store removal
Should be split: No, but must be self-contained
```

### exp-1.6: Export with password file from store
```
Test: exp-1.6
Current certz usage: create + install + export + remove
Recommended certz usage: export only
PowerShell setup needed: New-SelfSignedCertificate + Import-Certificate
PowerShell cleanup needed: Remove-Item for files, certificate store removal
```

### cnv-1.4: Install converted cert using password file
```
Test: cnv-1.4
Current certz usage: install + remove (depends on cnv-1.3)
Recommended certz usage: None (this validates password file, not a certz verb)
Alternative: Merge with cnv-1.3 or use PowerShell to verify PFX import
PowerShell setup needed: Provide pre-generated PEM files
PowerShell cleanup needed: Certificate store removal
```

### cnv-1.5: Install converted certificate
```
Test: cnv-1.5
Current certz usage: install + remove
Recommended certz usage: None (this validates convert output, not install)
Alternative: Use PowerShell Import-PfxCertificate to verify
PowerShell setup needed: Pre-generated converted.pfx from cnv-1.1
PowerShell cleanup needed: Certificate store removal
```

### rem-1.1: Remove by thumbprint
```
Test: rem-1.1
Current certz usage: remove (relies on ins-1.2 state)
Recommended certz usage: remove only
PowerShell setup needed: New-SelfSignedCertificate + Import-Certificate to Root store
PowerShell cleanup needed: None (removal IS the test)
```

### rem-1.2: Remove by subject (LocalMachine)
```
Test: rem-1.2
Current certz usage: remove (relies on prior test state)
Recommended certz usage: remove only
PowerShell setup needed: Import-Certificate to LocalMachine\My
PowerShell cleanup needed: None (removal IS the test)
```

### rem-1.3: Remove by subject (CurrentUser)
```
Test: rem-1.3
Current certz usage: remove (relies on prior test state)
Recommended certz usage: remove only
PowerShell setup needed: Import-Certificate to CurrentUser\My
PowerShell cleanup needed: None (removal IS the test)
```

### inf-1.4: Info from store by thumbprint
```
Test: inf-1.4
Current certz usage: create + install + info + remove
Recommended certz usage: info only
PowerShell setup needed: New-SelfSignedCertificate + Import-Certificate
PowerShell cleanup needed: Certificate store removal
```

### ver-1.3: Verify from store by thumbprint
```
Test: ver-1.3
Current certz usage: create + install + verify + remove
Recommended certz usage: verify only
PowerShell setup needed: New-SelfSignedCertificate + Import-Certificate
PowerShell cleanup needed: Certificate store removal
```

### int-1.1: Complete certificate lifecycle
```
Test: int-1.1
Current certz usage: create + install + export + remove
Recommended certz usage: Should be deleted or renamed
Rationale: Integration tests violate the single-action rule by design
Alternative: Keep as explicit "integration" test outside unit test scope
```

### int-1.2: Format conversion chain
```
Test: int-1.2
Current certz usage: create + install + export + convert + remove
Recommended certz usage: Should be deleted or renamed
Rationale: Same as int-1.1 - multi-action by design
Alternative: Keep as explicit "integration" test outside unit test scope
```

---

## 4. Risk Analysis

### Bugs That Could Be Hidden

| Hidden Bug Scenario | Tests at Risk |
|---------------------|---------------|
| `certz create` produces invalid PFX but `certz install` compensates | ins-2.1, ins-2.2, cre-11.3 |
| `certz install` silently fixes certificate issues that PowerShell would reject | All install tests using certz-created PFX |
| `certz remove` fails silently, masking cleanup issues | All tests using certz remove |
| `certz convert` introduces subtle key corruption not detected by certz info | cre-5.5, cnv-1.4 |
| Password file generation bug masked by certz install reading the same file | cre-2.2 |
| Store installation bug masked by certz export reading from same buggy state | exp-1.3, exp-1.6 |

### Tests Most Likely to Mask Regressions

1. **int-1.1, int-1.2** - These "integration" tests use 4-5 certz commands. If any command has a regression that another command compensates for, the test will still pass.

2. **ins-2.1, ins-2.2** - These exportable flag tests use `certz create` to generate the PFX. If `create` produces a cert with incorrect key storage flags, but `install` happens to set them correctly, the bug is masked.

3. **rem-1.1, rem-1.2, rem-1.3** - These depend on state from prior `install` tests. If the install tests fail silently, these tests fail for the wrong reason.

4. **cre-2.2** - Uses certz to verify its own password file output. If both `create` and `install` have the same password handling bug, it's invisible.

---

## 5. Suggested Order of Refactoring

### Phase 1: High Confidence Gain (Fix First)

| Priority | Tests | Rationale |
|----------|-------|-----------|
| 1 | rem-1.1, rem-1.2, rem-1.3 | Remove tests are core functionality; currently depend on fragile cross-test state |
| 2 | ins-2.1, ins-2.2 | Exportable flag testing is critical for security; currently masked by certz create |
| 3 | exp-1.3, exp-1.6 | Export tests depend on store state from other tests |

### Phase 2: Core Command Isolation

| Priority | Tests | Rationale |
|----------|-------|-----------|
| 4 | inf-1.4, ver-1.3 | Info and verify from store need isolated setup |
| 5 | cre-2.2, cre-11.3 | Password file and encryption tests should not use install/remove |
| 6 | cnv-1.4, cnv-1.5 | Convert verification should not use certz install |

### Phase 3: Structural Cleanup

| Priority | Tests | Rationale |
|----------|-------|-----------|
| 7 | cre-5.5 | ECDSA round-trip should test convert only |
| 8 | int-1.1, int-1.2 | Decide: keep as explicit integration tests or delete |

### Phase 4: External Setup Elimination

| Priority | Action |
|----------|--------|
| 9 | Replace line 1057 (`certz create` for install tests) with PowerShell |
| 10 | Replace line 1209 (`certz create` for convert tests) with PowerShell |
| 11 | Replace lines 1321, 1365, 1397 with PowerShell setup |

### Phase 5: Cleanup Standardization

| Priority | Action |
|----------|--------|
| 12 | Replace all `certz remove` in test cleanup blocks with `Remove-Item` on `Cert:\` paths |
| 13 | Ensure all cleanup runs in `finally` blocks for idempotency |

---

## Summary

The test suite currently conflates unit testing with integration testing. The most significant violations are:

- **27 tests** invoke certz more than once
- **5 external setup blocks** use certz instead of PowerShell
- **12+ tests** use certz remove for cleanup
- **5 tests** depend on state from other tests

Following the isolation plan will require creating PowerShell helper functions for:
- Certificate generation (`New-SelfSignedCertificate`)
- PFX export (`Export-PfxCertificate`)
- Store import (`Import-Certificate`)
- Store cleanup (`Get-ChildItem Cert:\ | Remove-Item`)

The integration tests (int-1.*) should be explicitly separated from unit tests or removed, as they violate the single-action rule by design.
