# Certificate Operations Refactoring Plan

**Status:** In Progress
**Started:** 2026-02-06
**Goal:** Consolidate CertificateOperations.cs and CertificateOperationsV2.cs to eliminate duplication and establish modern patterns.

## Overview

Currently, we have two certificate operation classes:
- `CertificateOperations.cs` - Legacy parameter-based API with direct console output
- `CertificateOperationsV2.cs` - Modern options-based API with structured results

**Problem:** V2 calls V1 utility methods, creating tight coupling. Shared code is duplicated.

**Solution:** Extract shared utilities into a new class, then gradually migrate all operations to the modern pattern.

## Refactoring Strategy

### Phase 1: Extract Shared Utilities ✅
Create `Services/CertificateUtilities.cs` with reusable helper methods.

**Methods to Extract:**
1. `GenerateSecurePassword()` - Password generation
2. `DisplayPasswordWarning()` - Console password display
3. `GetKeyStorageFlags()` - X509 key storage flag configuration
4. `WriteCertificateToFile()` - File writing for PFX/PEM formats
5. `InstallCertificate()` - Trust store installation

### Phase 2: Update References
Update both `CertificateOperations.cs` and `CertificateOperationsV2.cs` to use the new utilities.

### Phase 3: Verify & Commit
Compile and test after each extraction to ensure nothing breaks.

---

## Detailed Steps

### Step 1: Create CertificateUtilities.cs
- [ ] Create new file `Services/CertificateUtilities.cs`
- [ ] Add namespace and class declaration
- [ ] Make class `internal static`

### Step 2: Extract GenerateSecurePassword()
- [ ] Copy method to CertificateUtilities.cs
- [ ] Update CertificateOperations.cs to call CertificateUtilities.GenerateSecurePassword()
- [ ] Update CertificateOperationsV2.cs to call CertificateUtilities.GenerateSecurePassword()
- [ ] Compile and verify
- [ ] Commit changes

### Step 3: Extract DisplayPasswordWarning()
- [ ] Copy method to CertificateUtilities.cs
- [ ] Update CertificateOperations.cs references
- [ ] Compile and verify
- [ ] Commit changes

### Step 4: Extract GetKeyStorageFlags()
- [ ] Copy method to CertificateUtilities.cs
- [ ] Update CertificateOperations.cs references
- [ ] Compile and verify
- [ ] Commit changes

### Step 5: Extract WriteCertificateToFile()
- [ ] Copy method to CertificateUtilities.cs
- [ ] Update CertificateOperations.cs references
- [ ] Update CertificateOperationsV2.cs references
- [ ] Compile and verify
- [ ] Commit changes

### Step 6: Extract InstallCertificate()
- [ ] Copy method to CertificateUtilities.cs
- [ ] Update CertificateOperations.cs references
- [ ] Update CertificateOperationsV2.cs references
- [ ] Compile and verify
- [ ] Commit changes

### Step 7: Final Cleanup
- [ ] Remove extracted methods from CertificateOperations.cs
- [ ] Compile and verify all tests pass
- [ ] Update documentation
- [ ] Final commit

---

## Expected File Structure After Refactoring

```
Services/
├── CertificateUtilities.cs       ✨ NEW - Shared utilities
├── CertificateOperations.cs      📝 UPDATED - Legacy operations (fewer methods)
├── CertificateOperationsV2.cs    📝 UPDATED - Modern operations (cleaner)
├── CertificateGeneration.cs      (unchanged)
└── CertificateDisplay.cs         (unchanged)
```

---

## Verification Checklist

After each step:
- [ ] Code compiles without errors
- [ ] No new warnings introduced
- [ ] Git commit created with clear message
- [ ] Progress tracker updated

---

## Future Work (Post-Refactoring)

Once utilities are extracted:
1. Consider migrating remaining CertificateOperations methods to options pattern
2. Create InspectService, ConvertService, TrustService with structured results
3. Eventually deprecate parameter-based methods entirely

---

## Notes

- Keep commits small and atomic
- Each commit should compile successfully
- Use descriptive commit messages following project conventions
- Update this document as we progress
