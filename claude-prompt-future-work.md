# Claude Prompt: Complete Certificate Operations Modernization

## Context

You are helping complete the modernization of the `certz` certificate management tool. Phase 1 of the refactoring is complete - we've successfully extracted shared utilities into `CertificateUtilities.cs` and eliminated code duplication between `CertificateOperations.cs` (legacy) and `CertificateOperationsV2.cs` (modern).

## Current State

### What's Done ✅
- `CertificateUtilities.cs` - Shared utility methods (password generation, file I/O, trust store installation)
- `CertificateOperationsV2.cs` - Modern API with options pattern for all certificate operations
- `CertificateOperations.cs` - Legacy API (to be deprecated)

### SHORT TERM Complete ✅
All methods migrated to options pattern in `CertificateOperationsV2.cs`:
- `ConvertToPfx()`, `ConvertFromPfx()`, `ExportFromUrl()`, `ExportFromStore()`
- `ListCertificates()`, `RemoveCertificate()`, `ShowCertificateInfo*()`, `Verify*()`

### MEDIUM TERM Complete ✅
**Service Classes (2026-02-07):**
- `Services/ConvertService.cs` - PEM/PFX conversion operations
- `Services/InspectService.cs` - Certificate inspection and verification
- `Services/TrustService.cs` - Trust store management (add/remove/list)
- `Services/ExportService.cs` - Certificate export from URLs and stores
- Commands updated to use new service classes

**Phase 3 Guided Mode (2026-02-07):**
- `Services/CertificateWizard.cs` - Enhanced with beautiful Spectre.Console UI
- Step-by-step progression with inline educational help
- Summary table with confirmation before execution
- `certz create dev --guided` and `certz create ca --guided` fully functional

### Architecture Patterns

**Legacy Pattern (Old):**
```csharp
// Multiple parameters, returns void, direct console output
internal static async Task ConvertToPfx(
    FileInfo certFile, FileInfo keyFile, FileInfo pfxFile,
    string password, FileInfo? passwordFile = null,
    string pfxEncryption = "modern")
{
    // ... implementation with Console.WriteLine
}
```

**Modern Pattern (New):**
```csharp
// Options object, structured result, quiet operation
internal static async Task<ConversionResult> ConvertToPfx(ConvertToPfxOptions options)
{
    // ... quiet implementation
    return new ConversionResult
    {
        Success = true,
        OutputFile = options.OutputFile.FullName,
        // ... structured data
    };
}
```

### Key Files to Reference
- `Services/CertificateUtilities.cs` - Shared utilities
- `Services/CertificateOperationsV2.cs` - Modern pattern examples
- `Services/CertificateOperations.cs` - Legacy methods to migrate
- `Models/` - Options and result classes
- `Commands/Create/CreateDevCommand.cs` - Command integration example
- `test-isolation-plan.md` - Testing requirements

## Your Tasks

### SHORT TERM: Migrate Remaining Methods to Options Pattern

**Goal:** Convert legacy methods in `CertificateOperations.cs` to the modern pattern.

**Methods to Migrate:**
1. `ConvertToPfx()` → `ConvertToPfxOptions` → `ConversionResult`
2. `ConvertFromPfx()` → `ConvertFromPfxOptions` → `ConversionResult`
3. `ExportCertificate()` (URI overload) → `ExportFromUrlOptions` → `ExportResult`
4. `ExportCertificate()` (store overload) → `ExportFromStoreOptions` → `ExportResult`
5. `ListCertificates()` → `ListCertificatesOptions` → `CertificateListResult`
6. `RemoveCertificate()` → `RemoveCertificateOptions` → `RemovalResult`
7. `ShowCertificateInfo()` (all overloads) → `InspectOptions` → `InspectResult`
8. `VerifyCertificate()` → `VerifyOptions` → `VerificationResult`

**For Each Method:**
1. Create options class in `Models/` directory
2. Create result class in `Models/` directory
3. Create new method in `CertificateOperationsV2.cs`
4. Use `CertificateUtilities` for shared operations
5. Return structured results (no direct console output)
6. Update corresponding command to use new method
7. Add `--format json` support in command
8. Create test in appropriate test script (following test-isolation-plan.md)
9. Compile and commit

**Example Migration:**

```csharp
// 1. Create Models/ConvertToPfxOptions.cs
public class ConvertToPfxOptions
{
    public required FileInfo CertFile { get; set; }
    public required FileInfo KeyFile { get; set; }
    public required FileInfo OutputFile { get; set; }
    public string? Password { get; set; }
    public FileInfo? PasswordFile { get; set; }
    public string PfxEncryption { get; set; } = "modern";
}

// 2. Create Models/ConversionResult.cs
public class ConversionResult
{
    public required bool Success { get; set; }
    public required string OutputFile { get; set; }
    public required string InputCertificate { get; set; }
    public required string InputKey { get; set; }
    public string? GeneratedPassword { get; set; }
    public bool PasswordWasGenerated { get; set; }
}

// 3. Add to CertificateOperationsV2.cs
internal static async Task<ConversionResult> ConvertToPfx(ConvertToPfxOptions options)
{
    // Use CertificateUtilities.GenerateSecurePassword if needed
    // Quiet operation - no Console.WriteLine
    // Return structured result
}
```

### MEDIUM TERM: Create Specialized Service Classes

**Goal:** Organize operations into cohesive service classes.

**Services to Create:**

1. **`Services/ConvertService.cs`**
   - `ConvertToPfx(ConvertToPfxOptions)` → `ConversionResult`
   - `ConvertFromPfx(ConvertFromPfxOptions)` → `ConversionResult`

2. **`Services/InspectService.cs`**
   - `InspectFile(InspectOptions)` → `InspectResult`
   - `InspectUrl(InspectOptions)` → `InspectResult`
   - `InspectStore(InspectOptions)` → `InspectResult`
   - `VerifyCertificate(VerifyOptions)` → `VerificationResult`

3. **`Services/TrustService.cs`**
   - `AddToTrustStore(TrustAddOptions)` → `TrustResult`
   - `RemoveFromTrustStore(TrustRemoveOptions)` → `TrustResult`
   - `ListCertificates(ListOptions)` → `CertificateListResult`

4. **`Services/ExportService.cs`**
   - `ExportFromUrl(ExportFromUrlOptions)` → `ExportResult`
   - `ExportFromStore(ExportFromStoreOptions)` → `ExportResult`

**For Each Service:**
- Follow the same pattern as `CertificateOperationsV2.cs`
- Use dependency injection ready patterns (even if not using DI yet)
- All methods return structured results
- Use `CertificateUtilities` for shared operations
- Add comprehensive XML documentation
- Create corresponding tests

### MEDIUM TERM: Implement Phase 3 (Interactive/Guided Mode)

**Goal:** Add `--guided` wizard mode using Spectre.Console.

**Reference:** See `phase3-implementation-plan.md` for complete details.

**Key Tasks:**
1. Implement `Services/Interactive/CreateDevWizard.cs`
2. Implement `Services/Interactive/CreateCaWizard.cs`
3. Add `--guided` flag to `create dev` and `create ca` commands
4. Create `test-guided.ps1` test script
5. Use Spectre.Console for prompts, validation, and display
6. Integrate with existing V2 operations (reuse `CreateDevCertificate`, `CreateCACertificate`)

### LONG TERM: Deprecate Legacy Methods

**Goal:** Remove old parameter-based methods once all commands use modern pattern.

**Steps:**
1. Verify all commands use new service classes
2. Mark legacy methods as `[Obsolete]` with migration message
3. Update all documentation
4. After one version with obsolete warnings, remove entirely
5. Rename `CertificateOperationsV2.cs` → `CertificateService.cs`
6. Update namespace and references

## Instructions for Claude

**When working on these tasks:**

1. **Always read first:** Use the Read tool to examine existing patterns before creating new code
2. **Follow test-isolation-plan.md:** Each test should invoke certz.exe exactly once
3. **Incremental commits:** Compile and commit after each method migration
4. **Use TodoWrite:** Track progress for each subtask
5. **Maintain consistency:** Match existing code style, naming conventions, and patterns
6. **JSON support:** All new commands should support `--format json`
7. **Quiet by default:** New service methods should not write to console directly
8. **Error handling:** Use `CertificateException` for domain errors
9. **Documentation:** Add XML docs to all public/internal methods and classes

## Starting Point

**To begin SHORT TERM work, say:**
"Start migrating CertificateOperations methods to the options pattern. Begin with ConvertToPfx as the first example."

**To begin MEDIUM TERM work (services), say:**
"Create specialized service classes starting with ConvertService."

**To begin MEDIUM TERM work (Phase 3), say:**
"Implement Phase 3 interactive guided mode according to phase3-implementation-plan.md."

**To begin LONG TERM work, say:**
"Deprecate and remove legacy parameter-based methods from CertificateOperations."

## Success Criteria

- ✅ All operations use options pattern with structured results
- ✅ All commands support `--format json`
- ✅ Zero code duplication across services
- ✅ All tests pass (test scripts execute successfully)
- ✅ Build succeeds with no new warnings
- ✅ Documentation is complete and accurate
- ✅ Wizard mode works for `create dev` and `create ca`
- ✅ Legacy code is removed

## Questions to Ask

If unclear about any aspect, ask the user:
- "Should I implement browser trust store support now or defer to Phase 5?"
- "Do you want JSON output to use camelCase or PascalCase for property names?"
- "Should the wizard mode save a command template for future non-interactive use?"
- "What should happen if a certificate already exists with the same subject?"

---

**Ready to start? Copy this entire prompt to Claude and specify which term (SHORT/MEDIUM/LONG) you want to tackle first!**
