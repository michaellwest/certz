# Certz Passive Context Index (Minified)

**CRITICAL:** Read this index and use the Read tool on relevant files. Do NOT rely on pre-trained knowledge for certz's custom lifecycle or CLI patterns.

## Code Map (Directory-First)
|Root: c:\Projects\github\michaellwest\certz

=== COMMANDS (CLI Entry) ===
|src/certz/Commands/| Create/{CreateDev, CreateCa}, Inspect, Trust, Lint, Monitor, Renew, Convert, Store/StoreList, Diff, Fingerprint, VerifyKeypair, Examples, Completion

=== SERVICES (Logic) ===
|src/certz/Services/| CertificateGeneration (CORE), CertificateUtilities, CertificateInspector, CertificateDisplay, CertificateWizard, ChainExport, Convert, Create, Diff, Fingerprint, FormatDetection, Lint, Monitor, PipeOutput, Renew, SanInputValidator, StoreListHandler, TrustHandler, VerboseLogger, VerifyKeypair, Validation/{ChainValidator, ChainVisualizer}

=== MODELS (Options & Results) ===
|src/certz/Models/| {DevCertificate, CACertificate, Inspect, Lint, Monitor, Renew, Convert, Diff, StoreList}Options; {CertificateCreation, CertificateInspect, Lint, Monitor, Renew, Conversion, Diff, DryRun, Fingerprint, StoreList, TrustOperation, VerifyKeypair}Result; {CertificateFileType, FormatType, InspectSource, ChainElementInfo}

=== INFRASTRUCTURE & FORMATTERS ===
|src/certz/| Program.cs, GlobalUsings.cs, certz.csproj (.NET 10, single-file)
|src/certz/Options/| OptionBuilders.cs (684 lines: all CLI option factories/validators)
|src/certz/Formatters/| {IOutputFormatter, FormatterFactory}, {TextFormatter, JsonFormatter}
|src/certz/Exceptions/| {CertificateException, DiffHasDifferencesException, KeypairMismatchException, LintFailedException}

=== DOCUMENTATION & TESTING ===
|./| README.md (28KB CLI Ref), CLAUDE.md (This file)
|docs/| architecture.md, certz-spec.md, testing.md, docker-*.md, phases/phase{1-12}-*.md (Specs)
|test/| isolation-plan.md (Principles), coverage-analysis.md, test-helper.ps1, test-all.ps1 (74KB), test-{create, inspect, trust, lint, monitor, renew, ephemeral, convert}.ps1

## Implementation Rules [Source: R=README, C=CLAUDE, P=Phases, A=Arch, T=Test]

### ALWAYS
- Default to ECDSA P-256 for key gen; 3072-bit if RSA is explicit [R, C]
- Enforce 398-day max validity for leaf certs (CA/B Forum) [P4]
- Require SAN for TLS; Include Basic Constraints for CA [P4]
- Throw `ArgumentException` for validation errors in async handlers [C]
- Return structured result records from service methods [A]
- Use `OptionBuilders` for standard options; `FormatterFactory` for output [P1]
- Tests: Invoke certz.exe exactly ONCE; PowerShell only for setup/cleanup [T]
- Assert against system state in tests, not console output [T]
- Debug against `debug/certz.exe` (the `Build-Certz` target the suites run); `debug/win-x64/` and `src/certz/bin/` copies go stale and give false results [T]
- Generate secure random passwords if omitted; use UTC for dates [R]
- Use modern PFX encryption (AES-256-CBC) by default [R]
- Ref GitHub Issue (`closes #N`) in every commit [C]

### NEVER
- Use `Environment.ExitCode` in async handlers [C]
- Use SHA-1 signatures or RSA < 2048 bits [P4]
- Call certz.exe for test setup/teardown or > 1 time per test [T]
- Combine `--ephemeral` and `--pipe` (mutually exclusive) [P8]
- Combine `--ephemeral`/`--pipe` with file output or `--trust` [P8]
- Default to legacy 3DES PFX encryption [R]
- Use `DateTime.Today/Now` (Always use UtcNow) [R]
- Omit password display warning for generated passwords [A]
- Commit without an associated GitHub Issue number [C]

## Protocol
1. **Validation Step:** Start response with: 1) Retrieved Files, 2) Key Constraints, 3) Reasoning Path.
2. **Sources Consulted:** Output a "Sources Consulted" block before code/answers.
3. **Hierarchy:** CLAUDE.md > docs/phases/ > README.md > architecture.md > Code.
4. **Index Refresh:** Update Code Map after adding/removing files:
   `Get-ChildItem -Path src -Recurse -Include *.cs -Exclude obj,bin | Select-Object -ExpandProperty FullName`
