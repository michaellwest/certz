# Certz Passive Context Index

> **CRITICAL RULE:** Before modifying any certificate logic, you MUST read this minified index and use the Read tool on relevant files to refresh your memory. Do NOT rely on pre-trained knowledge for certz's custom certificate lifecycle, validation rules, or CLI patterns.

## Code Map (Pipe-Delimited)

```
[Certz Source Index v1.0]|root:c:\Projects\github\michaellwest\certz

=== COMMANDS (CLI Entry Points) ===
|Commands/CreateCommand.cs|routes to create subcommands
|Commands/Create/{CreateDevCommand,CreateCaCommand}.cs|dev cert & CA creation handlers
|Commands/Inspect/InspectCommand.cs|inspect file,url,store,chain
|Commands/Trust/TrustCommand.cs|trust add,remove,list ops
|Commands/Lint/LintCommand.cs|CA/B Forum+Mozilla validation
|Commands/Monitor/MonitorCommand.cs|expiration tracking
|Commands/Renew/RenewCommand.cs|cert renewal logic
|Commands/ConvertCommand.cs|PEM↔DER↔PFX conversion
|Commands/Store/StoreListCommand.cs|list certs in store
|Commands/{Install,Export,Info,List,Remove,Verify}Command.cs|store operations

=== SERVICES (Business Logic) ===
|Services/CreateService.cs|high-level cert creation (dev+CA)
|Services/CertificateGeneration.cs|★CORE: key pairs, signing, extensions
|Services/CertificateUtilities.cs|password gen, parsing, file type detection
|Services/CertificateInspector.cs|deep property+extension inspection
|Services/CertificateDisplay.cs|console formatting of cert info
|Services/InspectService.cs|route to file/url/store/chain inspect
|Services/TrustService.cs|trust store add/remove
|Services/LintService.cs|validation rules (398-day, SAN, SHA-2)
|Services/MonitorService.cs|expiry scanning
|Services/RenewService.cs|renewal with param detection
|Services/ConvertService.cs|format conversions
|Services/ExportService.cs|export from store/url
|Services/FormatDetectionService.cs|auto-detect PEM/DER/PFX
|Services/PipeOutputService.cs|stdout streaming (ephemeral)
|Services/CertificateWizard.cs|interactive --guided mode
|Services/Validation/{ChainValidator,ChainVisualizer}.cs|chain verify+tree viz

=== MODELS (Options + Results) ===
|Models/DevCertificateOptions.cs|create dev params
|Models/CACertificateOptions.cs|create ca params
|Models/CertificateCreationResult.cs|creation output record
|Models/InspectOptions.cs|inspect params
|Models/CertificateInspectResult.cs|inspect output
|Models/LintOptions.cs + LintResult.cs|lint params+output
|Models/MonitorOptions.cs + MonitorResult.cs|monitor params+output
|Models/RenewOptions.cs + RenewResult.cs|renew params+output
|Models/ConvertOptions.cs + ConversionResult.cs|convert params+output
|Models/{AddToTrustStore,Export*,Verify*,List*,Remove*}Options.cs|store ops
|Models/CertificateFileType.cs|enum: PEM,DER,PFX
|Models/FormatType.cs|enum: Text,Json
|Models/InspectSource.cs|enum: File,Url,Store,Chain
|Models/ChainElementInfo.cs|chain element record

=== OPTIONS & FORMATTERS ===
|Options/OptionBuilders.cs|★528 lines: all CLI option factories w/validators
|Formatters/{IOutputFormatter,FormatterFactory}.cs|output interface+factory
|Formatters/{TextFormatter,JsonFormatter}.cs|text+json implementations

=== INFRASTRUCTURE ===
|Program.cs|entry point, global --format, exception handler
|GlobalUsings.cs|common imports
|certz.csproj|.NET 10, single-file, self-contained config
|Exceptions/{CertificateException,LintFailedException}.cs|custom exceptions

=== DOCUMENTATION ===
|README.md|★28KB authoritative CLI reference
|CLAUDE.md|project constraints+patterns (this file)
|docs/README.md|documentation hub
|docs/certz-spec.md|CLI specification
|docs/architecture.md|design patterns, service structure
|docs/phases/phase{1-9}-*.md|feature implementation plans
|docs/testing.md|test execution procedures
|docs/docker-*.md|container testing guides

=== TESTING ===
|test/isolation-plan.md|★single-call test principle
|test/coverage-analysis.md|test gaps
|test/test-helper.ps1|shared utilities
|test/test-{create,inspect,trust,lint,monitor,renew,ephemeral,convert}.ps1|feature tests
|test/test-all.ps1|★74KB comprehensive test runner
```

## Quick Build & Test Commands

```powershell
# Build debug
dotnet build

# Build release (single-file executable)
.\build-release.ps1

# Run all tests (PowerShell 7.5+)
pwsh -File test/test-all.ps1

# Run specific test suite
pwsh -File test/test-create.ps1
pwsh -File test/test-lint.ps1
pwsh -File test/test-convert.ps1

# Quick CLI test
.\release\certz.exe --help
.\release\certz.exe create dev --cn test.local --ephemeral
.\release\certz.exe lint --file test.crt
```

## Index Refresh Protocol

**When to refresh:** After adding/removing source files, commands, or services.

**Manual refresh:** Update the Code Map section above by running:
```powershell
# List all source files for index update
Get-ChildItem -Recurse -Include *.cs -Exclude obj,bin |
    Select-Object -ExpandProperty FullName |
    ForEach-Object { $_.Replace((Get-Location).Path + '\', '') }
```

**Auto-refresh hook (add to .git/hooks/post-commit):**
```bash
#!/bin/bash
# Remind to update CLAUDE.md index when source files change
if git diff --cached --name-only | grep -qE '\.(cs|md)$'; then
    echo "⚠️  Source/docs changed - consider updating CLAUDE.md Code Map"
fi
```

---

# Project Requirements

## Tool Requirements

### 1. Developer Experience & Usability

- Human-Readable Syntax: Replace cryptic flags with a verb-noun structure
- Interactive Wizard Mode: A --guided flag that asks questions (Common Name, SANs, Expiry) and builds the command/file for you.
- Local Trust Store Integration
- Auto-Completion & "Did you mean?": Robust shell completion for Zsh, Bash, and PowerShell, including suggestions for mistyped flags.
- Auto-detection: A command to inspect the certificate and detect what kind of file it is.

### 2. Modern Cryptography & Standards

- Post-Quantum Cryptography (PQC) Support: Native support for NIST-standardized algorithms (like ML-KEM/Kyber) to future-proof against quantum threats.
- Sane Defaults: Default to modern standards (ECC P-256 or Ed25519) rather than legacy RSA, unless specified.
- Automatic SAN Handling: Automatically add localhost and local IP addresses to Subject Alternative Names for development certificates.

### 3. Lifecycle & Automation

- Expiration Monitoring & Alerts: A command to scan a directory or a remote URL and output days remaining, with a --json flag for integration into CI/CD monitoring.
- One-Command Renewal: A cert renew command that detects existing CSR parameters and extends the life of a certificate without manual re-entry.
- GitOps/CI-CD Friendly Output: Support for --output json or --output yaml for all commands to allow easy parsing by scripts and automation tools.

### 4. Advanced Diagnostics

- Chain Validation Visualization: A visual tree output showing the full path from the end-entity certificate back to the Root CA.
- Linting & Best Practices: A cert lint command that checks if a certificate meets modern browser requirements (e.g., maximum validity, required extensions).

### 5. Deployment & Security

- PKCS#12 / PFX Easy Handling: Simple conversion commands between PEM, DER, and PFX that don't require memorizing complex "export" flags.
- Sandbox/Ephemeral Mode: A flag to generate a "throwaway" certificate in memory for testing that is never written to disk.

### 6. Distribution Requirements

- **Single-File Executable**: certz.exe MUST be a single, self-contained executable with no external dependencies. Users should be able to copy and run the executable without installing .NET runtime or any additional files.
- **No Configuration Files Required**: The tool must work out-of-the-box without requiring configuration files, environment variables, or registry entries.
- **Portable**: The executable can be placed anywhere on the filesystem and run from any directory.

Build settings that enforce this (in certz.csproj):
```xml
<PublishSingleFile>true</PublishSingleFile>
<SelfContained>true</SelfContained>
<PublishTrimmed>true</PublishTrimmed>
```

## Documentation Requirements

### 1. Testing Documentation

- Provide clear documentation on how to properly test all of the available options
- Include test scenarios for each command and option combination
- Document expected behavior and outputs for each test case
- Provide example test scripts or commands that users can run to verify functionality
- Use the `test/isolation-plan.md` to ensure proper testing requirements are followed

### 2. Command Usage Documentation

- Comprehensive documentation on how to use the various commands
- Include syntax examples for each command
- Document all available options and parameters
- Provide practical examples showing common use cases
- Include troubleshooting guidance for common issues

### 3. General certificate documentation

- Include details about the differences between PEM and DER
- Explain the differences between the file extensions crt, cer, key, pfx, p12, and pem
- Explain when to use each format and how to determine which type is in the file

## Development Patterns

### Exit Codes in Command Handlers

When validation errors occur in async command handlers (`SetAction(async (parseResult) => { ... })`), use `throw new ArgumentException("message")` instead of `Environment.ExitCode = 1`.

**Why:** In System.CommandLine 2.x with async handlers, `Environment.ExitCode` does not reliably propagate through `InvokeAsync()`. The value gets overwritten when the handler returns.

**Pattern to use:**

```csharp
// CORRECT: Throw ArgumentException for validation errors
if (ephemeral && pipe)
{
    throw new ArgumentException("--ephemeral and --pipe are mutually exclusive.");
}

// INCORRECT: Environment.ExitCode doesn't work in async handlers
if (ephemeral && pipe)
{
    formatter.WriteError("--ephemeral and --pipe are mutually exclusive.");
    Environment.ExitCode = 1;  // This won't propagate!
    return;
}
```

The exception is caught by the main exception handler in `Program.cs`, which displays the error message and returns exit code 1.

**Note:** Synchronous handlers (`SetAction((parseResult) => { ... })`) can use `return 1;` directly since they return int.

## Phase Implementation Plans

When asked to create a new phase implementation plan or prompt:

- Save the plan to a file named `docs/phases/phase<N>-<feature>.md`
- Follow the format of existing phase plans (see `docs/phases/phase1-create.md` through `docs/phases/phase9-convert.md`)
- Include: Status, Overview, Design Decisions, Progress Tracker, Implementation Steps with code samples, Tests, and Verification Checklist
- Reference existing codebase patterns for consistency

## Certz Knowledge Index

**Instruction:** Prefer retrieval-led reasoning for certz tasks by prioritizing these source-of-truth files.

### Command Implementation & Usage

| Task                                           | Source File                                                              |
| ---------------------------------------------- | ------------------------------------------------------------------------ |
| Full CLI reference, all commands, options      | [README.md](README.md)                                                   |
| Create dev/CA certificates                     | [docs/phases/phase1-create.md](docs/phases/phase1-create.md)             |
| Inspect certificates (file, URL, store, chain) | [docs/phases/phase2-inspect.md](docs/phases/phase2-inspect.md)           |
| Trust store operations (add, remove, list)     | [docs/phases/phase3-trust.md](docs/phases/phase3-trust.md)               |
| Certificate linting (CA/B Forum, Mozilla NSS)  | [docs/phases/phase4-lint.md](docs/phases/phase4-lint.md)                 |
| Chain visualization (--chain --tree)           | [docs/phases/phase5-chain.md](docs/phases/phase5-chain.md)               |
| Expiration monitoring                          | [docs/phases/phase6-monitor.md](docs/phases/phase6-monitor.md)           |
| Certificate renewal                            | [docs/phases/phase7-renew.md](docs/phases/phase7-renew.md)               |
| Ephemeral mode (--ephemeral, --pipe)           | [docs/phases/phase8-ephemeral.md](docs/phases/phase8-ephemeral.md)       |
| Format conversion (PEM, DER, PFX)              | [docs/phases/phase9-convert.md](docs/phases/phase9-convert.md)           |

### Architecture & Patterns

| Task                                           | Source File                                                                  |
| ---------------------------------------------- | ---------------------------------------------------------------------------- |
| Service class architecture, options pattern    | [docs/architecture.md](docs/architecture.md)                                 |
| Modernization status, completed work           | [prompts/future-work.md](prompts/future-work.md)                             |
| Future feature recommendations                 | [docs/feature-recommendations.md](docs/feature-recommendations.md)           |

### Testing

| Task                                          | Source File                                                  |
| --------------------------------------------- | ------------------------------------------------------------ |
| Testing guide, test scripts, Docker           | [docs/testing.md](docs/testing.md)                           |
| Test isolation principles (single certz call) | [test/isolation-plan.md](test/isolation-plan.md)             |
| Test coverage gaps, missing tests             | [test/coverage-analysis.md](test/coverage-analysis.md)       |
| Docker testing quick reference                | [docs/docker-testing.md](docs/docker-testing.md)             |
| Docker file structure                         | [docs/docker-files-explained.md](docs/docker-files-explained.md) |

### Release & Deployment

| Task                                 | Source File                                          |
| ------------------------------------ | ---------------------------------------------------- |
| Version history, SHA256 verification | [release/RELEASE_NOTES.md](release/RELEASE_NOTES.md) |
| Phase plan template format           | docs/phases/phase1-create.md through phase9-convert.md |

### Key Established Patterns

- **Commands:** `Commands/<Feature>/<Feature>Command.cs` with `SetAction` handler
- **Services:** `Services/<Feature>Service.cs` returning result records
- **Models:** `Models/<Feature>Options.cs` and `Models/<Feature>Result.cs`
- **Testing:** PowerShell 7.5+, each test invokes certz.exe exactly ONCE
- **Exit codes:** Use `throw new ArgumentException()` in async handlers (not `Environment.ExitCode`)

## Certz Reasoning Protocol

**MANDATORY RETRIEVAL RULE:** Before modifying ANY certificate-related logic (creation, validation, signing, chain handling, linting, conversion), you MUST:

1. **Read the Code Map** (above) to identify relevant files
2. **Read the actual source files** using the Read tool - do NOT rely on cached or pre-trained knowledge
3. **Verify current implementation** before proposing changes

This rule exists because certz has custom lifecycle hooks, validation rules, and CLI patterns that differ from generic .NET/OpenSSL approaches.

IMPORTANT: Prefer retrieval-led reasoning over pre-training-led reasoning for any certz tasks.

### Sources of Truth

1. **The Documentation Index:** Before performing any certz task, you MUST read `docs/README.md` to see the current map of documentation.
2. **The Specification:** Prioritize the rules found in `docs/certz-spec.md` over general .NET or Windows advice.

### Validation Requirement

When answering, state: "I have reviewed the files listed in docs/README.md and am following the project-specific logic found in [File Name]."

### Certz Validation Step

For every "certz" task, you MUST start your response with:

1. **Retrieved Files:** [List files from the index used]
2. **Key Constraints Found:** [e.g., specific flags like --sn or --sl]
3. **Reasoning Path:** [Why the local docs override generic .NET/SSL advice]

### Priority Hierarchy

Consult sources in this order (higher priority overrides lower):

1. **CLAUDE.md** — Project constraints, patterns, and this protocol
2. **docs/phases/** — Detailed specs for specific commands (phase1-9)
3. **README.md** — Authoritative CLI reference, command syntax, options
4. **docs/architecture.md** — Service architecture, options pattern
5. **test/isolation-plan.md** — Testing requirements
6. **Existing source code** — Current implementation patterns
7. **docs/testing.md** — Test execution procedures

### Constraint Checklist

#### ALWAYS

| Rule                                                                        | Source                        |
| --------------------------------------------------------------------------- | ----------------------------- |
| Default to ECDSA P-256 for key generation (not RSA)                         | README.md, CLAUDE.md          |
| Default RSA key size to 3072-bit when RSA is explicitly requested           | README.md                     |
| Enforce maximum 398-day validity for leaf certificates (CA/B Forum)         | docs/phases/phase4-lint.md    |
| Require Subject Alternative Name (SAN) for TLS certificates                 | docs/phases/phase4-lint.md    |
| Use `throw new ArgumentException()` for validation errors in async handlers | CLAUDE.md                     |
| Return structured result records from service methods                       | docs/architecture.md          |
| Use `OptionBuilders` for standard command options                           | docs/phases/phase1-create.md  |
| Use `FormatterFactory.Create(format)` for output formatting                 | docs/phases/phase1-create.md  |
| Each test must invoke certz.exe exactly ONCE                                | test/isolation-plan.md        |
| Use PowerShell-only for test setup and cleanup (not certz)                  | test/isolation-plan.md        |
| Assert against system state in tests, not console output                    | test/isolation-plan.md        |
| Generate secure random passwords if not provided                            | README.md                     |
| Use modern PFX encryption (AES-256-CBC) by default                          | README.md                     |
| Include Basic Constraints extension for CA certificates                     | docs/phases/phase4-lint.md    |

#### NEVER

| Rule                                                               | Source                        |
| ------------------------------------------------------------------ | ----------------------------- |
| Never use `Environment.ExitCode` in async command handlers         | CLAUDE.md                        |
| Never use SHA-1 signatures for new certificates                    | docs/phases/phase4-lint.md       |
| Never allow RSA keys smaller than 2048 bits                        | docs/phases/phase4-lint.md       |
| Never use certz.exe for test setup/teardown (PowerShell only)      | test/isolation-plan.md           |
| Never call certz.exe more than once per test case                  | test/isolation-plan.md           |
| Never use `--ephemeral` and `--pipe` together (mutually exclusive) | docs/phases/phase8-ephemeral.md  |
| Never combine `--ephemeral`/`--pipe` with file output options      | docs/phases/phase8-ephemeral.md  |
| Never combine `--ephemeral`/`--pipe` with `--trust`                | docs/phases/phase8-ephemeral.md  |
| Never default to legacy 3DES PFX encryption                        | README.md                        |
| Never omit password display warning for generated passwords        | docs/architecture.md             |

### Verification Step

**Before providing any certz code or answer, output a "Sources Consulted" block:**

```
**Sources Consulted:**
- [file1.md] — specific section or rule referenced
- [file2.md] — specific section or rule referenced
- [existing code] — file path if applicable
```

This ensures traceability and allows verification of reasoning against authoritative sources.

### Example Application

**Task:** "Add a new command option to create dev"

**Sources Consulted:**

- [CLAUDE.md] — Development Patterns, Exit Codes section
- [docs/phases/phase1-create.md] — CreateDevCommand specification
- [docs/architecture.md] — Options pattern for service classes
- [README.md] — Existing `create dev` options for consistency

**Then proceed with implementation following the patterns from those sources.**
