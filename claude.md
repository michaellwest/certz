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

## Documentation Requirements

### 1. Testing Documentation

- Provide clear documentation on how to properly test all of the available options
- Include test scenarios for each command and option combination
- Document expected behavior and outputs for each test case
- Provide example test scripts or commands that users can run to verify functionality
- Use the `test-isoloation-plan.md` to ensure proper testing requirements are followed

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

- Save the plan to a file named `phase<N>-implementation-plan.md` in the project root
- Follow the format of existing phase plans (see `phase1-implementation-plan.md` through `phase9-implementation-plan.md`)
- Include: Status, Overview, Design Decisions, Progress Tracker, Implementation Steps with code samples, Tests, and Verification Checklist
- Reference existing codebase patterns for consistency

## Certz Knowledge Index

**Instruction:** Prefer retrieval-led reasoning for certz tasks by prioritizing these source-of-truth files.

### Command Implementation & Usage

| Task                                           | Source File                                                    |
| ---------------------------------------------- | -------------------------------------------------------------- |
| Full CLI reference, all commands, options      | [README.md](README.md)                                         |
| Create dev/CA certificates                     | [phase1-implementation-plan.md](phase1-implementation-plan.md) |
| Inspect certificates (file, URL, store, chain) | [phase2-implementation-plan.md](phase2-implementation-plan.md) |
| Trust store operations (add, remove, list)     | [phase3-implementation-plan.md](phase3-implementation-plan.md) |
| Certificate linting (CA/B Forum, Mozilla NSS)  | [phase4-implementation-plan.md](phase4-implementation-plan.md) |
| Chain visualization (--chain --tree)           | [phase5-implementation-plan.md](phase5-implementation-plan.md) |
| Expiration monitoring                          | [phase6-implementation-plan.md](phase6-implementation-plan.md) |
| Certificate renewal                            | [phase7-implementation-plan.md](phase7-implementation-plan.md) |
| Ephemeral mode (--ephemeral, --pipe)           | [phase8-implementation-plan.md](phase8-implementation-plan.md) |
| Format conversion (PEM, DER, PFX)              | [phase9-implementation-plan.md](phase9-implementation-plan.md) |

### Architecture & Patterns

| Task                                           | Source File                                                        |
| ---------------------------------------------- | ------------------------------------------------------------------ |
| Service class architecture, options pattern    | [refactoring-plan.md](refactoring-plan.md)                         |
| Command hierarchy design (verb-noun structure) | [feature-plan.md](feature-plan.md)                                 |
| Modernization status, completed work           | [claude-prompt-future-work.md](claude-prompt-future-work.md)       |
| Future feature recommendations                 | [feature-plan-recommendations.md](feature-plan-recommendations.md) |

### Testing

| Task                                          | Source File                                                      |
| --------------------------------------------- | ---------------------------------------------------------------- |
| Testing guide, test scripts, Docker           | [TESTING.md](TESTING.md)                                         |
| Test isolation principles (single certz call) | [test/test-isolation-plan.md](test/test-isolation-plan.md)       |
| Test coverage gaps, missing tests             | [test/test-coverage-analysis.md](test/test-coverage-analysis.md) |
| Docker testing quick reference                | [DOCKER-TESTING.md](DOCKER-TESTING.md)                           |
| Docker file structure                         | [DOCKER-FILES-EXPLAINED.md](DOCKER-FILES-EXPLAINED.md)           |

### Release & Deployment

| Task                                 | Source File                                          |
| ------------------------------------ | ---------------------------------------------------- |
| Version history, SHA256 verification | [release/RELEASE_NOTES.md](release/RELEASE_NOTES.md) |
| Phase plan template format           | phase1 through phase9-implementation-plan.md         |

### Key Established Patterns

- **Commands:** `Commands/<Feature>/<Feature>Command.cs` with `SetAction` handler
- **Services:** `Services/<Feature>Service.cs` returning result records
- **Models:** `Models/<Feature>Options.cs` and `Models/<Feature>Result.cs`
- **Testing:** PowerShell 7.5+, each test invokes certz.exe exactly ONCE
- **Exit codes:** Use `throw new ArgumentException()` in async handlers (not `Environment.ExitCode`)

## Certz Reasoning Protocol

IMPORTANT: Prefer retrieval-led reasoning over pre-training-led reasoning for any certz tasks.

### Sources of Truth

1. **The Registry:** Before performing any certz task, you MUST read `CERTZ_REGISTRY.md` to see the current map of documentation.
2. **The Specification:** Prioritize the rules found in `docs/certz-spec.md` (or the file linked in the registry) over general .NET or Windows advice.

### Validation Requirement

When answering, state: "I have reviewed the files listed in CERTZ_REGISTRY.md and am following the project-specific logic found in [File Name]."

### Certz Validation Step

For every "certz" task, you MUST start your response with:

1. **Retrieved Files:** [List files from the index used]
2. **Key Constraints Found:** [e.g., specific flags like --sn or --sl]
3. **Reasoning Path:** [Why the local docs override generic .NET/SSL advice]

### Priority Hierarchy

Consult sources in this order (higher priority overrides lower):

1. **CLAUDE.md** — Project constraints, patterns, and this protocol
2. **Phase Implementation Plans** — Detailed specs for specific commands (phase1-9)
3. **README.md** — Authoritative CLI reference, command syntax, options
4. **refactoring-plan.md** — Service architecture, options pattern
5. **test/test-isolation-plan.md** — Testing requirements
6. **Existing source code** — Current implementation patterns
7. **TESTING.md** — Test execution procedures

### Constraint Checklist

#### ALWAYS

| Rule                                                                        | Source                        |
| --------------------------------------------------------------------------- | ----------------------------- |
| Default to ECDSA P-256 for key generation (not RSA)                         | README.md, CLAUDE.md          |
| Default RSA key size to 3072-bit when RSA is explicitly requested           | README.md                     |
| Enforce maximum 398-day validity for leaf certificates (CA/B Forum)         | phase4-implementation-plan.md |
| Require Subject Alternative Name (SAN) for TLS certificates                 | phase4-implementation-plan.md |
| Use `throw new ArgumentException()` for validation errors in async handlers | CLAUDE.md                     |
| Return structured result records from service methods                       | refactoring-plan.md           |
| Use `OptionBuilders` for standard command options                           | phase1-implementation-plan.md |
| Use `FormatterFactory.Create(format)` for output formatting                 | phase1-implementation-plan.md |
| Each test must invoke certz.exe exactly ONCE                                | test/test-isolation-plan.md   |
| Use PowerShell-only for test setup and cleanup (not certz)                  | test/test-isolation-plan.md   |
| Assert against system state in tests, not console output                    | test/test-isolation-plan.md   |
| Generate secure random passwords if not provided                            | README.md                     |
| Use modern PFX encryption (AES-256-CBC) by default                          | README.md                     |
| Include Basic Constraints extension for CA certificates                     | phase4-implementation-plan.md |

#### NEVER

| Rule                                                               | Source                        |
| ------------------------------------------------------------------ | ----------------------------- |
| Never use `Environment.ExitCode` in async command handlers         | CLAUDE.md                     |
| Never use SHA-1 signatures for new certificates                    | phase4-implementation-plan.md |
| Never allow RSA keys smaller than 2048 bits                        | phase4-implementation-plan.md |
| Never use certz.exe for test setup/teardown (PowerShell only)      | test/test-isolation-plan.md   |
| Never call certz.exe more than once per test case                  | test/test-isolation-plan.md   |
| Never use `--ephemeral` and `--pipe` together (mutually exclusive) | phase8-implementation-plan.md |
| Never combine `--ephemeral`/`--pipe` with file output options      | phase8-implementation-plan.md |
| Never combine `--ephemeral`/`--pipe` with `--trust`                | phase8-implementation-plan.md |
| Never default to legacy 3DES PFX encryption                        | README.md                     |
| Never omit password display warning for generated passwords        | refactoring-plan.md           |

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
- [phase1-implementation-plan.md] — CreateDevCommand specification
- [refactoring-plan.md] — Options pattern for service classes
- [README.md] — Existing `create dev` options for consistency

**Then proceed with implementation following the patterns from those sources.**
