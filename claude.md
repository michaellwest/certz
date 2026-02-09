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
- Follow the format of existing phase plans (see `phase1-implementation-plan.md` through `phase6-implementation-plan.md`)
- Include: Status, Overview, Design Decisions, Progress Tracker, Implementation Steps with code samples, Tests, and Verification Checklist
- Reference existing codebase patterns for consistency
