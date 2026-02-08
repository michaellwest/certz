# Prompt: Create test-convert.ps1

Create a new test file `test-convert.ps1` for the `convert` command following the established patterns in this project.

## Context

The `convert` command converts between PFX and PEM certificate formats:
- **PEM to PFX:** `certz convert --cert <file> --key <file> --pfx <output>`
- **PFX to PEM:** `certz convert --pfx <file> --out-cert <output> --out-key <output>`

Options: `--password`, `--password-file`, `--pfx-encryption (modern|legacy)`, `--format (text|json)`

## Requirements

1. **Follow test isolation principles** from `test-isolation-plan.md`:
   - Each test invokes `certz.exe` exactly ONCE
   - Setup and teardown use pure PowerShell (no certz calls)
   - Assert against system state (files), NOT console output

2. **Use the same structure** as `test-create.ps1`, `test-inspect.ps1`, and `test-trust.ps1`:
   - Same helper functions (Test-ShouldRun, Write-TestHeader, Write-TestResult, etc.)
   - Same assertion functions (Assert-FileExists, Assert-ExitCode, Assert-Match)
   - Same Invoke-Test pattern with try/finally cleanup

3. **Test categories and IDs:**
   ```powershell
   $script:TestCategories = @{
       "pem-to-pfx" = @("cnv-1.1", "cnv-1.2", "cnv-1.3")
       "pfx-to-pem" = @("cnv-2.1", "cnv-2.2", "cnv-2.3")
       "encryption" = @("cnv-3.1", "cnv-3.2")
       "format" = @("fmt-1.1")
   }
   ```

4. **Required tests:**

   | Test ID | Description |
   |---------|-------------|
   | cnv-1.1 | Convert PEM cert+key to PFX |
   | cnv-1.2 | Convert with explicit password |
   | cnv-1.3 | Convert with password file |
   | cnv-2.1 | Convert PFX to PEM (cert only) |
   | cnv-2.2 | Convert PFX to PEM (cert+key) |
   | cnv-2.3 | PFX to PEM without password fails |
   | cnv-3.1 | PFX encryption modern |
   | cnv-3.2 | PFX encryption legacy |
   | fmt-1.1 | JSON output format |

5. **Setup pattern** - Create test certificates using PowerShell:
   ```powershell
   $cert = New-SelfSignedCertificate -Subject "CN=certz-convert-test-$guid" ...
   # Export to PEM format for testing
   ```

6. **Build and run from project root**, change to `docker\tools` for execution

## Reference Files

- `test-create.ps1` - Template for structure and helpers
- `test-inspect.ps1` - Template for file-based tests
- `Commands/ConvertCommand.cs` - Command implementation
- `Services/ConvertService.cs` - Service implementation
- `test-coverage-analysis.md` - Full gap analysis

## Success Criteria

- All 9 tests pass when run with `.\test-convert.ps1`
- Tests can be filtered by category: `.\test-convert.ps1 -Category pem-to-pfx`
- Tests can be filtered by ID: `.\test-convert.ps1 -TestId cnv-1.1`
- JSON output tests validate proper JSON structure
- Build succeeds before tests run
