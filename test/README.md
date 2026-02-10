# Test Documentation

## Quick Links

| Document | Description |
|----------|-------------|
| [Testing Guide](../docs/testing.md) | Main testing procedures and Docker support |
| [Isolation Plan](isolation-plan.md) | Single-call test principle |
| [Coverage Analysis](coverage-analysis.md) | Test coverage gaps and priorities |

## Key Principles

1. **Single Call per Test** - Each test invokes `certz.exe` exactly once
2. **PowerShell Setup/Teardown** - Use PowerShell for test fixtures, not certz
3. **Assert System State** - Verify actual results, not console output

## Test Scripts

Test scripts are located in this directory. Run with PowerShell 7.5+:

```powershell
# Run all tests
./test/run-tests.ps1

# Run specific test file
./test/test-create-dev.ps1
```

## Analysis Documents

| Document | Description |
|----------|-------------|
| [isolation-analysis-request.md](isolation-analysis-request.md) | Original analysis request |
| [isolation-analysis-result.md](isolation-analysis-result.md) | Analysis findings and recommendations |
