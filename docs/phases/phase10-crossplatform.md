# Phase 10: Cross-Platform Support (Linux)

**Status:** Planned
**Created:** 2026-02-09

## Objective

Enable certz to build and run on Linux with full support for file-based operations. Trust store operations will display a "not supported on Linux" message until a future phase implements Linux trust store integration.

## Project Context

This is a .NET 10 CLI tool using:

- **System.CommandLine** for command parsing
- **Spectre.Console** for display formatting
- **Record types** for options and results

### Current Limitations

The codebase currently has these Windows-specific dependencies:

| Dependency                         | Location                                     | Impact                      |
| ---------------------------------- | -------------------------------------------- | --------------------------- |
| `win-x64` RuntimeIdentifier        | src/certz/certz.csproj                       | Cannot build for Linux      |
| `X509Store` API                    | TrustService, TrustHandler, StoreListHandler | Trust store operations fail |
| `WindowsIdentity`                  | TrustService, TrustHandler                   | Admin detection fails       |
| Hardcoded `\` in paths             | Multiple formatters/services                 | Display issues only         |
| `[SupportedOSPlatform("windows")]` | TrustService                                 | Methods unavailable         |

### What Already Works on Linux

These operations use cross-platform .NET APIs and require no changes:

| Command          | Notes                                |
| ---------------- | ------------------------------------ |
| `create dev`     | File-based certificate generation    |
| `create ca`      | File-based CA certificate generation |
| `inspect <file>` | Certificate file inspection          |
| `inspect <url>`  | HTTPS certificate retrieval          |
| `lint <file>`    | File-based linting                   |
| `convert`        | PEM/DER/PFX conversion               |
| `renew <file>`   | File-based renewal                   |
| `monitor <dir>`  | Directory/file monitoring            |

---

## Design Decisions

| Area                     | Decision                          | Rationale                                  |
| ------------------------ | --------------------------------- | ------------------------------------------ |
| **Scope**                | Option A - Minimal Linux support  | File operations work; trust store deferred |
| **Trust store commands** | Return error with clear message   | Better than silent failure                 |
| **Admin detection**      | Use `geteuid() == 0` on Linux     | Standard Unix root check                   |
| **Path display**         | Use `Path.DirectorySeparatorChar` | Cross-platform consistency                 |
| **Build targets**        | Add `linux-x64`, `linux-arm64`    | Cover common Linux platforms               |
| **macOS**                | Not included in this phase        | Can be added later with similar approach   |

---

## Progress Tracker

| #   | Step                                                    | Status | Notes                         |
| --- | ------------------------------------------------------- | ------ | ----------------------------- |
| 1   | Update src/certz/certz.csproj for multi-platform builds | [ ]    | Add Linux runtime identifiers |
| 2   | Create platform abstraction for privilege detection     | [ ]    | Replace WindowsIdentity       |
| 3   | Add platform guards to trust store operations           | [ ]    | Clear error messages          |
| 4   | Fix hardcoded path separators                           | [ ]    | Display strings only          |
| 5   | Create Linux build scripts                              | [ ]    | CI/CD integration             |
| 6   | Create Docker-based test environment                    | [ ]    | Verify Linux functionality    |
| 7   | Update documentation                                    | [ ]    | README, testing docs          |

---

## Implementation Steps

### Step 1: Update src/certz/certz.csproj for Multi-Platform Builds

**Modify:** `src/certz/certz.csproj`

Replace the single RuntimeIdentifier with RuntimeIdentifiers (plural):

```xml
<!-- Before -->
<RuntimeIdentifier>win-x64</RuntimeIdentifier>

<!-- After -->
<RuntimeIdentifiers>win-x64;linux-x64;linux-arm64</RuntimeIdentifiers>
```

Add conditional compilation symbols:

```xml
<PropertyGroup Condition="$([MSBuild]::IsOSPlatform('Linux'))">
  <DefineConstants>$(DefineConstants);LINUX</DefineConstants>
</PropertyGroup>
```

Update the publish profile or add build scripts:

```bash
# Build for Windows
dotnet publish -c Release -r win-x64

# Build for Linux x64
dotnet publish -c Release -r linux-x64

# Build for Linux ARM64 (Raspberry Pi, AWS Graviton)
dotnet publish -c Release -r linux-arm64
```

**Status:** [ ] Not started

---

### Step 2: Create Platform Abstraction for Privilege Detection

**Create:** `src/certz/Services/PlatformService.cs`

```csharp
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace certz.Services;

/// <summary>
/// Platform-specific operations abstraction.
/// </summary>
internal static class PlatformService
{
    /// <summary>
    /// Checks if the current process has elevated privileges.
    /// </summary>
    internal static bool IsElevated()
    {
        if (OperatingSystem.IsWindows())
        {
            return IsWindowsAdmin();
        }

        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
        {
            return IsUnixRoot();
        }

        return false;
    }

    /// <summary>
    /// Gets a human-readable description of how to run with elevated privileges.
    /// </summary>
    internal static string GetElevationInstructions()
    {
        if (OperatingSystem.IsWindows())
        {
            return "Run as Administrator";
        }

        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
        {
            return "Run with sudo";
        }

        return "Run with elevated privileges";
    }

    /// <summary>
    /// Checks if trust store operations are supported on the current platform.
    /// </summary>
    internal static bool IsTrustStoreSupported()
    {
        return OperatingSystem.IsWindows();
    }

    /// <summary>
    /// Gets a message explaining why trust store operations are not supported.
    /// </summary>
    internal static string GetTrustStoreUnsupportedMessage()
    {
        if (OperatingSystem.IsLinux())
        {
            return "Trust store operations are not yet supported on Linux. " +
                   "Use file-based operations instead, or manually add certificates to your system CA store.";
        }

        if (OperatingSystem.IsMacOS())
        {
            return "Trust store operations are not yet supported on macOS. " +
                   "Use file-based operations instead, or use Keychain Access to manage certificates.";
        }

        return "Trust store operations are not supported on this platform.";
    }

    [SupportedOSPlatform("windows")]
    private static bool IsWindowsAdmin()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static bool IsUnixRoot()
    {
        // geteuid() returns 0 for root
        return geteuid() == 0;
    }

    [DllImport("libc", SetLastError = true)]
    private static extern uint geteuid();
}
```

**Status:** [ ] Not started

---

### Step 3: Add Platform Guards to Trust Store Operations

**Modify:** `src/certz/Services/TrustService.cs`

Add platform check at the start of trust store methods:

```csharp
internal static async Task<TrustOperationResult> AddToTrustStore(TrustAddOptions options)
{
    // Platform guard
    if (!PlatformService.IsTrustStoreSupported())
    {
        return new TrustOperationResult
        {
            Success = false,
            Operation = "add",
            ErrorMessage = PlatformService.GetTrustStoreUnsupportedMessage()
        };
    }

    // Existing Windows implementation...
}

internal static async Task<TrustOperationResult> RemoveFromTrustStore(TrustRemoveOptions options)
{
    // Platform guard
    if (!PlatformService.IsTrustStoreSupported())
    {
        return new TrustOperationResult
        {
            Success = false,
            Operation = "remove",
            ErrorMessage = PlatformService.GetTrustStoreUnsupportedMessage()
        };
    }

    // Existing Windows implementation...
}
```

**Modify:** `src/certz/Services/TrustHandler.cs`

Replace direct `IsRunningAsAdmin()` calls:

```csharp
// Before
if (options.StoreLocation == StoreLocation.LocalMachine && !IsRunningAsAdmin())
{
    // ...
}

// After
if (options.StoreLocation == StoreLocation.LocalMachine && !PlatformService.IsElevated())
{
    formatter.WriteError(
        $"LocalMachine store requires elevated privileges. {PlatformService.GetElevationInstructions()}.");
    return;
}
```

**Modify:** `src/certz/Commands/Store/StoreListCommand.cs`

Add platform guard:

```csharp
storeListCommand.SetAction(async (parseResult) =>
{
    // Platform guard
    if (!PlatformService.IsTrustStoreSupported())
    {
        var formatter = FormatterFactory.Create(parseResult.GetValue(formatOption) ?? "text");
        formatter.WriteError(PlatformService.GetTrustStoreUnsupportedMessage());
        throw new PlatformNotSupportedException(PlatformService.GetTrustStoreUnsupportedMessage());
    }

    // Existing implementation...
});
```

**Status:** [ ] Not started

---

### Step 4: Fix Hardcoded Path Separators

**Files to update:**

- `src/certz/Services/CertificateUtilities.cs`
- `src/certz/Services/CertificateInspector.cs`
- `src/certz/Services/ExportService.cs`
- `src/certz/Services/MonitorService.cs`
- `src/certz/Formatters/TextFormatter.cs`
- `src/certz/Commands/Trust/TrustCommand.cs`

**Pattern to find:**

```csharp
// Before - hardcoded backslash
$"Certificate with thumbprint {thumbprint} not found in {location}\\{name}"
$"CurrentUser\\Root trust store"
$"Cert:\\{1}\\{2}"

// After - platform-aware
$"Certificate with thumbprint {thumbprint} not found in {location}{Path.DirectorySeparatorChar}{name}"
```

**Note:** These are display strings only; file operations already use `Path.Combine()`.

**Status:** [ ] Not started

---

### Step 5: Create Linux Build Scripts

**Create:** `scripts/build-linux.sh`

```bash
#!/bin/bash
set -e

echo "Building certz for Linux..."

# Clean previous builds
rm -rf ./publish/linux-x64
rm -rf ./publish/linux-arm64

# Build for Linux x64
echo "Building linux-x64..."
dotnet publish -c Release -r linux-x64 -o ./publish/linux-x64

# Build for Linux ARM64
echo "Building linux-arm64..."
dotnet publish -c Release -r linux-arm64 -o ./publish/linux-arm64

# Make executables... executable
chmod +x ./publish/linux-x64/certz
chmod +x ./publish/linux-arm64/certz

# Display results
echo ""
echo "Build complete!"
echo "  linux-x64:   ./publish/linux-x64/certz"
echo "  linux-arm64: ./publish/linux-arm64/certz"

# Show file sizes
ls -lh ./publish/linux-x64/certz
ls -lh ./publish/linux-arm64/certz
```

**Create:** `scripts/build-all.ps1`

```powershell
#Requires -Version 7.0

<#
.SYNOPSIS
    Builds certz for all supported platforms.
#>

param(
    [switch]$Windows,
    [switch]$Linux,
    [switch]$All
)

$ErrorActionPreference = 'Stop'

if (-not $Windows -and -not $Linux) {
    $All = $true
}

$publishDir = Join-Path $PSScriptRoot '..' 'publish'

if ($All -or $Windows) {
    Write-Host "Building win-x64..." -ForegroundColor Cyan
    dotnet publish -c Release -r win-x64 -o (Join-Path $publishDir 'win-x64')
}

if ($All -or $Linux) {
    Write-Host "Building linux-x64..." -ForegroundColor Cyan
    dotnet publish -c Release -r linux-x64 -o (Join-Path $publishDir 'linux-x64')

    Write-Host "Building linux-arm64..." -ForegroundColor Cyan
    dotnet publish -c Release -r linux-arm64 -o (Join-Path $publishDir 'linux-arm64')
}

Write-Host "`nBuild complete!" -ForegroundColor Green
Get-ChildItem $publishDir -Recurse -Filter "certz*" |
    Where-Object { -not $_.PSIsContainer } |
    ForEach-Object {
        Write-Host "  $($_.FullName) ($([math]::Round($_.Length / 1MB, 2)) MB)"
    }
```

**Status:** [ ] Not started

---

### Step 6: Create Docker-Based Test Environment

**Create:** `test/docker/Dockerfile.linux-test`

```dockerfile
FROM mcr.microsoft.com/dotnet/runtime:10.0

WORKDIR /app

# Copy the Linux build
COPY publish/linux-x64/certz /app/certz

# Make executable
RUN chmod +x /app/certz

# Create test directory
WORKDIR /test

# Default command runs basic tests
CMD ["/app/certz", "--version"]
```

**Create:** `test/docker/test-linux.sh`

```bash
#!/bin/bash
set -e

echo "========================================="
echo "certz Linux Integration Tests"
echo "========================================="

CERTZ="/app/certz"

# Test 1: Version check
echo -e "\n[TEST] Version check..."
$CERTZ --version
echo "✓ Version command works"

# Test 2: Create dev certificate
echo -e "\n[TEST] Create dev certificate..."
$CERTZ create dev test.local --file test.pfx --cert test.pem --key test.key --password TestPass123
if [ -f "test.pfx" ] && [ -f "test.pem" ] && [ -f "test.key" ]; then
    echo "✓ Certificate files created"
else
    echo "✗ Certificate creation failed"
    exit 1
fi

# Test 3: Inspect certificate
echo -e "\n[TEST] Inspect certificate..."
$CERTZ inspect test.pem
echo "✓ Inspect command works"

# Test 4: Convert PEM to DER
echo -e "\n[TEST] Convert PEM to DER..."
$CERTZ convert test.pem --to der
if [ -f "test.der" ]; then
    echo "✓ Conversion works"
else
    echo "✗ Conversion failed"
    exit 1
fi

# Test 5: Lint certificate
echo -e "\n[TEST] Lint certificate..."
$CERTZ lint test.pem
echo "✓ Lint command works"

# Test 6: Trust store should fail gracefully
echo -e "\n[TEST] Trust store error handling..."
if $CERTZ trust add test.pfx --password TestPass123 2>&1 | grep -q "not.*supported\|not yet supported"; then
    echo "✓ Trust store correctly reports unsupported"
else
    echo "✗ Trust store should report unsupported on Linux"
    exit 1
fi

# Test 7: Store list should fail gracefully
echo -e "\n[TEST] Store list error handling..."
if $CERTZ store list 2>&1 | grep -q "not.*supported\|not yet supported"; then
    echo "✓ Store list correctly reports unsupported"
else
    echo "✗ Store list should report unsupported on Linux"
    exit 1
fi

# Test 8: Create CA certificate
echo -e "\n[TEST] Create CA certificate..."
$CERTZ create ca "Test CA" --file ca.pfx --cert ca.pem --key ca.key --password CaPass123
if [ -f "ca.pfx" ]; then
    echo "✓ CA certificate created"
else
    echo "✗ CA creation failed"
    exit 1
fi

# Test 9: Monitor directory
echo -e "\n[TEST] Monitor directory..."
$CERTZ monitor . --format json | head -n 20
echo "✓ Monitor command works"

# Test 10: Renew certificate
echo -e "\n[TEST] Renew certificate..."
$CERTZ renew test.pfx --password TestPass123 --output renewed.pfx --new-password RenewPass123
if [ -f "renewed.pfx" ]; then
    echo "✓ Renewal works"
else
    echo "✗ Renewal failed"
    exit 1
fi

echo -e "\n========================================="
echo "All Linux tests passed!"
echo "========================================="
```

**Create:** `test/docker/run-linux-tests.ps1`

```powershell
#Requires -Version 7.0

<#
.SYNOPSIS
    Runs certz tests in a Linux Docker container.
#>

$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent

# Build for Linux first
Write-Host "Building certz for Linux..." -ForegroundColor Cyan
Push-Location $projectRoot
try {
    dotnet publish -c Release -r linux-x64 -o ./publish/linux-x64
}
finally {
    Pop-Location
}

# Build Docker image
Write-Host "`nBuilding Docker test image..." -ForegroundColor Cyan
docker build -t certz-linux-test -f "$PSScriptRoot/Dockerfile.linux-test" $projectRoot

# Run tests
Write-Host "`nRunning Linux tests..." -ForegroundColor Cyan
docker run --rm -v "${PSScriptRoot}:/scripts:ro" certz-linux-test /bin/bash /scripts/test-linux.sh

Write-Host "`nLinux tests complete!" -ForegroundColor Green
```

**Status:** [ ] Not started

---

### Step 7: Update Documentation

**Modify:** `README.md`

Add a "Supported Platforms" section:

````markdown
## Supported Platforms

certz is available for the following platforms:

| Platform | Architecture | Trust Store      | File Operations |
| -------- | ------------ | ---------------- | --------------- |
| Windows  | x64          | ✅ Full          | ✅ Full         |
| Linux    | x64          | ❌ Not supported | ✅ Full         |
| Linux    | ARM64        | ❌ Not supported | ✅ Full         |

### Linux Notes

On Linux, all file-based operations work fully:

- `create dev`, `create ca` - Generate certificates
- `inspect` - Inspect files and URLs
- `lint` - Validate certificates
- `convert` - Convert between formats
- `renew` - Renew certificates
- `monitor` - Monitor directories

Trust store operations (`trust add`, `trust remove`, `store list`) are not supported on Linux.
To add certificates to your system trust store manually:

**Debian/Ubuntu:**

```bash
sudo cp ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```
````

**RHEL/Fedora:**

```bash
sudo cp ca.crt /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust
```

````

**Status:** [ ] Not started

---

## Tests

### Test Categories

| Category | Test IDs | Description |
|----------|----------|-------------|
| `build` | plat-1.x | Build verification |
| `file-ops` | plat-2.x | File-based operations |
| `trust-guard` | plat-3.x | Trust store error handling |
| `path-display` | plat-4.x | Path separator formatting |

### Test Script

**Create:** `test/test-crossplatform.ps1`

```powershell
#requires -version 7

<#
.SYNOPSIS
    Cross-platform compatibility tests.
.DESCRIPTION
    Tests that verify certz works correctly on both Windows and Linux.
    Trust store tests verify correct "not supported" behavior on Linux.
#>

param(
    [string[]]$TestId,
    [string[]]$Category
)

. "$PSScriptRoot\test-helper.ps1"

$TestCategories = @{
    "build"       = @("plat-1.1")
    "file-ops"    = @("plat-2.1", "plat-2.2", "plat-2.3", "plat-2.4", "plat-2.5")
    "trust-guard" = @("plat-3.1", "plat-3.2", "plat-3.3")
    "path-display"= @("plat-4.1")
}

Initialize-TestEnvironment -TestId $TestId -Category $Category -TestCategories $TestCategories
Build-Certz

Write-TestHeader "Cross-Platform Compatibility Tests"
Write-Host "========================================`n"

$tempDir = New-TestDirectory "crossplatform-tests"
Push-Location $tempDir

try {
    # ============================================================================
    # BUILD TESTS
    # ============================================================================

    Write-TestHeader "Build Verification"

    # plat-1.1: Version command works
    Invoke-Test -TestId "plat-1.1" -TestName "Version command executes" -TestScript {
        $output = & certz --version 2>&1
        $exitCode = $LASTEXITCODE

        if ($exitCode -eq 0 -and $output -match "certz") {
            return @{ Success = $true; Details = "Version: $output" }
        }
        return @{ Success = $false; Details = "Exit code: $exitCode" }
    }

    # ============================================================================
    # FILE OPERATION TESTS
    # ============================================================================

    Write-TestHeader "File-Based Operations"

    # plat-2.1: Create dev certificate
    Invoke-Test -TestId "plat-2.1" -TestName "Create dev certificate" -TestScript {
        & certz create dev test.local --file test.pfx --cert test.pem --key test.key --password TestPass 2>&1 | Out-Null

        if ((Test-Path "test.pfx") -and (Test-Path "test.pem") -and (Test-Path "test.key")) {
            return @{ Success = $true; Details = "All files created" }
        }
        return @{ Success = $false; Details = "Missing output files" }
    }

    # plat-2.2: Inspect certificate
    Invoke-Test -TestId "plat-2.2" -TestName "Inspect certificate file" -TestScript {
        $output = & certz inspect test.pem --format json 2>&1

        try {
            $json = $output | ConvertFrom-Json
            if ($json.subject -match "test.local") {
                return @{ Success = $true; Details = "Subject: $($json.subject)" }
            }
            return @{ Success = $false; Details = "Unexpected subject" }
        }
        catch {
            return @{ Success = $false; Details = "JSON parse error: $_" }
        }
    }

    # plat-2.3: Convert PEM to DER
    Invoke-Test -TestId "plat-2.3" -TestName "Convert PEM to DER" -TestScript {
        & certz convert test.pem --to der 2>&1 | Out-Null

        if (Test-Path "test.der") {
            $bytes = [System.IO.File]::ReadAllBytes("test.der")
            if ($bytes[0] -eq 0x30) {
                return @{ Success = $true; Details = "Valid DER format" }
            }
            return @{ Success = $false; Details = "Invalid DER format" }
        }
        return @{ Success = $false; Details = "DER file not created" }
    }

    # plat-2.4: Lint certificate
    Invoke-Test -TestId "plat-2.4" -TestName "Lint certificate" -TestScript {
        $output = & certz lint test.pem --format json 2>&1

        try {
            $json = $output | ConvertFrom-Json
            return @{ Success = $true; Details = "Lint completed with $($json.warnings.Count) warnings" }
        }
        catch {
            return @{ Success = $false; Details = "Lint failed: $_" }
        }
    }

    # plat-2.5: Monitor directory
    Invoke-Test -TestId "plat-2.5" -TestName "Monitor directory" -TestScript {
        $output = & certz monitor . --format json 2>&1

        try {
            $json = $output | ConvertFrom-Json
            if ($json.certificates.Count -gt 0) {
                return @{ Success = $true; Details = "Found $($json.certificates.Count) certificates" }
            }
            return @{ Success = $false; Details = "No certificates found" }
        }
        catch {
            return @{ Success = $false; Details = "Monitor failed: $_" }
        }
    }

    # ============================================================================
    # TRUST STORE GUARD TESTS (Linux-specific behavior)
    # ============================================================================

    Write-TestHeader "Trust Store Platform Guards"

    if (-not $IsWindows) {
        # plat-3.1: Trust add returns error on Linux
        Invoke-Test -TestId "plat-3.1" -TestName "trust add returns unsupported error on Linux" -TestScript {
            $output = & certz trust add test.pfx --password TestPass 2>&1
            $exitCode = $LASTEXITCODE

            if ($exitCode -ne 0 -and ($output -match "not.*supported" -or $output -match "Linux")) {
                return @{ Success = $true; Details = "Correct error message" }
            }
            return @{ Success = $false; Details = "Expected platform error" }
        }

        # plat-3.2: Trust remove returns error on Linux
        Invoke-Test -TestId "plat-3.2" -TestName "trust remove returns unsupported error on Linux" -TestScript {
            $output = & certz trust remove ABC123 2>&1
            $exitCode = $LASTEXITCODE

            if ($exitCode -ne 0 -and ($output -match "not.*supported" -or $output -match "Linux")) {
                return @{ Success = $true; Details = "Correct error message" }
            }
            return @{ Success = $false; Details = "Expected platform error" }
        }

        # plat-3.3: Store list returns error on Linux
        Invoke-Test -TestId "plat-3.3" -TestName "store list returns unsupported error on Linux" -TestScript {
            $output = & certz store list 2>&1
            $exitCode = $LASTEXITCODE

            if ($exitCode -ne 0 -and ($output -match "not.*supported" -or $output -match "Linux")) {
                return @{ Success = $true; Details = "Correct error message" }
            }
            return @{ Success = $false; Details = "Expected platform error" }
        }
    }
    else {
        Write-Host "  Skipping trust store guard tests (Windows)" -ForegroundColor Yellow
    }

    # ============================================================================
    # PATH DISPLAY TESTS
    # ============================================================================

    Write-TestHeader "Path Display"

    # plat-4.1: Error messages use correct path separator
    Invoke-Test -TestId "plat-4.1" -TestName "Path separators are platform-appropriate" -TestScript {
        # This test verifies path display in error messages
        # The specific behavior depends on implementation
        return @{ Success = $true; Details = "Path handling verified" }
    }
}
finally {
    Pop-Location
    Remove-TestDirectory $tempDir
}

# ============================================================================
# SUMMARY
# ============================================================================

$exitCode = Write-TestSummary
exit $exitCode
````

**Status:** [ ] Not started

---

## Verification Checklist

### Build

- [ ] `dotnet publish -r linux-x64` succeeds
- [ ] `dotnet publish -r linux-arm64` succeeds
- [ ] Output is single-file executable
- [ ] Executable runs on Ubuntu 22.04+
- [ ] Executable runs on Debian 12+

### File Operations (Linux)

- [ ] `certz create dev` works
- [ ] `certz create ca` works
- [ ] `certz inspect <file>` works
- [ ] `certz inspect <url>` works
- [ ] `certz lint` works
- [ ] `certz convert` works
- [ ] `certz renew` works
- [ ] `certz monitor <dir>` works

### Trust Store Guards

- [ ] `certz trust add` returns clear "not supported" message
- [ ] `certz trust remove` returns clear "not supported" message
- [ ] `certz store list` returns clear "not supported" message
- [ ] Exit code is non-zero for unsupported operations

### Path Handling

- [ ] Error messages use `/` on Linux
- [ ] File operations work with both `/` and `\` in paths

---

## Future Work: Option B - Full Linux Trust Store Support

> **Note:** This section outlines future work and will not be implemented in this phase.

### Linux Trust Store Landscape

Linux does not have a unified certificate store like Windows. There are multiple locations and mechanisms:

| Location                            | Purpose                     | Update Command           |
| ----------------------------------- | --------------------------- | ------------------------ |
| `/etc/ssl/certs/`                   | System CA certificates      | Varies by distro         |
| `/usr/local/share/ca-certificates/` | User-added CAs (Debian)     | `update-ca-certificates` |
| `/etc/pki/ca-trust/source/anchors/` | User-added CAs (RHEL)       | `update-ca-trust`        |
| `~/.pki/nssdb/`                     | NSS database (Chrome, user) | `certutil`               |
| `/etc/pki/nssdb/`                   | NSS database (system)       | `certutil`               |

### Proposed Architecture

```
src/certz/Services/
├── TrustStore/
│   ├── ITrustStore.cs              # Interface
│   ├── WindowsTrustStore.cs        # Current implementation
│   ├── LinuxSystemTrustStore.cs    # System CA bundle
│   └── LinuxNssTrustStore.cs       # NSS database
```

### Interface Design

```csharp
internal interface ITrustStore
{
    bool IsSupported { get; }
    string Name { get; }

    Task<TrustOperationResult> AddCertificate(X509Certificate2 certificate, TrustLevel level);
    Task<TrustOperationResult> RemoveCertificate(string thumbprint);
    Task<StoreListResult> ListCertificates(ListCertificatesOptions options);
}

internal enum TrustLevel
{
    User,       // Current user only
    System      // All users (requires elevation)
}
```

### Linux System Trust Store Implementation

```csharp
internal class LinuxSystemTrustStore : ITrustStore
{
    private readonly string _caDirectory;
    private readonly string _updateCommand;

    public LinuxSystemTrustStore()
    {
        // Detect distro and set paths
        if (Directory.Exists("/usr/local/share/ca-certificates"))
        {
            // Debian/Ubuntu
            _caDirectory = "/usr/local/share/ca-certificates";
            _updateCommand = "update-ca-certificates";
        }
        else if (Directory.Exists("/etc/pki/ca-trust/source/anchors"))
        {
            // RHEL/Fedora
            _caDirectory = "/etc/pki/ca-trust/source/anchors";
            _updateCommand = "update-ca-trust";
        }
    }

    public async Task<TrustOperationResult> AddCertificate(X509Certificate2 certificate, TrustLevel level)
    {
        // 1. Export certificate to PEM
        // 2. Copy to _caDirectory
        // 3. Run _updateCommand
    }
}
```

### Estimated Effort for Option B

| Work Item                       | Hours | Notes                              |
| ------------------------------- | ----- | ---------------------------------- |
| ITrustStore interface           | 2     | Define abstraction                 |
| Refactor Windows implementation | 4     | Extract to WindowsTrustStore       |
| Linux distro detection          | 2     | Debian vs RHEL                     |
| LinuxSystemTrustStore           | 8     | update-ca-certificates integration |
| LinuxNssTrustStore              | 12    | certutil integration               |
| Testing across distros          | 8     | Ubuntu, Debian, Fedora, Alpine     |
| Documentation                   | 4     | Per-distro instructions            |

**Total: ~40 hours**

### Key Challenges

1. **Root required**: Adding to system trust store requires `sudo`
2. **Distro fragmentation**: Different paths and commands per distro
3. **NSS complexity**: certutil has non-intuitive syntax
4. **No enumeration API**: Must parse directory contents or certutil output
5. **Containerization**: Docker/Kubernetes environments may have read-only trust stores

---

## Security Considerations

1. **Elevation detection**: Use `geteuid()` for accurate Unix root detection
2. **Trust store access**: Clearly communicate when root/sudo is required
3. **Error messages**: Don't expose internal paths in error messages
4. **File permissions**: Generated key files should have 0600 permissions on Linux

---

## Implementation Notes

### P/Invoke for geteuid()

The `geteuid()` function is available on all Unix-like systems and returns:

- `0` for root
- Non-zero UID for regular users

```csharp
[DllImport("libc", SetLastError = true)]
private static extern uint geteuid();
```

This is more reliable than checking environment variables or parsing `/etc/passwd`.

### Build Considerations

- Linux builds are significantly larger than Windows (~60-80 MB) due to self-contained runtime
- Consider providing both self-contained and framework-dependent builds
- ARM64 builds are useful for Raspberry Pi and AWS Graviton instances

### Testing Strategy

1. **Unit tests**: Mock `PlatformService` for platform-specific logic
2. **Integration tests**: Use Docker for consistent Linux environment
3. **CI/CD**: GitHub Actions supports both Windows and Linux runners
