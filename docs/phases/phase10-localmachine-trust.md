# Phase 10: Shift Trust Store Default to LocalMachine\Root

**Status:** Complete
**Last Updated:** 2026-02-10

## Overview

Shift the default trust store location for `--trust` and `trust add --store root` from `CurrentUser\Root` to `LocalMachine\Root` when running as Administrator. This eliminates the Windows Security UI confirmation dialog that hangs in non-interactive environments (Docker, CI/CD, headless servers).

## Problem Statement

On Windows, the .NET `X509Store.Add()` API triggers an **interactive Windows Security UI confirmation dialog** when adding certificates to `CurrentUser\Root`. This dialog:

1. **Cannot be suppressed programmatically** — no API flag, registry key, or group policy reliably disables it
2. **Hangs indefinitely** in non-interactive environments (Docker containers, CI/CD pipelines, remote sessions)
3. **Requires a mouse click** — even on interactive desktops, tests pause until the user clicks "Yes"

### Affected certz Commands

| Command | Code Path |
|---------|-----------|
| `certz create dev <domain> --trust` | `CreateService.cs` → `CertificateUtilities.InstallCertificate()` |
| `certz create ca --name <name> --trust` | `CreateService.cs` → `CertificateUtilities.InstallCertificate()` |
| `certz trust add <file> --store root` | `TrustCommand.cs` → `TrustHandler.AddToStore()` |
| `certz install --file <file> --sn root --sl CurrentUser` | `CertificateUtilities.InstallCertificate()` |

### Affected Tests

| Test ID | Test Script | Why It Hangs |
|---------|------------|--------------|
| tru-1.1 | test-create.ps1 | `certz create dev ... --trust` adds to `CurrentUser\Root` |
| tru-1.2 | test-create.ps1 | `certz create ca ... --trust` adds to `CurrentUser\Root` |
| tru-1.1 | test-trust.ps1 | `certz trust add ... --store root` adds to `CurrentUser\Root` |
| tru-1.2 | test-trust.ps1 | `certz trust add ... --store root` (PFX) adds to `CurrentUser\Root` |
| trm-1.1 through trm-2.4 | test-trust.ps1 | Setup imports certs to `CurrentUser\Root` |
| sto-1.2 | test-trust.ps1 | Setup imports cert to `CurrentUser\Root` |

### Why the Test Helper Works But certz.exe Doesn't

The test helper `Import-CertificateToStoreNoUI` (in `test-helper.ps1`) successfully bypasses the dialog by using `certutil.exe -user -addstore`, which has special Windows privileges. However, certz.exe uses .NET's `X509Store.Add()` internally, which always triggers the dialog for `CurrentUser\Root`.

## Design Decisions

| Area | Decision | Rationale |
|------|----------|-----------|
| **Default location** | Auto-detect: `LocalMachine` when admin, `CurrentUser` when not | Admin users get no-dialog behavior; non-admin users get clear error for Root store |
| **Scope** | `--trust` flag and `trust add` command | Both code paths that add to Root store |
| **Backwards compat** | `--trust-location` option preserved | Users can explicitly override the auto-detected default |
| **Test strategy** | All tests use `LocalMachine\Root` + admin guard | Docker already runs as `ContainerAdministrator` |
| **Cleanup** | Standard `X509Store.Remove()` for `LocalMachine` | No registry hacks needed (unlike `CurrentUser\Root`) |

### Comparison: CurrentUser\Root vs LocalMachine\Root

| Aspect | `CurrentUser\Root` | `LocalMachine\Root` |
|--------|-------------------|---------------------|
| **UI Dialog** | Always triggered by `X509Store.Add()` | No UI dialog |
| **Admin Required** | No | Yes |
| **Docker** | Dialog hangs (no interactive session) | Works — container runs as `ContainerAdministrator` |
| **CI/CD** | Hangs indefinitely | Works if agent runs as admin or SYSTEM |
| **Cleanup** | Must use registry hack (`HKCU:\...\Certificates`) | Standard `X509Store.Remove()` works |
| **Isolation** | Per-user (could pollute developer's store) | Machine-wide (Docker gives clean state) |
| **Consistency** | Inconsistent — desktop vs CI behavior differs | Consistent across all admin contexts |

## Progress Tracker

| # | Step | Status | Notes |
|---|------|--------|-------|
| 1 | Document analysis | [x] | This file |
| 2 | Update `OptionBuilders.CreateTrustLocationOption()` | [x] | Auto-detect admin → LocalMachine default |
| 3 | Update `TrustCommand.BuildAddCommand()` location default | [x] | Auto-detect admin → LocalMachine default |
| 4 | Update `Import-CertificateToStoreNoUI` helper | [x] | Support LocalMachine via `certutil -addstore` |
| 5 | Update test-trust.ps1 | [x] | Use `LocalMachine\Root` + admin guard |
| 6 | Update test-create.ps1 trust tests | [x] | Use `--trust-location LocalMachine` + admin guard |
| 7 | Update testing.md known limitations | [x] | Document new behavior |
| 8 | Update docker-testing.md | [x] | Remove Root store hang warnings |
| 9 | Build and verify | [x] | `dotnet build` succeeds (0 errors, 0 warnings) |

## Implementation Details

### Application Code Changes

#### `OptionBuilders.CreateTrustLocationOption()` — Auto-Detect Default

```csharp
internal static Option<StoreLocation> CreateTrustLocationOption()
{
    var trustLocationOption = new Option<StoreLocation>("--trust-location", "--tl")
    {
        Description = "Trust store location: LocalMachine (default when admin, system-wide) or CurrentUser (no admin required, but triggers UI dialog for Root store).",
        DefaultValueFactory = _ => TrustHandler.IsRunningAsAdmin()
            ? StoreLocation.LocalMachine
            : StoreLocation.CurrentUser
    };
    return trustLocationOption;
}
```

#### `TrustCommand.BuildAddCommand()` — Auto-Detect Default

```csharp
var locationOption = new Option<string>("--location", "-l")
{
    Description = "Store location (CurrentUser, LocalMachine). LocalMachine requires admin. Defaults to LocalMachine when running as admin.",
    DefaultValueFactory = _ => TrustHandler.IsRunningAsAdmin() ? "LocalMachine" : "CurrentUser"
};
```

### Test Changes

#### `test-helper.ps1` — Support LocalMachine

```powershell
function Import-CertificateToStoreNoUI {
    param(
        [string]$FilePath,
        [string]$StoreName,
        [string]$StoreLocation = "CurrentUser"
    )

    $absolutePath = (Resolve-Path $FilePath).Path

    if ($StoreLocation -eq "LocalMachine") {
        certutil.exe -addstore $StoreName $absolutePath | Out-Null
    } else {
        certutil.exe -user -addstore $StoreName $absolutePath | Out-Null
    }
}
```

#### Test scripts — Use LocalMachine\Root

All tests that operate on Root store will:
1. Use `Cert:\LocalMachine\Root` for assertions and cleanup
2. Pass `--location LocalMachine` or `--trust-location LocalMachine` to certz commands
3. Include an admin guard to skip when not elevated

### Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| Non-admin users get permission error | Auto-detect: only default to LocalMachine when admin |
| Parallel test interference on shared machines | Tests use unique GUIDs in CN names; thumbprint-based cleanup |
| Breaking existing `tru-1.4` test | Update to test non-admin behavior against LocalMachine explicitly |

## Verification Checklist

- [ ] `dotnet build` succeeds
- [ ] `certz trust add cert.cer --store root` uses LocalMachine when admin
- [ ] `certz trust add cert.cer --store root` uses CurrentUser when not admin
- [ ] `certz create dev test.local --trust` uses LocalMachine when admin
- [ ] `pwsh -File test/test-trust.ps1` passes (as admin)
- [ ] `pwsh -File test/test-create.ps1 -Category trust` passes (as admin)
- [ ] Docker Server Core tests pass without hanging
- [ ] `--trust-location CurrentUser` explicit override still works
