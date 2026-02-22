# Docker File Management - How It Works

This document explains how certz.exe and test scripts are made available in Docker containers.

## Build First

All Docker services depend on the debug build. Run this once before starting any container:

```powershell
pwsh -File build-debug.ps1
```

This produces:
- `debug/win-x64/certz.exe` and `debug/win-x64/certz.pdb` -- used by Windows services
- `debug/linux-x64/certz` -- used by Linux services

---

## Docker Images

| Image | Base | Purpose | Test Runner |
|---|---|---|---|
| `Dockerfile.test.win-smoke` | `nanoserver:ltsc2022` | Smoke tests on bare Nanoserver | `test-win-smoke.cmd` (CMD batch) |
| `Dockerfile.test.win` | `powershell:lts-windowsservercore-ltsc2022` | Full test suite (Windows) | `test-all.ps1` (PowerShell) |
| `Dockerfile.test.linux-smoke` | `debian:12-slim` | Smoke tests on minimal Linux | `test-linux-smoke.sh` (sh) |
| `Dockerfile.test.linux` | `powershell:lts-ubuntu-22.04` | Full test suite (Linux) | `test-all.ps1` (PowerShell) |

### Why Two Windows Images?

**`Dockerfile.test.win-smoke` (Nanoserver)** is a minimal Windows installation without PowerShell, PKI modules, or `certutil`. Since certz.exe is a self-contained single-file executable, it should run on Nanoserver without dependencies. The smoke test validates this.

**`Dockerfile.test.win` (Server Core)** provides the full Windows API surface including the PKI PowerShell module, `certutil.exe`, and the `Cert:\` drive. The comprehensive test suite requires these for test setup and teardown (creating certificates via `New-SelfSignedCertificate`, managing stores via `Cert:\`, etc.).

---

## Windows Smoke Tests (`Dockerfile.test.win-smoke`)

### How It Works

```dockerfile
FROM mcr.microsoft.com/windows/nanoserver:ltsc2022
WORKDIR /app
USER ContainerAdministrator
COPY debug/win-x64/certz.exe ./
COPY test/test-win-smoke.cmd ./test/
ENTRYPOINT ["cmd", "/c", "test\\test-win-smoke.cmd"]
```

The batch file runs every certz command sequentially and fails on the first non-zero exit code. No PowerShell, no test framework -- just certz.exe and CMD.

**File Flow:**

```
Host Machine                      Docker Image (Nanoserver)
-------------                     ------------------------
debug/win-x64/certz.exe --COPY--> /app/certz.exe
test/test-win-smoke.cmd           /app/test/test-win-smoke.cmd
```

**Commands tested:** `--version`, `--help`, `examples`, `create dev`, `create ca`, `create dev --ephemeral`, `inspect`, `lint`, `convert`, `renew`, `monitor`, `verify`, `list`, `install`

**Run:**

```powershell
pwsh -File build-debug.ps1
docker-compose -f docker-compose.test.yml up --build certz-win-test-smoke
```

---

## Windows Full Suite (`Dockerfile.test.win`)

### How It Works

```dockerfile
FROM mcr.microsoft.com/powershell:lts-windowsservercore-ltsc2022
SHELL ["pwsh", "-Command"]
WORKDIR /app
USER ContainerAdministrator
ENV DOTNET_ENVIRONMENT=Test
COPY debug/win-x64/certz.exe ./
COPY debug/win-x64/certz.pdb ./
COPY test/ ./test/
ENTRYPOINT ["pwsh", "-File", "./test/test-all.ps1"]
CMD ["-Verbose"]
```

**File Flow:**

```
Host Machine                       Docker Image (Server Core)
-------------                      --------------------------
debug/win-x64/certz.exe  --COPY--> /app/certz.exe
debug/win-x64/certz.pdb  --COPY--> /app/certz.pdb
test/                    --COPY--> /app/test/
                                     test-all.ps1
                                     test-helper.ps1
                                     test-create.ps1
                                     test-inspect.ps1
                                     ... (all test scripts)
```

**Container Detection:**

The test helper functions automatically detect container environments via `DOTNET_ENVIRONMENT=Test`:

```powershell
# In test-helper.ps1
# Build-Certz skips building when in a container (certz.exe is pre-built)
# Enter-ToolsDirectory skips directory navigation (certz.exe is in working directory)
```

**Run:**

```powershell
pwsh -File build-debug.ps1
docker-compose -f docker-compose.test.yml up --build certz-win-test
```

---

## Linux Smoke Tests (`Dockerfile.test.linux-smoke`)

### How It Works

```dockerfile
FROM debian:12-slim
WORKDIR /app
COPY debug/linux-x64/certz ./
COPY test/test-linux-smoke.sh ./test/
RUN chmod +x /app/certz /app/test/test-linux-smoke.sh
ENTRYPOINT ["/bin/sh", "/app/test/test-linux-smoke.sh"]
```

Uses `debian:12-slim` — glibc-based, no PowerShell, no package extras. Mirrors the Nanoserver smoke test: just the binary and a shell script. Tests 19 commands across create, inspect, lint, convert, renew, and monitor. Trust store operations (install/list/verify) are excluded since they require distro tools; those are covered by `certz-linux-test`.

**File Flow:**

```
Host Machine                           Docker Image (Debian 12 slim)
-------------                          -----------------------------
debug/linux-x64/certz      --COPY-->   /app/certz
test/test-linux-smoke.sh   --COPY-->   /app/test/test-linux-smoke.sh
```

**Run:**

```powershell
pwsh -File build-debug.ps1
docker-compose -f docker-compose.test.yml up --build certz-linux-test-smoke
```

---

## Linux Full Suite (`Dockerfile.test.linux`)

### How It Works

```dockerfile
FROM mcr.microsoft.com/powershell:lts-ubuntu-22.04
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates ...
ENV DOTNET_ENVIRONMENT=Test
COPY debug/linux-x64/certz ./
COPY test/ ./test/
RUN chmod +x /app/certz
ENTRYPOINT ["pwsh", "-File", "./test/test-all.ps1"]
CMD ["-Verbose"]
```

**File Flow:**

```
Host Machine                        Docker Image (Ubuntu 22.04)
-------------                       ---------------------------
debug/linux-x64/certz    --COPY-->  /app/certz
test/                    --COPY-->  /app/test/
```

**Run:**

```powershell
pwsh -File build-debug.ps1
docker-compose -f docker-compose.test.yml up --build certz-linux-test
```

---

## Docker Compose

The `docker-compose.test.yml` provides six services:

| Service | Dockerfile | Platform | Description |
|---|---|---|---|
| `certz-win-test-smoke` | `Dockerfile.test.win-smoke` | Windows | Nanoserver smoke tests |
| `certz-win-test` | `Dockerfile.test.win` | Windows | Full test suite (baked-in files) |
| `certz-win-test-dev` | `Dockerfile.test.win` | Windows | Development mode (volume mounts) |
| `certz-linux-test-smoke` | `Dockerfile.test.linux-smoke` | Linux | Debian slim smoke tests |
| `certz-linux-test` | `Dockerfile.test.linux` | Linux | Full test suite (baked-in files) |
| `certz-linux-test-dev` | `Dockerfile.test.linux` | Linux | Development mode (volume mounts) |

```powershell
# Build all debug binaries first (required once, re-run after code changes)
pwsh -File build-debug.ps1

# Run individual services
docker-compose -f docker-compose.test.yml up --build certz-win-test-smoke
docker-compose -f docker-compose.test.yml up --build certz-win-test
docker-compose -f docker-compose.test.yml up --build certz-win-test-dev
docker-compose -f docker-compose.test.yml up --build certz-linux-test-smoke
docker-compose -f docker-compose.test.yml up --build certz-linux-test
docker-compose -f docker-compose.test.yml up --build certz-linux-test-dev
```

The `-dev` services mount `debug/win-x64/` or `debug/linux-x64/` from the host, so you only need to rebuild with `build-debug.ps1` (no Docker image rebuild) when the binary changes.

---

## .dockerignore Configuration

The `.dockerignore` file ensures required files are included:

```
# Excludes build outputs, IDE files, documentation, etc.
# Test scripts (test/*.ps1, test/*.cmd) and debug binaries (debug/*) are NOT excluded,
# ensuring the COPY commands in Dockerfiles can access them.
```

The `release/` directory is excluded from Docker context since Docker images always use the debug build.

---

## Troubleshooting

### Baked-In Files Are Outdated

Rebuild the image:

```powershell
# Nanoserver
docker-compose -f docker-compose.test.yml build --no-cache certz-win-test-smoke

# Server Core
docker-compose -f docker-compose.test.yml build --no-cache certz-win-test

# Linux smoke
docker-compose -f docker-compose.test.yml build --no-cache certz-linux-test-smoke

# Linux full suite
docker-compose -f docker-compose.test.yml build --no-cache certz-linux-test
```

---

## Summary

| Scenario | Use This |
|---|---|
| Quick Windows binary compatibility check | `certz-win-test-smoke` (Nanoserver) |
| Quick Linux binary compatibility check | `certz-linux-test-smoke` (Debian slim) |
| Full Windows test coverage in isolation | `certz-win-test` (Server Core) |
| Full Linux test coverage in isolation | `certz-linux-test` (Ubuntu 22.04) |
| Active Windows development (live changes) | `certz-win-test-dev` (volume mounts) |
| Active Linux development (live changes) | `certz-linux-test-dev` (volume mounts) |
| CI/CD pipeline | Smoke tests first (fast), then full suites (thorough) |
