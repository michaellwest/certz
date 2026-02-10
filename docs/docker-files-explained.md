# Docker File Management - How It Works

This document explains how certz.exe and test scripts are made available in Docker containers.

## Two Docker Images

The project uses two Docker images for testing:

| Image | Base | Purpose | Test Runner |
|---|---|---|---|
| `Dockerfile.test.nanoserver` | `nanoserver:ltsc2022` | Smoke tests on bare Nanoserver | `test-nanoserver.cmd` (CMD batch) |
| `Dockerfile.test.servercore` | `powershell:lts-windowsservercore-ltsc2022` | Full test suite | `test-all.ps1` (PowerShell) |

### Why Two Images?

**Nanoserver** is a minimal Windows installation without PowerShell, PKI modules, or `certutil`. Since certz.exe is a self-contained single-file executable, it should run on Nanoserver without dependencies. The smoke test validates this.

**Server Core** provides the full Windows API surface including the PKI PowerShell module, `certutil.exe`, and the `Cert:\` drive. The comprehensive test suite requires these for test setup and teardown (creating certificates via `New-SelfSignedCertificate`, managing stores via `Cert:\`, etc.).

---

## Nanoserver Smoke Tests (`Dockerfile.test.nanoserver`)

### How It Works

```dockerfile
FROM mcr.microsoft.com/windows/nanoserver:ltsc2022
WORKDIR /app
USER ContainerAdministrator
COPY debug/certz.exe ./
COPY test/test-nanoserver.cmd ./test/
ENTRYPOINT ["cmd", "/c", "test\\test-nanoserver.cmd"]
```

The batch file runs every certz command sequentially and fails on the first non-zero exit code. No PowerShell, no test framework -- just certz.exe and CMD.

**File Flow:**

```
Host Machine                    Docker Image (Nanoserver)
-------------                   ------------------------
debug/certz.exe   --COPY-->     /app/certz.exe
test/test-nanoserver.cmd        /app/test/test-nanoserver.cmd
```

**Commands tested:** `--version`, `--help`, `examples`, `create dev`, `create ca`, `create dev --ephemeral`, `inspect`, `lint`, `convert`, `renew`, `monitor`, `verify`, `list`, `install`

**Run:**

```powershell
dotnet publish src/certz/certz.csproj -c Debug -o debug
docker build -t certz-test-smoke:latest -f Dockerfile.test.nanoserver .
docker run --rm --isolation=process certz-test-smoke:latest
```

---

## Server Core Full Suite (`Dockerfile.test.servercore`)

### How It Works

```dockerfile
FROM mcr.microsoft.com/powershell:lts-windowsservercore-ltsc2022
SHELL ["pwsh", "-Command"]
WORKDIR /app
USER ContainerAdministrator
ENV DOTNET_ENVIRONMENT=Test
COPY debug/certz.exe ./
COPY debug/certz.pdb ./
COPY test/ ./test/
ENTRYPOINT ["pwsh", "-File", "./test/test-all.ps1"]
CMD ["-Verbose"]
```

**File Flow:**

```
Host Machine                    Docker Image (Server Core)
-------------                   --------------------------
debug/certz.exe   --COPY-->     /app/certz.exe
debug/certz.pdb   --COPY-->     /app/certz.pdb
test/             --COPY-->     /app/test/
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

**Run via test-all.ps1:**

```powershell
.\test\test-all.ps1 -UseDocker
```

**Run manually:**

```powershell
docker build -t certz-test:latest -f Dockerfile.test.servercore .
docker run --rm --isolation=process certz-test:latest
```

---

## Docker Compose

The `docker-compose.test.yml` provides three services:

| Service | Dockerfile | Description |
|---|---|---|
| `certz-test-smoke` | `Dockerfile.test.nanoserver` | Nanoserver smoke tests |
| `certz-test` | `Dockerfile.test.servercore` | Full test suite (baked-in files) |
| `certz-test-dev` | `Dockerfile.test.servercore` | Development mode (volume mounts) |

```powershell
# Run nanoserver smoke tests
docker-compose -f docker-compose.test.yml up --build certz-test-smoke

# Run full test suite
docker-compose -f docker-compose.test.yml up --build certz-test

# Run both
docker-compose -f docker-compose.test.yml up --build
```

---

## .dockerignore Configuration

The `.dockerignore` file ensures required files are included:

```
# Excludes build outputs, IDE files, documentation, etc.
# Test scripts (test/*.ps1, test/*.cmd) and debug binaries (debug/*) are NOT excluded,
# ensuring the COPY commands in Dockerfiles can access them.
```

---

## Troubleshooting

### Baked-In Files Are Outdated

Rebuild the image:

```powershell
# Nanoserver
docker build --no-cache -t certz-test-smoke:latest -f Dockerfile.test.nanoserver .

# Server Core
docker build --no-cache -t certz-test:latest -f Dockerfile.test.servercore .
```

---

## Summary

| Scenario | Use This |
|---|---|
| Quick binary compatibility check | `Dockerfile.test.nanoserver` (Nanoserver) |
| Full test coverage in isolation | `Dockerfile.test.servercore` (Server Core) |
| CI/CD pipeline | Both: Nanoserver first (fast), then Server Core (thorough) |
| Active development (live changes) | `certz-test-dev` service via Docker Compose |
