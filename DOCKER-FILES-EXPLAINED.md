# Docker File Management - How It Works

This document explains how certz.exe and test-all.ps1 are made available in Docker containers.

## The Problem

Docker containers need access to your local files (certz.exe, test-all.ps1) to run tests. There are two ways to accomplish this:

## Solution 1: COPY (Baked-In Files)

### How It Works
```dockerfile
# In Dockerfile.test
COPY docker/tools/certz.exe ./
COPY docker/tools/certz.pdb ./
COPY test-all.ps1 ./
```

**Process:**
1. When you run `.\test-all.ps1 -UseDocker`:
   - Docker builds an image using Dockerfile.test
   - `COPY` commands copy files from your host into the image
   - Files become permanent part of the image layers
   - Image is tagged as `certz-test:latest`

2. When container starts:
   - Files are already inside the container
   - No external dependencies needed
   - Container is self-contained

**File Flow:**
```
Host Machine                    Docker Image
─────────────                   ────────────
docker/tools/certz.exe   ──┐
docker/tools/certz.pdb   ──┤ COPY  ──→  /app/certz.exe
test-all.ps1             ──┘           /app/certz.pdb
                                       /app/test-all.ps1
```

**Lifecycle:**
```
Change certz.exe ──→ Must rebuild image ──→ Run container
                    (docker build)         (files baked in)
```

### Pros & Cons

✅ **Pros:**
- Self-contained image (works offline)
- Reproducible builds
- Faster container startup
- Perfect for CI/CD

❌ **Cons:**
- Must rebuild image after every file change
- Slower development iteration
- Larger image size (includes all files)

---

## Solution 2: Volumes (DevMode)

### How It Works
```powershell
# Command line
docker run -v ./docker/tools/certz.exe:/app/certz.exe:ro certz-test:latest
```

**Process:**
1. When you run `.\test-all.ps1 -UseDocker -DevMode`:
   - Uses existing certz-test:latest image (builds if needed)
   - Does NOT rebuild image
   - Passes volume mount flags to `docker run`

2. When container starts:
   - Docker mounts host files into container at runtime
   - Container reads files directly from your host machine
   - Changes to host files are immediately visible in container

**File Flow:**
```
Host Machine                         Docker Container
─────────────                        ────────────────
docker/tools/certz.exe   ────┐
                          Mount  ──→  /app/certz.exe (live link)
docker/tools/certz.pdb   ────┤
                          Mount  ──→  /app/certz.pdb (live link)
test-all.ps1             ────┘
                          Mount  ──→  /app/test-all.ps1 (live link)
```

**Lifecycle:**
```
Change certz.exe ──→ No rebuild needed ──→ Run container
                                          (files mounted dynamically)
```

### Pros & Cons

✅ **Pros:**
- No rebuild needed for file changes
- Instant feedback loop
- Perfect for active development
- Test changes immediately

❌ **Cons:**
- Requires files to exist on host
- Slightly more complex setup
- Host paths must be correct

---

## Comparison Table

| Feature | Baked-In (COPY) | Volume Mounts (DevMode) |
|---------|----------------|-------------------------|
| **Command** | `.\test-all.ps1 -UseDocker` | `.\test-all.ps1 -UseDocker -DevMode` |
| **Build Required** | Yes, every time files change | No, uses existing image |
| **File Location** | Inside image | On host, mounted at runtime |
| **Update Process** | Rebuild image | Just rerun tests |
| **Offline Work** | Yes | Yes (if image exists) |
| **Best For** | CI/CD, Production | Active development |
| **Speed (after change)** | Slow (rebuild ~30s) | Fast (instant) |

---

## Practical Examples

### Example 1: Active Development

You're fixing a bug in certz:

```powershell
# Edit certz code
code Commands/CreateCommand.cs

# Build
dotnet build -c Release
Copy-Item bin/Release/net7.0/certz.exe docker/tools/

# Test with DevMode (instant - no Docker rebuild!)
.\test-all.ps1 -UseDocker -DevMode

# Make another change
code Commands/CreateCommand.cs
dotnet build -c Release
Copy-Item bin/Release/net7.0/certz.exe docker/tools/

# Test again (still instant!)
.\test-all.ps1 -UseDocker -DevMode
```

**Time saved:** ~30 seconds per iteration (no Docker rebuild)

### Example 2: CI/CD Pipeline

GitHub Actions workflow:

```yaml
- name: Run tests
  run: .\test-all.ps1 -UseDocker
```

Uses baked-in files because:
- Reproducible builds
- No dependency on host file system
- Self-contained image
- Consistent across runs

### Example 3: Testing Script Changes

You're modifying the test script:

```powershell
# Edit test script
code test-all.ps1

# Test with DevMode (uses updated script immediately!)
.\test-all.ps1 -UseDocker -DevMode

# No need to rebuild Docker image
# Changes to test-all.ps1 are picked up automatically
```

---

## Technical Details

### Baked-In Files (COPY)

**Dockerfile.test:**
```dockerfile
FROM mcr.microsoft.com/dotnet/sdk:10.0-nanoserver-ltsc2022
WORKDIR /app
USER ContainerAdministrator

# Set environment variable to help script detect container environment
ENV DOTNET_ENVIRONMENT=Test

# Files are copied during build directly to /app
# (not to /app/docker/tools - they're already in the right place)
COPY docker/tools/certz.exe ./
COPY docker/tools/certz.pdb ./
COPY test-all.ps1 ./

ENTRYPOINT ["pwsh", "-File", "./test-all.ps1"]
```

**Build command:**
```powershell
docker build -t certz-test:latest -f Dockerfile.test .
```

### Volume Mounts (DevMode)

**test-all.ps1 implementation:**
```powershell
if ($DevMode) {
    $currentPath = (Get-Location).Path
    $dockerArgs = @(
        "run", "--rm", "--isolation=process",
        "-e", "DOTNET_ENVIRONMENT=Test",  # Tells script it's in container
        "-v", "${currentPath}\docker\tools\certz.exe:/app/certz.exe:ro",
        "-v", "${currentPath}\docker\tools\certz.pdb:/app/certz.pdb:ro",
        "-v", "${currentPath}\test-all.ps1:/app/test-all.ps1:ro",
        "certz-test:latest"
    )
}
```

**Container Detection:**
The script automatically detects if it's running inside a container:
```powershell
# In test-all.ps1
$isInsideContainer = $env:DOTNET_ENVIRONMENT -eq "Test" -or (Test-Path "./certz.exe")

if (-not $isInsideContainer) {
    # On host: navigate to docker\tools subdirectory
    Push-Location -Path (Join-Path -Path $PSScriptRoot -ChildPath "docker\tools")
} else {
    # In container: files are already in /app, no navigation needed
    Write-Verbose "Running inside Docker container"
}
```

**Docker Compose (docker-compose.test.yml):**
```yaml
certz-test-dev:
  image: certz-test:latest
  volumes:
    - ./docker/tools/certz.exe:/app/certz.exe:ro
    - ./docker/tools/certz.pdb:/app/certz.pdb:ro
    - ./test-all.ps1:/app/test-all.ps1:ro
```

---

## .dockerignore Configuration

The `.dockerignore` file ensures required files are included:

```
# Exclude most files
**/Dockerfile*
**/docker-compose*

# But include files needed for test container
!test-all.ps1
!docker/tools/certz.exe
!docker/tools/certz.pdb
```

This prevents accidentally excluding the files needed for the COPY commands.

---

## Which Should You Use?

### Use Baked-In Files When:
- ✅ Running in CI/CD pipelines
- ✅ Creating reproducible builds
- ✅ Deploying to other machines
- ✅ Files don't change frequently
- ✅ You want self-contained images

### Use Volume Mounts (DevMode) When:
- ✅ Actively developing certz
- ✅ Debugging test failures
- ✅ Making frequent code changes
- ✅ Testing script modifications
- ✅ You want instant feedback

### Use Both:
Many developers use DevMode during development, then switch to baked-in files for final validation before committing:

```powershell
# During development
.\test-all.ps1 -UseDocker -DevMode

# Before committing
.\test-all.ps1 -UseDocker  # Verify with clean build
```

---

## Troubleshooting

### "File not found" with DevMode

Files must exist on host:
```powershell
# Verify files exist
Test-Path docker/tools/certz.exe  # Should be True
Test-Path test-all.ps1             # Should be True

# Build if missing
dotnet build -c Release
Copy-Item bin/Release/net7.0/certz.exe docker/tools/
```

### Baked-In Files Are Outdated

Rebuild the image:
```powershell
# Force rebuild
docker build --no-cache -t certz-test:latest -f Dockerfile.test .

# Or just use DevMode
.\test-all.ps1 -UseDocker -DevMode
```

---

## Summary

Both approaches have their place:
- **Baked-In (COPY):** Best for production, CI/CD, and distribution
- **Volume Mounts (DevMode):** Best for development and debugging

The test script supports both seamlessly with the `-DevMode` flag!
