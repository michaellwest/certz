# Docker File Management - How It Works

This document explains how certz.exe and test-all.ps1 are made available in Docker containers.

## How Files Are Baked Into the Image

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
-------------                   ------------
docker/tools/certz.exe   --+
docker/tools/certz.pdb   --+  COPY  -->  /app/certz.exe
test-all.ps1             --+            /app/certz.pdb
                                        /app/test-all.ps1
```

**Lifecycle:**
```
Change certz.exe --> Rebuild image --> Run container
                    (docker build)    (files baked in)
```

### Benefits

- Self-contained image (works offline)
- Reproducible builds
- Faster container startup
- Perfect for CI/CD

---

## Practical Examples

### Example 1: Running Tests

```powershell
# Build and run tests in Docker
.\test-all.ps1 -UseDocker
```

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

---

## Technical Details

### Dockerfile.test

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

## Troubleshooting

### Baked-In Files Are Outdated

Rebuild the image:
```powershell
# Force rebuild
docker build --no-cache -t certz-test:latest -f Dockerfile.test .
```

---

## Summary

The Docker testing approach uses baked-in files via COPY commands. This provides:
- Self-contained images
- Reproducible builds
- Perfect for CI/CD and distribution
