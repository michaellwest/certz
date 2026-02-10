# Docker File Management - How It Works

This document explains how certz.exe and test scripts are made available in Docker containers.

## How Files Are Baked Into the Image

### How It Works

```dockerfile
# In Dockerfile.test
COPY debug/certz.exe ./
COPY debug/certz.pdb ./
COPY test/ ./test/
```

**Process:**

1. When you run `.\test\test-all.ps1 -UseDocker`:
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
debug/certz.exe   --COPY-->     /app/certz.exe
debug/certz.pdb   --COPY-->     /app/certz.pdb
test/             --COPY-->     /app/test/
                                  test-all.ps1
                                  test-helper.ps1
                                  test-create.ps1
                                  test-inspect.ps1
                                  ... (all test scripts)
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
.\test\test-all.ps1 -UseDocker
```

### Example 2: CI/CD Pipeline

GitHub Actions workflow:

```yaml
- name: Run tests
  run: .\test\test-all.ps1 -UseDocker
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

# Set environment variable to help scripts detect container environment
ENV DOTNET_ENVIRONMENT=Test

# Copy built executable and all test scripts
COPY debug/certz.exe ./
COPY debug/certz.pdb ./
COPY test/ ./test/

ENTRYPOINT ["pwsh", "-File", "./test/test-all.ps1"]
```

**Build command:**

```powershell
docker build -t certz-test:latest -f Dockerfile.test .
```

**Container Detection:**
The test helper functions automatically detect container environments via `DOTNET_ENVIRONMENT=Test`:

```powershell
# In test-helper.ps1
# Build-Certz skips building when in a container (certz.exe is pre-built)
# Enter-ToolsDirectory skips directory navigation (certz.exe is in working directory)
```

---

## .dockerignore Configuration

The `.dockerignore` file ensures required files are included:

```
# Excludes build outputs, IDE files, documentation, etc.
# Test scripts (test/*.ps1) and debug binaries (debug/*) are NOT excluded,
# ensuring the COPY commands in Dockerfile.test can access them.
```

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
