# Docker Testing Quick Reference

This guide provides quick commands and troubleshooting for running certz tests in Docker containers.

## Quick Start

### Which Mode Should I Use?

| Mode | Command | Best For | Rebuild Needed? |
|------|---------|----------|----------------|
| **Standard** | `.\test-all.ps1 -UseDocker` | CI/CD, Production | Yes, after file changes |
| **DevMode** | `.\test-all.ps1 -UseDocker -DevMode` | Active Development | No, uses volumes |

### Quick Commands

```powershell
# Standard mode: Files baked into image (requires rebuild for changes)
.\test-all.ps1 -UseDocker

# Standard mode with verbose output
.\test-all.ps1 -UseDocker -DockerVerbose

# Development mode: Files mounted as volumes (no rebuild needed)
.\test-all.ps1 -UseDocker -DevMode

# Development mode with verbose output
.\test-all.ps1 -UseDocker -DevMode -DockerVerbose
```

## Prerequisites

1. **Install Docker Desktop for Windows**
   - Download from: https://www.docker.com/products/docker-desktop/
   - Install and restart your computer

2. **Switch to Windows Containers**
   - Right-click Docker Desktop icon in system tray
   - Select "Switch to Windows containers..."
   - Wait for Docker to restart

3. **Verify Docker is Working**
   ```powershell
   docker --version
   docker info
   ```

## Understanding Docker File Management

The Docker test setup supports **two approaches** for making certz.exe and test-all.ps1 available in the container:

### Approach 1: Baked-In Files (Default - Best for CI/CD)

**How it works:**
- Files are copied into the Docker image during build using `COPY` commands
- Files become part of the image layers
- Changes to source files require rebuilding the image

**When to use:**
- CI/CD pipelines
- Production testing
- When you want consistent, reproducible builds
- When files don't change frequently

**Command:**
```powershell
.\test-all.ps1 -UseDocker
```

**Pros:**
- ✅ Self-contained image (no external dependencies)
- ✅ Guaranteed consistency
- ✅ Faster container startup
- ✅ Works offline after initial build

**Cons:**
- ❌ Must rebuild image after changing certz.exe or test-all.ps1
- ❌ Slower development iteration

### Approach 2: Volume Mounts (DevMode - Best for Active Development)

**How it works:**
- Files are mounted from host into container at runtime using volumes
- Changes to source files are immediately reflected in container
- No rebuild required

**When to use:**
- Active development
- Debugging tests
- Frequent changes to certz.exe or test scripts
- Rapid iteration

**Command:**
```powershell
.\test-all.ps1 -UseDocker -DevMode
```

**Pros:**
- ✅ No rebuild needed for file changes
- ✅ Instant feedback loop
- ✅ Perfect for debugging
- ✅ Test changes immediately

**Cons:**
- ❌ Requires files to exist on host
- ❌ Paths must be correct
- ❌ Slightly slower container startup

## Docker Testing Commands

### Basic Testing (Baked-In Files)
```powershell
# Run all tests in Docker (standard mode)
.\test-all.ps1 -UseDocker

# Run with verbose output for debugging
.\test-all.ps1 -UseDocker -DockerVerbose
```

### Development Testing (Volume Mounts)
```powershell
# Run with volume mounts (no rebuild needed for changes)
.\test-all.ps1 -UseDocker -DevMode

# With verbose output
.\test-all.ps1 -UseDocker -DevMode -DockerVerbose

# After making changes to certz.exe or test-all.ps1, just re-run:
.\test-all.ps1 -UseDocker -DevMode
# No rebuild needed!
```

### Manual Docker Commands

If you want more control over the Docker container:

```powershell
# Build the test image
docker build -t certz-test:latest -f Dockerfile.test .

# Run the tests
docker run --rm --isolation=process certz-test:latest

# Run with verbose flag
docker run --rm --isolation=process certz-test:latest -Verbose

# Run tests and keep container for debugging (remove --rm)
docker run --name certz-test-debug --isolation=process certz-test:latest

# View logs from debug container
docker logs certz-test-debug

# Remove debug container when done
docker rm certz-test-debug
```

### Using Docker Compose

The project includes two Docker Compose services:

**Standard Mode (certz-test):**
```powershell
# Run tests with baked-in files
docker-compose -f docker-compose.test.yml up --build certz-test

# Run in detached mode
docker-compose -f docker-compose.test.yml up --build -d certz-test

# View logs
docker-compose -f docker-compose.test.yml logs -f certz-test

# Clean up
docker-compose -f docker-compose.test.yml down
```

**Development Mode (certz-test-dev):**
```powershell
# Run tests with volume mounts (no rebuild needed for file changes)
docker-compose -f docker-compose.test.yml up certz-test-dev

# With rebuild (first time or after Dockerfile changes)
docker-compose -f docker-compose.test.yml up --build certz-test-dev

# View logs
docker-compose -f docker-compose.test.yml logs -f certz-test-dev

# Clean up
docker-compose -f docker-compose.test.yml down
```

## Troubleshooting

### Error: "image operating system ... cannot be used"

**Problem:** Docker is in Linux containers mode, but certz requires Windows containers.

**Solution:**
```powershell
# Switch to Windows containers
# Right-click Docker Desktop icon > Switch to Windows containers
```

### Error: "docker: command not found"

**Problem:** Docker is not installed or not in PATH.

**Solution:**
1. Install Docker Desktop for Windows
2. Restart PowerShell/Terminal
3. Verify: `docker --version`

### Error: "Cannot connect to Docker daemon"

**Problem:** Docker Desktop is not running.

**Solution:**
1. Start Docker Desktop
2. Wait for it to fully start (icon turns green)
3. Try command again

### Error: Build fails with "failed to solve with frontend"

**Problem:** Base image cannot be pulled or network issues.

**Solution:**
```powershell
# Pull the base image manually
docker pull mcr.microsoft.com/dotnet/sdk:7.0-nanoserver-ltsc2022

# Then retry the build
.\test-all.ps1 -UseDocker
```

### Error: "Insufficient memory"

**Problem:** Docker doesn't have enough RAM allocated.

**Solution:**
1. Open Docker Desktop
2. Settings → Resources
3. Increase Memory to at least 4GB
4. Click "Apply & Restart"

### Volume Mount Issues (DevMode)

**Problem:** Files not found or permission errors with `-DevMode`

**Solution:**
```powershell
# Verify files exist
Test-Path docker/tools/certz.exe
Test-Path docker/tools/certz.pdb
Test-Path test-all.ps1

# Check file permissions
Get-Acl docker/tools/certz.exe

# Try without DevMode to use baked-in files
.\test-all.ps1 -UseDocker
```

### Path Issues Inside Container

**Problem:** "Cannot find path 'C:\app\docker\tools'" error

**Explanation:** This error occurs when the test script tries to navigate to `docker\tools` subdirectory inside the container, but files are directly in `/app`.

**Solution:** This is now automatically handled by the script detecting when it's running inside a container (via `DOTNET_ENVIRONMENT=Test` environment variable). If you still see this error:

```powershell
# Ensure you're using the latest version of test-all.ps1
git pull

# Rebuild the Docker image
docker build --no-cache -t certz-test:latest -f Dockerfile.test .

# Run tests again
.\test-all.ps1 -UseDocker
```

### Tests Fail Inside Container

**Debugging Steps:**

```powershell
# Run container interactively (baked-in files)
docker run --rm -it --isolation=process certz-test:latest powershell

# Inside container, run tests manually
.\test-all.ps1 -Verbose

# Or run individual commands
.\certz.exe list
.\certz.exe create --f test.pfx
```

**For DevMode debugging:**
```powershell
# Run interactively with volume mounts
docker run --rm -it --isolation=process `
  -v ${PWD}/docker/tools/certz.exe:/app/certz.exe:ro `
  -v ${PWD}/docker/tools/certz.pdb:/app/certz.pdb:ro `
  -v ${PWD}/test-all.ps1:/app/test-all.ps1:ro `
  certz-test:latest powershell

# Inside container, verify files
Get-ChildItem
.\certz.exe --version
.\test-all.ps1 -Verbose
```

### Build is Very Slow

**Optimization:**

```powershell
# Clean up old images and build cache
docker system prune -f

# Rebuild without cache
docker build --no-cache -t certz-test:latest -f Dockerfile.test .
```

## Development Workflow Examples

### Scenario 1: Testing Code Changes (DevMode Recommended)

You're actively developing certz and want to test changes quickly:

```powershell
# 1. Build your changes
dotnet build -c Release

# 2. Copy to docker/tools
Copy-Item bin/Release/net7.0/win-x64/publish/certz.exe docker/tools/
Copy-Item bin/Release/net7.0/win-x64/publish/certz.pdb docker/tools/

# 3. Run tests with DevMode (no Docker rebuild needed!)
.\test-all.ps1 -UseDocker -DevMode

# 4. Make more changes to code, rebuild, and test again
dotnet build -c Release
Copy-Item bin/Release/net7.0/win-x64/publish/certz.exe docker/tools/
.\test-all.ps1 -UseDocker -DevMode  # Instant - no Docker rebuild!

# 5. Modify test script
# Edit test-all.ps1...
.\test-all.ps1 -UseDocker -DevMode  # Tests use updated script immediately!
```

### Scenario 2: CI/CD Pipeline (Baked-In Recommended)

You're running tests in a CI/CD pipeline:

```powershell
# 1. Build project
dotnet build -c Release

# 2. Copy binaries
Copy-Item bin/Release/net7.0/win-x64/publish/* docker/tools/

# 3. Run tests (image is built with files baked in)
.\test-all.ps1 -UseDocker -DockerVerbose

# Image is self-contained and reproducible
```

### Scenario 3: First-Time Setup

```powershell
# 1. Clone repository
git clone https://github.com/yourusername/certz.git
cd certz

# 2. Build project
dotnet build -c Release

# 3. Copy binaries
Copy-Item bin/Release/net7.0/win-x64/publish/certz.exe docker/tools/
Copy-Item bin/Release/net7.0/win-x64/publish/certz.pdb docker/tools/

# 4. Run tests (use DevMode for development)
.\test-all.ps1 -UseDocker -DevMode
```

## Advanced Usage

### Running Specific Test Scenarios

Since the test script is comprehensive, you might want to run only certain tests:

```powershell
# Build the image
docker build -t certz-test:latest -f Dockerfile.test .

# Run container interactively
docker run --rm -it --isolation=process certz-test:latest powershell

# Inside container, run individual certz commands
.\certz.exe create --f test.pfx
.\certz.exe list
# etc.
```

### Mounting Local Directories

To access test results outside the container:

```powershell
# Create test results directory
mkdir test-results

# Run with volume mount
docker run --rm --isolation=process `
  -v ${PWD}/test-results:c:/app/test-results `
  certz-test:latest
```

### Custom Base Image

If you need a different Windows version:

Edit `Dockerfile.test` and change the base image:

```dockerfile
# For Windows Server 2019
FROM mcr.microsoft.com/dotnet/sdk:7.0-nanoserver-1809

# For Windows Server 2022 (default)
FROM mcr.microsoft.com/dotnet/sdk:7.0-nanoserver-ltsc2022
```

## CI/CD Integration

### GitHub Actions

Create `.github/workflows/test.yml`:

```yaml
name: Certz Tests

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: windows-latest

    steps:
    - name: Checkout code
      uses: actions/checkout@v3

    - name: Build project
      run: dotnet build -c Release

    - name: Copy binaries to docker/tools
      run: |
        Copy-Item bin/Release/net7.0/win-x64/publish/* docker/tools/

    - name: Run tests in Docker
      run: .\test-all.ps1 -UseDocker -DockerVerbose

    - name: Upload test results
      if: always()
      uses: actions/upload-artifact@v3
      with:
        name: test-results
        path: test-results/
```

### Azure DevOps

Create `azure-pipelines.yml`:

```yaml
trigger:
  branches:
    include:
    - main
    - develop

pool:
  vmImage: 'windows-latest'

steps:
- task: DotNetCoreCLI@2
  displayName: 'Build project'
  inputs:
    command: 'build'
    configuration: 'Release'

- task: CopyFiles@2
  displayName: 'Copy binaries'
  inputs:
    SourceFolder: 'bin/Release/net7.0/win-x64/publish'
    Contents: '**'
    TargetFolder: 'docker/tools'

- task: PowerShell@2
  displayName: 'Run Docker tests'
  inputs:
    targetType: 'inline'
    script: |
      .\test-all.ps1 -UseDocker -DockerVerbose
      if ($LASTEXITCODE -ne 0) {
        throw "Tests failed"
      }

- task: PublishTestResults@2
  condition: always()
  displayName: 'Publish test results'
  inputs:
    testResultsFormat: 'NUnit'
    testResultsFiles: '**/test-results/*.xml'
```

## Performance Tips

1. **Layer Caching:** Docker caches layers, so subsequent builds are faster
2. **Multi-stage Builds:** Already optimized in Dockerfile.test
3. **Minimal Base Image:** Using nanoserver for smaller image size
4. **Clean Builds:** Run `docker system prune` periodically

## Benefits of Docker Testing

- ✅ **Isolation:** No pollution of host certificate stores
- ✅ **Consistency:** Same environment across all machines
- ✅ **CI/CD Ready:** Easy integration with pipelines
- ✅ **No Admin Rights:** Docker handles elevation internally
- ✅ **Reproducible:** Same results every time
- ✅ **Clean State:** Fresh environment for each run

## File Reference

- **Dockerfile.test** - Test container definition
- **docker-compose.test.yml** - Compose configuration
- **test-all.ps1** - Test script (works both locally and in Docker)
- **.dockerignore** - Files excluded from Docker build context

## Support

For issues or questions:
1. Check this troubleshooting guide
2. Review [TESTING.md](TESTING.md) for detailed test documentation
3. Check Docker Desktop logs
4. Ensure Windows containers are enabled

## Version Compatibility

| Component | Version | Notes |
|-----------|---------|-------|
| Docker Desktop | 4.0+ | Windows containers support |
| Windows | 10/11, Server 2019/2022 | Container host |
| .NET SDK | 7.0 | Base image |
| PowerShell | 5.1+ | Script execution |

---

**Last Updated:** 2026-01-25
