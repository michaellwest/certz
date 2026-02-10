# Docker Testing Quick Reference

This guide provides quick commands and troubleshooting for running certz tests in Docker containers.

## Quick Start

### Quick Commands

```powershell
# Run full test suite in Docker (Server Core)
.\test\test-all.ps1 -UseDocker

# Run with verbose output
.\test\test-all.ps1 -UseDocker -DockerVerbose

# Run nanoserver smoke tests only (build certz first)
dotnet publish src/certz/certz.csproj -c Debug -o debug
docker build -t certz-test-smoke:latest -f Dockerfile.test.nanoserver .
docker run --rm --isolation=process certz-test-smoke:latest
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

## Two Docker Images

The project uses two Docker images for different testing purposes:

### Nanoserver Smoke Tests (`Dockerfile.test.nanoserver`)

**Base image:** `mcr.microsoft.com/windows/nanoserver:ltsc2022`

Runs a simple CMD batch file ([test/test-nanoserver.cmd](../test/test-nanoserver.cmd)) that executes every certz command and verifies exit code 0. No PowerShell, no test framework -- just certz.exe on bare Nanoserver.

**Purpose:** Validate that the self-contained certz.exe binary runs correctly on minimal Windows without any runtime dependencies.

**Commands:**

```powershell
# Build certz, then build and run the Docker image
dotnet publish src/certz/certz.csproj -c Debug -o debug
docker build -t certz-test-smoke:latest -f Dockerfile.test.nanoserver .
docker run --rm --isolation=process certz-test-smoke:latest

# Debug interactively
docker run --rm -it --isolation=process --entrypoint cmd certz-test-smoke:latest
```

### Server Core Full Suite (`Dockerfile.test.servercore`)

**Base image:** `mcr.microsoft.com/powershell:lts-windowsservercore-ltsc2022`

Runs the full PowerShell test suite (`test-all.ps1`) with all individual test scripts. Server Core provides the PKI module, `certutil`, and `Cert:\` drive needed by the test infrastructure.

**Purpose:** Run the comprehensive test suite with full certificate store operations, PKI setup/teardown, and detailed assertions.

**Commands:**

```powershell
# Via test-all.ps1 (recommended)
.\test\test-all.ps1 -UseDocker

# Manual build and run
docker build -t certz-test:latest -f Dockerfile.test.servercore .
docker run --rm --isolation=process certz-test:latest

# Run with verbose flag
docker run --rm --isolation=process certz-test:latest -Verbose

# Debug interactively
docker run --rm -it --isolation=process --entrypoint pwsh certz-test:latest
```

## Docker Testing Commands

### Basic Testing

```powershell
# Run full test suite in Docker (Server Core)
.\test\test-all.ps1 -UseDocker

# Run with verbose output for debugging
.\test\test-all.ps1 -UseDocker -DockerVerbose

# Run specific test categories
.\test\test-all.ps1 -UseDocker -Category create, lint
```

### Using Docker Compose

The project includes Docker Compose configuration:

```powershell
# Run nanoserver smoke tests
docker-compose -f docker-compose.test.yml up --build certz-test-smoke

# Run full test suite (Server Core)
docker-compose -f docker-compose.test.yml up --build certz-test

# Run both
docker-compose -f docker-compose.test.yml up --build

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
# Pull the base images manually
docker pull mcr.microsoft.com/windows/nanoserver:ltsc2022
docker pull mcr.microsoft.com/powershell:lts-windowsservercore-ltsc2022

# Then retry the build
.\test\test-all.ps1 -UseDocker
```

### Error: "Insufficient memory"

**Problem:** Docker doesn't have enough RAM allocated.

**Solution:**

1. Open Docker Desktop
2. Settings -> Resources
3. Increase Memory to at least 4GB
4. Click "Apply & Restart"

### Path Issues Inside Container

**Problem:** "Cannot find path 'C:\app\debug'" error

**Explanation:** This error occurs when the test script tries to navigate to `debug` subdirectory inside the container, but files are directly in `/app`.

**Solution:** This is automatically handled by the script detecting when it's running inside a container (via `DOTNET_ENVIRONMENT=Test` environment variable). If you still see this error:

```powershell
# Rebuild the Docker image
docker build --no-cache -t certz-test:latest -f Dockerfile.test.servercore .

# Run tests again
.\test\test-all.ps1 -UseDocker
```

### Tests Fail Inside Container

**Debugging Steps:**

```powershell
# Server Core: Run container interactively
docker run --rm -it --isolation=process --entrypoint pwsh certz-test:latest

# Inside container, run all tests manually
pwsh -File ./test/test-all.ps1 -Verbose

# Or run a specific test suite
pwsh -File ./test/test-create.ps1

# Or run individual certz commands
.\certz.exe list
.\certz.exe create dev test.local --ephemeral

# Nanoserver: Run container interactively
docker run --rm -it --isolation=process --entrypoint cmd certz-test-smoke:latest

# Inside container, run certz commands directly
C:\app\certz.exe --version
C:\app\certz.exe create dev test.local --ephemeral
```

### Build is Very Slow

**Optimization:**

```powershell
# Clean up old images and build cache
docker system prune -f

# Rebuild without cache
docker build --no-cache -t certz-test:latest -f Dockerfile.test.servercore .
```

## Development Workflow Examples

### Scenario 1: Quick Nanoserver Compatibility Check

```powershell
# 1. Build certz
dotnet publish src/certz/certz.csproj -c Debug -o debug

# 2. Run nanoserver smoke tests
docker build -t certz-test-smoke:latest -f Dockerfile.test.nanoserver .
docker run --rm --isolation=process certz-test-smoke:latest
```

### Scenario 2: Full Test Suite in Docker

```powershell
# 1. Build and run all tests (builds certz automatically)
.\test\test-all.ps1 -UseDocker
```

### Scenario 3: CI/CD Pipeline

```powershell
# 1. Build project
dotnet publish src/certz/certz.csproj -c Debug -o debug

# 2. Run nanoserver smoke tests (fast, validates binary compatibility)
docker build -t certz-test-smoke:latest -f Dockerfile.test.nanoserver .
docker run --rm --isolation=process certz-test-smoke:latest

# 3. Run full test suite (comprehensive)
.\test\test-all.ps1 -UseDocker -DockerVerbose
```

## Advanced Usage

### Running Specific Test Suites

All test scripts are available in the Server Core container under `/app/test/`:

```powershell
# Build the image
docker build -t certz-test:latest -f Dockerfile.test.servercore .

# Run container interactively
docker run --rm -it --isolation=process --entrypoint pwsh certz-test:latest

# Inside container, run a specific test suite
pwsh -File ./test/test-create.ps1
pwsh -File ./test/test-lint.ps1
pwsh -File ./test/test-convert.ps1
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

## CI/CD Integration

### GitHub Actions

Create `.github/workflows/test.yml`:

```yaml
name: Certz Tests

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  smoke-test:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      - name: Build project
        run: dotnet publish src/certz/certz.csproj -c Debug -o debug
      - name: Nanoserver smoke tests
        run: |
          docker build -t certz-test-smoke:latest -f Dockerfile.test.nanoserver .
          docker run --rm --isolation=process certz-test-smoke:latest

  full-test:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run full test suite in Docker
        run: .\test\test-all.ps1 -UseDocker -DockerVerbose
      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: test-results
          path: test-results/
```

## Performance Tips

1. **Layer Caching:** Docker caches layers, so subsequent builds are faster
2. **Nanoserver First:** Run nanoserver smoke tests first (faster, catches binary issues early)
3. **Clean Builds:** Run `docker system prune` periodically

## Benefits of Docker Testing

- **Isolation:** No pollution of host certificate stores
- **Consistency:** Same environment across all machines
- **CI/CD Ready:** Easy integration with pipelines
- **No Admin Rights:** Docker handles elevation internally
- **Reproducible:** Same results every time
- **Clean State:** Fresh environment for each run
- **Nanoserver Validation:** Confirms the binary works on minimal Windows

## File Reference

- **Dockerfile.test.nanoserver** - Nanoserver smoke test (bare certz.exe validation)
- **Dockerfile.test.servercore** - Server Core full test suite
- **docker-compose.test.yml** - Compose configuration for both images
- **test/test-nanoserver.cmd** - CMD batch file for nanoserver smoke tests
- **test/test-all.ps1** - PowerShell test runner (uses Server Core in Docker mode)
- **test/test-helper.ps1** - Shared test utilities (container-aware)
- **test/test-*.ps1** - Individual test suites (create, inspect, lint, etc.)
- **.dockerignore** - Files excluded from Docker build context

## Support

For issues or questions:

1. Check this troubleshooting guide
2. Review [testing.md](testing.md) for detailed test documentation
3. Check Docker Desktop logs
4. Ensure Windows containers are enabled

## Version Compatibility

| Component      | Version                 | Notes                                    |
| -------------- | ----------------------- | ---------------------------------------- |
| Docker Desktop | 4.0+                    | Windows containers support               |
| Windows        | 10/11, Server 2019/2022 | Container host                           |
| PowerShell     | 7.4+ (LTS image)        | Server Core base image & script execution |
| Nanoserver     | ltsc2022                | Smoke test target (no PowerShell needed) |
