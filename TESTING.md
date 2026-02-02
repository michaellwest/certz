# Certz Testing Guide

This guide provides comprehensive documentation on how to test all commands and options available in the certz certificate management tool.

## Prerequisites

- Windows operating system
- Administrator privileges (required for LocalMachine store operations)
- .NET runtime installed
- PowerShell 5.1 or later

## Test Environment Setup

Before running tests, ensure you have a clean test environment:

```powershell
# Run PowerShell as Administrator
# Navigate to the certz directory
cd c:\Projects\github\michaellwest\certz

# Build the project (if needed)
dotnet build
```

## Quick Start - Automated Testing

### v2.0 Test Suites (Recommended)

Run the dedicated test scripts for each command group:

```powershell
# Test certificate creation (create dev, create ca)
.\test-create.ps1

# Test certificate inspection (inspect file, URL, store)
.\test-inspect.ps1

# Test trust store management (trust add, trust remove, store list)
.\test-trust.ps1

# Run specific test by ID
.\test-inspect.ps1 -TestId "ins-1.1"
.\test-trust.ps1 -TestId "tru-1.1"

# Run tests by category
.\test-inspect.ps1 -Category inspect-file
.\test-trust.ps1 -Category trust-add
```

### Legacy Testing (v1.x Commands)

Run the comprehensive test script to validate all legacy features:

```powershell
# From the project root directory (requires Administrator privileges)
.\test-all.ps1
```

This will automatically test all commands and options with detailed output.

### Docker Container Testing (Isolated Environment)

For isolated testing in a containerized environment, use the Docker option.

**Two modes available:**

1. **Standard Mode** (files baked into image - best for CI/CD):
```powershell
# Run tests in a Windows Docker container
.\test-all.ps1 -UseDocker

# Run with verbose output
.\test-all.ps1 -UseDocker -DockerVerbose
```

**Docker Testing Prerequisites:**
- Docker Desktop for Windows installed
- Windows containers enabled in Docker Desktop (switch from Linux containers if needed)
- At least 4GB of RAM allocated to Docker
- Internet connection (for pulling base images on first run)

**Benefits of Docker Testing:**
- Complete isolation from your host system
- No administrator privileges required on host (Docker handles elevation)
- Clean environment for each test run
- No leftover certificates or files on your system
- Consistent test environment across different machines
- Easy CI/CD integration

**Docker Testing Notes:**
- The `-SkipCleanup` flag is ignored in Docker mode (container is ephemeral)
- Test results will be displayed in the console output
- Container is automatically removed after tests complete
- Exit code reflects test success (0) or failure (1)

#### Switching Docker to Windows Containers

If you encounter errors about incompatible image platforms:

1. Right-click Docker Desktop icon in system tray
2. Select "Switch to Windows containers..."
3. Wait for Docker to restart
4. Run the test command again

#### Docker Test Architecture

The Docker testing setup uses:
- **Dockerfile.test** - Specialized test container configuration
- **docker-compose.test.yml** - Docker Compose configuration for test orchestration
- Base image: `mcr.microsoft.com/dotnet/sdk:10.0-nanoserver-ltsc2022`
- Runs as ContainerAdministrator for certificate operations
- Executes the same test-all.ps1 script in isolated environment

---

## v2.0 Command Testing

The following sections document testing for the new v2.0 command structure.

### CREATE DEV Command

Create development certificates with modern defaults.

#### Test: Basic Development Certificate
```powershell
certz create dev localhost
```
**Expected:** Creates `certz-localhost.pfx` with ECDSA P-256 key, 90-day validity.

#### Test: Development Certificate with Trust
```powershell
certz create dev api.local --trust
```
**Expected:** Creates certificate and installs to CurrentUser\Root store.

#### Test: Development Certificate with SANs
```powershell
certz create dev myapp.local --san "*.myapp.local" --san "127.0.0.1"
```
**Expected:** Certificate includes all specified Subject Alternative Names.

#### Test: CA-Signed Development Certificate
```powershell
certz create ca --name "Test CA" --file ca.pfx --password TestPass
certz create dev api.local --issuer-cert ca.pfx --issuer-password TestPass
```
**Expected:** Creates certificate signed by the CA, not self-signed.

### CREATE CA Command

Create Certificate Authority certificates.

#### Test: Basic CA Certificate
```powershell
certz create ca --name "Development Root CA"
```
**Expected:** Creates CA certificate with KeyCertSign, CRLSign key usage.

#### Test: CA Certificate with Trust
```powershell
certz create ca --name "Dev CA" --trust
```
**Expected:** Creates CA and installs to CurrentUser\Root store.

### INSPECT Command

Inspect certificates from various sources.

#### Test: Inspect PFX File
```powershell
certz inspect cert.pfx --password MyPassword
```
**Expected:** Displays certificate details including subject, issuer, validity, key info.

#### Test: Inspect Remote URL
```powershell
certz inspect https://github.com
```
**Expected:** Retrieves and displays remote server certificate.

#### Test: Inspect with Chain
```powershell
certz inspect https://github.com --chain
```
**Expected:** Displays certificate chain tree from root to leaf.

#### Test: Inspect with Revocation Check
```powershell
certz inspect https://github.com --chain --crl
```
**Expected:** Checks OCSP/CRL and displays revocation status.

#### Test: Inspect from Store
```powershell
certz inspect <thumbprint> --store Root
```
**Expected:** Retrieves certificate from Windows store by thumbprint.

#### Test: Save Certificate
```powershell
certz inspect https://github.com --save github.cer
```
**Expected:** Saves certificate to PEM file.

#### Test: Save in DER Format
```powershell
certz inspect cert.pfx --password Pass --save out.der --save-format der
```
**Expected:** Saves certificate in DER binary format.

#### Test: JSON Output
```powershell
certz inspect cert.pfx --password Pass --format json
```
**Expected:** Outputs certificate info as JSON.

### TRUST ADD Command

Add certificates to trust store.

#### Test: Add to Root Store
```powershell
certz trust add ca.cer --store Root
```
**Expected:** Certificate added to CurrentUser\Root store.

#### Test: Add PFX to Store
```powershell
certz trust add cert.pfx --password MyPassword --store Root
```
**Expected:** Certificate from PFX added to store.

#### Test: LocalMachine Requires Admin
```powershell
certz trust add ca.cer --store Root --location LocalMachine
```
**Expected:** Fails with clear error if not running as Administrator.

### TRUST REMOVE Command

Remove certificates from trust store.

#### Test: Remove by Thumbprint
```powershell
certz trust remove <thumbprint> --force
```
**Expected:** Certificate removed from store without prompting.

#### Test: Remove by Subject
```powershell
certz trust remove --subject "CN=dev*" --force
```
**Expected:** All matching certificates removed.

#### Test: Multiple Matches Without Force
```powershell
certz trust remove --subject "CN=test*"
```
**Expected:** Lists matching certificates and requires --force to proceed.

### STORE LIST Command

List certificates in store.

#### Test: List Default Store
```powershell
certz store list
```
**Expected:** Lists certificates in CurrentUser\My store.

#### Test: List Root Store
```powershell
certz store list --store Root
```
**Expected:** Lists certificates in Root store.

#### Test: List Expiring Certificates
```powershell
certz store list --expiring 30
```
**Expected:** Shows only certificates expiring within 30 days.

#### Test: JSON Output
```powershell
certz store list --format json
```
**Expected:** Outputs certificate list as JSON.

---

## Legacy Manual Testing - Command by Command

> **Note:** The following sections document v1.x commands which are still available for backwards compatibility.

### 1. CREATE Command (Legacy)

#### Test 1.1: Create with Default Options
**Purpose:** Verify certificate creation with minimal parameters

```powershell
.\certz.exe create
```

**Expected Results:**
- Creates `devcert.pfx` file
- Creates `devcert.pfx.password.txt` file containing "changeit"
- Certificate valid for 365 days
- Default SANs: *.dev.local, *.localhost, *.test

**Validation:**
```powershell
Test-Path "devcert.pfx"  # Should return True
Get-Content "devcert.pfx.password.txt"  # Should display "changeit"
```

#### Test 1.2: Create with Custom PFX and Password
**Purpose:** Verify custom file name and password

```powershell
.\certz.exe create --f mycert.pfx --p MySecurePass123
```

**Expected Results:**
- Creates `mycert.pfx` file
- Password file contains "MySecurePass123"

#### Test 1.3: Create with Custom SANs
**Purpose:** Verify Subject Alternative Names customization

```powershell
.\certz.exe create --f testcert.pfx --san *.example.com localhost 127.0.0.1 192.168.1.100
```

**Expected Results:**
- Certificate includes all specified DNS names and IP addresses
- Both DNS and IP SANs are properly formatted

#### Test 1.4: Create with Custom Validity Period
**Purpose:** Verify custom certificate expiration

```powershell
.\certz.exe create --f longcert.pfx --days 1825
```

**Expected Results:**
- Certificate valid for approximately 5 years (1825 days)
- Expiration date adjusted to avoid weekends

#### Test 1.5: Create with All Options
**Purpose:** Verify all options work together

```powershell
.\certz.exe create --f fulltest.pfx --c fulltest.cer --k fulltest.key --p ComplexPass456 --san *.dev.local *.test.com 127.0.0.1 --days 730
```

**Expected Results:**
- Creates PFX file (fulltest.pfx)
- Creates PEM certificate file (fulltest.cer)
- Creates PEM key file (fulltest.key)
- All files contain valid certificate data
- Password file created for each output file

#### Test 1.6: Create PEM-Only Certificates
**Purpose:** Verify PEM format generation without PFX

```powershell
.\certz.exe create --c pemonly.cer --k pemonly.key --p PemPass789
```

**Expected Results:**
- Creates only PEM certificate and key files
- No PFX file created
- Password files created for both outputs

#### Test 1.7: Create with Multiple SANs
**Purpose:** Test handling of multiple DNS entries

```powershell
.\certz.exe create --f multisan.pfx --san *.app1.local *.app2.local *.app3.local localhost
```

**Expected Results:**
- Certificate includes all four DNS entries in SAN extension

---

### 2. INSTALL Command

#### Test 2.1: Install to Default Store (My/LocalMachine)
**Purpose:** Verify basic installation

```powershell
# First create a certificate
.\certz.exe create --f install-test.pfx --p InstallPass123

# Install it
.\certz.exe install --f install-test.pfx --p InstallPass123
```

**Expected Results:**
- Certificate installed to Cert:\LocalMachine\My
- Certificate visible in Windows Certificate Manager (certmgr.msc)

**Validation:**
```powershell
Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*dev.local*" }
```

#### Test 2.2: Install to Root Store
**Purpose:** Verify installation to trusted root certificates

```powershell
.\certz.exe install --f install-test.pfx --p InstallPass123 --sn root
```

**Expected Results:**
- Certificate installed to Cert:\LocalMachine\Root
- Certificate trusted as root CA

**Validation:**
```powershell
Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like "*dev.local*" }
```

#### Test 2.3: Install to CurrentUser Store
**Purpose:** Verify user-level installation (no admin required)

```powershell
.\certz.exe install --f install-test.pfx --p InstallPass123 --sl CurrentUser --sn My
```

**Expected Results:**
- Certificate installed to Cert:\CurrentUser\My
- Accessible without admin privileges

**Validation:**
```powershell
Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*dev.local*" }
```

#### Test 2.4: Install with All Store Options
**Purpose:** Test various store combinations

```powershell
# Install to CA store
.\certz.exe install --f install-test.pfx --p InstallPass123 --sn CA --sl LocalMachine

# Install to Trust store
.\certz.exe install --f install-test.pfx --p InstallPass123 --sn Trust --sl CurrentUser
```

---

### 3. LIST Command

#### Test 3.1: List from Default Store
**Purpose:** Verify certificate listing

```powershell
.\certz.exe list
```

**Expected Results:**
- Displays all certificates from Cert:\LocalMachine\My
- Shows thumbprint, subject, and expiration date

#### Test 3.2: List from Root Store
**Purpose:** Verify listing from different store

```powershell
.\certz.exe list --sn root --sl LocalMachine
```

**Expected Results:**
- Displays all root certificates
- Includes system and user-installed certificates

#### Test 3.3: List from CurrentUser Store
**Purpose:** Verify user-level certificate listing

```powershell
.\certz.exe list --sl CurrentUser --sn My
```

**Expected Results:**
- Displays only current user's certificates

#### Test 3.4: List All Store Combinations
**Purpose:** Comprehensive store enumeration

```powershell
.\certz.exe list --sn My --sl LocalMachine
.\certz.exe list --sn Root --sl LocalMachine
.\certz.exe list --sn CA --sl LocalMachine
.\certz.exe list --sn My --sl CurrentUser
```

---

### 4. REMOVE Command

#### Test 4.1: Remove by Thumbprint
**Purpose:** Verify precise certificate removal

```powershell
# Get thumbprint from list
.\certz.exe list --sn root

# Remove specific certificate
.\certz.exe remove --thumb <THUMBPRINT_VALUE> --sn root
```

**Expected Results:**
- Only specified certificate removed
- Other certificates remain

**Validation:**
```powershell
# Certificate should not be found
Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq "<THUMBPRINT_VALUE>" }
```

#### Test 4.2: Remove by Subject
**Purpose:** Verify subject-based removal

```powershell
.\certz.exe remove --subject "*.dev.local" --sn root --sl LocalMachine
```

**Expected Results:**
- All certificates matching "CN=*.dev.local" removed
- May remove multiple certificates if duplicates exist

#### Test 4.3: Remove with CN Prefix Auto-Detection
**Purpose:** Verify automatic CN= prepending

```powershell
# Both should work identically
.\certz.exe remove --subject "*.dev.local" --sn My
.\certz.exe remove --subject "CN=*.dev.local" --sn My
```

**Expected Results:**
- Both commands remove the same certificate(s)

#### Test 4.4: Remove from Different Stores
**Purpose:** Test removal across store locations

```powershell
# Remove from CurrentUser
.\certz.exe remove --subject "*.dev.local" --sl CurrentUser --sn My

# Remove from LocalMachine
.\certz.exe remove --subject "*.dev.local" --sl LocalMachine --sn Root
```

---

### 5. EXPORT Command

#### Test 5.1: Export from Remote URL
**Purpose:** Verify remote certificate download

```powershell
.\certz.exe export --url https://www.github.com --f github.pfx --c github.cer
```

**Expected Results:**
- Downloads certificate from GitHub
- Creates PFX and PEM files
- Password file created with default "changeit"

**Validation:**
```powershell
Test-Path "github.pfx"  # Should return True
Test-Path "github.cer"  # Should return True
```

#### Test 5.2: Export from Remote with Custom Password
**Purpose:** Verify custom password on export

```powershell
.\certz.exe export --url https://www.microsoft.com --f microsoft.pfx --p CustomExportPass
```

**Expected Results:**
- Certificate exported with custom password
- Password file contains "CustomExportPass"

#### Test 5.3: Export from Certificate Store by Thumbprint
**Purpose:** Verify local store export

```powershell
# First install a certificate
.\certz.exe create --f export-source.pfx --p TestPass
.\certz.exe install --f export-source.pfx --p TestPass --sn My

# Get the thumbprint
$thumb = (Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*dev.local*" })[0].Thumbprint

# Export it
.\certz.exe export --thumb $thumb --f exported.pfx --c exported.cer --p ExportPass123
```

**Expected Results:**
- Certificate exported from store to file
- Both PFX and PEM formats created

#### Test 5.4: Export PEM Only from URL
**Purpose:** Verify certificate-only export

```powershell
.\certz.exe export --url https://www.google.com --c google.cer
```

**Expected Results:**
- Only PEM certificate file created
- No PFX file generated

#### Test 5.5: Export Multiple Formats
**Purpose:** Verify all export format options

```powershell
.\certz.exe export --url https://www.amazon.com --f amazon.pfx --c amazon.cer --k amazon.key
```

**Expected Results:**
- PFX, certificate, and key files all created
- All formats contain valid data

---

### 6. CONVERT Command

#### Test 6.1: Convert CER/KEY to PFX
**Purpose:** Verify basic conversion

```powershell
# First create PEM files
.\certz.exe create --c convert-source.cer --k convert-source.key

# Convert to PFX
.\certz.exe convert --c convert-source.cer --k convert-source.key --f converted.pfx --p ConvertPass123
```

**Expected Results:**
- Creates valid PFX file from separate PEM files
- Password protected with specified password

**Validation:**
```powershell
# Try to install the converted certificate
.\certz.exe install --f converted.pfx --p ConvertPass123
```

#### Test 6.2: Convert with Default Password
**Purpose:** Verify default password handling

```powershell
.\certz.exe convert --c convert-source.cer --k convert-source.key --f converted-default.pfx
```

**Expected Results:**
- PFX created with default password "changeit"
- Password file contains "changeit"

#### Test 6.3: Convert CRT Format
**Purpose:** Verify CRT file handling

```powershell
# Rename .cer to .crt
Copy-Item convert-source.cer convert-source.crt

# Convert using .crt extension
.\certz.exe convert --c convert-source.crt --k convert-source.key --f converted-crt.pfx
```

**Expected Results:**
- Accepts both .cer and .crt formats
- Produces valid PFX file

---

## Testing INFO Command

### Test 1: Display Certificate Info from PFX File

**Purpose:** View detailed information about a certificate stored in a PFX file

```powershell
.\certz.exe info --file devcert.pfx --password changeit
```

**Expected Results:**
- Displays certificate subject and issuer
- Shows thumbprint and serial number
- Shows validity period and days remaining
- Displays public key algorithm and size
- Lists Subject Alternative Names (SANs)
- Shows Enhanced Key Usage
- Shows Key Usage flags
- Shows Basic Constraints
- Indicates if private key is present

---

### Test 2: Display Certificate Info from PEM File

**Purpose:** View information about a PEM certificate

```powershell
.\certz.exe info --file devcert.cer
```

**Expected Results:**
- Same detailed information as PFX
- Works with .cer, .crt, and .pem extensions

---

### Test 3: Display Certificate Info from URL

**Purpose:** Retrieve and display information about a remote server's certificate

```powershell
.\certz.exe info --url https://www.github.com
```

**Expected Results:**
- Connects to remote server via HTTPS
- Displays certificate information
- Shows certificate chain details
- Works with any valid HTTPS URL

---

### Test 4: Display Certificate Info from Windows Store

**Purpose:** View information about a certificate in the Windows certificate store

```powershell
# First, get a thumbprint from installed certificates
.\certz.exe list --sn My --sl LocalMachine

# Use the thumbprint to get detailed info
.\certz.exe info --thumbprint ABC123... --sn My --sl LocalMachine
```

**Expected Results:**
- Retrieves certificate from specified store
- Displays full certificate details
- Works with any store location and name

---

## Testing VERIFY Command

### Test 1: Verify Certificate from PFX File

**Purpose:** Validate a certificate's expiration, chain, and trust status

```powershell
.\certz.exe verify --file devcert.pfx --password changeit
```

**Expected Results:**
- Shows validation report header
- Check 1: Expiration status ([PASS]/[WARN]/[FAIL])
- Check 2: Certificate chain validation
- Check 3: Trust status
- Summary: Overall PASS or FAIL

---

### Test 2: Verify with Custom Warning Days

**Purpose:** Set custom threshold for expiration warnings

```powershell
.\certz.exe verify --file devcert.pfx --password changeit --warning-days 60
```

**Expected Results:**
- Uses 60-day threshold instead of default 30 days
- Shows [WARN] if certificate expires within 60 days
- Otherwise same as Test 1

---

### Test 3: Verify with Revocation Check

**Purpose:** Check if certificate has been revoked (requires network access)

```powershell
.\certz.exe verify --file devcert.pfx --password changeit --check-revocation
```

**Expected Results:**
- Performs all standard validation checks
- Additional Check 4: Revocation status
- May show [WARN] if revocation server is offline
- Shows [FAIL] if certificate is revoked

---

### Test 4: Verify Certificate from Windows Store

**Purpose:** Validate a certificate installed in the certificate store

```powershell
# Get thumbprint from list
.\certz.exe list --sn My --sl LocalMachine

# Verify the certificate
.\certz.exe verify --thumbprint ABC123... --sn My --sl LocalMachine
```

**Expected Results:**
- Retrieves certificate from store
- Performs validation checks
- Displays validation report

---

### Test 5: Verify Expired Certificate

**Purpose:** Test validation behavior with an expired certificate

```powershell
# Create a certificate that expired yesterday
.\certz.exe create --file expired.pfx --days -1

# Verify it
.\certz.exe verify --file expired.pfx
```

**Expected Results:**
- Check 1 shows [FAIL] for expiration
- Shows "Expired X days ago"
- Overall summary shows [FAIL]

---

## Testing Enhanced CONVERT Command (PFX to PEM)

### Test 1: Convert PFX to Both Certificate and Key

**Purpose:** Extract both certificate and private key from PFX

```powershell
.\certz.exe convert --pfx devcert.pfx --password changeit --out-cert output.cer --out-key output.key
```

**Expected Results:**
- Creates output.cer (PEM certificate)
- Creates output.key (PEM private key in PKCS#8 format)
- Shows success message with file names
- Both files are in PEM text format

---

### Test 2: Convert PFX to Certificate Only

**Purpose:** Extract only the certificate without the private key

```powershell
.\certz.exe convert --pfx devcert.pfx --password changeit --out-cert output.cer
```

**Expected Results:**
- Creates output.cer
- Does NOT create .key file
- Shows success message

---

### Test 3: Convert PFX to Private Key Only

**Purpose:** Extract only the private key

```powershell
.\certz.exe convert --pfx devcert.pfx --password changeit --out-key output.key
```

**Expected Results:**
- Creates output.key
- Does NOT create .cer file
- Shows success message

---

### Test 4: Round-Trip Conversion (PFX → PEM → PFX)

**Purpose:** Verify bidirectional conversion works correctly

```powershell
# Step 1: PFX to PEM
.\certz.exe convert --pfx original.pfx --password OrigPass --out-cert intermediate.cer --out-key intermediate.key

# Step 2: PEM back to PFX
.\certz.exe convert --cert intermediate.cer --key intermediate.key --pfx final.pfx --password FinalPass

# Step 3: Verify the final PFX
.\certz.exe info --file final.pfx --password FinalPass
```

**Expected Results:**
- Both conversions succeed
- Final PFX is valid
- INFO command shows expected certificate details
- Certificate properties match original

---

### Test 5: Error Handling - PFX Without Private Key

**Purpose:** Test conversion when PFX has no private key

```powershell
# Export a certificate without private key (from URL)
.\certz.exe export --url https://www.github.com --file noprivatekey.pfx

# Try to extract private key (should fail)
.\certz.exe convert --pfx noprivatekey.pfx --out-key test.key
```

**Expected Results:**
- Shows error message: "PFX file does not contain a private key"
- Exit code indicates failure
- No .key file is created

---

### Test 6: Verify Conversion Parameter Combinations

**Purpose:** Test various valid and invalid parameter combinations

```powershell
# Valid: PEM to PFX (original functionality)
.\certz.exe convert --cert test.cer --key test.key --pfx output.pfx

# Valid: PFX to PEM (new functionality)
.\certz.exe convert --pfx test.pfx --out-cert output.cer --out-key output.key

# Invalid: Missing output parameters
.\certz.exe convert --pfx test.pfx  # Should show error with usage hint

# Invalid: Mixing conversion modes
.\certz.exe convert --cert test.cer --pfx output.pfx --out-cert other.cer  # Should fail
```

**Expected Results:**
- Valid combinations succeed
- Invalid combinations show helpful error messages
- Error messages explain correct usage for each conversion direction

---

## Error Condition Testing

### Test Invalid Inputs

#### Missing Required Parameters
```powershell
# Should fail - no cert/file specified
.\certz.exe create --k only-key.key

# Should fail - no key specified when cert is provided
.\certz.exe create --c only-cert.cer

# Should fail - missing required cert
.\certz.exe convert --k somekey.key --f output.pfx

# Should fail - missing required key
.\certz.exe convert --c somecert.cer --f output.pfx
```

#### Invalid File Paths
```powershell
# Should fail gracefully
.\certz.exe install --f nonexistent.pfx --p password

# Should fail gracefully
.\certz.exe convert --c missing.cer --k missing.key --f output.pfx
```

#### Invalid Store Names
```powershell
# Should fail - invalid store name
.\certz.exe list --sn InvalidStoreName
```

#### Invalid URL Format
```powershell
# Should fail - not HTTPS
.\certz.exe export --url http://www.example.com --f test.pfx

# Should fail - invalid URL
.\certz.exe export --url not-a-valid-url --f test.pfx
```

---

## Integration Testing Scenarios

### Scenario 1: Complete Certificate Lifecycle
**Purpose:** Test create → install → list → export → remove workflow

```powershell
# 1. Create certificate
.\certz.exe create --f lifecycle.pfx --p LifecyclePass --c lifecycle.cer --k lifecycle.key

# 2. Install to store
.\certz.exe install --f lifecycle.pfx --p LifecyclePass --sn My

# 3. List and verify
.\certz.exe list --sn My

# 4. Export from store
$thumb = (Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*dev.local*" })[0].Thumbprint
.\certz.exe export --thumb $thumb --f lifecycle-export.pfx

# 5. Remove from store
.\certz.exe remove --thumb $thumb --sn My

# 6. Verify removal
.\certz.exe list --sn My
```

### Scenario 2: Multi-Store Operations
**Purpose:** Test certificate in multiple stores

```powershell
.\certz.exe create --f multi.pfx --p MultiPass

# Install to multiple stores
.\certz.exe install --f multi.pfx --p MultiPass --sn My --sl LocalMachine
.\certz.exe install --f multi.pfx --p MultiPass --sn Root --sl LocalMachine
.\certz.exe install --f multi.pfx --p MultiPass --sn My --sl CurrentUser

# List all locations
.\certz.exe list --sn My --sl LocalMachine
.\certz.exe list --sn Root --sl LocalMachine
.\certz.exe list --sn My --sl CurrentUser

# Remove from all
.\certz.exe remove --subject "*.dev.local" --sn My --sl LocalMachine
.\certz.exe remove --subject "*.dev.local" --sn Root --sl LocalMachine
.\certz.exe remove --subject "*.dev.local" --sn My --sl CurrentUser
```

### Scenario 3: Format Conversion Chain
**Purpose:** Test PFX → PEM → PFX conversion

```powershell
# Create original PFX
.\certz.exe create --f original.pfx --p OriginalPass

# Export to PEM
$thumb = (Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*dev.local*" })[0].Thumbprint
.\certz.exe export --thumb $thumb --c intermediate.cer --k intermediate.key

# Convert back to PFX
.\certz.exe convert --c intermediate.cer --k intermediate.key --f final.pfx --p FinalPass

# Verify both PFX files work
.\certz.exe install --f original.pfx --p OriginalPass --sn My
.\certz.exe install --f final.pfx --p FinalPass --sn My
```

---

## Performance Testing

### Test Large SAN Lists
```powershell
.\certz.exe create --f large-san.pfx --san *.domain1.com *.domain2.com *.domain3.com *.domain4.com *.domain5.com localhost 127.0.0.1 192.168.1.1 10.0.0.1
```

### Test Long Validity Periods
```powershell
.\certz.exe create --f long-lived.pfx --days 3650  # 10 years
```

---

## Security Testing

### Test Password Protection
```powershell
# Create with strong password
.\certz.exe create --f secure.pfx --p "StrongP@ssw0rd!123"

# Verify password file is created
Get-Content "secure.pfx.password.txt"

# Verify wrong password fails
.\certz.exe install --f secure.pfx --p "WrongPassword"  # Should fail
```

### Test Certificate Validation
```powershell
# Export from trusted site
.\certz.exe export --url https://www.microsoft.com --f microsoft.pfx

# Verify certificate chain
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("microsoft.pfx", "changeit")
$cert.Verify()  # Should return True for trusted site
```

---

## Cleanup After Testing

Remove all test certificates and files:

```powershell
# Remove from stores
.\certz.exe remove --subject "*.dev.local" --sn My --sl LocalMachine
.\certz.exe remove --subject "*.dev.local" --sn Root --sl LocalMachine
.\certz.exe remove --subject "*.dev.local" --sn My --sl CurrentUser

# Remove test files
Get-ChildItem -Path . -File | Where-Object {
    $_.Name -like "*.pfx" -or
    $_.Name -like "*.cer" -or
    $_.Name -like "*.crt" -or
    $_.Name -like "*.key" -or
    $_.Name -like "*.password.txt"
} | Remove-Item
```

---

## Troubleshooting

### Common Issues and Solutions

**Issue:** "Access Denied" when installing to LocalMachine
- **Solution:** Run PowerShell as Administrator

**Issue:** Certificate not found in store after installation
- **Solution:** Check store name and location match the install command

**Issue:** "Password is incorrect" error
- **Solution:** Check the .password.txt file for the actual password

**Issue:** Remote certificate export fails
- **Solution:** Ensure URL uses HTTPS (port 443 required)

**Issue:** Convert command fails with PEM files
- **Solution:** Verify both cert and key files are in PEM format

---

## Expected Test Results Summary

| Command | Test Cases | Expected Success Rate |
|---------|-----------|----------------------|
| CREATE  | 7 test scenarios | 100% |
| INSTALL | 4 test scenarios | 100% with admin rights |
| LIST    | 4 test scenarios | 100% |
| REMOVE  | 4 test scenarios | 100% |
| EXPORT  | 5 test scenarios | 100% with network access |
| CONVERT | 9 test scenarios | 100% |
| INFO    | 4 test scenarios | 100% |
| VERIFY  | 5 test scenarios | 100% |

---

## Continuous Testing

For ongoing development, run the automated test suite:

### Local Testing
```powershell
# Run all tests locally
.\test-all.ps1

# Run with verbose output
.\test-all.ps1 -Verbose

# Check for failures
echo $LASTEXITCODE
```

### Docker Testing (Recommended for CI/CD)
```powershell
# Run tests in isolated Docker container
.\test-all.ps1 -UseDocker

# CI/CD pipeline example
.\test-all.ps1 -UseDocker -DockerVerbose
if ($LASTEXITCODE -ne 0) {
    Write-Error "Tests failed!"
    exit 1
}
```

### CI/CD Integration Examples

**GitHub Actions:**
```yaml
name: Test Certz

on: [push, pull_request]

jobs:
  test:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run tests in Docker
        run: .\test-all.ps1 -UseDocker -DockerVerbose
```

**Azure DevOps:**
```yaml
steps:
- task: PowerShell@2
  displayName: 'Run Certz Tests'
  inputs:
    targetType: 'inline'
    script: |
      .\test-all.ps1 -UseDocker -DockerVerbose
      if ($LASTEXITCODE -ne 0) {
        throw "Tests failed"
      }
```

A successful test run should:
- Create all expected files
- Install/remove certificates correctly
- Display clear success/failure messages
- Clean up temporary files (local mode only)
- Return exit code 0
