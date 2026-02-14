# certz

A standards-compliant certificate utility built on .NET for Windows, with support for modern cryptographic algorithms and RFC 5280 compliance.

## Quick Start

```bash
# Interactive wizard — guided mode for all operations
certz --guided

# Create a development certificate for localhost
certz create dev localhost

# Create a development certificate and trust it immediately
certz create dev api.local --trust

# Create a Certificate Authority
certz create ca --name "My Dev CA"

# Inspect any certificate (file, URL, or thumbprint)
certz inspect cert.pfx --password MyPassword
certz inspect https://github.com
certz inspect ABC123DEF456 --store Root
```

## Command Reference

```
Description:
  Certz: A Simple Certificate Utility

Usage:
  certz [command] [options]

Options:
  --guided              Launch interactive wizard for any operation
  --format <text|json>  Output format (default: text)
  --version             Show version information
  -?, -h, --help        Show help and usage information

Commands:
  create dev <domain>    Create a development/server certificate
  create ca              Create a Certificate Authority (CA) certificate
  inspect <source>       Inspect certificate from file, URL, or store
  lint <source>          Validate certificate against industry standards
  monitor <sources...>   Monitor certificates for expiration
  renew <source>         Renew an existing certificate with extended validity
  trust add <file>       Add certificate to trust store
  trust remove           Remove certificate from trust store
  store list             List certificates in a store
  convert                Convert between PEM, DER, and PFX formats
```

---

## Certificate Creation

### Development Certificates

Create certificates for local development with modern defaults (ECDSA P-256, 90 days).

```bash
# Basic: Create certificate for localhost
certz create dev localhost

# With custom domain and auto-trust
certz create dev api.local --trust

# With additional Subject Alternative Names
certz create dev myapp.local --san "*.myapp.local" --san "127.0.0.1"

# Signed by your own CA
certz create dev api.local --issuer-cert ca.pfx --issuer-password CaPassword

# Interactive wizard mode
certz create dev localhost --guided

# Output to specific files
certz create dev localhost --file server.pfx --cert server.cer --key server.key
```

**Options:**
| Option | Description |
|--------|-------------|
| `--trust` | Install to Root trust store after creation |
| `--trust-location` | CurrentUser (default) or LocalMachine |
| `--san <name>` | Additional Subject Alternative Names (repeatable) |
| `--days <n>` | Validity period (default: 90, max: 398) |
| `--key-type` | ECDSA-P256 (default), ECDSA-P384, ECDSA-P521, RSA |
| `--key-size` | RSA key size: 2048, 3072 (default), 4096 |
| `--guided` | Launch interactive wizard |
| `--issuer-cert` | Sign with existing CA (PFX or PEM) |
| `--issuer-key` | CA private key (for PEM issuer) |
| `--issuer-password` | Password for CA PFX |
| `--file` | Output PFX filename |
| `--cert` | Output certificate filename |
| `--key` | Output private key filename |
| `--password` | PFX password (auto-generated if not provided) |
| `--ephemeral, -e` | Generate certificate in memory only |
| `--pipe` | Stream certificate to stdout |
| `--pipe-format` | Pipe output format: pem, pfx, cert, key |
| `--pipe-password` | Password for PFX pipe output |

### CA Certificates

Create Certificate Authority certificates for signing other certificates.

```bash
# Create a Root CA
certz create ca --name "Development Root CA"

# Create and trust the CA
certz create ca --name "Dev CA" --trust

# With specific validity and path length
certz create ca --name "My CA" --days 3650 --path-length 1

# With CRL and OCSP URLs
certz create ca --name "My CA" --crl-url http://crl.example.com/ca.crl --ocsp-url http://ocsp.example.com

# Interactive wizard mode
certz create ca --guided
```

**Options:**
| Option | Description |
|--------|-------------|
| `--name` | CA Common Name (required) |
| `--trust` | Install to Root trust store |
| `--days <n>` | Validity period (default: 3650 / ~10 years) |
| `--path-length <n>` | Maximum chain depth (-1 = unlimited) |
| `--crl-url` | CRL Distribution Point URL |
| `--ocsp-url` | OCSP responder URL |
| `--guided` | Launch interactive wizard |
| `--ephemeral, -e` | Generate certificate in memory only (no files written) |
| `--pipe` | Stream certificate to stdout (no files written) |
| `--pipe-format` | Pipe output format: pem (default), pfx, cert, key |
| `--pipe-password` | Password for PFX pipe output |

---

## Ephemeral & Pipe Modes

### Ephemeral Mode

Generate certificates in memory without writing files to disk:

```bash
# Create ephemeral certificate (displays details, no files)
certz create dev example.com --ephemeral

# Ephemeral with custom options
certz create dev app.local --ephemeral --san "*.app.local" --key-type RSA

# Ephemeral CA certificate
certz create ca --name "Test CA" --ephemeral

# JSON output for scripting
certz create dev test.local --ephemeral --format json
```

**Use cases:**
- Testing certificate settings before committing to files
- CI/CD pipelines without cleanup requirements
- Security-sensitive environments (keys never touch disk)
- Training and demonstrations

### Pipe Mode

Stream certificate content to stdout for piping to other tools:

```bash
# Pipe full PEM (cert + key) to stdout
certz create dev example.com --pipe

# Pipe to kubectl to create Kubernetes secret
certz create dev app.local --pipe | kubectl create secret tls my-cert --cert=/dev/stdin --key=/dev/stdin

# Pipe certificate only (no private key)
certz create dev example.com --pipe --pipe-format cert

# Pipe private key only
certz create dev example.com --pipe --pipe-format key

# Pipe as base64 PFX with specified password
certz create dev example.com --pipe --pipe-format pfx --pipe-password "MySecret"

# Pipe PFX with auto-generated password (password written to stderr)
certz create dev example.com --pipe --pipe-format pfx 2>password.txt > cert.b64
```

**Pipe Formats:**

| Format | Output |
|--------|--------|
| `pem` (default) | Certificate + private key in PEM format |
| `pfx` | Base64-encoded PFX (password required or auto-generated to stderr) |
| `cert` | Certificate only (PEM format) |
| `key` | Private key only (PEM format) |

### Restrictions

Both `--ephemeral` and `--pipe` are mutually exclusive with:
- `--file`, `--cert`, `--key` (file output options)
- `--trust` (cannot install in-memory certificate)
- `--password-file` (no file to protect)

You cannot use both `--ephemeral` and `--pipe` together.

---

## Certificate Inspection

Inspect certificates from files, remote URLs, or the Windows certificate store.

```bash
# Inspect a local file
certz inspect cert.pfx --password MyPassword
certz inspect cert.pem
certz inspect cert.der

# Inspect remote HTTPS certificate
certz inspect https://github.com
certz inspect https://localhost:8443

# Inspect with certificate chain
certz inspect https://github.com --chain

# Detailed chain tree with key info, SANs, signatures
certz inspect https://github.com --chain --tree

# Check revocation status (OCSP/CRL)
certz inspect https://github.com --chain --crl

# Detailed chain with revocation check
certz inspect https://github.com --chain --tree --crl

# Inspect from certificate store by thumbprint
certz inspect ABC123DEF456
certz inspect ABC123DEF456 --store Root --location LocalMachine

# Warn if expiring soon
certz inspect cert.pfx --password Pass --warn 30

# Save certificate to file
certz inspect https://github.com --save github.cer
certz inspect cert.pfx --password Pass --save out.cer --save-key out.key

# Export in DER format
certz inspect cert.pfx --password Pass --save out.der --save-format der

# JSON output for automation
certz inspect cert.pfx --password Pass --format json
```

**Options:**
| Option | Description |
|--------|-------------|
| `--chain` | Show certificate chain tree |
| `--tree` | Show detailed tree with key info, SANs, signatures (requires --chain) |
| `--crl` | Check revocation status (OCSP preferred, CRL fallback) |
| `--warn <days>` | Warn if certificate expires within N days |
| `--save <file>` | Save certificate to file (PEM default) |
| `--save-key <file>` | Save private key to file |
| `--save-format` | Export format: pem (default) or der |
| `--store` | Store name for thumbprint lookup (My, Root, CA) |
| `--location` | Store location (CurrentUser, LocalMachine) |
| `--format` | Output format: text or json |

---

## Trust Store Management

### Add Certificates

Add certificates to the Windows trust store.

```bash
# Add to Root store (CurrentUser)
certz trust add ca.cer --store Root

# Add PFX to trust store
certz trust add cert.pfx --password MyPassword --store Root

# Add to LocalMachine (requires Administrator)
certz trust add ca.cer --store Root --location LocalMachine
```

**Options:**
| Option | Description |
|--------|-------------|
| `--store` | Target store: Root (default), CA, My, TrustedPeople |
| `--location` | CurrentUser (default) or LocalMachine |
| `--password` | Password for PFX files |

### Remove Certificates

Remove certificates from the Windows trust store.

```bash
# Remove by full thumbprint (40 chars)
certz trust remove ABC123DEF456789012345678901234567890ABCD --force

# Remove by partial thumbprint (8+ chars prefix match)
certz trust remove ABC123DE --force

# Remove by subject pattern
certz trust remove --subject "CN=dev*" --force

# Remove from specific store
certz trust remove ABC123DEF456 --store Root --force

# Interactive removal (prompts for confirmation)
certz trust remove ABC123DEF456
```

**Partial Thumbprint Matching:**
- Minimum 8 characters required for partial thumbprint
- Uses prefix matching (StartsWith)
- If multiple certificates match, `--force` is required
- Full 40-character thumbprint performs exact match

**Options:**
| Option | Description |
|--------|-------------|
| `--subject` | Remove certificates matching subject pattern (wildcards supported) |
| `--store` | Target store: Root (default), CA, My, TrustedPeople |
| `--location` | CurrentUser (default) or LocalMachine |
| `--force` | Remove without confirmation (required for multiple matches) |

---

## Store Operations

### List Certificates

List certificates in the Windows certificate store.

```bash
# List certificates in My store
certz store list

# List certificates in Root store
certz store list --store Root

# List from LocalMachine
certz store list --store Root --location LocalMachine

# Show only expired certificates
certz store list --expired

# Show certificates expiring within 30 days
certz store list --expiring 30

# JSON output
certz store list --format json
```

**Options:**
| Option | Description |
|--------|-------------|
| `--store` | Store name: My (default), Root, CA, TrustedPeople, TrustedPublisher |
| `--location` | CurrentUser (default) or LocalMachine |
| `--expired` | Show only expired certificates |
| `--expiring <days>` | Show certificates expiring within N days |
| `--format` | Output format: text or json |

---

## Format Conversion

Convert certificates between PEM, DER, and PFX formats with automatic format detection.

### Simplified Syntax

```bash
certz convert <input> --to <format> [options]
```

### Examples

```bash
# PFX to PEM (extracts certificate and private key)
certz convert server.pfx --to pem --password secret

# PEM to DER (binary format)
certz convert server.pem --to der

# DER to PEM
certz convert server.der --to pem

# PEM to PFX (auto-discovers server.key)
certz convert server.pem --to pfx

# PEM to PFX with explicit key file
certz convert server.pem --to pfx --key private.key

# Custom output path
certz convert server.pfx --to pem --password secret --output /certs/server.pem

# Certificate only (no private key)
certz convert server.pfx --to pem --password secret --include-key:false
```

### Format Detection

The input format is automatically detected:

| Extension | Detected Format |
|-----------|-----------------|
| .pfx, .p12 | PFX (PKCS#12) |
| .der | DER (binary) |
| .pem | PEM (text) |
| .crt, .cer | Auto-detect from content |

### Options

| Option | Description |
|--------|-------------|
| `--to, -t` | Output format: `pem`, `der`, `pfx` (required) |
| `--output, -o` | Output file path (default: auto-generated) |
| `--key` | Private key file (for PFX output) |
| `--password, -p` | Password for PFX input/output |
| `--password-file` | Read/write password from file |
| `--pfx-encryption` | `modern` (default) or `legacy` |
| `--include-key` | Include private key in output |
| `--format` | Display format: `text`, `json` |

### Legacy Syntax

The original flag-based syntax remains supported:

```bash
# PEM + KEY to PFX
certz convert --cert certificate.crt --key private.key --file output.pfx --password MyPassword

# PFX to PEM files
certz convert --pfx devcert.pfx --password YourPassword --out-cert certificate.cer --out-key private.key
```

### Format Reference

| Format | Description | Use Case |
|--------|-------------|----------|
| **PEM** | Base64 text with headers | Web servers, most Linux tools |
| **DER** | Binary ASN.1 encoding | Java keystores, some Windows apps |
| **PFX** | Password-protected bundle | Windows, IIS, certificate export |

---

## Certificate Linting

Validate certificates against industry standards including CA/Browser Forum Baseline Requirements and Mozilla NSS Policy.

```bash
# Lint a certificate file (CA/B Forum rules by default)
certz lint cert.pfx --password MyPassword

# Lint with Mozilla NSS policy (includes CA/B Forum rules)
certz lint cert.pem --policy mozilla

# Lint a remote certificate
certz lint https://example.com

# Lint with development certificate rules (relaxed)
certz lint devcert.pfx --password Pass --policy dev

# Lint all policy sets
certz lint cert.pfx --password Pass --policy all

# Show only errors (filter out warnings and info)
certz lint cert.pfx --password Pass --severity error

# Lint certificate from store
certz lint ABC123DEF456 --store My

# JSON output for CI/CD integration
certz lint cert.pfx --password Pass --format json
```

**Options:**
| Option | Description |
|--------|-------------|
| `--password, -p` | Password for PFX/P12 files |
| `--policy` | Policy set: cabf (default), mozilla, dev, or all |
| `--severity, -s` | Minimum severity to report: info (default), warning, or error |
| `--store` | Certificate store name (My, Root, CA) for thumbprint lookup |
| `--location, -l` | Store location (CurrentUser or LocalMachine) |
| `--format` | Output format: text (default) or json |

### Policy Sets

| Policy | Description |
|--------|-------------|
| `cabf` | CA/Browser Forum Baseline Requirements (default) |
| `mozilla` | Mozilla NSS Policy (includes CA/B Forum rules) |
| `dev` | Relaxed rules for development certificates |
| `all` | All policy checks combined |

### Lint Rules

The lint command checks for common certificate issues:

**CA/B Forum Baseline Requirements:**
- Maximum 398-day validity for leaf certificates
- RSA key size minimum 2048 bits
- SHA-1 signatures prohibited
- Subject Alternative Name required
- Basic Constraints required for CA certificates
- Key Usage extension recommended

**Mozilla NSS Policy:**
- Root CA maximum 25-year validity recommended
- Intermediate CA maximum 10-year validity recommended
- Name Constraints recommended for intermediates

**Development Certificate Checks:**
- Warns if validity exceeds 398 days
- Recommends localhost and 127.0.0.1 in SANs

### Exit Codes

- `0` - All checks passed (no errors)
- `1` - One or more errors found

---

## Certificate Expiration Monitoring

Monitor certificates for expiration across files, directories, URLs, and certificate stores. Ideal for CI/CD pipelines and infrastructure monitoring.

```bash
# Monitor a single certificate file
certz monitor cert.pfx --password MyPassword

# Monitor a directory of certificates
certz monitor ./certs --password MyPassword

# Monitor directory recursively
certz monitor ./certs --recursive --password MyPassword

# Monitor remote URL certificate
certz monitor https://github.com

# Monitor multiple sources at once
certz monitor ./certs https://github.com https://google.com

# Monitor certificate store
certz monitor --store My --location CurrentUser

# Custom warning threshold (default is 30 days)
certz monitor ./certs --warn 90

# Quiet mode - only show certificates within warning threshold
certz monitor ./certs --quiet

# CI/CD integration - fail on warning
certz monitor ./certs --fail-on-warning

# JSON output for automation
certz monitor ./certs --format json

# Use a password map file for directories with mixed passwords
certz monitor ./certs --password-map passwords.txt

# Combine password map with a fallback password
certz monitor ./certs --password-map passwords.txt --password FallbackPass
```

**Password Map File Format:**
```
# Lines starting with # are comments
# Format: glob_pattern=password (first match wins)
prod-*.pfx=Pr0dP@ss!
staging-*.pfx=StagingPass
*.pfx=DefaultPass
```

**Options:**
| Option | Description |
|--------|-------------|
| `--warn, -w <days>` | Warning threshold in days (default: 30) |
| `--recursive, -r` | Scan subdirectories for certificate files |
| `--password, -p` | Password for PFX files (or use env: CERTZ_PASSWORD) |
| `--password-map, --pm` | File mapping glob patterns to PFX passwords (pattern=password per line) |
| `--store, -s` | Certificate store to scan (My, Root, CA) |
| `--location, -l` | Store location (CurrentUser, LocalMachine) |
| `--quiet, -q` | Only output certificates within warning threshold |
| `--fail-on-warning` | Exit with code 1 if certificates within threshold |
| `--format` | Output format: text (default) or json |

### Exit Codes

| Code | Description |
|------|-------------|
| `0` | All certificates valid and outside warning threshold |
| `1` | Certificates expiring within threshold (with `--fail-on-warning`) |
| `2` | Expired certificates found |

### Example Output

**Text Format:**
```
Certificate Expiration Monitor
Threshold: 30 days

╭────────────┬───────╮
│ Status     │ Count │
├────────────┼───────┤
│ Valid      │ 3     │
│ Expiring   │ 1     │
│ Expired    │ 0     │
│ Total      │ 4     │
╰────────────┴───────╯

╭─────────────────────┬─────────────────┬────────────┬──────┬──────────╮
│ Source              │ Subject         │ Expires    │ Days │ Status   │
├─────────────────────┼─────────────────┼────────────┼──────┼──────────┤
│ ./certs/api.pfx     │ api.company.com │ 2026-03-01 │ 21   │ Expiring │
│ ./certs/web.pfx     │ www.company.com │ 2026-06-15 │ 127  │ Valid    │
│ https://example.com │ example.com     │ 2027-01-01 │ 327  │ Valid    │
╰─────────────────────┴─────────────────┴────────────┴──────┴──────────╯
```

**JSON Format:**
```json
{
  "success": true,
  "totalScanned": 4,
  "validCount": 3,
  "expiringCount": 1,
  "expiredCount": 0,
  "skippedCount": 0,
  "warnThreshold": 30,
  "certificates": [
    {
      "source": "./certs/api.pfx",
      "subject": "CN=api.company.com",
      "thumbprint": "ABC123...",
      "notAfter": "2026-03-01T00:00:00Z",
      "daysRemaining": 21,
      "status": "Expiring",
      "isWarning": true
    }
  ]
}
```

---

## Certificate Renewal

Renew an existing certificate with extended validity while preserving its parameters (subject, SANs, key type).

```bash
# Renew a self-signed certificate
certz renew server.pfx --password MyPassword

# Renew with custom validity (max 398 days)
certz renew server.pfx --password MyPassword --days 180

# Renew CA-signed certificate (requires issuer)
certz renew server.pfx --password MyPassword --issuer-cert ca.pfx --issuer-password CaPassword

# Preserve original private key
certz renew server.pfx --password MyPassword --keep-key

# Specify output file and password
certz renew server.pfx --password MyPassword --out server-2024.pfx --out-password NewPassword

# Renew from certificate store (by thumbprint)
certz renew ABC123DEF456 --store My --out renewed.pfx

# JSON output for automation
certz renew server.pfx --password MyPassword --format json
```

**Options:**
| Option | Description |
|--------|-------------|
| `--days, -d` | New validity period in days (default: original, max 398) |
| `--password, -p` | Password for source PFX (or env: CERTZ_PASSWORD) |
| `--out, -o` | Output file path (default: `<original>-renewed.pfx`) |
| `--out-password` | Password for output file (auto-generated if not set) |
| `--keep-key` | Preserve existing private key instead of generating new |
| `--issuer-cert` | CA certificate for re-signing (required for CA-signed certs) |
| `--issuer-key` | CA private key file (PEM format) |
| `--issuer-password` | Password for issuer PFX |
| `--store` | Certificate store name for thumbprint lookup (My, Root, CA) |
| `--location, -l` | Store location (CurrentUser, LocalMachine) |
| `--format` | Output format: text (default) or json |

### Self-Signed vs CA-Signed Renewal

- **Self-signed certificates**: Can be renewed directly without an issuer
- **CA-signed certificates**: Require the original issuer (`--issuer-cert`) to re-sign

The command auto-detects whether a certificate is self-signed by comparing Subject and Issuer fields.

### Exit Codes

| Code | Description |
|------|-------------|
| `0` | Certificate renewed successfully |
| `1` | Source certificate not found or invalid |
| `2` | Cannot renew (missing issuer for CA-signed cert) |

---

## Global Options

These options are available on all commands:

| Option | Description |
|--------|-------------|
| `--format <text\|json>` | Output format for automation |
| `--help` | Show help for a command |
| `--version` | Show version information |

---

## Standards Compliance

certz is designed to meet current industry standards and best practices for certificate generation:

### Cryptographic Standards

#### Key Types and Sizes

- **ECDSA**: P-256, P-384, P-521 curves (NIST SP 800-186)
  - P-256: Equivalent to 3072-bit RSA, recommended for TLS 1.3
  - P-384: Equivalent to 7680-bit RSA
  - P-521: Maximum ECDSA security
- **RSA**: Configurable 2048, 3072, or 4096 bits (default: 3072)
  - 2048 bits: Current minimum standard (NIST SP 800-131A Rev. 2)
  - 3072 bits: **Default** - Recommended for protection beyond 2030 (NIST SP 800-57 Part 1 Rev. 5)
  - 4096 bits: Maximum security for long-lived certificates

#### RSA Signature Padding

- **RSA-PSS** (default): Modern padding scheme, recommended for new certificates
- **PKCS#1 v1.5**: Wider compatibility with older systems

#### Hash Algorithms

- **SHA-256**: Standard for RSA 2048-bit keys
- **SHA-384**: Recommended for RSA 3072-bit keys and ECDSA P-384
- **SHA-512**: Recommended for RSA 4096-bit keys and ECDSA P-521
- **Auto-selection**: Automatically matches hash strength to key size/type

### Certificate Validity (CA/Browser Forum Compliance)

certz enforces [CA/Browser Forum Ballot SC-081v3](https://cabforum.org/2025/04/11/ballot-sc081v3/) validity limits:

- **Current (until March 15, 2026)**: Maximum 398 days
- **After March 15, 2026**: Maximum 200 days
- **After March 15, 2027**: Maximum 100 days
- **After March 15, 2029**: Maximum 47 days

**Default**: 90 days (future-proof and aligned with industry trends)

### RFC 5280 (X.509) Compliance

certz implements all critical RFC 5280 extensions:

#### Mandatory Extensions

- **Subject Key Identifier (2.5.29.14)**: Uniquely identifies the certificate's public key
- **Authority Key Identifier (2.5.29.35)**: Links to the issuing CA's key
- **Basic Constraints (2.5.29.19)**: Identifies CA vs end-entity certificates
- **Key Usage (2.5.29.15)**: Defines permitted cryptographic operations
- **Subject Alternative Names (2.5.29.17)**: Modern standard for certificate identities

#### Optional Extensions

- **Enhanced Key Usage (2.5.29.37)**: Purpose-specific usage (Server Authentication, etc.)
- **CRL Distribution Points (2.5.29.31)**: Revocation checking via CRL
- **Authority Information Access (1.3.6.1.5.5.7.1.1)**: OCSP responder and CA issuer URLs

### Security Features

#### Password Security

- **No default passwords**: Secure random passwords generated if not provided
- **No plaintext storage**: Passwords displayed once with warning to store securely
- **NIST SP 800-63B compliant**: 24-character random passwords with mixed character types

#### Private Key Protection

- **Secure key generation**: Uses platform cryptographic APIs with Microsoft CNG
- **PKCS#8 format**: Standard private key export format
- **Configurable exportability**: Control whether private keys can be exported from certificate store

#### PFX/PKCS#12 Encryption

- **Modern (default)**: AES-256-CBC with SHA-256 and 100,000 iterations
- **Legacy**: 3DES encryption for compatibility with older systems (use `--pfx-encryption legacy`)

### Standards References

- [NIST SP 800-57 Part 1 Rev. 5](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final) - Key Management Recommendations
- [NIST SP 800-131A Rev. 2](https://csrc.nist.gov/pubs/sp/800/131/a/r2/final) - Cryptographic Algorithm Transitions
- [NIST SP 800-186](https://csrc.nist.gov/publications/detail/sp/800/186/final) - Discrete Logarithm-Based Cryptography
- [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) - X.509 Certificate and CRL Profile
- [RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017) - PKCS #1 RSA Cryptography (includes RSA-PSS)
- [CA/Browser Forum Baseline Requirements](https://cabforum.org/working-groups/server/baseline-requirements/)

---

## Testing

Comprehensive testing documentation and automated test scripts are available:

- **[TESTING.md](TESTING.md)** - Complete testing guide
- **test-create.ps1** - Tests for certificate creation
- **test-inspect.ps1** - Tests for certificate inspection
- **test-trust.ps1** - Tests for trust store management
- **test-lint.ps1** - Tests for certificate linting
- **test-monitor.ps1** - Tests for certificate expiration monitoring
- **test-renew.ps1** - Tests for certificate renewal
- **test-ephemeral.ps1** - Tests for ephemeral and pipe modes

### Quick Test

Run the test suites:

```powershell
# Test certificate creation
.\test-create.ps1

# Test certificate inspection
.\test-inspect.ps1

# Test trust store operations
.\test-trust.ps1

# Test certificate linting
.\test-lint.ps1

# Test certificate monitoring
.\test-monitor.ps1

# Test certificate renewal
.\test-renew.ps1

# Test ephemeral and pipe modes
.\test-ephemeral.ps1

# Run specific test by ID
.\test-inspect.ps1 -TestId "ins-1.1"
.\test-lint.ps1 -TestId "lin-1.1"
.\test-monitor.ps1 -TestId "mon-1.1"
.\test-renew.ps1 -TestId "ren-1.1"
```

For detailed testing instructions, see [TESTING.md](TESTING.md).

---

## Migration from v1.x

If you're upgrading from certz v1.x, here's how commands have changed:

| v1.x Command | v2.0 Command |
|--------------|--------------|
| `certz create --is-ca` | `certz create ca --name "CA Name"` |
| `certz create --dns domain` | `certz create dev domain` |
| `certz install --file cert.pfx` | `certz trust add cert.pfx` |
| `certz remove --thumb ABC123` | `certz trust remove ABC123` |
| `certz list` | `certz store list` |
| `certz info --file cert.pfx` | `certz inspect cert.pfx` |
| `certz info --url https://...` | `certz inspect https://...` |
| `certz verify --file cert.pfx` | `certz inspect cert.pfx --chain --crl` |
| `certz export --url https://...` | `certz inspect https://... --save cert.cer` |

The v1.x commands are still available for backwards compatibility but will be removed in a future release.
