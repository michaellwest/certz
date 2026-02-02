# certz

A standards-compliant certificate utility built on .NET for Windows, with support for modern cryptographic algorithms and RFC 5280 compliance.

## Quick Start

```bash
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
  --format <text|json>  Output format (default: text)
  --version             Show version information
  -?, -h, --help        Show help and usage information

Commands:
  create dev <domain>    Create a development/server certificate
  create ca              Create a Certificate Authority (CA) certificate
  inspect <source>       Inspect certificate from file, URL, or store
  trust add <file>       Add certificate to trust store
  trust remove           Remove certificate from trust store
  store list             List certificates in a store
  convert                Convert between PFX and PEM formats
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

# Check revocation status (OCSP/CRL)
certz inspect https://github.com --chain --crl

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
# Remove by thumbprint
certz trust remove ABC123DEF456 --force

# Remove by subject pattern
certz trust remove --subject "CN=dev*" --force

# Remove from specific store
certz trust remove ABC123DEF456 --store Root --force

# Interactive removal (prompts for confirmation)
certz trust remove ABC123DEF456
```

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

Convert between PFX and PEM certificate formats.

```bash
# Convert PEM + KEY to PFX
certz convert --cert certificate.crt --key private.key --file output.pfx --password MyPassword

# Convert PFX to PEM files
certz convert --pfx devcert.pfx --password YourPassword --out-cert certificate.cer --out-key private.key
```

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

### Quick Test

Run the test suites:

```powershell
# Test certificate creation
.\test-create.ps1

# Test certificate inspection
.\test-inspect.ps1

# Test trust store operations
.\test-trust.ps1

# Run specific test by ID
.\test-inspect.ps1 -TestId "ins-1.1"
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
