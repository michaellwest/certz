# Certz CLI Specification

**Version:** 2.0
**Generated:** 2026-02-09
**Source:** Analyzed from certz source code

This document serves as the authoritative specification for the `certz` CLI tool, derived entirely from the codebase implementation.

---

## Table of Contents

- [Global Options](#global-options)
- [Command Reference](#command-reference)
  - [create dev](#create-dev)
  - [create ca](#create-ca)
  - [create (legacy)](#create-legacy)
  - [inspect](#inspect)
  - [lint](#lint)
  - [monitor](#monitor)
  - [renew](#renew)
  - [convert](#convert)
  - [trust add](#trust-add)
  - [trust remove](#trust-remove)
  - [store list](#store-list)
  - [install (legacy)](#install-legacy)
  - [list (legacy)](#list-legacy)
  - [remove (legacy)](#remove-legacy)
  - [info (legacy)](#info-legacy)
  - [verify (legacy)](#verify-legacy)
  - [export (legacy)](#export-legacy)
- [Type Definitions](#type-definitions)
- [Default Values](#default-values)
- [Logic Flows](#logic-flows)
- [Project Quirks and Constraints](#project-quirks-and-constraints)
- [Exit Codes](#exit-codes)
- [Usage Examples](#usage-examples)

---

## Global Options

These options are available on all commands:

| Option | Aliases | Type | Default | Description |
|--------|---------|------|---------|-------------|
| `--format` | `--fmt` | string | `text` | Output format: `text` or `json` |
| `--version` | | flag | | Show version information |
| `--help` | `-?`, `-h` | flag | | Show help and usage information |

---

## Command Reference

### create dev

Creates a development/server certificate.

**Syntax:**
```
certz create dev <domain> [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `domain` | Yes (unless `--guided`) | Primary domain name for the certificate |

**Options:**

| Option | Aliases | Type | Default | Description |
|--------|---------|------|---------|-------------|
| `--guided` | `-g` | bool | `false` | Launch interactive wizard mode |
| `--trust` | `-t` | bool | `false` | Install to Root trust store after creation |
| `--trust-location` | `--tl` | StoreLocation | `CurrentUser` | Trust store location: `CurrentUser` or `LocalMachine` |
| `--san` | | string[] | | Additional Subject Alternative Names (repeatable) |
| `--days` | | int | `90` | Validity period in days (max: 398, enforced) |
| `--key-type` | `--kt` | string | `ECDSA-P256` | Key type: `RSA`, `ECDSA-P256`, `ECDSA-P384`, `ECDSA-P521` |
| `--key-size` | `--ks` | int | `3072` | RSA key size: `2048`, `3072`, `4096` |
| `--hash-algorithm` | `--hash` | string | `auto` | Hash algorithm: `auto`, `SHA256`, `SHA384`, `SHA512` |
| `--rsa-padding` | `--rp` | string | `pss` | RSA padding: `pss` (modern) or `pkcs1` (compatibility) |
| `--pfx-encryption` | `--pe` | string | `modern` | PFX encryption: `modern` (AES-256) or `legacy` (3DES) |
| `--file` | `--f`, `--pkcs12` | FileInfo | `<domain>.pfx` | Output PFX filename |
| `--cert` | `--c` | FileInfo | | Output certificate filename (PEM) |
| `--key` | `--k` | FileInfo | | Output private key filename (PEM) |
| `--password` | `--pass`, `--p` | string | auto-generated | Password for PFX file |
| `--password-file` | `--pf` | FileInfo | | File to write generated password |
| `--issuer-cert` | | FileInfo | | Sign with existing CA (PFX or PEM) |
| `--issuer-key` | | FileInfo | | CA private key (for PEM issuer) |
| `--issuer-password` | | string | | Password for CA PFX |
| `--ephemeral` | `-e` | bool | `false` | Generate certificate in memory only |
| `--pipe` | | bool | `false` | Stream certificate to stdout |
| `--pipe-format` | | string | `pem` | Pipe output format: `pem`, `pfx`, `cert`, `key` |
| `--pipe-password` | | string | | Password for PFX pipe output |

**Mutual Exclusivity Constraints:**
- `--ephemeral` and `--pipe` cannot be used together
- `--ephemeral`/`--pipe` cannot be used with `--file`, `--cert`, `--key`, `--trust`, or `--password-file`

---

### create ca

Creates a Certificate Authority (CA) certificate.

**Syntax:**
```
certz create ca --name <name> [options]
```

**Options:**

| Option | Aliases | Type | Default | Description |
|--------|---------|------|---------|-------------|
| `--name` | | string | **required** | CA Common Name |
| `--guided` | `-g` | bool | `false` | Launch interactive wizard mode |
| `--trust` | `-t` | bool | `false` | Install to Root trust store |
| `--trust-location` | `--tl` | StoreLocation | `CurrentUser` | Trust store location |
| `--days` | | int | `3650` | Validity period (~10 years) |
| `--path-length` | | int | `-1` | Path length constraint (-1 = unlimited) |
| `--key-type` | `--kt` | string | `ECDSA-P256` | Key type |
| `--key-size` | `--ks` | int | `3072` | RSA key size |
| `--hash-algorithm` | `--hash` | string | `auto` | Hash algorithm |
| `--rsa-padding` | `--rp` | string | `pss` | RSA signature padding |
| `--pfx-encryption` | `--pe` | string | `modern` | PFX encryption mode |
| `--crl-url` | | string | | CRL Distribution Point URL |
| `--ocsp-url` | | string | | OCSP responder URL |
| `--ca-issuers-url` | | string | | CA Issuers URL |
| `--file` | `--f`, `--pkcs12` | FileInfo | `<name>.pfx` | Output PFX filename |
| `--cert` | `--c` | FileInfo | | Output certificate filename |
| `--key` | `--k` | FileInfo | | Output private key filename |
| `--password` | `--pass`, `--p` | string | auto-generated | PFX password |
| `--password-file` | `--pf` | FileInfo | | Password output file |
| `--ephemeral` | `-e` | bool | `false` | In-memory only |
| `--pipe` | | bool | `false` | Stream to stdout |
| `--pipe-format` | | string | `pem` | Pipe output format |
| `--pipe-password` | | string | | Pipe PFX password |

---

### create (legacy)

Legacy create command for backward compatibility.

**Syntax:**
```
certz create [options]
```

**Options:**

| Option | Aliases | Type | Default | Description |
|--------|---------|------|---------|-------------|
| `--file` | `--f`, `--pkcs12` | FileInfo | `devcert.pfx` | Output PFX file |
| `--cert` | `--c` | FileInfo | | Output certificate file |
| `--key` | `--k` | FileInfo | | Output key file |
| `--password` | `--pass`, `--p` | string | auto-generated | PFX password |
| `--password-file` | `--pf` | FileInfo | | Password output file |
| `--dns` | `--san` | string[] | `*.dev.local, *.localhost, *.test` | Subject Alternative Names |
| `--days` | | int | `90` | Validity period |
| `--key-size` | `--ks` | int | `3072` | RSA key size |
| `--hash-algorithm` | `--hash` | string | `auto` | Hash algorithm |
| `--key-type` | `--kt` | string | `ECDSA-P256` | Key type |
| `--rsa-padding` | `--rp` | string | `pss` | RSA padding |
| `--pfx-encryption` | `--pe` | string | `modern` | PFX encryption |
| `--is-ca` | | bool | `false` | Generate CA certificate |
| `--path-length` | | int | `-1` | CA path length constraint |
| `--crl-url` | | string | | CRL Distribution Point |
| `--ocsp-url` | | string | | OCSP responder URL |
| `--ca-issuers-url` | | string | | CA Issuers URL |
| `--subject-o` | `--o` | string | | Subject Organization |
| `--subject-ou` | `--ou` | string | | Subject Organizational Unit |
| `--subject-c` | `--c` | string | | Subject Country (2-letter code) |
| `--subject-st` | `--st` | string | | Subject State/Province |
| `--subject-l` | `--l` | string | | Subject Locality |

**Validation:** Both `--cert` and `--key` must be specified together, or neither.

---

### inspect

Inspects certificates from files, URLs, or certificate stores.

**Syntax:**
```
certz inspect <source> [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `source` | Yes | File path, URL (`https://...`), or certificate thumbprint |

**Options:**

| Option | Aliases | Type | Default | Description |
|--------|---------|------|---------|-------------|
| `--password` | `--pass`, `--p` | string | | Password for PFX files |
| `--chain` | `-c` | bool | `false` | Show certificate chain |
| `--tree` | `-t` | bool | `false` | Show detailed tree (implies `--chain`) |
| `--crl` | | bool | `false` | Check revocation status (OCSP/CRL) |
| `--warn` | `-w` | int? | | Warn if expires within N days |
| `--save` | | string | | Save certificate to file |
| `--save-key` | | string | | Save private key to file |
| `--save-format` | | string | `pem` | Export format: `pem` or `der` |
| `--store` | `-s` | string | | Store name (My, Root, CA) - forces thumbprint lookup |
| `--location` | `-l` | string | | Store location (CurrentUser, LocalMachine) |

**Source Auto-Detection Priority:**
1. Starts with `https://` -> URL inspection
2. `--store` provided -> Thumbprint lookup
3. File exists at path -> File inspection
4. 40-char hex string -> Thumbprint lookup (default store: My)
5. Otherwise -> File not found error

---

### lint

Validates certificates against industry standards.

**Syntax:**
```
certz lint <source> [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `source` | Yes | File path, URL, or thumbprint |

**Options:**

| Option | Aliases | Type | Default | Description |
|--------|---------|------|---------|-------------|
| `--password` | `--pass`, `--p` | string | | Password for PFX files |
| `--policy` | `-p` | string | `cabf` | Policy set: `cabf`, `mozilla`, `dev`, `all` |
| `--severity` | `-s` | string | `info` | Minimum severity: `info`, `warning`, `error` |
| `--store` | | string | | Store name for thumbprint lookup |
| `--location` | `-l` | string | | Store location |

**Policy Sets:**
- `cabf`: CA/Browser Forum Baseline Requirements
- `mozilla`: Mozilla NSS Policy (includes CA/B Forum rules)
- `dev`: Relaxed rules for development certificates
- `all`: All policy checks combined

---

### monitor

Monitors certificates for expiration.

**Syntax:**
```
certz monitor <sources...> [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `sources` | Yes (or `--store`) | Files, directories, or URLs to scan |

**Options:**

| Option | Aliases | Type | Default | Description |
|--------|---------|------|---------|-------------|
| `--warn` | `-w` | int | `30` | Warning threshold in days |
| `--recursive` | `-r` | bool | `false` | Scan subdirectories |
| `--password` | `--pass`, `--p` | string | env: `CERTZ_PASSWORD` | Password for PFX files |
| `--store` | `-s` | string | | Certificate store to scan |
| `--location` | `-l` | string | | Store location |
| `--quiet` | `-q` | bool | `false` | Only show certificates within threshold |
| `--fail-on-warning` | | bool | `false` | Exit code 1 if certificates within threshold |

---

### renew

Renews an existing certificate with extended validity.

**Syntax:**
```
certz renew <source> [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `source` | Yes | Existing certificate (file path or thumbprint) |

**Options:**

| Option | Aliases | Type | Default | Description |
|--------|---------|------|---------|-------------|
| `--days` | `-d` | int? | original | New validity period (max 398) |
| `--password` | `--pass`, `--p` | string | env: `CERTZ_PASSWORD` | Source PFX password |
| `--out` | `-o` | FileInfo | `<original>-renewed.pfx` | Output file path |
| `--out-password` | | string | auto-generated | Output file password |
| `--keep-key` | | bool | `false` | Preserve existing private key |
| `--issuer-cert` | | FileInfo | | CA certificate for re-signing |
| `--issuer-key` | | FileInfo | | CA private key (PEM format) |
| `--issuer-password` | | string | | Issuer PFX password |
| `--store` | | string | | Store name for thumbprint lookup |
| `--location` | `-l` | string | | Store location |

---

### convert

Converts between certificate formats (PEM, DER, PFX).

**Syntax (Simplified):**
```
certz convert <input> --to <format> [options]
```

**Syntax (Legacy):**
```
certz convert --cert <file> --key <file> --pfx <output>
certz convert --pfx <file> --out-cert <output> --out-key <output>
```

**Arguments (Simplified):**

| Argument | Required | Description |
|----------|----------|-------------|
| `input` | Yes (simplified) | Input certificate file (format auto-detected) |

**Options (Simplified Interface):**

| Option | Aliases | Type | Default | Description |
|--------|---------|------|---------|-------------|
| `--to` | `-t` | string | **required** | Output format: `pem`, `der`, `pfx` |
| `--output` | `-o` | FileInfo | auto-generated | Output file path |
| `--key` | `--k` | FileInfo | | Private key file (for PFX output) |
| `--password` | `--pass`, `--p` | string | | Password for PFX input/output |
| `--password-file` | `--pf` | FileInfo | | Password file |
| `--pfx-encryption` | `--pe` | string | `modern` | PFX encryption mode |
| `--include-key` | | bool | `true` | Include private key in output |

**Options (Legacy Interface):**

| Option | Aliases | Type | Description |
|--------|---------|------|-------------|
| `--cert` | `--c` | FileInfo | Input certificate file |
| `--key` | `--k` | FileInfo | Input private key file |
| `--file` | `--f`, `--pfx` | FileInfo | PFX file (input or output) |
| `--out-cert` | `--oc` | FileInfo | Output certificate file |
| `--out-key` | `--ok` | FileInfo | Output private key file |

**Format Auto-Detection:**

| Extension | Detected Format |
|-----------|-----------------|
| `.pfx`, `.p12` | PFX (PKCS#12) |
| `.der` | DER (binary) |
| `.pem` | PEM (text) |
| `.crt`, `.cer` | Auto-detect from content |

---

### trust add

Adds a certificate to the Windows trust store.

**Syntax:**
```
certz trust add <file> [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `file` | Yes | Certificate file to add (PFX, PEM, DER) |

**Options:**

| Option | Aliases | Type | Default | Description |
|--------|---------|------|---------|-------------|
| `--password` | `--pass`, `--p` | string | | Password for PFX files |
| `--store` | `-s` | string | `Root` | Target store: `Root`, `CA`, `My`, `TrustedPeople` |
| `--location` | `-l` | string | `CurrentUser` | Store location (LocalMachine requires admin) |

---

### trust remove

Removes certificates from the Windows trust store.

**Syntax:**
```
certz trust remove [thumbprint] [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `thumbprint` | Conditional | Certificate thumbprint (full 40-char or partial 8+ char prefix) |

**Options:**

| Option | Aliases | Type | Default | Description |
|--------|---------|------|---------|-------------|
| `--subject` | | string | | Remove by subject pattern (wildcards supported) |
| `--store` | `-s` | string | `Root` | Target store |
| `--location` | `-l` | string | `CurrentUser` | Store location |
| `--force` | `-f` | bool | `false` | Remove without confirmation (required for multiple matches) |

**Thumbprint Matching:**
- Minimum 8 characters required for partial matching
- Uses prefix matching (StartsWith, case-insensitive)
- Full 40-character thumbprint performs exact match
- Multiple matches require `--force` flag

---

### store list

Lists certificates in a Windows certificate store.

**Syntax:**
```
certz store list [options]
```

**Options:**

| Option | Aliases | Type | Default | Description |
|--------|---------|------|---------|-------------|
| `--store` | `-s` | string | `My` | Store name: `My`, `Root`, `CA`, `TrustedPeople`, `TrustedPublisher` |
| `--location` | `-l` | string | `CurrentUser` | Store location |
| `--expired` | | bool | `false` | Show only expired certificates |
| `--expiring` | | int? | | Show certificates expiring within N days |

---

### install (legacy)

Legacy command for installing certificates to the Windows store.

**Syntax:**
```
certz install --file <file> [options]
```

**Options:**

| Option | Aliases | Type | Default | Description |
|--------|---------|------|---------|-------------|
| `--file` | `--f`, `--pkcs12`, `--cert`, `--c` | FileInfo | **required** | Certificate file to install |
| `--password` | `--pass`, `--p` | string | | Password for PFX |
| `--storename` | `--sn` | StoreName | `My` | Target store name |
| `--storelocation` | `--sl` | StoreLocation | `LocalMachine` | Target store location |
| `--exportable` | `--exp` | bool | `true` | Allow private key export |

---

### list (legacy)

Legacy command for listing certificates (see `store list`).

---

### remove (legacy)

Legacy command for removing certificates (see `trust remove`).

---

### info (legacy)

Legacy command for certificate info (see `inspect`).

---

### verify (legacy)

Legacy command for certificate verification (see `inspect --chain --crl`).

---

### export (legacy)

Legacy command for exporting certificates (see `inspect --save`).

---

## Type Definitions

### StoreName (System.Security.Cryptography.X509Certificates)

Used for specifying Windows certificate store names.

| Value | Description |
|-------|-------------|
| `My` | Personal certificates (default for many operations) |
| `Root` | Trusted Root Certification Authorities |
| `CA` | Intermediate Certification Authorities |
| `TrustedPeople` | Trusted People |
| `TrustedPublisher` | Trusted Publishers |

### StoreLocation (System.Security.Cryptography.X509Certificates)

Used for specifying Windows certificate store location.

| Value | Description |
|-------|-------------|
| `CurrentUser` | User-specific store (no admin required) |
| `LocalMachine` | System-wide store (requires administrator) |

### FormatType (certz.Models)

Used for certificate file format detection and conversion.

| Value | Description |
|-------|-------------|
| `Pem` | Base64 with BEGIN/END headers |
| `Der` | Binary ASN.1 encoding |
| `Pfx` | PKCS#12 password-protected bundle |
| `Unknown` | Format could not be determined |

### LintSeverity (certz.Models)

Used for categorizing lint findings.

| Value | Numeric | Description |
|-------|---------|-------------|
| `Info` | 0 | Informational finding |
| `Warning` | 1 | Warning-level finding |
| `Error` | 2 | Error-level finding (causes lint failure) |

### InspectSource (certz.Models)

Used internally for source type detection.

| Value | Description |
|-------|-------------|
| `File` | Local file system |
| `Url` | Remote HTTPS URL |
| `Store` | Windows certificate store (thumbprint lookup) |

### CertificateFileType (certz.Models)

Used for specifying output file types.

| Value | Description |
|-------|-------------|
| `Pfx` | PKCS#12 format (includes private key) |
| `PemCer` | PEM-encoded certificate only |
| `PemKey` | PEM-encoded private key only |

---

## Default Values

### Certificate Creation Defaults

| Parameter | Dev Certificate | CA Certificate |
|-----------|-----------------|----------------|
| Validity (days) | `90` | `3650` (~10 years) |
| Validity start | Midnight UTC today | Midnight UTC today |
| Key Type | `ECDSA-P256` | `ECDSA-P256` |
| RSA Key Size | `3072` | `3072` |
| Hash Algorithm | `auto` | `auto` |
| RSA Padding | `pss` | `pss` |
| PFX Encryption | `modern` (AES-256-CBC) | `modern` (AES-256-CBC) |
| Path Length | N/A | `-1` (unlimited) |
| Trust Location | `CurrentUser` | `CurrentUser` |

### Store Defaults

| Parameter | Default |
|-----------|---------|
| Store Name (new commands) | `My` |
| Store Name (trust add) | `Root` |
| Store Location (new commands) | `CurrentUser` |
| Store Location (legacy install) | `LocalMachine` |

### Monitoring Defaults

| Parameter | Default |
|-----------|---------|
| Warning Threshold | `30` days |
| Recursive Scan | `false` |
| Quiet Mode | `false` |
| Fail on Warning | `false` |

### Output Format Defaults

| Parameter | Default |
|-----------|---------|
| Global Format | `text` |
| Save Format | `pem` |
| Pipe Format | `pem` |

### Legacy Create Defaults

| Parameter | Default |
|-----------|---------|
| DNS Names | `*.dev.local`, `*.localhost`, `*.test` |
| Output File | `devcert.pfx` |

---

## Logic Flows

### PFX Generation Flow

```
1. Parse command options and validate
2. Generate password if not provided
   - 32 bytes random -> 64-character hex string (256 bits entropy)
3. Compute validity period using UTC time (midnight UTC today + days)
4. Create key pair based on key type
   - ECDSA-P256/P384/P521 -> ECDsa.Create(curve)
   - RSA -> RSA.Create(keySize)
5. Build X500 Distinguished Name
6. Create certificate request with extensions:
   - Subject Key Identifier
   - Authority Key Identifier (if signed)
   - Basic Constraints (CA flag, path length)
   - Key Usage
   - Enhanced Key Usage
   - Subject Alternative Names
   - CRL Distribution Points (if specified)
   - Authority Information Access (OCSP, CA Issuers)
7. Self-sign or sign with issuer certificate
8. Export to PFX format:
   - Modern: AES-256-CBC + SHA-256 + 100,000 iterations
   - Legacy: 3DES (for older systems)
9. Write to file(s)
10. Display password warning if auto-generated
```

### Certificate Installation Flow

```
1. Load PFX file with password
2. Determine key storage flags:
   - Exportable (if --exportable)
   - PersistKeySet (always for install)
   - MachineKeySet or UserKeySet (based on location)
3. Open certificate store with ReadWrite access
4. Add certificate to store
5. Close store
```

### Source Detection Flow (inspect, lint)

```
1. If source starts with "https://" -> URL inspection
2. If --store flag provided -> Thumbprint lookup in specified store
3. If file exists at path -> File inspection
4. If 40-character hex string -> Thumbprint lookup (default store: My)
5. Otherwise -> FileNotFoundException
```

### Password Generation

```csharp
// 32 bytes = 256 bits of entropy
byte[] data = RandomNumberGenerator.GetBytes(32);
string password = Convert.ToHexString(data);  // 64 hex characters
```

---

## Project Quirks and Constraints

### CA/Browser Forum Validity Limits

The tool enforces CA/Browser Forum Ballot SC-081v3 validity limits:

| Date | Maximum Validity |
|------|------------------|
| Current (until March 15, 2026) | 398 days |
| After March 15, 2026 | 200 days |
| After March 15, 2027 | 100 days |
| After March 15, 2029 | 47 days |

**Implementation:** Validation occurs in `OptionBuilders.CreateDaysOption()`. Values > 398 produce errors; values > 200 produce warnings.

### UTC Time for Certificate Validity

All certificate validity periods (NotBefore/NotAfter) are computed using UTC time per RFC 5280 Section 4.1.2.5. Both `CreateService` and `RenewService` use `DateTimeOffset.UtcNow` to set validity boundaries, ensuring certificates have consistent timestamps regardless of the machine's local timezone.

### RSA Key Size Recommendations

| Size | Status |
|------|--------|
| 2048 | Minimum accepted (warning shown) |
| 3072 | **Default** - NIST recommended for protection beyond 2030 |
| 4096 | Maximum security option |

### Ephemeral and Pipe Mode Restrictions

Both `--ephemeral` and `--pipe` are mutually exclusive with:
- File output options (`--file`, `--cert`, `--key`)
- Trust installation (`--trust`)
- Password file (`--password-file`)

Additionally, `--ephemeral` and `--pipe` cannot be used together.

### Partial Thumbprint Matching

When removing certificates by thumbprint:
- Minimum 8 characters required
- Uses prefix matching (StartsWith, case-insensitive)
- Full 40-character thumbprint = exact match
- Multiple matches require `--force` flag

### Admin Requirements

Operations on `LocalMachine` store location require administrator privileges:
- `trust add --location LocalMachine`
- `trust remove --location LocalMachine`
- `install --storelocation LocalMachine`

### Default PFX Filename Generation

| Command | Pattern |
|---------|---------|
| `create dev <domain>` | `<domain>.pfx` (dots to dashes, asterisks to "wildcard") |
| `create ca --name <name>` | `<name>.pfx` (spaces to dashes, lowercase) |
| Legacy `create` | `devcert.pfx` |

### Environment Variable Support

| Variable | Used By |
|----------|---------|
| `CERTZ_PASSWORD` | `monitor`, `renew` commands (fallback password) |

### Hash Algorithm Auto-Selection

When `--hash-algorithm auto` (default):
- Hash strength is matched to key size/type
- SHA-256 for RSA 2048-bit / ECDSA P-256
- SHA-384 for RSA 3072-bit / ECDSA P-384
- SHA-512 for RSA 4096-bit / ECDSA P-521

### PFX Encryption Modes

| Mode | Algorithm | Iterations | Compatibility |
|------|-----------|------------|---------------|
| `modern` | AES-256-CBC + SHA-256 | 100,000 | Windows Server 2019+, Windows 11 |
| `legacy` | 3DES | Default | Windows XP, Server 2003, older systems |

---

## Exit Codes

### General

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | General error / validation failure |

### lint Command

| Code | Description |
|------|-------------|
| 0 | All checks passed (no errors) |
| 1 | One or more error-level findings |

### monitor Command

| Code | Description |
|------|-------------|
| 0 | All certificates valid and outside warning threshold |
| 1 | Certificates expiring within threshold (with `--fail-on-warning`) |
| 2 | Expired certificates found |

### renew Command

| Code | Description |
|------|-------------|
| 0 | Certificate renewed successfully |
| 1 | Source certificate not found or invalid |
| 2 | Cannot renew (missing issuer for CA-signed certificate) |

### inspect Command

| Code | Description |
|------|-------------|
| 0 | Success (no warnings) |
| 1 | Warnings present |

---

## Usage Examples

### Basic Certificate Creation

```bash
# Create development certificate for localhost
certz create dev localhost

# Create with custom validity and trust
certz create dev api.local --days 180 --trust

# Create CA certificate
certz create ca --name "My Dev CA" --days 3650

# Create CA-signed certificate
certz create dev app.local --issuer-cert ca.pfx --issuer-password secret

# Interactive mode
certz create dev localhost --guided
```

### Ephemeral and Pipe Modes

```bash
# Generate in memory only (testing)
certz create dev example.com --ephemeral

# Pipe to stdout as PEM
certz create dev example.com --pipe

# Pipe as base64 PFX with password
certz create dev example.com --pipe --pipe-format pfx --pipe-password secret
```

### Certificate Inspection

```bash
# Inspect local file
certz inspect cert.pfx --password secret

# Inspect remote URL
certz inspect https://github.com

# Inspect with chain and revocation check
certz inspect https://github.com --chain --crl

# Inspect from store by thumbprint
certz inspect ABC123DEF456 --store Root
```

### Trust Store Management

```bash
# Add to Root store
certz trust add ca.cer --store Root

# Remove by thumbprint (partial match)
certz trust remove ABC123DE --force

# Remove by subject pattern
certz trust remove --subject "CN=dev*" --force

# List certificates
certz store list --store Root --expired
```

### Format Conversion

```bash
# PFX to PEM
certz convert server.pfx --to pem --password secret

# PEM to PFX
certz convert server.pem --to pfx --key server.key

# DER to PEM
certz convert cert.der --to pem
```

### Monitoring and Renewal

```bash
# Monitor directory
certz monitor ./certs --warn 30 --recursive

# Monitor URLs
certz monitor https://github.com https://google.com

# Renew certificate
certz renew server.pfx --password secret --days 90
```

### JSON Output

```bash
# Any command with JSON output
certz inspect cert.pfx --password secret --format json
certz monitor ./certs --format json
certz lint cert.pfx --password secret --format json
```

---

## Migration from v1.x to v2.0

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

**Note:** v1.x commands remain available for backward compatibility but are deprecated.
