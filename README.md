# certz 🔐

A standards-compliant certificate utility built on .NET for Windows, with support for modern cryptographic algorithms and RFC 5280 compliance.

```
Description:
  Certz: A Simple Certificate Utility

Usage:
  certz [command] [options]

Options:
  --version       Show version information
  -?, -h, --help  Show help and usage information

Commands:
  list     Lists all certificates.
  install  Installs a certificate.
  create   Creates a certificate.
  remove   Removes the specified certificate.
  export   Exports the specified certificate.
  convert  Converts between PFX and PEM certificate formats.
  info     Displays detailed information about a certificate.
  verify   Validates a certificate and checks its trust chain.
```

**Example:** The following lists all the installed certificates from the specified locations.

`certz.exe list --storename root --storelocation localmachine`

**Example:** The following creates a new certificate.

```
certz.exe create --f devcert.pfx --p Password12345 --dns *.devx.local
```

**Example:** The following creates PFX and CER certificate files with a secure generated password (displayed once).

```
certz.exe create --f devcert.pfx --c devcert.cer --k devcert.key --days 90
```

**Example:** The following creates a 3072-bit RSA certificate with SHA-384 for long-term security.

```
certz.exe create --f devcert.pfx --p MySecurePassword123! --dns *.example.com --key-size 3072 --hash-algorithm SHA384
```

**Example:** The following creates an ECDSA P-256 certificate (modern, fast, TLS 1.3 optimized).

```
certz.exe create --f devcert.pfx --p MySecurePassword123! --dns *.example.com --key-type ECDSA-P256
```

**Example:** The following creates a CA certificate with CRL and OCSP support.

```
certz.exe create --f ca.pfx --p MySecurePassword123! --dns "My Root CA" --is-ca --path-length 2 --crl-url http://crl.example.com/ca.crl --ocsp-url http://ocsp.example.com --days 3650
```

**Example:** The following creates a certificate with full Distinguished Name fields.

```
certz.exe create --f devcert.pfx --p MySecurePassword123! --dns *.example.com --subject-o "Acme Corporation" --subject-ou "Engineering" --subject-c US --subject-st "California" --subject-l "San Francisco"
```

**Example:** The following installs a certificate with the provided password.

```
certz.exe install --f C:\certs\devcert.pfx --p Password12345 --sn root --sl localmachine
```

**Example:** The following removes a certificate matching the provided thumbprint.

```
certz.exe remove --thumb 94163681942B9B440A22535B3E6BFEA64DE9A3E7 --sn root
```

**Example:** The following downloads a certificate from the provided url.

```
certz.exe export --f devcert-bak.pfx --c devcert-bak.pem --url https://www.github.com
```

**Example:** The following converts a CER/CRT and KEY file to a PFX file.

```
certz.exe convert --c certificate.crt --k private.key --f output.pfx --p Password12345
```

**Example:** The following converts a PFX file to separate CER and KEY files.

```
certz.exe convert --pfx devcert.pfx --p YourPassword --out-cert certificate.cer --out-key private.key
```

**Example:** The following displays detailed information about a certificate from a file.

```
certz.exe info --file devcert.pfx --password YourPassword
```

**Example:** The following displays certificate information from a remote URL.

```
certz.exe info --url https://www.github.com
```

**Example:** The following displays certificate information from the Windows certificate store.

```
certz.exe info --thumbprint 94163681942B9B440A22535B3E6BFEA64DE9A3E7 --sn My --sl LocalMachine
```

**Example:** The following validates a certificate and checks its expiration and trust chain.

```
certz.exe verify --file devcert.pfx --password YourPassword
```

**Example:** The following verifies a certificate with a custom expiration warning threshold and revocation check.

```
certz.exe verify --file devcert.pfx --password YourPassword --warning-days 60 --check-revocation
```

**Example:** The following verifies a certificate from the Windows certificate store.

```
certz.exe verify --thumbprint 94163681942B9B440A22535B3E6BFEA64DE9A3E7 --sn My --sl LocalMachine
```

## Standards Compliance

certz is designed to meet current industry standards and best practices for certificate generation:

### Cryptographic Standards

#### Key Types and Sizes
- **RSA**: Configurable 2048, 3072, or 4096 bits
  - 2048 bits: Current minimum standard (NIST SP 800-131A Rev. 2)
  - 3072 bits: Recommended for protection beyond 2030 (NIST SP 800-57 Part 1 Rev. 5)
  - 4096 bits: Maximum security for long-lived certificates
- **ECDSA**: P-256, P-384, P-521 curves (NIST SP 800-186)
  - P-256: Equivalent to 3072-bit RSA, recommended for TLS 1.3
  - P-384: Equivalent to 7680-bit RSA
  - P-521: Maximum ECDSA security

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

The tool will warn you if creating certificates that will violate upcoming limits.

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

#### Extension Criticality
certz correctly implements RFC 5280 criticality requirements:
- **Critical**: Basic Constraints, Key Usage (as recommended)
- **Non-critical**: Enhanced Key Usage, AIA, CRL Distribution Points
- **Context-dependent**: SAN (critical only when subject DN is empty)

### Security Features

#### Password Security
- **No default passwords**: Secure random passwords generated if not provided
- **No plaintext storage**: Passwords displayed once with warning to store securely
- **NIST SP 800-63B compliant**: 24-character random passwords with mixed character types

#### Private Key Protection
- **Secure key generation**: Uses platform cryptographic APIs (RSA.Create, ECDsa.Create)
- **PKCS#8 format**: Standard private key export format
- **Configurable exportability**: Control whether private keys can be exported from certificate store

### Distinguished Names

certz supports full X.500 Distinguished Names per RFC 5280:
- **CN** (Common Name): Required, typically the primary domain name
- **O** (Organization): Company or organization name
- **OU** (Organizational Unit): Department or division
- **C** (Country): Two-letter ISO country code
- **ST** (State/Province): State, province, or region
- **L** (Locality): City or locality

### CA Certificate Support

certz can generate proper Certificate Authority certificates with:
- **Correct Key Usage**: KeyCertSign, CRLSign, DigitalSignature
- **Path Length Constraints**: Control certificate chain depth
- **No EKU**: CA certificates omit Enhanced Key Usage extension (correct per RFC 5280)

### Standards References

- [NIST SP 800-57 Part 1 Rev. 5](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final) - Key Management Recommendations
- [NIST SP 800-131A Rev. 2](https://csrc.nist.gov/pubs/sp/800/131/a/r2/final) - Cryptographic Algorithm Transitions
- [NIST SP 800-186](https://csrc.nist.gov/publications/detail/sp/800-186/final) - Discrete Logarithm-Based Cryptography
- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) - Digital Identity Guidelines: Authentication
- [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) - X.509 Certificate and CRL Profile
- [RFC 8446](https://tools.ietf.org/html/rfc8446) - TLS 1.3 Protocol
- [CA/Browser Forum Baseline Requirements](https://cabforum.org/working-groups/server/baseline-requirements/)
- [CA/Browser Forum SC-081v3](https://cabforum.org/2025/04/11/ballot-sc081v3/) - Certificate Validity Period Reductions

## Testing

Comprehensive testing documentation and automated test scripts are available to validate all features:

- **[TESTING.md](TESTING.md)** - Complete testing guide with manual test scenarios for all commands
- **[test-all.ps1](test-all.ps1)** - Automated test suite that validates all features
- **[Dockerfile.test](Dockerfile.test)** - Docker configuration for isolated container testing
- **[DOCKER-TESTING.md](DOCKER-TESTING.md)** - Docker testing quick reference and troubleshooting
- **[DOCKER-FILES-EXPLAINED.md](DOCKER-FILES-EXPLAINED.md)** - Understanding how files are made available in containers

### Quick Test

Run the comprehensive test suite locally (requires Administrator privileges):

```powershell
.\test-all.ps1
```

Or run in an isolated Windows Docker container:

```powershell
# Standard mode (files baked into image)
.\test-all.ps1 -UseDocker

# Development mode (files mounted as volumes - no rebuild needed for changes)
.\test-all.ps1 -UseDocker -DevMode
```

For detailed testing instructions, see [TESTING.md](TESTING.md).