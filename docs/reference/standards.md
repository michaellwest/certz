# Standards Reference

certz is built to meet current industry standards and best practices for certificate generation.

**See also:** [Compliance Standards](../concepts/compliance-standards.md) · [RSA vs ECDSA](../concepts/rsa-vs-ecdsa.md) · [Certificate Lifecycle](../concepts/certificate-lifecycle.md)

---

## Key Types and Sizes

**ECDSA** (default):

| Curve | Equivalent RSA | Notes |
|-------|----------------|-------|
| P-256 | ~3072-bit RSA | Default — recommended for TLS 1.3 |
| P-384 | ~7680-bit RSA | Higher security applications |
| P-521 | Maximum ECDSA | Highest security |

**RSA** (use `--key-type RSA`):

| Size | Security level | Notes |
|------|----------------|-------|
| 2048 | Current minimum | NIST SP 800-131A Rev. 2 minimum |
| 3072 | **Default** | Recommended beyond 2030 (NIST SP 800-57) |
| 4096 | Maximum practical | Long-lived certificates |

---

## RSA Signature Padding

- **RSA-PSS** (default): Modern padding scheme, recommended for new certificates
- **PKCS#1 v1.5**: Wider compatibility with older systems

---

## Hash Algorithms

certz automatically selects the hash algorithm based on key type and size:

| Key | Hash |
|-----|------|
| RSA 2048 | SHA-256 |
| RSA 3072 / ECDSA P-384 | SHA-384 |
| RSA 4096 / ECDSA P-521 | SHA-512 |

---

## Certificate Validity (CA/Browser Forum)

certz enforces [CA/Browser Forum Ballot SC-081v3](https://cabforum.org/2025/04/11/ballot-sc081v3/) validity limits:

| Effective date | Maximum leaf cert validity |
|----------------|---------------------------|
| Until March 15, 2026 | 398 days |
| March 15, 2026 | 200 days |
| March 15, 2027 | 100 days |
| March 15, 2029 | 47 days |

**Default:** 90 days (future-proof and aligned with industry trends).

All validity periods use UTC time (RFC 5280 §4.1.2.5). NotBefore is set to midnight UTC of the current day.

---

## RFC 5280 Extensions

**Mandatory extensions in certz output:**

| Extension | OID | Purpose |
|-----------|-----|---------|
| Subject Key Identifier | 2.5.29.14 | Uniquely identifies the public key |
| Authority Key Identifier | 2.5.29.35 | Links to the issuing CA's key |
| Basic Constraints | 2.5.29.19 | CA vs end-entity flag |
| Key Usage | 2.5.29.15 | Permitted cryptographic operations |
| Subject Alternative Names | 2.5.29.17 | Certificate identities |

**Optional extensions:**

| Extension | OID | Purpose |
|-----------|-----|---------|
| Enhanced Key Usage | 2.5.29.37 | Purpose-specific usage (Server Auth, etc.) |
| CRL Distribution Points | 2.5.29.31 | Revocation via CRL |
| Authority Information Access | 1.3.6.1.5.5.7.1.1 | OCSP responder and CA issuer URLs |

---

## Password Security

- Secure random passwords generated when `--password` is omitted
- Passwords displayed once with a warning to store securely
- NIST SP 800-63B compliant: 24-character random passwords with mixed character types

---

## PFX Encryption

| Mode | Algorithm | Use |
|------|-----------|-----|
| `modern` (default) | AES-256-CBC, SHA-256, 100k iterations | All modern systems |
| `legacy` | 3DES | Compatibility with older Java and Windows versions |

---

## Standards References

- [NIST SP 800-57 Part 1 Rev. 5](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final) — Key Management Recommendations
- [NIST SP 800-131A Rev. 2](https://csrc.nist.gov/pubs/sp/800/131/a/r2/final) — Cryptographic Algorithm Transitions
- [NIST SP 800-186](https://csrc.nist.gov/publications/detail/sp/800/186/final) — Discrete Logarithm-Based Cryptography
- [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) — X.509 Certificate and CRL Profile
- [RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017) — PKCS #1 RSA Cryptography (includes RSA-PSS)
- [CA/Browser Forum Baseline Requirements](https://cabforum.org/working-groups/server/baseline-requirements/)
