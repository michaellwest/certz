# certz inspect -- Reference

Deep-read a certificate from any source and display its properties, extensions, chain,
and optionally check revocation status.

**See also:**
[Certificate Formats](../concepts/certificate-formats.md) |
[Certificate Chain](../concepts/certificate-chain.md) |
[Windows Trust Store](../concepts/windows-trust-store.md) |
[Exit Codes](exit-codes.md)

---

## Source Types

`inspect` accepts three kinds of source identifiers. It detects the type automatically:

| Priority | Condition | Action |
|----------|-----------|--------|
| 1 | Source starts with `https://` | Remote TLS inspection |
| 2 | `--store` flag is provided | Thumbprint lookup in that store |
| 3 | A file exists at the path | File inspection |
| 4 | Source is a 40-char hex string | Thumbprint lookup in default store |
| 5 | None of the above | Error: file not found |

### File

```bash
# PFX (password required)
certz inspect server.pfx --password MyPassword

# PEM certificate (no password)
certz inspect server.pem
certz inspect server.crt
certz inspect server.cer

# DER-encoded binary certificate
certz inspect server.der

# JSON output for scripting
certz inspect server.pfx --password MyPassword --format json
```

### Remote HTTPS URL

No password needed -- certz connects and reads the certificate from the TLS handshake:

```bash
# Standard HTTPS
certz inspect https://example.com

# Non-standard port
certz inspect https://api.internal:8443
certz inspect https://localhost:8443

# With expiry warning
certz inspect https://example.com --warn 30
```

### Windows Certificate Store

Provide a thumbprint (full 40-char or partial 8+ char prefix) plus `--store`:

```bash
# Inspect from My store (CurrentUser -- default when no --store)
certz inspect ABC123DEF456789012345678901234567890ABCD

# Specify store and location explicitly
certz inspect ABC123DEF456 --store Root
certz inspect ABC123DEF456 --store Root --location LocalMachine
certz inspect ABC123DEF456 --store CA --location CurrentUser
```

---

## Chain Inspection

### `--chain` -- include chain information

Fetches and validates the full certificate chain from end-entity up to the Root CA.

```bash
certz inspect https://example.com --chain
certz inspect server.pfx --password Pass --chain
```

### `--tree` -- detailed chain tree

`--tree` implies `--chain`. Displays each chain element with key info, SANs, validity
dates, signature algorithm, and any validation errors.

```bash
certz inspect https://example.com --tree
```

Sample tree output:

```
Certificate Chain
=================

Root CA (depth 2)
  Subject:    CN=GlobalSign Root CA R3
  Thumbprint: D69B561148F01C77C54578C10926DF5B856976AD
  Key:        RSA 2048
  Validity:   2009-03-18 to 2029-03-18 (1,089 days remaining)
  Self-signed: Yes

Intermediate CA (depth 1)
  Subject:    CN=GlobalSign RSA OV SSL CA 2018
  Issuer:     CN=GlobalSign Root CA R3
  Thumbprint: 8F103249518BC1273CA0F6B19C655EA5F4CAFA2
  Key:        RSA 2048
  Validity:   2018-11-21 to 2028-11-21 (973 days remaining)

End-entity (depth 0)
  Subject:    CN=example.com
  Issuer:     CN=GlobalSign RSA OV SSL CA 2018
  Thumbprint: 1A2B3C4D5E6F...
  Key:        ECDSA P-256
  SANs:       example.com, www.example.com
  Validity:   2025-01-01 to 2026-01-01 (127 days remaining)
```

### `--crl` -- revocation check

Checks each certificate in the chain for revocation. OCSP is attempted first; CRL is the
fallback. The result is shown in `--tree` output as `Revocation: Good` / `Revoked` / `Unknown`.

```bash
# Chain + revocation check
certz inspect https://example.com --chain --crl

# Detailed tree with revocation
certz inspect https://example.com --tree --crl
```

> **Note:** Revocation checking requires network access to OCSP/CRL endpoints. Certificates
> that omit these extensions will show `Revocation: Unknown`.

---

## Save Output Options

Save the certificate (and optionally its private key) to files for use in other tools.

```bash
# Save certificate as PEM (default)
certz inspect https://example.com --save github.cer

# Save certificate and private key from PFX
certz inspect server.pfx --password Pass --save cert.pem --save-key key.pem

# Save certificate in DER format
certz inspect server.pfx --password Pass --save cert.der --save-format der
```

| Option | Default | Description |
|--------|---------|-------------|
| `--save <file>` | (none) | Save the certificate to a file |
| `--save-key <file>` | (none) | Save the private key to a file (only available when source has a private key) |
| `--save-format` | `pem` | Output format for saved files: `pem` or `der` |

---

## Full Options

| Option | Default | Description |
|--------|---------|-------------|
| `<source>` | (required) | File path, `https://` URL, or certificate thumbprint |
| `--password, -p` | (none) | Password for PFX files. Also reads from `CERTZ_PASSWORD` env var. |
| `--chain, -c` | `false` | Include the full certificate chain in output |
| `--tree, -t` | `false` | Detailed chain tree with key info, SANs, signatures (implies `--chain`) |
| `--crl` | `false` | Check revocation status (OCSP preferred, CRL fallback) |
| `--warn, -w <days>` | (none) | Warn and exit 1 if certificate expires within N days |
| `--save <file>` | (none) | Save certificate to file |
| `--save-key <file>` | (none) | Save private key to file |
| `--save-format` | `pem` | Save format: `pem` or `der` |
| `--store, -s` | (none) | Certificate store for thumbprint lookup: `My`, `Root`, `CA` |
| `--location, -l` | `CurrentUser` | Store location: `CurrentUser` or `LocalMachine` |
| `--format` | `text` | Output format: `text` or `json` |

---

## JSON Output Schema

```bash
certz inspect server.pfx --password Pass --format json
```

Example output:

```json
{
  "subject": "CN=api.company.com, O=Company, C=US",
  "issuer": "CN=api.company.com, O=Company, C=US",
  "thumbprint": "A1B2C3D4E5F6789012345678901234567890ABCD",
  "serialNumber": "1234567890ABCDEF",
  "notBefore": "2025-10-26T00:00:00",
  "notAfter": "2026-01-23T00:00:00",
  "daysRemaining": 64,
  "keyAlgorithm": "ECDSA",
  "keySize": 256,
  "signatureAlgorithm": "sha256ECDSA",
  "subjectAlternativeNames": ["api.company.com", "localhost", "127.0.0.1"],
  "keyUsages": ["DigitalSignature"],
  "enhancedKeyUsages": ["Server Authentication", "Client Authentication"],
  "isCa": false,
  "pathLengthConstraint": null,
  "hasPrivateKey": true,
  "source": "File",
  "sourcePath": "server.pfx",
  "chainIsValid": false,
  "chain": null,
  "warnings": []
}
```

When `--chain` is provided, `chain` is an array of chain elements:

```json
{
  "chain": [
    {
      "subject": "CN=api.company.com",
      "issuer": "CN=Dev CA",
      "thumbprint": "A1B2C3D4...",
      "serialNumber": "01",
      "notBefore": "2025-10-26T00:00:00",
      "notAfter": "2026-01-23T00:00:00",
      "isCa": false,
      "isSelfSigned": false,
      "keyAlgorithm": "ECDSA",
      "keySize": 256,
      "signatureAlgorithm": "sha256ECDSA",
      "subjectAlternativeNames": ["api.company.com", "localhost"],
      "daysRemaining": 64,
      "revocationStatus": null,
      "crlDistributionPoints": [],
      "ocspResponder": null,
      "validationErrors": []
    }
  ]
}
```

Top-level fields:

| Field | Type | Description |
|-------|------|-------------|
| `subject` | string | Subject Distinguished Name |
| `issuer` | string | Issuer Distinguished Name |
| `thumbprint` | string | SHA-1 thumbprint (hex, uppercase, no colons) |
| `serialNumber` | string | Certificate serial number (hex) |
| `notBefore` | ISO 8601 | Validity start (UTC) |
| `notAfter` | ISO 8601 | Expiry date (UTC) |
| `daysRemaining` | int | Days until expiry; negative if expired |
| `keyAlgorithm` | string | Key algorithm: `RSA`, `ECDSA`, etc. |
| `keySize` | int | Key size in bits (256 for ECDSA P-256, 2048/3072/4096 for RSA) |
| `signatureAlgorithm` | string | Signature hash and algorithm (e.g., `sha256ECDSA`) |
| `subjectAlternativeNames` | string[] | DNS names, IP addresses, and URIs in the SAN extension |
| `keyUsages` | string[] | Key Usage extension values (e.g., `DigitalSignature`) |
| `enhancedKeyUsages` | string[] | EKU OID friendly names (e.g., `Server Authentication`) |
| `isCa` | bool | `true` if Basic Constraints has `CA:TRUE` |
| `pathLengthConstraint` | int or null | Path length constraint for CA certs; null if not set |
| `hasPrivateKey` | bool | `true` if source included a private key (PFX) |
| `source` | string | `"File"`, `"Url"`, or `"Store"` |
| `sourcePath` | string or null | File path, URL, or store reference |
| `chainIsValid` | bool | `true` when chain is present and valid |
| `chain` | array or null | Chain elements (only when `--chain` was used) |
| `warnings` | string[] | Any warnings raised during inspection |

Each `chain[]` element:

| Field | Type | Description |
|-------|------|-------------|
| `subject` | string | Subject DN |
| `issuer` | string | Issuer DN |
| `thumbprint` | string | SHA-1 thumbprint |
| `serialNumber` | string | Serial number (hex) |
| `notBefore` | ISO 8601 | Validity start |
| `notAfter` | ISO 8601 | Expiry date |
| `isCa` | bool | Whether this element is a CA cert |
| `isSelfSigned` | bool | `true` when Subject equals Issuer |
| `keyAlgorithm` | string or null | Key algorithm |
| `keySize` | int | Key size in bits |
| `signatureAlgorithm` | string or null | Signature algorithm |
| `subjectAlternativeNames` | string[] | SANs (typically non-empty only for end-entity) |
| `daysRemaining` | int | Days until expiry |
| `revocationStatus` | string or null | `"Good"`, `"Revoked"`, `"Unknown"`, or null (not checked) |
| `crlDistributionPoints` | string[] | CRL Distribution Point URLs |
| `ocspResponder` | string or null | OCSP responder URL |
| `validationErrors` | string[] | Chain validation errors for this element |

---

## Troubleshooting

| Problem | Likely cause | Fix |
|---------|--------------|-----|
| "File not found" on a PFX | Wrong path or typo | Verify the file path and check with `dir` or `ls`. |
| "Cannot open PFX" or invalid password | Wrong password for the PFX file | Provide the correct password with `--password`. |
| Chain incomplete for a URL | Server not sending intermediate certificates | Note: this is a server-side configuration issue. Run `certz inspect --chain` against the URL; missing intermediates will show as chain errors. |
| Thumbprint lookup returns no results | Wrong store or location | Run `certz store list --store My` (and `Root`, `CA`) to find where the cert is installed. Add `--location LocalMachine` if installed machine-wide. |
| `chainIsValid: false` despite cert looking correct | Root CA not trusted on this machine | The root must be in the `Root` trust store. Add it with `certz trust add ca.cer --store Root`. |
| Revocation shows `Unknown` | Certificate has no OCSP/CRL endpoints, or network blocked | Expected for self-signed or internal CA certs. For public certs, check firewall or proxy rules. |
| Exit code 1 after a successful inspect | `--warn` threshold triggered | `daysRemaining` is below the `--warn` value. Renew the certificate or remove `--warn`. |
