# certz diff -- Reference

Compare two certificates side-by-side and highlight which fields changed.
Useful when validating renewals, auditing cert rotations, or checking that staging and production certs are equivalent.

**See also:**
[inspect](inspect.md) |
[Exit Codes](exit-codes.md)

---

## Usage

```
certz diff <source1> <source2> [options]
```

### Source types

Each source can be a file path, HTTPS URL, or certificate store thumbprint -- the same auto-detection logic used by `certz inspect`.

| Source | Example | Notes |
|--------|---------|-------|
| File path | `cert.pem`, `cert.pfx`, `cert.der` | PEM, DER, PFX, .crt, .cer all supported |
| HTTPS URL | `https://example.com` | Fetches the server's leaf certificate |
| Thumbprint | `ABC123...` (40 hex chars) | Requires `--store` to specify the store name |

---

## Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--password` | `--pass`, `-p` | _(none)_ | Password for source1 (PFX files) |
| `--password2` | `--pass2` | _(none)_ | Password for source2 (PFX files) |
| `--store` | `-s` | _(none)_ | Store name for source1 thumbprint lookup (My, Root, CA) |
| `--store2` | | _(none)_ | Store name for source2 thumbprint lookup |
| `--location` | `-l` | `CurrentUser` | Store location for source1: `CurrentUser` or `LocalMachine` |
| `--location2` | | `CurrentUser` | Store location for source2: `CurrentUser` or `LocalMachine` |
| `--format` | `--fmt` | `text` | Output format: `text` or `json` |

---

## Compared Fields

`certz diff` compares the following fields between the two certificates:

| Field | Notes |
|-------|-------|
| Subject | Full Distinguished Name |
| Issuer | Full Distinguished Name |
| Serial Number | Unique per CA issuance |
| Thumbprint | SHA-1 hash of the certificate |
| Valid From | Certificate NotBefore date (UTC) |
| Valid To | Certificate NotAfter date (UTC) |
| Key Algorithm | Algorithm and key size (e.g., ECDSA P-256, RSA 3072 bits) |
| Signature Algorithm | Hash+key algorithm used to sign the cert |
| SANs | Subject Alternative Names (comma-joined) |
| Key Usage | e.g., Digital Signature, Key Encipherment |
| Enhanced Key Usage | e.g., Server Authentication, Client Authentication |
| Is CA | Whether the certificate has the CA basic constraint |
| Path Length | CA path length constraint (shown only for CA certs) |

---

## Examples

### File comparisons

```bash
# Compare two PEM certificates
certz diff old.pem new.pem

# Compare two PFX files with separate passwords
certz diff old.pfx new.pfx --password OldPass --password2 NewPass

# Compare a PFX with a PEM
certz diff server.pfx server.pem --password MyPass

# Compare a local cert with a live server cert
certz diff cert.pem https://example.com
```

### JSON output

```bash
certz diff old.pem new.pem --format json
```

```json
{
  "success": true,
  "areIdentical": false,
  "differenceCount": 3,
  "source1": "old.pem",
  "source2": "new.pem",
  "fields": [
    { "name": "Serial Number", "leftValue": "3F2A",       "rightValue": "7C9B",       "status": "changed" },
    { "name": "Valid From",    "leftValue": "2024-01-01", "rightValue": "2025-01-01", "status": "changed" },
    { "name": "Valid To",      "leftValue": "2024-04-01", "rightValue": "2025-04-01", "status": "changed" },
    { "name": "Subject",       "leftValue": "CN=api.local", "rightValue": "CN=api.local", "status": "unchanged" }
  ]
}
```

### Store thumbprint comparison

```bash
certz diff <thumbprint1> <thumbprint2> --store My --store2 My
```

---

## Text output format

The text output shows a four-column table: Property, Left, Right, Status.

- **Changed** fields: property name and values highlighted in yellow/red/green
- **Unchanged** fields: dimmed with `unchanged` marker
- Footer shows the resolved paths for both sources

```
+------------------+-------------------+-------------------+-----------+
| Property         | Left              | Right             | Status    |
+------------------+-------------------+-------------------+-----------+
| Serial Number    | 3F2A              | 7C9B              | changed   |
| Valid From       | 2024-01-01 UTC    | 2025-01-01 UTC    | changed   |
| Valid To         | 2024-04-01 UTC    | 2025-04-01 UTC    | changed   |
| Subject          | CN=api.local      | CN=api.local      | unchanged |
+------------------+-------------------+-------------------+-----------+

  Left:  old.pem
  Right: new.pem
```

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Certificates are identical (all fields match) |
| `1` | Certificates differ OR source could not be loaded |
