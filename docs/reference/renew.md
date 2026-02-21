# certz renew -- Reference

Extend the validity of an existing certificate without re-entering its parameters.
certz reads the source certificate, preserves its subject, SANs, and key type, then
issues a new certificate with a fresh validity window.

**See also:**
[Certificate Lifecycle](../concepts/certificate-lifecycle.md) |
[RSA vs ECDSA](../concepts/rsa-vs-ecdsa.md) |
[Exit Codes](exit-codes.md)

---

## What Renewal Does

`certz renew` is a one-command alternative to the full create-inspect-trust cycle when
you only need to extend a certificate's expiry date. It:

1. Reads the existing certificate from the PFX (or certificate store)
2. Extracts the subject DN, SANs, and key type
3. Generates a new key pair (unless `--keep-key` is used)
4. Issues a new certificate with the same identity but a new validity period
5. Writes the renewed certificate to the output file

Self-signed certificates renew without any extra flags. CA-signed certificates require
`--issuer-cert` because certz cannot automatically locate the issuer.

---

## What Is Preserved vs What You Can Override

| Parameter | Preserved automatically | Override flag |
|-----------|-------------------------|---------------|
| Subject (CN, O, OU, C, etc.) | Yes | Not currently overridable |
| Subject Alternative Names | Yes | Not currently overridable |
| Key type (ECDSA P-256, RSA, etc.) | Yes | Not currently overridable |
| Private key itself | No -- new key generated | `--keep-key` reuses existing key |
| Validity period | No -- specify new period | `--days` (default: 90, max: 398) |
| Issuer | No -- must be provided for CA-signed | `--issuer-cert` + `--issuer-password` |
| Output file path | No -- defaults to `<original>-renewed.pfx` | `--out` |
| Output password | No -- auto-generated | `--out-password` |

---

## Before/After: Self-Signed Renewal

**Before:**

```
Subject:    CN=api.company.com
Issuer:     CN=api.company.com (self-signed)
SANs:       api.company.com, localhost, 127.0.0.1
Key:        ECDSA P-256
Not Before: 2025-08-01 00:00:00 UTC
Not After:  2025-10-29 00:00:00 UTC    <- expires in 3 days
Thumbprint: A1B2C3D4E5F6...
```

**Renewal command:**

```bash
certz renew api.pfx --password MyPassword --days 90
```

**After:**

```
Subject:    CN=api.company.com          <- unchanged
Issuer:     CN=api.company.com          <- unchanged
SANs:       api.company.com, localhost, 127.0.0.1  <- unchanged
Key:        ECDSA P-256                 <- unchanged
Not Before: 2025-10-26 00:00:00 UTC    <- new (today)
Not After:  2026-01-23 00:00:00 UTC    <- new (90 days from now)
Thumbprint: B3C4D5E6F7A8...            <- different -- this is a new certificate
```

Only the validity window and thumbprint change. Everything else is carried forward.

---

## Before/After: CA-Signed Renewal

When the original certificate was signed by a CA, you must supply the issuer on renewal.
certz cannot auto-locate the CA from the certificate alone.

**Before:**

```
Subject:    CN=api.company.com
Issuer:     CN=Dev CA                  <- CA-signed, not self-signed
SANs:       api.company.com, localhost, 127.0.0.1
Key:        ECDSA P-256
Not Before: 2025-08-01 00:00:00 UTC
Not After:  2025-10-29 00:00:00 UTC    <- expires in 3 days
```

**Renewal command:**

```bash
certz renew server.pfx --password ServerPass \
  --issuer-cert ca.pfx --issuer-password CaPass \
  --days 90
```

**After:**

```
Subject:    CN=api.company.com          <- unchanged
Issuer:     CN=Dev CA                  <- unchanged (re-signed by same CA)
SANs:       api.company.com, localhost, 127.0.0.1  <- unchanged
Key:        ECDSA P-256                 <- unchanged
Not Before: 2025-10-26 00:00:00 UTC    <- new
Not After:  2026-01-23 00:00:00 UTC    <- new
Thumbprint: C4D5E6F7A8B9...            <- different
```

The renewed certificate is signed by the same CA. The chain of trust is maintained --
clients that already trust the CA will trust the renewed cert without any store changes.

---

## Key Reuse with `--keep-key`

By default, certz generates a fresh key pair on every renewal. Use `--keep-key` to
reuse the original private key.

```bash
# Generate new key (default -- recommended for scheduled rotation)
certz renew server.pfx --password MyPassword --days 90

# Reuse existing key
certz renew server.pfx --password MyPassword --days 90 --keep-key
```

**When to reuse the key (`--keep-key`):**
- You have distributed or pinned the public key in dependent systems
- Minimal disruption is required -- no re-distribution of the key needed

**When to generate a new key (default):**
- Scheduled key rotation policy
- Suspected compromise of the private key
- You want a clean rotation with a fresh key

> **Security note:** Reusing a key means a compromised private key stays compromised across
> renewals. Unless you have a specific reason to pin the key, generating a new one on each
> renewal is the safer default.

---

## Full Options

| Option | Default | Description |
|--------|---------|-------------|
| `<source>` | (required) | PFX file path or certificate store thumbprint to renew. |
| `--password, -p` | (none) | Password for the source PFX. Also reads from `CERTZ_PASSWORD` env var. |
| `--days` | `90` | New validity period in days. Maximum 398. |
| `--keep-key` | `false` | Reuse the existing private key instead of generating a new one. |
| `--issuer-cert` | (none) | CA certificate file. Required if the original cert was CA-signed. |
| `--issuer-key` | (none) | CA private key file. Required when `--issuer-cert` is a PEM without embedded key. |
| `--issuer-password` | (none) | Password for a PFX `--issuer-cert`. |
| `--out, -o` | `<original>-renewed.pfx` | Output file path for the renewed certificate. |
| `--out-password` | (auto-generated) | Password for the output PFX. Printed to console when auto-generated. |
| `--store` | (none) | Certificate store name for thumbprint-based lookup: `My`, `Root`, `CA`. |
| `--location, -l` | `CurrentUser` | Store location: `CurrentUser` or `LocalMachine`. |
| `--format` | `text` | Output format: `text` or `json`. |

---

## JSON Output Schema

```bash
certz renew server.pfx --password MyPassword --format json
```

Example output:

```json
{
  "success": true,
  "errorMessage": null,
  "originalSubject": "CN=api.company.com",
  "originalThumbprint": "A1B2C3D4E5F6...",
  "originalNotAfter": "2025-10-29T00:00:00Z",
  "newSubject": "CN=api.company.com",
  "newThumbprint": "B3C4D5E6F7A8...",
  "newNotBefore": "2025-10-26T00:00:00Z",
  "newNotAfter": "2026-01-23T00:00:00Z",
  "outputFile": "api-renewed.pfx",
  "password": "Xk9!mP2rLq",
  "passwordWasGenerated": true,
  "sans": ["api.company.com", "localhost", "127.0.0.1"],
  "keyType": "ECDSA-P256",
  "keyWasPreserved": false,
  "wasResigned": false
}
```

| Field | Type | Description |
|-------|------|-------------|
| `success` | bool | `true` if renewal completed without errors |
| `errorMessage` | string or null | Error description if `success` is `false` |
| `originalSubject` | string | Subject DN before renewal |
| `originalThumbprint` | string | SHA-1 thumbprint of the original certificate |
| `originalNotAfter` | ISO 8601 | Expiry of the original certificate (UTC) |
| `newSubject` | string or null | Subject DN of the renewed certificate (same as original) |
| `newThumbprint` | string or null | SHA-1 thumbprint of the renewed certificate |
| `newNotBefore` | ISO 8601 or null | Validity start of the renewed certificate (UTC) |
| `newNotAfter` | ISO 8601 or null | Expiry of the renewed certificate (UTC) |
| `outputFile` | string or null | Path to the output PFX file |
| `password` | string or null | Output PFX password (only present when auto-generated) |
| `passwordWasGenerated` | bool | `true` when certz chose the output password |
| `sans` | string[] or null | Subject Alternative Names carried forward from the original |
| `keyType` | string or null | Key algorithm: `ECDSA-P256`, `ECDSA-P384`, `ECDSA-P521`, or `RSA` |
| `keyWasPreserved` | bool | `true` when `--keep-key` was used |
| `wasResigned` | bool | `true` when `--issuer-cert` was provided and used for signing |

---

## Troubleshooting

| Problem | Likely cause | Fix |
|---------|--------------|-----|
| "Issuer not provided" error | CA-signed cert renewed without `--issuer-cert` | certz cannot auto-locate the issuer. Provide `--issuer-cert ca.pfx --issuer-password CaPass`. |
| Renewed cert still shows old expiry in browser | Browser or server has cached the old certificate | Restart the web server and clear the browser certificate cache. |
| "Max validity exceeded" | `--days` value is over 398 | Use `--days 398` or lower. For longer durations, plan more frequent renewals. |
| Renewed cert has a different key than expected | New key generated by default | Add `--keep-key` to preserve the original private key. |
| "Source certificate not found" | Wrong file path or thumbprint | Verify the path, or run `certz store list --store My` to confirm the thumbprint. |
