# certz fingerprint -- Reference

Output the SHA-256 (or SHA-384 / SHA-512) fingerprint of a certificate.
By default the bytes are colon-separated (`AA:BB:CC`); use `--no-separator` for raw hex or `--separator` for any custom delimiter.
This is the single-line equivalent of `openssl x509 -fingerprint -sha256 -noout -in cert.pem`.

**See also:**
[inspect](inspect.md) |
[Exit Codes](exit-codes.md)

---

## Usage

```
certz fingerprint <source> [options]
```

### Source types

| Source | Example | Notes |
|--------|---------|-------|
| File path | `cert.pem` | PEM, DER, PFX, .crt, .cer all supported |
| HTTPS URL | `https://example.com` | Fingerprints the server's leaf certificate |

---

## Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--algorithm` | `-a` | `sha256` | Hash algorithm: `sha256`, `sha384`, or `sha512` |
| `--separator` | | `:` | Delimiter between hex byte groups (e.g. `""`, `" "`, `"-"`) |
| `--no-separator` | | `false` | Output raw hex with no delimiter (equivalent to `--separator ""`) |
| `--password` | `--pass`, `-p` | _(none)_ | Password for PFX files |
| `--format` | `--fmt` | `text` | Output format: `text` or `json` |

`--separator` and `--no-separator` are mutually exclusive.

---

## Examples

### File sources

```bash
# SHA-256 fingerprint of a PEM certificate (default algorithm)
certz fingerprint cert.pem

# Raw hex (no colons) -- matches Windows cert store thumbprint style
certz fingerprint cert.pem --no-separator

# Custom delimiter
certz fingerprint cert.pem --separator " "
certz fingerprint cert.pem --separator "-"

# SHA-256 fingerprint of a PFX file
certz fingerprint server.pfx --password MyPassword

# SHA-384 fingerprint
certz fingerprint cert.pem --algorithm sha384

# SHA-512 fingerprint
certz fingerprint cert.pem --algorithm sha512

# DER-encoded certificate
certz fingerprint cert.der
```

### URL sources

```bash
# Fingerprint the TLS certificate served by a remote host
certz fingerprint https://example.com

# JSON output for scripting
certz fingerprint https://example.com --format json
```

### JSON output

```bash
certz fingerprint cert.pem --format json
```

```json
{
  "success": true,
  "algorithm": "SHA256",
  "fingerprint": "AA:BB:CC:DD:...",
  "source": "cert.pem",
  "subject": "CN=example.com"
}
```

---

## Text output format

```
SHA256: AA:BB:CC:DD:EE:FF:...
```

The label (`SHA256`, `SHA384`, or `SHA512`) always matches the algorithm used.

---

## Comparison with OpenSSL

| OpenSSL | certz equivalent |
|---------|-----------------|
| `openssl x509 -fingerprint -sha256 -noout -in cert.pem` | `certz fingerprint cert.pem` |
| `openssl x509 -fingerprint -sha384 -noout -in cert.pem` | `certz fingerprint cert.pem --algorithm sha384` |
| `openssl s_client -connect host:443 </dev/null 2>/dev/null \| openssl x509 -fingerprint -sha256 -noout` | `certz fingerprint https://host` |

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Fingerprint computed successfully |
| `1` | Source not found, unreadable, invalid algorithm, or conflicting separator flags |
