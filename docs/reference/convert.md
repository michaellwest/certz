# certz convert — Reference

Convert certificates between PEM, DER, and PFX formats with automatic input format detection.

**See also:** [Certificate Formats](../concepts/certificate-formats.md)

---

## Simplified Syntax

```bash
certz convert <input> --to <format> [options]
```

## Examples

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

---

## Format Detection

The input format is automatically detected:

| Extension | Detected Format |
|-----------|-----------------|
| `.pfx`, `.p12` | PFX (PKCS#12) |
| `.der` | DER (binary) |
| `.pem` | PEM (text) |
| `.crt`, `.cer` | Auto-detect from content |

---

## Options

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

---

## Legacy Syntax

The original flag-based syntax remains supported:

```bash
# PEM + KEY to PFX
certz convert --cert certificate.crt --key private.key --file output.pfx --password MyPassword

# PFX to PEM files
certz convert --pfx devcert.pfx --password YourPassword --out-cert certificate.cer --out-key private.key
```

---

## Format Reference

| Format | Description | Common Use |
|--------|-------------|------------|
| **PEM** | Base64 text with headers | Web servers, most Linux tools |
| **DER** | Binary ASN.1 encoding | Java keystores, some Windows apps |
| **PFX** | Password-protected bundle | Windows, IIS, certificate export |
