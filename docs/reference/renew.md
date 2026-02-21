# certz renew — Reference

Renew an existing certificate with extended validity while preserving its parameters (subject, SANs, key type). certz automatically detects whether the certificate is self-signed or CA-signed.

**See also:** [Certificate Lifecycle](../concepts/certificate-lifecycle.md) · [RSA vs ECDSA](../concepts/rsa-vs-ecdsa.md) · [Exit Codes](exit-codes.md)

---

## Examples

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

---

## Options

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

---

## Self-Signed vs CA-Signed Renewal

- **Self-signed certificates**: Can be renewed directly without an issuer
- **CA-signed certificates**: Require the original issuer (`--issuer-cert`) to re-sign

The command auto-detects whether a certificate is self-signed by comparing Subject and Issuer fields.

---

## Exit Codes

| Code | Description |
|------|-------------|
| `0` | Certificate renewed successfully |
| `1` | Source certificate not found or invalid |
| `2` | Cannot renew (missing issuer for CA-signed cert) |
