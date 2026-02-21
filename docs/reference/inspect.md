# certz inspect — Reference

Inspect certificates from files, remote URLs, or the Windows certificate store. Displays subject, issuer, validity dates, SANs, key info, extensions, and optionally the full certificate chain.

**See also:** [Certificate Formats](../concepts/certificate-formats.md) · [Certificate Chain](../concepts/certificate-chain.md) · [Windows Trust Store](../concepts/windows-trust-store.md)

---

## Examples

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

# Detailed chain tree with key info, SANs, signatures
certz inspect https://github.com --chain --tree

# Check revocation status (OCSP/CRL)
certz inspect https://github.com --chain --crl

# Detailed chain with revocation check
certz inspect https://github.com --chain --tree --crl

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

---

## Options

| Option | Description |
|--------|-------------|
| `--chain` | Show certificate chain tree |
| `--tree` | Show detailed tree with key info, SANs, signatures (requires --chain) |
| `--crl` | Check revocation status (OCSP preferred, CRL fallback) |
| `--warn <days>` | Warn if certificate expires within N days |
| `--save <file>` | Save certificate to file (PEM default) |
| `--save-key <file>` | Save private key to file |
| `--save-format` | Export format: pem (default) or der |
| `--store` | Store name for thumbprint lookup (My, Root, CA) |
| `--location` | Store location (CurrentUser, LocalMachine) |
| `--format` | Output format: text or json |
