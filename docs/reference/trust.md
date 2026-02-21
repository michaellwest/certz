# certz trust — Reference

Add and remove certificates from the Windows trust store. Adding a CA to the Root store causes Windows and browsers to trust all certificates it has signed.

> **Security note:** Only add CAs you control to the Root trust store. A trusted CA can issue certificates for any domain. See [Windows Trust Store](../concepts/windows-trust-store.md) for full context.

**See also:** [Windows Trust Store](../concepts/windows-trust-store.md) · [Certificate Chain](../concepts/certificate-chain.md)

---

## Add Certificates

Add certificates to the Windows trust store.

```bash
# Add to Root store (CurrentUser)
certz trust add ca.cer --store Root

# Add PFX to trust store
certz trust add cert.pfx --password MyPassword --store Root

# Add to LocalMachine (requires Administrator)
certz trust add ca.cer --store Root --location LocalMachine
```

**Options:**

| Option | Description |
|--------|-------------|
| `--store` | Target store: Root (default), CA, My, TrustedPeople |
| `--location` | CurrentUser (default) or LocalMachine |
| `--password` | Password for PFX files |

---

## Remove Certificates

Remove certificates from the Windows trust store.

```bash
# Remove by full thumbprint (40 chars)
certz trust remove ABC123DEF456789012345678901234567890ABCD --force

# Remove by partial thumbprint (8+ chars prefix match)
certz trust remove ABC123DE --force

# Remove by subject pattern
certz trust remove --subject "CN=dev*" --force

# Remove from specific store
certz trust remove ABC123DEF456 --store Root --force

# Interactive removal (prompts for confirmation)
certz trust remove ABC123DEF456
```

**Partial Thumbprint Matching:**

- Minimum 8 characters required for partial thumbprint
- Uses prefix matching (StartsWith)
- If multiple certificates match, `--force` is required
- Full 40-character thumbprint performs exact match

**Options:**

| Option | Description |
|--------|-------------|
| `--subject` | Remove certificates matching subject pattern (wildcards supported) |
| `--store` | Target store: Root (default), CA, My, TrustedPeople |
| `--location` | CurrentUser (default) or LocalMachine |
| `--force` | Remove without confirmation (required for multiple matches) |
