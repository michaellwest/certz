# certz store list — Reference

List and filter certificates in the Windows certificate store. Useful for auditing what is installed, finding expiring certificates, and locating thumbprints.

**See also:** [Windows Trust Store](../concepts/windows-trust-store.md) · [certz trust](trust.md) · [certz monitor](monitor.md)

---

## Examples

```bash
# List certificates in My store
certz store list

# List certificates in Root store
certz store list --store Root

# List from LocalMachine
certz store list --store Root --location LocalMachine

# Show only expired certificates
certz store list --expired

# Show certificates expiring within 30 days
certz store list --expiring 30

# JSON output
certz store list --format json
```

---

## Options

| Option | Description |
|--------|-------------|
| `--store` | Store name: My (default), Root, CA, TrustedPeople, TrustedPublisher |
| `--location` | CurrentUser (default) or LocalMachine |
| `--expired` | Show only expired certificates |
| `--expiring <days>` | Show certificates expiring within N days |
| `--format` | Output format: text or json |
