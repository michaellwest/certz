# certz monitor — Reference

Monitor certificates for expiration across files, directories, URLs, and certificate stores. Ideal for CI/CD pipelines and infrastructure monitoring.

**See also:** [Certificate Lifecycle](../concepts/certificate-lifecycle.md) · [Exit Codes](exit-codes.md) · [CI/CD Integration](../guides/cicd-integration.md)

---

## Examples

```bash
# Monitor a single certificate file
certz monitor cert.pfx --password MyPassword

# Monitor a directory of certificates
certz monitor ./certs --password MyPassword

# Monitor directory recursively
certz monitor ./certs --recursive --password MyPassword

# Monitor remote URL certificate
certz monitor https://github.com

# Monitor multiple sources at once
certz monitor ./certs https://github.com https://google.com

# Monitor certificate store
certz monitor --store My --location CurrentUser

# Custom warning threshold (default is 30 days)
certz monitor ./certs --warn 90

# Quiet mode - only show certificates within warning threshold
certz monitor ./certs --quiet

# CI/CD integration - fail on warning
certz monitor ./certs --fail-on-warning

# JSON output for automation
certz monitor ./certs --format json

# Use a password map file for directories with mixed passwords
certz monitor ./certs --password-map passwords.txt

# Combine password map with a fallback password
certz monitor ./certs --password-map passwords.txt --password FallbackPass
```

---

## Password Map File Format

When a directory contains PFX files with different passwords, use a password map file:

```
# Lines starting with # are comments
# Format: glob_pattern=password (first match wins)
prod-*.pfx=Pr0dP@ss!
staging-*.pfx=StagingPass
*.pfx=DefaultPass
```

---

## Options

| Option | Description |
|--------|-------------|
| `--warn, -w <days>` | Warning threshold in days (default: 30) |
| `--recursive, -r` | Scan subdirectories for certificate files |
| `--password, -p` | Password for PFX files (or use env: CERTZ_PASSWORD) |
| `--password-map, --pm` | File mapping glob patterns to PFX passwords (pattern=password per line) |
| `--store, -s` | Certificate store to scan (My, Root, CA) |
| `--location, -l` | Store location (CurrentUser, LocalMachine) |
| `--quiet, -q` | Only output certificates within warning threshold |
| `--fail-on-warning` | Exit with code 1 if certificates within threshold |
| `--format` | Output format: text (default) or json |

---

## Exit Codes

| Code | Description |
|------|-------------|
| `0` | All certificates valid and outside warning threshold |
| `1` | Certificates expiring within threshold (with `--fail-on-warning`) |
| `2` | Expired certificates found |

---

## Example Output

**Text Format:**

```
Certificate Expiration Monitor
Threshold: 30 days

╭────────────┬───────╮
│ Status     │ Count │
├────────────┼───────┤
│ Valid      │ 3     │
│ Expiring   │ 1     │
│ Expired    │ 0     │
│ Total      │ 4     │
╰────────────┴───────╯

╭─────────────────────┬─────────────────┬────────────┬──────┬──────────╮
│ Source              │ Subject         │ Expires    │ Days │ Status   │
├─────────────────────┼─────────────────┼────────────┼──────┼──────────┤
│ ./certs/api.pfx     │ api.company.com │ 2026-03-01 │ 21   │ Expiring │
│ ./certs/web.pfx     │ www.company.com │ 2026-06-15 │ 127  │ Valid    │
│ https://example.com │ example.com     │ 2027-01-01 │ 327  │ Valid    │
╰─────────────────────┴─────────────────┴────────────┴──────┴──────────╯
```

**JSON Format:**

```json
{
  "success": true,
  "totalScanned": 4,
  "validCount": 3,
  "expiringCount": 1,
  "expiredCount": 0,
  "skippedCount": 0,
  "warnThreshold": 30,
  "certificates": [
    {
      "source": "./certs/api.pfx",
      "subject": "CN=api.company.com",
      "thumbprint": "ABC123...",
      "notAfter": "2026-03-01T00:00:00Z",
      "daysRemaining": 21,
      "status": "Expiring",
      "isWarning": true
    }
  ]
}
```
