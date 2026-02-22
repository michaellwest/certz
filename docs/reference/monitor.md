# certz monitor -- Reference

Scan certificates for upcoming expiration across files, directories, HTTPS URLs, and
Windows certificate stores. Use interactively for a quick health check or wire it into
CI/CD and cron jobs to catch expirations before they become incidents.

**See also:**
[Certificate Lifecycle](../concepts/certificate-lifecycle.md) |
[Exit Codes](exit-codes.md) |
[CI/CD Integration](../guides/cicd-integration.md)

---

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `<sources>...` | (required) | One or more file paths, directory paths, or HTTPS URLs. Repeatable. |
| `--warn, -w <days>` | `30` | Flag as "Expiring" when days remaining falls below this value. |
| `--recursive, -r` | `false` | Scan subdirectories when a source is a directory. |
| `--password, -p` | (none) | Password for PFX files. Also reads from `CERTZ_PASSWORD` env var. |
| `--password-map, --pm` | (none) | Path to a password map file for directories with mixed PFX passwords. |
| `--store` | (none) | Scan a Windows certificate store: `My`, `Root`, or `CA`. |
| `--location, -l` | `CurrentUser` | Store location: `CurrentUser` or `LocalMachine`. |
| `--quiet, -q` | `false` | Suppress valid certificates; show only expiring and expired. |
| `--fail-on-warning` | `false` | Exit with code 1 when any certificate is within the warning threshold. |
| `--format` | `text` | Output format: `text` or `json`. |
| `--guided` | `false` | Launch the interactive wizard for monitor. Prompts for sources, warn threshold, and output format. |

---

## Source Types

### Single file

```bash
certz monitor server.pfx --password MyPassword
certz monitor server.pfx --password MyPassword --warn 60
certz monitor server.pem
```

### Directory

```bash
# Flat scan (top-level files only)
certz monitor ./certs --password SharedPass

# Recursive scan (all subdirectories)
certz monitor ./certs --recursive --password SharedPass

# Mixed passwords -- use a password map file
certz monitor ./certs --password-map passwords.txt

# Password map with a fallback for unmatched files
certz monitor ./certs --password-map passwords.txt --password FallbackPass
```

### Remote HTTPS URL

No password needed -- certz fetches the certificate from the TLS handshake:

```bash
certz monitor https://example.com
certz monitor https://api.internal:8443
```

### Multiple sources

Mix any combination of files, directories, and URLs in a single command:

```bash
certz monitor ./certs https://example.com https://api.internal
certz monitor ./certs --recursive https://example.com --warn 90
```

### Windows certificate store

```bash
certz monitor --store My --location CurrentUser
certz monitor --store Root --location LocalMachine
certz monitor --store CA --location LocalMachine --warn 90
```

---

## Password Map File

When a directory contains PFX files with different passwords, create a password map
file and pass it with `--password-map`. Each line is a glob pattern and password
separated by `=`. The first matching pattern wins.

```
# Lines starting with # are comments
# Format: glob_pattern=password  (first match wins)
prod-*.pfx=Pr0dP@ss!
staging-*.pfx=StagingPass
*.pfx=DefaultPass
```

Matching rules:
- Patterns match the **filename only** (not the full path)
- Matching is case-insensitive on Windows
- First match wins -- order patterns from most specific to least specific
- Files with no matching pattern fall through to `--password` if supplied, then are skipped

Combine with `--password` as a catch-all:

```bash
certz monitor ./certs --password-map passwords.txt --password GenericPass
```

---

## Warning Threshold and Exit Codes

| Exit code | Meaning |
|-----------|---------|
| `0` | All certificates valid and outside the warning threshold |
| `1` | One or more certificates are within the warning threshold (only when `--fail-on-warning` is set) |
| `2` | One or more certificates are expired |

Without `--fail-on-warning`, expiring-but-not-yet-expired certificates do not affect
the exit code. This lets you log warnings without blocking a pipeline.

```bash
# Report but never fail on expiring certs
certz monitor ./certs --warn 60 --format json

# Fail the pipeline if any cert expires within 30 days
certz monitor ./certs --warn 30 --fail-on-warning
echo "Exit: $?"
```

---

## Example Output

**Text format:**

```
Certificate Expiration Monitor
Threshold: 30 days

+------------+-------+
| Status     | Count |
+------------+-------+
| Valid      |     3 |
| Expiring   |     1 |
| Expired    |     0 |
| Total      |     4 |
+------------+-------+

+---------------------+-----------------+------------+------+----------+
| Source              | Subject         | Expires    | Days | Status   |
+---------------------+-----------------+------------+------+----------+
| ./certs/api.pfx     | api.company.com | 2026-03-01 |   21 | Expiring |
| ./certs/web.pfx     | www.company.com | 2026-06-15 |  127 | Valid    |
| https://example.com | example.com     | 2027-01-01 |  327 | Valid    |
+---------------------+-----------------+------------+------+----------+
```

Use `--quiet` to suppress Valid rows and show only Expiring and Expired certificates.

---

## JSON Output Schema

```bash
certz monitor ./certs https://example.com --format json
```

Example output:

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
      "thumbprint": "ABC123DEF456...",
      "notAfter": "2026-03-01T00:00:00Z",
      "daysRemaining": 21,
      "status": "Expiring",
      "isWarning": true
    },
    {
      "source": "https://example.com",
      "subject": "CN=example.com",
      "thumbprint": "789XYZ...",
      "notAfter": "2027-01-01T00:00:00Z",
      "daysRemaining": 327,
      "status": "Valid",
      "isWarning": false
    }
  ]
}
```

Top-level fields:

| Field | Type | Description |
|-------|------|-------------|
| `success` | bool | `false` only if the scan itself failed (e.g. unreadable directory) |
| `totalScanned` | int | Total certificates successfully read |
| `validCount` | int | Certificates with `daysRemaining` above the warn threshold |
| `expiringCount` | int | Certificates within the warn threshold but not yet expired |
| `expiredCount` | int | Certificates where `daysRemaining` is 0 or negative |
| `skippedCount` | int | Files that could not be read (wrong password, unsupported format) |
| `warnThreshold` | int | The `--warn` value used for this scan |
| `certificates` | array | One entry per certificate successfully scanned |

Each certificate entry:

| Field | Type | Description |
|-------|------|-------------|
| `source` | string | File path or URL where the certificate was found |
| `subject` | string | Subject DN of the certificate |
| `thumbprint` | string | SHA-1 thumbprint (hex, no colons) |
| `notAfter` | ISO 8601 | Expiry date (UTC) |
| `daysRemaining` | int | Days until expiry. Negative means already expired. |
| `status` | string | `"Valid"`, `"Expiring"`, or `"Expired"` |
| `isWarning` | bool | `true` when `daysRemaining` is below `warnThreshold` |

---

## CI/CD Recipes

### GitHub Actions -- Scheduled weekly check

```yaml
name: Certificate Expiry Check
on:
  schedule:
    - cron: '0 8 * * 1'  # Every Monday at 08:00 UTC
  workflow_dispatch:

jobs:
  monitor:
    runs-on: windows-latest
    steps:
      - name: Download certz
        run: Invoke-WebRequest -Uri $env:CERTZ_URL -OutFile certz.exe
        env:
          CERTZ_URL: ${{ vars.CERTZ_DOWNLOAD_URL }}

      - name: Check certificate expiry
        run: |
          ./certz.exe monitor https://example.com --warn 30 --fail-on-warning --format json |
            Tee-Object monitor-results.json
        continue-on-error: true

      - name: Upload results artifact
        uses: actions/upload-artifact@v4
        with:
          name: cert-monitor-results
          path: monitor-results.json

      - name: Fail if expiring or expired
        run: |
          $r = Get-Content monitor-results.json | ConvertFrom-Json
          if ($r.expiringCount -gt 0 -or $r.expiredCount -gt 0) {
            Write-Error "Certs expiring=$($r.expiringCount) expired=$($r.expiredCount)"
            exit 1
          }
```

### Linux/macOS -- Daily cron job

```bash
# /etc/cron.d/certz-monitor
# Check every day at 06:00; mail admin if any cert expires within 30 days
0 6 * * * root /usr/local/bin/certz monitor /etc/ssl/certs \
  --recursive --warn 30 --fail-on-warning --format json \
  >> /var/log/certz-monitor.log 2>&1 \
  || mail -s "Cert Expiry Alert" admin@example.com < /var/log/certz-monitor.log
```

### Parse JSON with jq

```bash
# Show only certificates within the warning window
certz monitor https://example.com --format json \
  | jq '.certificates[] | select(.isWarning) | {source, daysRemaining, status}'

# Count expiring certificates
certz monitor ./certs --format json | jq '.expiringCount'

# Exit non-zero if anything is expiring (without --fail-on-warning)
certz monitor ./certs --format json \
  | jq -e '.expiringCount == 0 and .expiredCount == 0' > /dev/null
```

### PowerShell

```powershell
$result = certz monitor ./certs --format json | ConvertFrom-Json

$expiring = $result.certificates | Where-Object { $_.isWarning }
if ($expiring) {
    foreach ($cert in $expiring) {
        Write-Warning "Expiring: $($cert.source) -- $($cert.daysRemaining) days remaining"
    }
    exit 1
}

Write-Host "All $($result.totalScanned) certificates are healthy."
```

---

## Troubleshooting

| Problem | Likely cause | Fix |
|---------|--------------|-----|
| PFX files skipped in directory scan (`skippedCount` > 0) | No password provided and no password map | Add `--password SharedPass` or `--password-map passwords.txt` |
| URL returns "connection refused" or times out | Port not open, wrong hostname, or firewall blocking TLS | Verify connectivity with `certz inspect https://...` first |
| Exit code 1 even though all certs appear valid | `--fail-on-warning` triggered by a cert within the warn threshold | Check `daysRemaining` vs `--warn` in JSON output; renew the certificate or raise `--warn` |
| Mixed passwords in directory -- some certs skipped | A single `--password` does not match all files | Switch to `--password-map` with per-file glob patterns |
| `skippedCount` is non-zero but unclear which files | Directory contains unsupported or corrupt files alongside PFX | Run `certz inspect <file>` on each suspected file to diagnose the individual failure |
