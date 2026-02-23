# Exit Codes -- Reference

All certz commands return a standard exit code on completion. This page is the
consolidated reference for every exit code across all commands.

---

## Universal Exit Codes

These apply to every certz command:

| Code | Meaning |
|------|---------|
| `0` | Success -- the operation completed without errors |
| `1` | Error -- invalid arguments, file not found, wrong password, or operation failed |

---

## Command-Specific Exit Codes

Some commands return additional exit codes beyond 0/1 to distinguish between warning
and error states.

### certz inspect

| Code | Condition |
|------|-----------|
| `0` | Inspection completed, no warnings |
| `1` | One or more warnings (e.g., `--warn` threshold triggered, or validation issues found) |

> `certz inspect` returns exit code 1 when `warnings[]` is non-empty in the result.
> The most common cause is `--warn <days>` when the certificate is within that threshold.

### certz diff

| Code | Condition |
|------|-----------|
| `0` | Certificates are identical (all compared fields match) |
| `1` | One or more fields differ between the two certificates |

> Exit code 1 signals that differences were found -- it is not an error.
> To detect errors (source not found, bad password, etc.), check stderr.

### certz lint

| Code | Condition |
|------|-----------|
| `0` | All lint checks passed (no errors found at the requested severity) |
| `1` | One or more lint errors found |

> Use `--severity error` to fail only on errors, not warnings or info findings.

### certz monitor

| Code | Condition |
|------|-----------|
| `0` | All certificates are valid and outside the warning threshold |
| `1` | One or more certificates are within the warning threshold (`--fail-on-warning` required) |
| `2` | One or more certificates have already expired |

> Exit code `2` (expired) takes precedence over `1` (expiring within threshold).
> Without `--fail-on-warning`, expiring-but-not-expired certificates do not affect the
> exit code -- only already-expired certificates trigger a non-zero result.

### certz renew

| Code | Condition |
|------|-----------|
| `0` | Certificate renewed successfully |
| `1` | Source certificate not found, invalid, or renewal failed |
| `2` | Cannot renew -- missing issuer for a CA-signed certificate |

---

## Exit Code Summary Table

| Command | Code | Meaning |
|---------|------|---------|
| Any | `0` | Success |
| Any | `1` | Error (argument, file not found, operation failed) |
| `diff` | `0` | Certificates are identical |
| `diff` | `1` | Certificates differ (not an error -- use exit code to drive scripts) |
| `inspect` | `1` | Warnings present (e.g., `--warn` threshold triggered) |
| `lint` | `1` | Lint errors found |
| `monitor` | `1` | Expiring certs within threshold (`--fail-on-warning` set) |
| `monitor` | `2` | Expired certs found (takes precedence over code 1) |
| `renew` | `2` | Cannot renew -- CA-signed cert missing `--issuer-cert` |

---

## Using Exit Codes in Scripts

### Bash / sh

```bash
# Fail pipeline if cert has lint errors
certz lint cert.pfx --password "$PASS" --severity error
if [ $? -ne 0 ]; then
  echo "Cert failed lint -- blocking deployment"
  exit 1
fi

# Monitor with fail-on-warning
certz monitor ./certs --warn 30 --fail-on-warning
if [ $? -ne 0 ]; then
  echo "Certificate expiry alert"
  exit 1
fi

# Chaining with &&: stop on first failure
certz lint cert.pfx --password "$PASS" --severity error &&
certz monitor cert.pfx --warn 30 --fail-on-warning &&
echo "All checks passed"
```

### PowerShell

```powershell
# Fail pipeline if cert has lint errors
certz lint cert.pfx --password $env:CERT_PASS --severity error
if ($LASTEXITCODE -ne 0) {
    Write-Error "Cert failed lint -- blocking deployment"
    exit 1
}

# Monitor with fail-on-warning
certz monitor ./certs --warn 30 --fail-on-warning
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Certificate expiry alert (exit code: $LASTEXITCODE)"
    exit $LASTEXITCODE
}

# Parse JSON and react to specific codes
$result = certz monitor ./certs --format json | ConvertFrom-Json
if ($result.expiredCount -gt 0) {
    Write-Error "Expired certs found: $($result.expiredCount)"
    exit 2
} elseif ($result.expiringCount -gt 0) {
    Write-Warning "Expiring certs: $($result.expiringCount)"
    exit 1
}
```

### GitHub Actions

```yaml
- name: Lint certificate
  run: certz lint cert.pfx --password ${{ secrets.CERT_PASS }} --severity error

- name: Monitor certificate expiry
  run: |
    certz monitor ./certs --warn 30 --fail-on-warning --format json |
      Tee-Object monitor-results.json
  continue-on-error: true

- name: Fail job if expiring
  run: |
    $r = Get-Content monitor-results.json | ConvertFrom-Json
    if ($r.expiredCount -gt 0 -or $r.expiringCount -gt 0) {
      exit 1
    }
```

---

## Global Options

These options are available on every certz command:

| Option | Description |
|--------|-------------|
| `--format <text\|json>` | Output format. Use `json` for scripting and automation. |
| `--guided` | Launch the interactive wizard instead of using flags |
| `--help` | Show help text for the command |
| `--version` | Show the certz version |
