# Exit Codes — Reference

All certz commands return a standard exit code. This page consolidates exit codes across all commands.

---

## Universal Exit Codes

These apply to all commands:

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Error — invalid arguments, file not found, operation failed |

---

## Command-Specific Exit Codes

### certz lint

| Code | Description |
|------|-------------|
| `0` | All checks passed (no errors) |
| `1` | One or more lint errors found |

### certz monitor

| Code | Description |
|------|-------------|
| `0` | All certificates valid and outside warning threshold |
| `1` | Certificates expiring within threshold (only with `--fail-on-warning`) |
| `2` | Expired certificates found |

> Exit code `2` (expired) takes precedence over `1` (expiring within threshold).

### certz renew

| Code | Description |
|------|-------------|
| `0` | Certificate renewed successfully |
| `1` | Source certificate not found or invalid |
| `2` | Cannot renew — missing issuer for a CA-signed certificate |

---

## Using Exit Codes in Scripts

**Bash / sh:**

```bash
certz lint cert.pfx --password "$PASS" --severity error
if [ $? -ne 0 ]; then
  echo "Cert failed lint — blocking deployment"
  exit 1
fi
```

**PowerShell:**

```powershell
certz lint cert.pfx --password $env:CERT_PASS --severity error
if ($LASTEXITCODE -ne 0) {
  Write-Error "Cert failed lint — blocking deployment"
  exit 1
}
```

**Chaining (bash):**

```bash
# Fail fast: lint then monitor, stop on first failure
certz lint cert.pfx --password "$PASS" --severity error &&
certz monitor cert.pfx --fail-on-warning &&
echo "All checks passed"
```

---

## Global Options

These options are available on every command:

| Option | Description |
|--------|-------------|
| `--format <text\|json>` | Output format for automation |
| `--guided` | Launch interactive wizard |
| `--help` | Show help for a command |
| `--version` | Show version information |
