# CI/CD Integration Guide

certz is designed to work cleanly in automated pipelines. Every command supports
`--format json` for machine-readable output, structured exit codes for shell
conditionals, and `CERTZ_PASSWORD` for secure credential injection without flag
exposure.

This guide covers general integration patterns. For per-command CI/CD recipes see:
- [certz monitor -- CI/CD Recipes](../reference/monitor.md#cicd-recipes)
- [Exit Codes](../reference/exit-codes.md)

**See also:**
[Security Best Practices](security-best-practices.md) |
[certz monitor](../reference/monitor.md) |
[certz lint](../reference/lint.md)

---

## CI/CD-Friendly Features

| Feature | Flag / mechanism | Pipeline use |
|---------|-----------------|--------------|
| JSON output | `--format json` | Machine-readable results for all commands |
| Structured exit codes | See [exit-codes.md](../reference/exit-codes.md) | Shell conditionals and fail-fast |
| Ephemeral mode | `--ephemeral` | Generate a test cert with no disk cleanup needed |
| Pipe mode | `--pipe` | Feed certificate bytes directly to another process |
| Fail on warning | `--fail-on-warning` (monitor) | Block pipeline on certs expiring within N days |
| Severity filter | `--severity error` (lint) | Only fail builds on hard lint errors, not warnings |
| Password env var | `CERTZ_PASSWORD` | Inject passwords without exposing them in process lists |

---

## Downloading certz in CI

### GitHub Actions (Windows runner)

```yaml
- name: Download certz
  run: |
    Invoke-WebRequest -Uri $env:CERTZ_URL -OutFile certz.exe
    .\certz.exe --version
  env:
    CERTZ_URL: ${{ vars.CERTZ_DOWNLOAD_URL }}
```

### Azure DevOps (Windows agent)

```yaml
- task: PowerShell@2
  displayName: Download certz
  inputs:
    targetType: inline
    script: |
      Invoke-WebRequest -Uri $env:CERTZ_URL -OutFile certz.exe
      .\certz.exe --version
  env:
    CERTZ_URL: $(CERTZ_DOWNLOAD_URL)
```

### Linux / macOS runner

```bash
curl -Lo certz "$CERTZ_DOWNLOAD_URL"
chmod +x certz
./certz --version
```

Store `CERTZ_DOWNLOAD_URL` as a CI/CD variable or pipeline variable pointing to the
release download URL. Do not hardcode version numbers in pipeline scripts -- update
the variable when you update certz.

---

## Using JSON Output for Automation

Add `--format json` to any certz command to get structured output instead of formatted
text. Parse the JSON downstream with `jq` (bash) or `ConvertFrom-Json` (PowerShell).

### Bash with `jq`

```bash
# Inspect and extract specific fields
result=$(certz inspect cert.pfx --password "$CERTZ_PASSWORD" --format json)
thumbprint=$(echo "$result" | jq -r '.thumbprint')
days=$(echo "$result" | jq -r '.daysRemaining')

echo "Thumbprint: $thumbprint"
echo "Days remaining: $days"

# Fail if expiring within 30 days
if [ "$(echo "$result" | jq '.daysRemaining')" -lt 30 ]; then
  echo "Certificate expires in less than 30 days -- renew now"
  exit 1
fi
```

### PowerShell

```powershell
# Inspect and extract specific fields
$result = certz inspect cert.pfx --password $env:CERTZ_PASSWORD --format json |
    ConvertFrom-Json

Write-Host "Thumbprint: $($result.thumbprint)"
Write-Host "Days remaining: $($result.daysRemaining)"

# Fail if expiring within 30 days
if ($result.daysRemaining -lt 30) {
    Write-Error "Certificate expires in less than 30 days -- renew now"
    exit 1
}
```

### Parse lint results

```bash
# Bash -- show only error-severity findings
certz lint cert.pfx --password "$CERTZ_PASSWORD" --format json \
  | jq '.findings[] | select(.severity == "Error") | {ruleId, message}'

# PowerShell -- count errors
$lint = certz lint cert.pfx --password $env:CERTZ_PASSWORD --format json |
    ConvertFrom-Json
Write-Host "Errors: $($lint.errorCount), Warnings: $($lint.warningCount)"
```

---

## Pattern 1 -- Lint Gate: Fail the Build on Cert Violations

Block the pipeline if a certificate fails lint checks. Use `--severity error` to
fail only on hard errors and not on informational findings.

### Bash

```bash
certz lint cert.pfx --password "$CERTZ_PASSWORD" --severity error --format json \
  > lint-result.json

if [ $? -ne 0 ]; then
  echo "Lint failed -- errors found:"
  jq '.findings[] | select(.severity == "Error") | "  [\(.ruleId)] \(.message)"' \
    lint-result.json
  exit 1
fi

echo "Lint passed"
```

### GitHub Actions

```yaml
- name: Lint certificate
  run: |
    certz lint cert.pfx --password $env:CERTZ_PASSWORD --severity error --format json |
      Tee-Object lint-result.json
  env:
    CERTZ_PASSWORD: ${{ secrets.CERT_PASS }}

- name: Upload lint result
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: lint-result
    path: lint-result.json
```

### GitLab CI

```yaml
lint-cert:
  script:
    - certz lint cert.pfx --severity error --format json > lint-result.json
  artifacts:
    paths:
      - lint-result.json
    when: always
  variables:
    CERTZ_PASSWORD: $CERT_PASS    # set in GitLab CI/CD variables
```

---

## Pattern 2 -- Monitor Gate: Block Deployment on Expiring Certs

Fail the pipeline if any certificate is close to expiry. Pair with `--fail-on-warning`
and a meaningful `--warn` threshold.

```bash
# Fail if any cert expires within 30 days
certz monitor ./certs --warn 30 --fail-on-warning --format json > monitor-result.json

EXIT=$?
if [ $EXIT -eq 1 ]; then
  echo "Expiring certificates:"
  jq '.certificates[] | select(.isWarning) | "  \(.source): \(.daysRemaining) days"' \
    monitor-result.json
  exit 1
elif [ $EXIT -eq 2 ]; then
  echo "EXPIRED certificates found -- deployment blocked"
  jq '.certificates[] | select(.status == "Expired") | .source' monitor-result.json
  exit 1
fi

echo "All certs healthy"
```

For a full GitHub Actions weekly-scheduled monitoring workflow, see
[certz monitor -- CI/CD Recipes](../reference/monitor.md#cicd-recipes).

---

## Pattern 3 -- Ephemeral Cert: Test, No Cleanup

Use `--ephemeral` to generate a certificate in memory for integration tests or
pipeline validation. No files are written to disk, so no cleanup step is needed.

```bash
# Generate a test cert and extract its thumbprint -- never touches disk
certz create dev test.local --ephemeral --format json \
  | jq '{subject, thumbprint, notAfter, sans: .subjectAlternativeNames}'
```

```powershell
# PowerShell -- generate ephemeral cert and check its properties
$cert = certz create dev test.local --ephemeral --format json | ConvertFrom-Json
Write-Host "Created ephemeral cert: $($cert.subject)"
Write-Host "Expires: $($cert.notAfter)"
# No cleanup -- nothing was written to disk
```

Ephemeral certs are valid for all the same checks (inspect, lint) as file-based
certs -- the difference is that the private key never leaves memory.

---

## Pattern 4 -- Pipe Mode: Cert Directly Into Another Tool

Use `--pipe` to stream the certificate bytes to stdout so you can pipe them into
another process without an intermediate file.

### kubectl -- create a TLS secret directly

```bash
# Pipe the cert and key directly into kubectl
# (kubectl reads --cert and --key from stdin when path is /dev/stdin)
certz create dev app.cluster.local --pipe | \
  kubectl create secret tls app-tls \
    --cert=/dev/stdin \
    --key=/dev/stdin \
    --namespace=production
```

### Helm -- inject cert into a values file

```bash
# Extract PEM-encoded cert from pipe output and encode for Helm values
CERT_PEM=$(certz create dev app.cluster.local --pipe | base64 -w0)
helm upgrade my-app ./chart --set tls.cert="$CERT_PEM"
```

### Write to stdout for further processing

```bash
# Pipe to openssl for additional inspection
certz create dev test.local --pipe | openssl x509 -text -noout
```

See [certz create -- Pipe mode](../reference/create.md) for pipe output formats and
restrictions.

---

## Environment Variables

| Variable | Read by | Purpose |
|----------|---------|---------|
| `CERTZ_PASSWORD` | `inspect`, `lint`, `monitor`, `renew`, `convert` | PFX password fallback when `--password` is not provided |

Set `CERTZ_PASSWORD` in your CI/CD secret store and do not pass passwords as
command-line arguments -- they appear in process lists and are visible in pipeline
logs.

```yaml
# GitHub Actions -- inject password from secrets
- name: Monitor certificates
  run: certz monitor ./certs --warn 30 --fail-on-warning
  env:
    CERTZ_PASSWORD: ${{ secrets.CERT_PASS }}
```

---

## Complete Pipeline Example

A full certificate lifecycle check in GitHub Actions: download certz, lint the cert,
monitor expiry, fail with details if either check fails.

```yaml
name: Certificate Health Check
on:
  push:
    paths: ['certs/**']
  schedule:
    - cron: '0 8 * * 1'    # Every Monday at 08:00 UTC
  workflow_dispatch:

jobs:
  cert-check:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4

      - name: Download certz
        run: Invoke-WebRequest -Uri $env:CERTZ_URL -OutFile certz.exe
        env:
          CERTZ_URL: ${{ vars.CERTZ_DOWNLOAD_URL }}

      - name: Lint certificate
        run: |
          .\certz.exe lint certs/api.pfx --severity error --format json |
            Tee-Object lint-result.json
        env:
          CERTZ_PASSWORD: ${{ secrets.CERT_PASS }}

      - name: Monitor expiry
        run: |
          .\certz.exe monitor ./certs --warn 30 --fail-on-warning --format json |
            Tee-Object monitor-result.json
        env:
          CERTZ_PASSWORD: ${{ secrets.CERT_PASS }}

      - name: Upload results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: cert-health-results
          path: |
            lint-result.json
            monitor-result.json
```

---

## Troubleshooting CI/CD Issues

| Problem | Likely cause | Fix |
|---------|--------------|-----|
| `CERTZ_PASSWORD` not picked up | Variable not exported to the certz process | Ensure the variable is set in the `env:` block for the step, not just the job |
| Exit code 1 on `monitor` even though certs look valid | `--fail-on-warning` triggered by a cert within `--warn` days | Check `daysRemaining` in the JSON output; renew the cert or adjust `--warn` |
| JSON output contains ANSI escape codes | certz detected a TTY when there is none | certz should auto-detect non-TTY -- open an issue if ANSI codes appear in piped output |
| `certz.exe` not found after download | Executable not on PATH or wrong filename | Use the full path `.\certz.exe` or add the directory to PATH before running |
| Lint passes locally but fails in CI | Different certz version or policy set | Pin the certz download URL to a specific release tag and use the same `--policy` flag |
