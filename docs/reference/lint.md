# certz lint -- Reference

Validate certificates against industry compliance standards before deployment.
`certz lint` runs the same checks that browsers and CAs apply, so violations
surface in your terminal rather than as trust errors in production.

**See also:**
[Compliance Standards](../concepts/compliance-standards.md) |
[Subject Alternative Names](../concepts/subject-alternative-names.md) |
[RSA vs ECDSA](../concepts/rsa-vs-ecdsa.md) |
[Exit Codes](exit-codes.md)

---

## Quick Examples

```bash
# Lint a PFX (CA/B Forum rules by default)
certz lint cert.pfx --password MyPassword

# Lint a PEM file
certz lint cert.pem --policy cabf

# Lint a remote certificate
certz lint https://example.com

# Lint with Mozilla NSS policy (stricter -- includes CA/B Forum)
certz lint cert.pem --policy mozilla

# Relaxed rules for development certificates
certz lint devcert.pfx --password Pass --policy dev

# All policy sets combined
certz lint cert.pfx --password Pass --policy all

# Fail fast: only surface errors, suppress warnings and info
certz lint cert.pfx --password Pass --severity error

# Lint from Windows certificate store
certz lint ABC123DEF456 --store My

# Machine-readable output
certz lint cert.pfx --password Pass --format json
```

---

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `<source>` | (required) | Certificate file path, HTTPS URL, or store thumbprint. |
| `--password, -p` | (none) | Password for PFX/P12 input files. |
| `--policy` | `cabf` | Policy set to apply. See [Policy Sets](#policy-sets) below. |
| `--severity, -s` | `info` | Minimum severity to report: `info`, `warning`, or `error`. |
| `--store` | `My` | Certificate store name for thumbprint lookups: `My`, `Root`, `CA`. |
| `--location, -l` | `CurrentUser` | Store location: `CurrentUser` or `LocalMachine`. |
| `--format` | `text` | Output format: `text` or `json`. |
| `--guided` | `false` | Launch the interactive wizard for lint. Prompts for source, policy, and severity. |

---

## Policy Sets

| Policy | Includes | When to use |
|--------|----------|-------------|
| `cabf` (default) | CA/B Forum Baseline Requirements | Any certificate you deploy to a web server or trust store |
| `mozilla` | CA/B Forum BR + Mozilla NSS rules | CAs intended for Firefox or the Mozilla Root Program |
| `dev` | Relaxed development-specific checks | Local development only -- not for production |
| `all` | All three policy sets combined | Thorough audit before any deployment |

See [Compliance Standards](../concepts/compliance-standards.md) for background on what each standard covers and who enforces it.

---

## Lint Rules

Findings are ordered by severity (errors first), then by rule ID.

### CA/B Forum Baseline Requirements (`cabf`)

| Rule ID | Rule | Severity | Applies to | Trigger |
|---------|------|----------|------------|---------|
| BR-001 | Maximum Validity Period | **Error** | Leaf certs | Validity > 398 days |
| BR-003 | RSA Key Size | **Error** | All | RSA key < 2048 bits |
| BR-004 | ECDSA Key Size | **Error** | All | ECDSA key < P-256 (256 bits) |
| BR-005 | SHA-1 Signature Prohibited | **Error** | All | Signature algorithm uses SHA-1 |
| BR-007 | Subject Alternative Name Required | **Error** | Leaf certs | SAN extension absent |
| BR-008 | CN Must Be In SAN | Warning | Leaf certs | CN value does not appear in SAN list |
| BR-009 | Basic Constraints Required for CA | **Error** | CA certs | BasicConstraints extension absent |
| BR-009 | Basic Constraints Must Be Critical | Warning | CA certs | BasicConstraints present but not marked critical |
| BR-010 | CA Key Usage (keyCertSign) | **Error** | CA certs | keyCertSign flag absent from Key Usage |
| BR-010 | Key Usage Recommended | Warning | All | Key Usage extension absent entirely |
| BR-011 | Extended Key Usage Recommended | Info | Leaf certs | EKU extension absent |
| BR-012 | Authority Key Identifier Required | Warning | Non-root | AKI extension absent |
| BR-013 | Subject Key Identifier Recommended | Info | All | SKI extension absent |
| BR-015 | Country Code Length | **Error** | All | Country (C) present but not exactly 2 characters |
| BR-016 | Organization Requires Country | **Error** | All | Organization (O) present but Country (C) absent |
| BR-017 | Wildcard Position | **Error** | Leaf certs | Wildcard (`*`) appears outside the leftmost label |

### Mozilla NSS Policy (`mozilla`)

Includes all CA/B Forum rules above, plus:

| Rule ID | Rule | Severity | Applies to | Trigger |
|---------|------|----------|------------|---------|
| NSS-002 | Root CA Maximum Validity | Warning | Root CAs | Root CA validity > 25 years |
| NSS-003 | Intermediate CA Maximum Validity | Warning | Intermediate CAs | Intermediate CA validity > 10 years |
| NSS-004 | Name Constraints Recommended | Info | Intermediate CAs | NameConstraints extension absent |
| NSS-005 | Revocation Information Required | Warning | Intermediate CAs | Neither CRL Distribution Points nor AIA (OCSP) present |

### Development Policy (`dev`)

Relaxed checks intended for local development certificates only:

| Rule ID | Rule | Severity | Applies to | Trigger |
|---------|------|----------|------------|---------|
| DEV-001 | Long Validity | Warning | Leaf certs | Validity > 398 days |
| DEV-003 | Local Development SANs | Info | Leaf certs | `localhost` or `127.0.0.1` absent from SANs |

> **Note:** The `dev` policy never produces errors. Use `cabf` before deploying to any shared or production environment.

---

## Severity Levels

| Severity | Meaning | Effect on exit code |
|----------|---------|---------------------|
| `info` | Best-practice suggestion | None -- exit code 0 |
| `warning` | Deviation from recommended practice | None -- exit code 0 |
| `error` | Compliance failure -- cert will be rejected by browsers or CAs | Exit code 1 |

Only `error`-severity findings cause a non-zero exit code.
Use `--severity error` to suppress warnings and info in output entirely:

```bash
certz lint cert.pfx --password Pass --severity error
echo "Exit: $?"   # 0 = clean, 1 = errors found
```

---

## Using lint in CI/CD

### Fail-fast check

```bash
certz lint cert.pfx --password "$PFX_PASS" --severity error
if [ $? -ne 0 ]; then
  echo "Certificate has compliance errors. Blocking deployment."
  exit 1
fi
```

### GitHub Actions

```yaml
- name: Lint TLS certificate
  run: certz lint cert.pfx --password "${{ secrets.PFX_PASS }}" --severity error
```

### Parse JSON findings

```bash
# Show only error messages
certz lint cert.pfx --password Pass --format json \
  | jq '.findings[] | select(.severity == "Error") | .message'

# Count errors
certz lint cert.pfx --password Pass --format json | jq '.errorCount'
```

---

## JSON Output Schema

```bash
certz lint cert.pfx --password Pass --format json
```

Example output:

```json
{
  "subject": "CN=api.local",
  "thumbprint": "A1B2C3D4E5F6...",
  "passed": false,
  "policySet": "cabf",
  "isCa": false,
  "isRoot": false,
  "sourcePath": "cert.pfx",
  "errorCount": 1,
  "warningCount": 2,
  "infoCount": 1,
  "findings": [
    {
      "ruleId": "BR-001",
      "ruleName": "Maximum Validity Period",
      "severity": "Error",
      "message": "Leaf certificate validity exceeds 398 days (CA/B Forum limit)",
      "policy": "CA/B Forum BR",
      "actualValue": "730 days",
      "expectedValue": "<= 398 days"
    },
    {
      "ruleId": "BR-010",
      "ruleName": "Key Usage Recommended",
      "severity": "Warning",
      "message": "Key Usage extension is recommended",
      "policy": "CA/B Forum BR",
      "actualValue": null,
      "expectedValue": null
    }
  ]
}
```

Top-level fields:

| Field | Type | Description |
|-------|------|-------------|
| `subject` | string | Subject DN of the linted certificate |
| `thumbprint` | string | SHA-1 thumbprint (hex, no colons) |
| `passed` | bool | `true` when no error-severity findings exist |
| `policySet` | string | Policy applied: `cabf`, `mozilla`, `dev`, or `all` |
| `isCa` | bool | `true` if BasicConstraints has `CA=true` |
| `isRoot` | bool | `true` if subject equals issuer (self-signed) |
| `sourcePath` | string or null | File path or URL that was linted |
| `errorCount` | int | Number of error-severity findings |
| `warningCount` | int | Number of warning-severity findings |
| `infoCount` | int | Number of info-severity findings |
| `findings` | array | All findings matching the `--severity` filter, errors first |

Each finding:

| Field | Type | Description |
|-------|------|-------------|
| `ruleId` | string | Rule identifier: `BR-001`, `NSS-003`, `DEV-001`, etc. |
| `ruleName` | string | Short human-readable rule name |
| `severity` | string | `"Error"`, `"Warning"`, or `"Info"` |
| `message` | string | Full description of the violation |
| `policy` | string | Policy that defines this rule |
| `actualValue` | string or null | Value found in the certificate (where applicable) |
| `expectedValue` | string or null | Required or recommended value (where applicable) |

---

## Troubleshooting

| Problem | Likely cause | Fix |
|---------|--------------|-----|
| `BR-007`: SAN required | Certificate created by a tool that does not add a SAN extension | Recreate with `certz create dev` -- certz always adds SANs automatically. See [Subject Alternative Names](../concepts/subject-alternative-names.md). |
| `BR-001`: Validity error on a CA cert | CA cert linted with `cabf`; the 398-day rule applies to leaf certs only | Verify `isCa` is `true` in JSON output. If it is, this finding is a certz bug -- please report it. |
| `BR-003`/`BR-004`: Key size error | Certificate generated with a legacy tool using RSA-1024 or small ECDSA | Regenerate with `certz create dev` (defaults to ECDSA P-256). See [RSA vs ECDSA](../concepts/rsa-vs-ecdsa.md). |
| All findings are warnings but exit code is 1 | Not possible -- only errors produce exit code 1 | Run without `--severity error` to see the full finding list; one of them is an error. |
| `NSS-002`/`NSS-003` warnings on local CA | Internal CA linted with `mozilla` or `all`; NSS validity guidance targets public CAs | Expected for internal use. Switch to `--policy cabf` or `--policy dev` for local-only CAs. |
