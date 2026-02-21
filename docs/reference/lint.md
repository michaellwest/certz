# certz lint — Reference

Validate certificates against industry standards including CA/Browser Forum Baseline Requirements and Mozilla NSS Policy.

**See also:** [Compliance Standards](../concepts/compliance-standards.md) · [Subject Alternative Names](../concepts/subject-alternative-names.md) · [RSA vs ECDSA](../concepts/rsa-vs-ecdsa.md) · [Exit Codes](exit-codes.md)

---

## Examples

```bash
# Lint a certificate file (CA/B Forum rules by default)
certz lint cert.pfx --password MyPassword

# Lint with Mozilla NSS policy (includes CA/B Forum rules)
certz lint cert.pem --policy mozilla

# Lint a remote certificate
certz lint https://example.com

# Lint with development certificate rules (relaxed)
certz lint devcert.pfx --password Pass --policy dev

# Lint all policy sets
certz lint cert.pfx --password Pass --policy all

# Show only errors (filter out warnings and info)
certz lint cert.pfx --password Pass --severity error

# Lint certificate from store
certz lint ABC123DEF456 --store My

# JSON output for CI/CD integration
certz lint cert.pfx --password Pass --format json
```

---

## Options

| Option | Description |
|--------|-------------|
| `--password, -p` | Password for PFX/P12 files |
| `--policy` | Policy set: cabf (default), mozilla, dev, or all |
| `--severity, -s` | Minimum severity to report: info (default), warning, or error |
| `--store` | Certificate store name (My, Root, CA) for thumbprint lookup |
| `--location, -l` | Store location (CurrentUser or LocalMachine) |
| `--format` | Output format: text (default) or json |

---

## Policy Sets

| Policy | Description |
|--------|-------------|
| `cabf` | CA/Browser Forum Baseline Requirements (default) |
| `mozilla` | Mozilla NSS Policy (includes CA/B Forum rules) |
| `dev` | Relaxed rules for development certificates |
| `all` | All policy checks combined |

---

## Lint Rules

**CA/B Forum Baseline Requirements:**

- Maximum 398-day validity for leaf certificates
- RSA key size minimum 2048 bits
- SHA-1 signatures prohibited
- Subject Alternative Name required
- Basic Constraints required for CA certificates
- Key Usage extension recommended

**Mozilla NSS Policy:**

- Root CA maximum 25-year validity recommended
- Intermediate CA maximum 10-year validity recommended
- Name Constraints recommended for intermediates

**Development Certificate Checks:**

- Warns if validity exceeds 398 days
- Recommends localhost and 127.0.0.1 in SANs

---

## Exit Codes

| Code | Description |
|------|-------------|
| `0` | All checks passed (no errors) |
| `1` | One or more errors found |
