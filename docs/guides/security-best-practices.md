# Security Best Practices

certz makes it easy to create and manage certificates, but how you handle the output --
passwords, private keys, and trust store entries -- determines your actual security
posture. This guide covers the hygiene rules that matter most.

**See also:**
[RSA vs ECDSA](../concepts/rsa-vs-ecdsa.md) |
[Windows Trust Store](../concepts/windows-trust-store.md) |
[certz renew](../reference/renew.md) |
[certz monitor](../reference/monitor.md)

---

## Password Handling

### Auto-generated passwords

When you run `certz create` or `certz renew` without `--password`, certz generates a
cryptographically random password and prints it once to stdout:

```
  Pass: Xk9!mP2rLq          <- displayed once, then gone
```

Treat this output the same way you treat any other secret. Store it in a password
manager or secret store immediately. It is not recoverable -- if you lose it, you
must re-create the certificate.

### `--password-file` -- write the password to a file

```bash
certz create dev api.local --password-file api-local.pass
```

certz writes the password to `api-local.pass` in addition to displaying it. Secure
this file the same way you would secure a private key:

- Set restrictive file permissions (Windows: remove All Users / Everyone; Unix: `chmod 600`)
- Do not commit it to version control (add to `.gitignore`)
- Rotate it when you rotate the certificate

### `CERTZ_PASSWORD` environment variable

In CI/CD pipelines, avoid passing passwords as command-line flags -- they can appear
in process lists and log files. Use the `CERTZ_PASSWORD` environment variable instead:

```bash
# Set in your CI/CD secret manager, not in the script
export CERTZ_PASSWORD="$SECRET_CERT_PASS"
certz monitor ./certs
```

certz reads `CERTZ_PASSWORD` as the PFX password fallback whenever `--password` is
not provided. Supported by: `inspect`, `lint`, `monitor`, `renew`, `convert`.

### Never hardcode passwords in scripts

```bash
# BAD -- password in source control, visible in process list
certz inspect cert.pfx --password MyPassword123

# GOOD -- password from environment variable
certz inspect cert.pfx --password "$CERTZ_PASSWORD"

# GOOD -- password from a secrets manager at runtime
CERTZ_PASSWORD=$(vault read -field=password secret/certs/api) certz inspect cert.pfx
```

Use your organization's secret manager (GitHub Secrets, Azure Key Vault, HashiCorp
Vault, AWS Secrets Manager) to inject passwords at runtime rather than storing them
in scripts or config files.

---

## Trust Store Hygiene

### Only add CAs you control

Adding a certificate to the Root store grants it the ability to sign certificates
for **any domain**. A compromised or malicious CA in your Root store can issue
certificates for `github.com`, `google.com`, or your organization's internal services.

Only add CAs you generated yourself (via `certz create ca`) or CAs from explicitly
trusted organizations.

### Prefer `CurrentUser` over `LocalMachine` for dev CAs

| Location | Blast radius if CA is compromised |
|----------|----------------------------------|
| `CurrentUser` | Only the logged-in user is affected |
| `LocalMachine` | All users on the machine are affected |

Use `CurrentUser` (the default for standard users) for development CAs. Reserve
`LocalMachine` for machine-wide trust requirements such as CI agents or services
running as LocalSystem.

### Remove dev CAs when no longer needed

```bash
# Remove a specific dev CA by subject
certz trust remove --subject "CN=My Dev Root CA" --force

# Or by thumbprint
certz trust remove A1B2C3D4E5F6789012345678901234567890ABCD --force
```

Leaving development CAs permanently in the trust store unnecessarily expands your
trust boundary. Remove them when you finish the project, rotate to a new CA, or
move to a shared team CA.

### Audit the Root store periodically

```bash
# List all trusted Root CAs, filter to expired ones
certz store list --store Root --expired

# Export as JSON for automated auditing
certz store list --store Root --format json | jq '.certificates[] | select(.isExpired)'
```

Expired trusted roots are harmless but clutter the store and make audits harder.
Remove them with `certz trust remove`.

---

## Certificate Lifetime

### Keep dev certs short-lived

certz defaults to 90-day validity for leaf certificates -- the same period used by
Let's Encrypt. Short-lived certificates limit exposure if the private key is
compromised: the window for misuse closes when the certificate expires.

### Never exceed 398 days for leaf certificates

Browsers enforce the CA/Browser Forum limit of 398 days for publicly trusted
certificates. certz enforces this limit in `certz lint` and will flag violations.
Even for internal certificates, staying under 398 days is good practice:

```bash
# Lint will flag this
certz create dev api.local --days 730    # > 398 days

# This passes
certz create dev api.local --days 90    # default -- safe
certz create dev api.local --days 365   # under limit -- safe
```

### Monitor expirations proactively

Do not wait for a certificate to expire to discover it needs renewal. Set up
monitoring as part of your workflow:

```bash
# Warn 30 days before expiry; fail the pipeline if any cert has already expired
certz monitor ./certs --warn 30 --fail-on-warning

# Or just log -- no pipeline failure
certz monitor ./certs --warn 60 --format json >> cert-status.log
```

See [certz monitor](../reference/monitor.md) and the
[CI/CD Integration](cicd-integration.md) guide for scheduled monitoring recipes.

---

## Private Key Hygiene

### Treat `.key` and `.pfx` files as passwords

A private key file (`api-local.key`) or a PFX file (`api-local.pfx`) gives anyone
who has it the ability to impersonate your server or decrypt captured traffic. Protect
them accordingly:

- **Filesystem permissions:** Restrict read access to the owning service account only
- **No version control:** Add `*.key`, `*.pfx`, `*.pass` to `.gitignore`
- **Encrypted at rest:** Use encrypted storage (LUKS, BitLocker, FileVault) for
  machines that hold production private keys

### Recommended `.gitignore` entries

Add these to your project's `.gitignore` to prevent accidental commits:

```gitignore
# Certificate private keys and PFX bundles
*.key
*.pfx
*.p12
*.pass
*.password

# certz password files
*.certz-pass
```

### Use `--ephemeral` when keys must not touch disk

In automated testing or security-sensitive environments, use ephemeral mode to
generate a certificate entirely in memory -- nothing is written to disk:

```bash
# Certificate is created and used in memory; exits with no files on disk
certz create dev test.local --ephemeral --format json | jq '{thumbprint, notAfter}'
```

See [certz create](../reference/create.md) for ephemeral and pipe mode details.

### Use `--keep-key` on renewal only when necessary

By default, `certz renew` generates a fresh key pair on every renewal. This is the
safer option -- a new key means a compromised old key cannot be used to impersonate
the renewed certificate.

Only use `--keep-key` when you have a specific reason to keep the same key, such as
key pinning in dependent systems:

```bash
# Fresh key -- safer (default)
certz renew api-local.pfx --password "$CERTZ_PASSWORD" --days 90

# Preserve key -- use only when pinning requires it
certz renew api-local.pfx --password "$CERTZ_PASSWORD" --days 90 --keep-key
```

---

## Why certz Defaults to ECDSA P-256

certz uses ECDSA P-256 as the default key type for all certificates. This is not
arbitrary:

| Property | ECDSA P-256 | RSA 2048 | RSA 3072 |
|----------|-------------|----------|----------|
| Security level | ~128 bits | ~112 bits | ~128 bits |
| Key size | 256 bits | 2048 bits | 3072 bits |
| TLS handshake speed | Fast | Slower | Slower |
| Browser support | All modern browsers | Universal | Universal |
| Recommended by | NIST, CABF | Legacy | NIST |

ECDSA P-256 achieves the same security level as RSA 3072 with a much smaller key,
resulting in faster TLS handshakes and smaller certificate sizes.

Do not override to RSA unless you need compatibility with legacy systems that do not
support ECDSA (e.g., some older Java runtimes, embedded devices, or very old browsers).

```bash
# Default -- ECDSA P-256
certz create dev api.local

# RSA only when legacy compatibility is needed
certz create dev api.local --key-type rsa --key-size 3072
```

See [RSA vs ECDSA](../concepts/rsa-vs-ecdsa.md) for a full comparison.

---

## Storing PFX Passwords Safely

| What | Recommendation |
|------|----------------|
| Development passwords | Local password manager (1Password, Bitwarden, etc.) |
| Team-shared certs | Shared vault entry, not a file on a shared drive |
| CI/CD pipelines | Platform secret store (GitHub Secrets, Azure Key Vault, GitLab CI variables) |
| Production passwords | HSM or enterprise secret manager with audit logging |

### What not to do

```bash
# BAD: password in a script file checked into git
CERT_PASS="MyP@ssw0rd"
certz inspect cert.pfx --password "$CERT_PASS"

# BAD: password file committed alongside the PFX
git add cert.pfx cert.pass    # never do this

# BAD: password in a CI/CD job log
echo "Cert password: $CERT_PASS"    # visible in pipeline logs
```

### Separating secrets from certificates

It is acceptable to commit the `.pfx` file to version control in some contexts (e.g.,
development certificates for a shared project). What must never be in the same
repository is the password. Use a `.gitignore` entry to exclude password files, and
store passwords separately in a secret manager.

```gitignore
# Allow the PFX (no private key for public CA cert), exclude its password
docs/certs/ca.pfx       # could be committed if it is a public CA cert
*.pass                  # always excluded
*.key                   # always excluded -- private key material
```
