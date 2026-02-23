# certz trust -- Reference

Add and remove certificates from the Windows certificate trust store. Adding a CA to the
Root store causes Windows and all browsers to trust every certificate that CA has signed.

**See also:**
[Windows Trust Store](../concepts/windows-trust-store.md) |
[Certificate Chain](../concepts/certificate-chain.md) |
[Exit Codes](exit-codes.md)

> **Security warning:** Only add CAs you control or explicitly trust to the Root store.
> A trusted Root CA can issue certificates for any domain. A compromised or malicious CA
> can silently intercept HTTPS traffic. See [Windows Trust Store](../concepts/windows-trust-store.md)
> for a full explanation of the trust model.

---

## trust add

Add a certificate to the Windows trust store.

### Quick Examples

```bash
# Add a CA certificate to the Root store (CurrentUser)
certz trust add ca.cer --store Root

# Add from a PFX file
certz trust add ca.pfx --password MyPassword --store Root

# Add to LocalMachine (requires Administrator)
certz trust add ca.cer --store Root --location LocalMachine

# Add to the Intermediate CA store instead of Root
certz trust add intermediate.cer --store CA
```

### Auto-location Default

When `certz trust add` is run as Administrator, the default location is `LocalMachine`
(machine-wide trust, no UI dialog). When run as a standard user, the default is
`CurrentUser` (trust for the current user only).

You can always override this with `--location`:

```bash
# Force CurrentUser even when running as admin
certz trust add ca.cer --store Root --location CurrentUser

# Force LocalMachine (will fail without admin rights)
certz trust add ca.cer --store Root --location LocalMachine
```

### trust add Options

| Option | Default | Description |
|--------|---------|-------------|
| `<file>` | (required) | Certificate file to add: PFX, PEM, DER, or CER |
| `--password, -p` | (none) | Password for PFX files. Also reads from `CERTZ_PASSWORD` env var. |
| `--store, -s` | `Root` | Target store: `Root`, `CA`, `My`, `TrustedPeople` |
| `--location, -l` | `LocalMachine` (admin) or `CurrentUser` | Store location: `CurrentUser` or `LocalMachine` |
| `--dry-run, --dr` | `false` | Show where the certificate would be added without modifying the store. |
| `--format` | `text` | Output format: `text` or `json` |

---

## trust remove

Remove certificates from the Windows trust store by thumbprint or subject pattern.

### Quick Examples

```bash
# Remove by full thumbprint (40 hex chars) -- no confirmation prompt with --force
certz trust remove ABC123DEF456789012345678901234567890ABCD --force

# Remove by partial thumbprint (8+ chars prefix match) -- interactive confirmation
certz trust remove ABC123DE

# Remove by subject pattern (wildcards supported)
certz trust remove --subject "CN=Dev CA*" --force

# Remove from a specific store and location
certz trust remove ABC123DEF456 --store Root --location LocalMachine --force
```

### Partial Thumbprint Matching

You can provide a shortened thumbprint prefix instead of the full 40-character value.

Rules:
- Minimum **8 characters** required (shorter values are rejected)
- Matching is **case-insensitive prefix match** (StartsWith)
- A **full 40-character** thumbprint performs an exact match
- Only hex characters are accepted (`0-9`, `A-F`)
- If **multiple certificates match**, `--force` is required; otherwise certz lists the
  matches and exits without removing anything

```bash
# Ambiguous -- lists matches and exits without removing (add --force to proceed)
certz trust remove ABC12

# At least 8 chars required
certz trust remove ABCDE            # error: too short (5 chars)

# Multiple matches found -- certz lists them and exits
certz trust remove ABC123DE         # three certs share this prefix -- add --force

# Multiple matches -- remove all matching
certz trust remove ABC123DE --force
```

### Subject Pattern Matching

Use `--subject` with wildcard patterns to match by Distinguished Name:

```bash
# Remove all Dev CA certs
certz trust remove --subject "CN=Dev CA" --force

# Wildcard match
certz trust remove --subject "CN=Dev*" --force

# Combine with store/location
certz trust remove --subject "CN=My Org*" --store Root --location LocalMachine --force
```

### Interactive Confirmation

When `--force` is not provided and exactly one certificate matches, certz prompts for
confirmation before removing:

```
Remove certificate 'Dev CA' (ABC123DEF456789012345678901234567890ABCD)?
[y/n] (n):
```

Type `y` to confirm, or press Enter to cancel. In JSON output mode (`--format json`),
`--force` is required to bypass the interactive prompt.

### trust remove Options

| Option | Default | Description |
|--------|---------|-------------|
| `[thumbprint]` | (none) | Full (40-char) or partial (8+ char) thumbprint. Required unless `--subject` is provided. |
| `--subject` | (none) | Remove certificates matching this subject pattern. Wildcards supported. |
| `--store, -s` | `Root` | Target store: `Root`, `CA`, `My`, `TrustedPeople` |
| `--location, -l` | `LocalMachine` (admin) or `CurrentUser` | Store location: `CurrentUser` or `LocalMachine` |
| `--force, -f` | `false` | Remove without interactive confirmation. Required when multiple certificates match. |
| `--dry-run, --dr` | `false` | Show which certificates would be removed without modifying the store. |
| `--format` | `text` | Output format: `text` or `json` |

---

## Store Names

| Store | Contains | Common use |
|-------|----------|------------|
| `Root` | Trusted Root CAs | Add self-signed or internal CA certs here to establish trust |
| `CA` | Intermediate CAs | Add intermediate CA certs here to complete chains |
| `My` | Personal certificates with private keys | Certs used by this machine for authentication or TLS |
| `TrustedPeople` | User-trusted certificates | Peer-to-peer trust; less common |

---

## Security Notes

### What a trusted Root CA can do

When you add a certificate to the `Root` store:

- Every certificate signed by that CA is **automatically trusted** by Windows and browsers
- The CA can issue certificates for **any domain name** -- including `github.com`, `google.com`, etc.
- If the CA's private key is stolen, an attacker can issue fraudulent certificates for any site

**Only add CAs you generated yourself** (via `certz create ca`) or CAs from organizations
you explicitly trust.

### CurrentUser vs LocalMachine

| Location | Who is affected | Requires admin |
|----------|-----------------|----------------|
| `CurrentUser` | Only the logged-in user | No |
| `LocalMachine` | All users on the machine | Yes (run as Administrator) |

For development environments, `CurrentUser` is sufficient and does not require elevation.
Use `LocalMachine` only when machine-wide trust is needed (e.g., for services running
as LocalSystem or in CI agents).

---

## Troubleshooting

| Problem | Likely cause | Fix |
|---------|--------------|-----|
| "Access denied" when adding to LocalMachine | Not running as Administrator | Right-click the terminal and "Run as Administrator", then retry. |
| Windows security dialog appears when adding to Root | Adding to CurrentUser Root store requires user confirmation (Windows security feature) | Run as Administrator to add to LocalMachine Root store and bypass the dialog. |
| "No matching certificates found" on `trust remove` | Wrong thumbprint, store, or location | Run `certz store list --store Root` (and other stores) to find the certificate and confirm its thumbprint. |
| Thumbprint too short error | Fewer than 8 characters provided | Provide at least 8 hex characters. Full thumbprint is always safe. |
| Browser still shows untrusted warning after `trust add` | Browser certificate cache | Close and reopen the browser. Some browsers (Firefox) use their own trust store -- add the cert via the browser's settings instead. |
| `trust remove` lists matches but does not remove | Multiple certs matched; `--force` not provided | Review the listed certs, then re-run with `--force` to remove all matches, or use a longer thumbprint prefix to narrow the match. |
