# certz 🔐

A standards-compliant certificate utility for creating, inspecting, linting, converting, and monitoring X.509 certificates on Windows.

## Install

Download the latest single-file executable from the [Releases](https://github.com/michaellwest/certz/releases) page. No .NET runtime required -- copy `certz.exe` anywhere and run it.

## Shell Completion

Enable tab completion for option names and values in PowerShell:

```powershell
certz completion powershell >> $PROFILE
. $PROFILE
```

After reloading your profile, press Tab after any certz option to cycle through valid values:

```powershell
certz create dev --key-type <TAB>   # ECDSA-P256  ECDSA-P384  ECDSA-P521  RSA
certz create dev --eku <TAB>        # serverAuth  clientAuth  codeSigning  emailProtection
certz --format <TAB>                # json  text
certz store list --store <TAB>      # My  Root  CA  TrustedPeople  ...
```

See [docs/guides/completion.md](docs/guides/completion.md) for full details including context-aware completions and troubleshooting.

## Quick Start

```bash
# Interactive wizard — guided mode for all operations
certz --guided

# Create a development certificate for localhost and trust it
certz create dev localhost --trust

# Inspect any certificate (file, URL, or store thumbprint)
certz inspect https://github.com --chain

# Validate against CA/Browser Forum standards
certz lint cert.pfx --password MyPassword --severity error

# Convert between PEM, DER, and PFX formats
certz convert server.pfx --to pem --password MyPassword

# Monitor certificates for expiration
certz monitor ./certs https://example.com --warn 30 --fail-on-warning

# Renew an expiring certificate
certz renew server.pfx --password MyPassword --days 90
```

## Commands

```
certz [command] [options]

Options:
  --guided              Launch interactive wizard for any operation
  --format <text|json>  Output format (default: text)
  --version             Show version information
  -?, -h, --help        Show help and usage information

Commands:
  create dev <domain>    Create a development/server certificate
  create ca              Create a Certificate Authority (CA) certificate
  inspect <source>       Inspect certificate from file, URL, or store
  lint <source>          Validate certificate against industry standards
  monitor <sources...>   Monitor certificates for expiration
  renew <source>         Renew an existing certificate with extended validity
  trust add <file>       Add certificate to trust store
  trust remove           Remove certificate from trust store
  store list             List certificates in a store
  convert                Convert between PEM, DER, and PFX formats
```

## Documentation

### Guides

| Guide | Description |
|-------|-------------|
| [Quick Start Tutorial](docs/guides/quickstart.md) | Build a full local PKI: CA → sign cert → trust → inspect |
| [Interactive Wizard](docs/guides/wizard.md) | Use `certz --guided` for any operation |
| [Security Best Practices](docs/guides/security-best-practices.md) | Passwords, trust store hygiene, key handling |
| [CI/CD Integration](docs/guides/cicd-integration.md) | GitHub Actions, pipeline recipes, JSON output patterns |

### Command Reference

| Command | Reference |
|---------|-----------|
| `create dev` / `create ca` | [docs/reference/create.md](docs/reference/create.md) |
| `inspect` | [docs/reference/inspect.md](docs/reference/inspect.md) |
| `trust add` / `trust remove` | [docs/reference/trust.md](docs/reference/trust.md) |
| `store list` | [docs/reference/store.md](docs/reference/store.md) |
| `lint` | [docs/reference/lint.md](docs/reference/lint.md) |
| `monitor` | [docs/reference/monitor.md](docs/reference/monitor.md) |
| `renew` | [docs/reference/renew.md](docs/reference/renew.md) |
| `convert` | [docs/reference/convert.md](docs/reference/convert.md) |
| Exit codes | [docs/reference/exit-codes.md](docs/reference/exit-codes.md) |
| Cryptographic standards | [docs/reference/standards.md](docs/reference/standards.md) |

### Concepts

| Topic | Description |
|-------|-------------|
| [Certificate Formats](docs/concepts/certificate-formats.md) | PEM, DER, PFX — and the confusing file extensions |
| [RSA vs ECDSA](docs/concepts/rsa-vs-ecdsa.md) | Key types, sizes, and security tradeoffs |
| [Subject Alternative Names](docs/concepts/subject-alternative-names.md) | Why SANs are required and how certz handles them |
| [Enhanced Key Usage](docs/concepts/enhanced-key-usage.md) | What EKU restricts and what certz sets by default |
| [Certificate Chain](docs/concepts/certificate-chain.md) | Root, intermediate, and leaf certificates explained |
| [Windows Trust Store](docs/concepts/windows-trust-store.md) | Store names, locations, and admin requirements |
| [Certificate Lifecycle](docs/concepts/certificate-lifecycle.md) | Validity dates, the 398-day limit, and renewal |
| [Compliance Standards](docs/concepts/compliance-standards.md) | CA/Browser Forum, Mozilla NSS, and what they govern |
