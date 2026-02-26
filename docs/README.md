# Certz Documentation

## Guides

Step-by-step tutorials and walkthroughs.

| Guide | Description |
|-------|-------------|
| [Quick Start Tutorial](guides/quickstart.md) | Build a full local PKI: CA → sign cert → trust → inspect |
| [Interactive Wizard](guides/wizard.md) | Use `certz --guided` for any operation |
| [Security Best Practices](guides/security-best-practices.md) | Passwords, trust store hygiene, key handling |
| [CI/CD Integration](guides/cicd-integration.md) | GitHub Actions, pipeline recipes, JSON output patterns |

---

## Command Reference

Command-by-command option documentation with examples, JSON schemas, and troubleshooting.

| Command | Reference |
|---------|-----------|
| `create dev` / `create ca` | [reference/create.md](reference/create.md) |
| `inspect` | [reference/inspect.md](reference/inspect.md) |
| `trust add` / `trust remove` | [reference/trust.md](reference/trust.md) |
| `store list` | [reference/store.md](reference/store.md) |
| `lint` | [reference/lint.md](reference/lint.md) |
| `monitor` | [reference/monitor.md](reference/monitor.md) |
| `renew` | [reference/renew.md](reference/renew.md) |
| `convert` | [reference/convert.md](reference/convert.md) |
| Exit codes | [reference/exit-codes.md](reference/exit-codes.md) |
| Cryptographic standards | [reference/standards.md](reference/standards.md) |

---

## Concepts

Background knowledge: PKI building blocks, certificate formats, and compliance standards.

| Topic | Description |
|-------|-------------|
| [Certificate Formats](concepts/certificate-formats.md) | PEM, DER, PFX — and the confusing file extensions |
| [RSA vs ECDSA](concepts/rsa-vs-ecdsa.md) | Key types, sizes, and security tradeoffs |
| [Subject Alternative Names](concepts/subject-alternative-names.md) | Why SANs are required and how certz handles them |
| [Enhanced Key Usage](concepts/enhanced-key-usage.md) | What EKU restricts and what certz sets by default |
| [Certificate Chain](concepts/certificate-chain.md) | Root, intermediate, and leaf certificates explained |
| [Windows Trust Store](concepts/windows-trust-store.md) | Store names, locations, and admin requirements |
| [Certificate Lifecycle](concepts/certificate-lifecycle.md) | Validity dates, the 398-day limit, and renewal |
| [Compliance Standards](concepts/compliance-standards.md) | CA/Browser Forum, Mozilla NSS, and what they govern |

---

## Quick Links

| Document | Description |
|----------|-------------|
| [CLI Specification](certz-spec.md) | Authoritative command reference |
| [Architecture](architecture.md) | Design patterns and service structure |
| [Testing Guide](testing.md) | How to test certz |

---

## Development

### Feature Implementation

All features have been implemented and documented in phase plans.

| Phase | Feature | Documentation |
|-------|---------|---------------|
| 1 | Create Commands | [phase1-create.md](phases/phase1-create.md) |
| 2 | Inspect Commands | [phase2-inspect.md](phases/phase2-inspect.md) |
| 3 | Trust Store | [phase3-trust.md](phases/phase3-trust.md) |
| 4 | Linting | [phase4-lint.md](phases/phase4-lint.md) |
| 5 | Chain Visualization | [phase5-chain.md](phases/phase5-chain.md) |
| 6 | Expiration Monitoring | [phase6-monitor.md](phases/phase6-monitor.md) |
| 7 | Renewal | [phase7-renew.md](phases/phase7-renew.md) |
| 8 | Ephemeral Mode | [phase8-ephemeral.md](phases/phase8-ephemeral.md) |
| 9 | Format Conversion | [phase9-convert.md](phases/phase9-convert.md) |
| 10 | Global Guided Wizard | [phase10-guided.md](phases/phase10-guided.md) |
| 11 | Wizard UX Enhancements | [phase11-wizard-enhancements.md](phases/phase11-wizard-enhancements.md) |
| 12 | Wizard Navigation Improvements | [phase12-wizard-navigation.md](phases/phase12-wizard-navigation.md) |

### Release & Deployment

| Document | Description |
|----------|-------------|
| [Release Process](reference/release.md) | How to publish a new certz release using `scripts/release.ps1` |
| [Verifying Downloads](reference/verify-download.md) | SHA-256 verification for end-users |
| [Docker Testing](docker-testing.md) | Quick reference for Docker-based testing |
| [Docker Files Explained](docker-files-explained.md) | How Docker files are structured |

### Future Work

| Document | Description |
|----------|-------------|
| [Feature Recommendations](feature-recommendations.md) | Proposed future enhancements |
| [Partial Thumbprint Plan](partial-thumbprint-plan.md) | Partial thumbprint matching design |

### Testing

See also: [Test Documentation](../test/README.md)

| Document | Description |
|----------|-------------|
| [Testing Guide](testing.md) | Main testing procedures |
| [Test Isolation](../test/isolation-plan.md) | Single-call test principle |
| [Coverage Analysis](../test/coverage-analysis.md) | Test coverage gaps |
