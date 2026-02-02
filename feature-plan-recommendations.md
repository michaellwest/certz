# Feature Plan Recommendations

## Executive Summary

This document outlines recommendations for evolving certz from its current flat-command structure (8 commands with 40+ options) to a hierarchical, intent-based CLI following modern patterns like `kubectl` and `docker`.

---

## Requirements Decisions

Based on clarifying questions, the following decisions have been made:

| Area | Decision | Notes |
|------|----------|-------|
| **Backwards Compatibility** | Breaking change OK | Major version bump to 2.0, no aliases required |
| **CLI Framework** | Hybrid approach | System.CommandLine for parsing + Spectre.Console for display |
| **CSR Workflow** | Skip | `create csr` feature not needed |
| **Trust Stores** | Windows + Browsers | Support Chrome, Firefox, Edge in addition to Windows |
| **Guided Mode** | Full wizard | Step-by-step with explanations and recommendations |
| **Output Format** | JSON primary | Focus on JSON for CI/CD integration |
| **Lint Rules** | CA/B + Mozilla | CA/B Forum Baseline Requirements + Mozilla NSS Policy |
| **Chain Visualization** | Rich ASCII art | Spectre.Console tree with colors and formatting |
| **PQC Support** | Wait for .NET | Defer until .NET has native PQC support |
| **Config File** | None | Always require explicit flags, no persistence |
| **Renew Command** | Auto-detect | Read existing cert, preserve parameters, extend validity |
| **Auto-trust** | Yes, to Root store | CA certs → Trusted Root, end-entity → Personal |
| **JSON Scope** | Global option | `--format json` available on all commands |
| **Export Design** | `inspect --save` | Unified export via inspect for all sources |
| **Revocation Checking** | OCSP preferred, CRL fallback | `--crl` flag checks OCSP first, falls back to CRL if unavailable |
| **Trust Remove Confirmation** | Interactive unless `--force` | Prompt for confirmation; `--force` skips prompt |
| **Multiple Subject Matches** | List + require `--force` | Show matching certs; require `--force` to delete multiple |
| **Inspect Source Detection** | File exists first | Check if file exists; use `--store` flag to force thumbprint lookup |
| **LocalMachine Permissions** | Fail with clear error | No silent fallback or auto-elevation; clear error message |
| **Export Format** | PEM default + `--save-format` | `--save` defaults to PEM; use `--save-format` for DER |

---

## Current State Analysis

### Existing Commands
| Command | Maps To (Proposed) | Notes |
|---------|-------------------|-------|
| `create` | `create dev`, `create ca` | Split by intent; add `--issuer` for CA signing |
| `info` | `inspect <file/url/thumbprint>` | Rename and expand |
| `verify` | `inspect --chain --crl --warn` | Merge into inspect with flags |
| `list` | `store list` | Move under store management (export via inspect) |
| `install` | `trust add` | Align with feature plan |
| `remove` | `trust remove` | Support thumbprint + `--subject` |
| `export` | `inspect --save` | Remote export via inspect |
| `convert` | `convert` | Keep as-is |

### Current Architecture Strengths
- Well-structured service layer (`CertificateOperations.cs`)
- Centralized option definitions (`OptionBuilders.cs`)
- Extension method pattern allows loose coupling
- Async throughout
- Modern .NET 10 with current crypto APIs

### Gaps vs Feature Plan
1. **No hierarchical command structure** - Currently flat commands
2. **No JSON output** - Text only (JSON prioritized for CI/CD)
3. **No interactive/guided mode** - CLAUDE.md requires `--guided`
4. **CLI framework** - Need Spectre.Console for display (hybrid approach)
5. **No linting command** - Need CA/B Forum + Mozilla NSS validation
6. **No chain visualization** - Need rich ASCII tree output
7. **No browser trust store support** - Need Chrome, Firefox, Edge integration

---

## Recommended Implementation Phases

### Phase 1: Command Structure Migration
Migrate to hierarchical verb-noun pattern. Breaking changes acceptable for v2.0.

**New Command Tree:**
```
certz [--format text|json]
├── create
│   ├── ca          [Root/Intermediate CA creation]
│   │   └── --guided, --issuer, --issuer-cert, --issuer-key
│   └── dev         [Quick dev certificate]
│       └── --guided, --issuer, --issuer-cert, --issuer-key, --trust
├── inspect <file|url|thumbprint>
│   └── --chain, --crl, --warn, --save, --save-key
├── trust
│   ├── add <file>  [Install to Windows/browser trust store]
│   │   └── --browser (chrome|firefox|edge)
│   └── remove      [Remove from trust store]
│       └── <thumbprint> or --subject
├── store
│   └── list        [List certificates in store]
├── convert         [Format conversions PEM/PFX/DER]
├── lint <file|url> [CA/B Forum + Mozilla NSS validation]
└── renew <file>    [Auto-detect params, extend validity]
    └── --days, --out
```

### Phase 2: Output Format Support
Add `--format` global option supporting:
- `text` (default, current behavior)
- `json` (primary for CI/CD automation)

Recommend creating an `IOutputFormatter` interface with `TextFormatter` and `JsonFormatter` implementations.

### Phase 3: Interactive Mode
Implement `--guided` flag that invokes a full wizard using Spectre.Console prompts:
- Step-by-step certificate creation
- Explanations and recommendations at each step
- Smart defaults based on use case

### Phase 4: Advanced Diagnostics
- Chain validation with rich ASCII tree (Spectre.Console)
- Linting against CA/B Forum Baseline Requirements
- Linting against Mozilla NSS Policy
- Expiration monitoring with `--format json` output

### Phase 5: Browser Trust Store Integration
Extend `trust add/remove` to support:
- Chrome (Windows certificate store, NSS for Linux)
- Firefox (NSS certutil)
- Edge (Windows certificate store)

---

## CLI Framework Decision

### Decision: Hybrid Approach

**Keep System.CommandLine** for command parsing and argument handling:
- Already integrated and working
- Microsoft-supported
- Good for programmatic use
- Maintains familiar codebase structure

**Add Spectre.Console** for display and interaction:
- Rich console UI (prompts, trees, tables)
- Required for `--guided` wizard mode
- Enables rich ASCII chain visualization
- Colorized and formatted output

This approach minimizes migration effort while gaining all required interactive features.

---

## Backwards Compatibility Strategy

### Decision: Clean Break with v2.0

Breaking changes are acceptable with a major version bump. No aliases or deprecation period required.

**Migration approach:**
- Document all command changes in CHANGELOG and migration guide
- Old v1.x syntax will no longer work in v2.0
- Users must update scripts to new syntax

**Example changes:**
```bash
# v1.x (old)
certz create --is-ca --subject dev-root
certz install --file cert.pfx
certz info --file cert.pem

# v2.0 (new)
certz create ca --name dev-root
certz trust add cert.pfx
certz inspect cert.pem
```

---

## Clarifying Questions (Resolved)

All 10 clarifying questions have been answered. See **Requirements Decisions** table at the top of this document for the summary.

---

## Feature Gap Analysis (v1.x → v2.0)

### Identified Gaps

| v1.x Feature | Current Command | Proposed v2.0 | Resolution |
|--------------|-----------------|---------------|------------|
| Export from URL | `export --url` | — | Add `inspect --save` for remote cert export |
| Sign with existing CA | `create --cert --key` | `create dev/ca` | Add `--issuer` options |
| CRL revocation check | `verify --check-revocation` | `inspect` | Add `--crl` flag |
| Expiration warning | `verify --warning-days` | `inspect` | Add `--warn` flag |
| Remove by subject | `remove --subject` | `trust remove` | Support `--subject` option |

### Mitigation Details

#### 1. Remote Certificate Export
Current `export --url` fetches certificates from remote URLs. Preserve this in `inspect`:
```bash
# v2.0 - fetch and save remote certificate
certz inspect https://example.com --save cert.pem
certz inspect https://example.com:8443 --save cert.pem --chain
```

#### 2. CA-Signed Certificate Creation
Current `create --cert ca.pem --key ca.key` signs with an existing CA. Preserve in v2.0:
```bash
# v2.0 - sign with existing CA (PFX)
certz create dev --issuer ca.pfx --issuer-password secret

# v2.0 - sign with existing CA (PEM files)
certz create dev --issuer-cert ca.pem --issuer-key ca.key
```

#### 3. Verification Features in Inspect
Migrate `verify` options to `inspect`:
```bash
# v2.0 - check revocation status
certz inspect cert.pem --crl

# v2.0 - expiration warning threshold
certz inspect cert.pem --warn 30

# v2.0 - full chain visualization
certz inspect cert.pem --chain

# v2.0 - combined
certz inspect https://example.com --chain --crl --warn 30
```

#### 4. Trust Remove Options
Preserve both removal methods:
```bash
# v2.0 - remove by thumbprint (positional)
certz trust remove ABC123DEF456

# v2.0 - remove by subject (multiple matches possible)
certz trust remove --subject "CN=dev.local"
```

#### 5. Auto-Trust on Creation
The `--trust` flag auto-installs certificates after creation:
```bash
# v2.0 - create and trust in one step
certz create dev api.local --trust

# Behavior:
# - CA certificates → Trusted Root Certification Authorities
# - End-entity certificates → Personal store
```

#### 6. Certificate Renewal
Auto-detect parameters from existing certificate and extend validity:
```bash
# v2.0 - renew existing certificate
certz renew server.pfx --days 90 --out server-renewed.pfx

# Behavior:
# - Reads subject, SANs, key type from existing cert
# - Generates new key pair
# - Creates new cert with extended validity
# - Preserves all extensions and attributes
```

### Summary

**No features are lost** with these mitigations. All v1.x capabilities map to v2.0 commands with improved ergonomics.

---

## Architecture Recommendations

### 1. Extract Output Formatting
Create pluggable formatters for text and JSON output:

```
Services/
├── Formatters/
│   ├── IOutputFormatter.cs
│   ├── TextFormatter.cs
│   └── JsonFormatter.cs
```

### 2. Command Structure
Organize commands into hierarchical folders:

```
Commands/
├── Create/
│   ├── CreateCaCommand.cs
│   └── CreateDevCommand.cs
├── Inspect/
│   └── InspectCommand.cs       [Handles file, URL, store + --save]
├── Trust/
│   ├── TrustAddCommand.cs
│   └── TrustRemoveCommand.cs
├── Store/
│   └── StoreListCommand.cs
├── LintCommand.cs
├── ConvertCommand.cs
└── RenewCommand.cs
```

### 3. Guided Mode Service
Separate interactive wizard logic from command execution:

```
Services/
├── Interactive/
│   ├── IWizardService.cs
│   ├── CreateCaWizard.cs
│   └── CreateDevWizard.cs
```

### 4. Chain Validation Service
Extract certificate chain operations with Spectre.Console visualization:

```
Services/
├── Validation/
│   ├── IChainValidator.cs
│   ├── ChainValidator.cs
│   └── ChainVisualizer.cs  [Spectre.Console Tree output]
```

### 5. Linting Service
Implement standards validation:

```
Services/
├── Linting/
│   ├── ILintRule.cs
│   ├── CabForumRules.cs    [CA/B Forum Baseline Requirements]
│   ├── MozillaNssRules.cs  [Mozilla NSS Policy]
│   └── LintEngine.cs
```

### 6. Browser Trust Store Service
Abstract browser-specific trust operations:

```
Services/
├── TrustStore/
│   ├── ITrustStore.cs
│   ├── WindowsTrustStore.cs
│   ├── ChromeTrustStore.cs
│   ├── FirefoxTrustStore.cs
│   └── EdgeTrustStore.cs
```

---

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| Breaking existing scripts | Medium | Clear v2.0 migration guide |
| Scope creep with new features | Medium | Phased implementation |
| Browser trust store complexity | Medium | Abstract via ITrustStore interface |
| Spectre.Console integration | Low | Hybrid approach keeps parsing stable |
| PQC algorithm instability | Low | Deferred until .NET native support |

---

## Next Steps

1. **Add Spectre.Console NuGet package** for display/interaction
2. **Create IOutputFormatter infrastructure** for text/JSON output
3. **Implement `create dev` command** as proof of concept with `--guided`
4. **Implement `create ca` command** with new structure
5. **Implement `inspect` command** with chain visualization
6. **Implement `lint` command** with CA/B + Mozilla rules
7. **Implement `trust add/remove`** with browser support
8. **Write v2.0 migration guide** documenting all changes

---

## References

- [feature-plan.md](feature-plan.md) - Original feature plan
- [CLAUDE.md](CLAUDE.md) - Project requirements
- [test-isolation-plan.md](test-isolation-plan.md) - Testing guidelines
