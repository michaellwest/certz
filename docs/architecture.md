# Certz Architecture

This document describes the architecture, design patterns, and command structure of certz.

---

## Command Structure

Certz uses a hierarchical, intent-based command system following the verb-noun pattern (like `kubectl` or `docker`):

```bash
# General Syntax
certz [verb] [noun] [positional-arg] [flags]

# Examples
certz create dev api.local --trust --format json
certz inspect https://internal-api:8443 --chain
```

### Command Hierarchy

| Verb | Noun | Purpose |
|------|------|---------|
| `create` | `dev` | Development/server certificates |
| `create` | `ca` | Certificate Authority certificates |
| `inspect` | - | Certificate inspection (file, URL, store) |
| `lint` | - | Certificate validation against standards |
| `monitor` | - | Expiration monitoring |
| `renew` | - | Certificate renewal |
| `convert` | - | Format conversion (PEM, DER, PFX) |
| `trust` | `add` | Add certificate to trust store |
| `trust` | `remove` | Remove certificate from trust store |
| `store` | `list` | List certificates in a store |

### Design Goals

1. **Guessable** - Users can predict parameters without checking help
2. **Intent-Based** - Commands split by purpose to reduce flag clutter
3. **Composable** - Flags combine naturally (`--trust --format json`)

---

## Service Architecture

All certificate operations follow the **Options Pattern** with specialized service classes.

### Pattern Overview

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Options Class  │────▶│  Service Class  │────▶│  Result Class   │
│ (DevCertOptions)│     │ (CreateService) │     │ (CreationResult)│
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                │
                                ▼
                        ┌─────────────────┐
                        │    Formatter    │
                        │ (Text/Json)     │
                        └─────────────────┘
```

### Service Classes

| Service | Responsibility |
|---------|----------------|
| `CreateService` | Certificate creation (dev and CA) |
| `ConvertService` | Format conversion (PEM/PFX/DER) |
| `ExportService` | Certificate export (URL and store) |
| `InspectService` | Certificate inspection and verification |
| `TrustService` | Trust store operations |

### Supporting Classes

| Class | Purpose |
|-------|---------|
| `CertificateUtilities` | Shared utilities (password generation, file writing, key storage flags) |
| `CertificateGeneration` | Low-level certificate generation |
| `CertificateDisplay` | Certificate information display helpers |

### File Structure

```
Services/
├── CertificateUtilities.cs    # Shared utilities
├── CreateService.cs           # Certificate creation (dev/CA)
├── ConvertService.cs          # Format conversion (PEM/PFX)
├── ExportService.cs           # Certificate export (URL/store)
├── InspectService.cs          # Certificate inspection/verification
├── TrustService.cs            # Trust store operations
├── CertificateGeneration.cs   # Low-level generation
└── CertificateDisplay.cs      # Display helpers

Models/
├── DevCertificateOptions.cs   # Options for dev certificate creation
├── CaCertificateOptions.cs    # Options for CA certificate creation
├── ConvertToPfxOptions.cs     # Options for PFX conversion
├── CertificateCreationResult.cs
├── ConversionResult.cs
└── ...
```

---

## Benefits of This Architecture

1. **Single Responsibility** - Each service class has one clear purpose
2. **Testability** - Services can be tested independently with mock options
3. **Consistency** - All operations follow the same pattern
4. **Extensibility** - New commands add new service classes without modifying existing ones
5. **Structured Output** - Result classes enable consistent JSON/text formatting

---

## Refactoring History

### Completed Work (2026-02)

**Phase 1:** Extracted shared utilities into `CertificateUtilities.cs`
- `GenerateSecurePassword()` - Password generation
- `DisplayPasswordWarning()` - Console password display
- `GetKeyStorageFlags()` - X509 key storage flag configuration
- `WriteCertificateToFile()` - File writing for PFX/PEM formats
- `InstallCertificate()` - Trust store installation

**Phase 2:** Created specialized service classes
- Removed legacy `CertificateOperations.cs` (parameter-based API)
- Removed `CertificateOperationsV2.cs` (methods moved to services)
- All commands now use options pattern with structured results

### Metrics

- ~200 lines of duplicate code eliminated
- 5 utility methods consolidated
- 2 legacy files removed
- All operations migrated to options pattern
