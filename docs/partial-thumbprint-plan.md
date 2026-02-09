# Partial Thumbprint Matching for Trust Remove

**Status:** Complete
**Created:** 2026-02-08
**Completed:** 2026-02-08

## Overview

Enable `certz trust remove` to accept partial thumbprint prefixes (minimum 8 characters) for certificate removal, rather than requiring the full 40-character SHA-1 thumbprint. This improves usability while maintaining safety through existing multiple-match safeguards.

## Current Behavior

```bash
# Must specify full 40-character thumbprint
certz trust remove ABC123DEF456789012345678901234567890ABCD
```

## Proposed Behavior

```bash
# Full thumbprint (40 chars) - exact match
certz trust remove ABC123DEF456789012345678901234567890ABCD

# Partial thumbprint (8+ chars) - prefix match
certz trust remove ABC123DE
certz trust remove ABC123DEF456

# Too short (< 8 chars) - error
certz trust remove ABC123   # Error: minimum 8 characters required
```

## Safety Measures

1. **Minimum 8-character prefix**: Provides ~2^32 possible combinations, making accidental collisions unlikely
2. **Existing --force requirement**: If multiple certificates match the prefix, user must specify `--force`
3. **Display all matches**: Before removal, show all matching certificates
4. **Interactive confirmation**: In text mode without `--force`, prompt for confirmation

## Design Decisions

| Area | Decision | Rationale |
|------|----------|-----------|
| **Minimum length** | 8 characters | Balance between usability and collision risk |
| **Match type** | Case-insensitive StartsWith | Consistent with existing thumbprint handling |
| **Multiple matches** | Require `--force` | Existing behavior, prevents accidents |
| **Error handling** | Clear message for too-short input | User guidance |

## Progress Tracker

| # | Step | Status | Notes |
|---|------|--------|-------|
| 1 | Document proposed changes | [x] | This file |
| 2 | Update TrustHandler.FindMatchingCertificates | [x] | Prefix matching for < 40 chars |
| 3 | Add validation for minimum length | [x] | 8-character minimum with hex validation |
| 4 | Update command help text | [x] | Updated argument description |
| 5 | Add tests | [x] | trm-2.1 to trm-2.4 in test-trust.ps1 |
| 6 | Update documentation | [x] | README.md updated |

---

## Implementation Steps

### Step 1: Update TrustHandler.FindMatchingCertificates

**Modify:** `Services/TrustHandler.cs`

Current code (lines 73-82):
```csharp
if (!string.IsNullOrEmpty(thumbprint))
{
    // Find by thumbprint
    var normalizedThumbprint = thumbprint.Replace(" ", "").ToUpperInvariant();
    var found = store.Certificates.Find(X509FindType.FindByThumbprint, normalizedThumbprint, false);
    foreach (var cert in found)
    {
        matching.Add(X509CertificateLoader.LoadCertificate(cert.RawData));
    }
}
```

New code:
```csharp
if (!string.IsNullOrEmpty(thumbprint))
{
    var normalizedThumbprint = thumbprint.Replace(" ", "").ToUpperInvariant();

    if (normalizedThumbprint.Length == 40)
    {
        // Exact match for full thumbprint
        var found = store.Certificates.Find(X509FindType.FindByThumbprint, normalizedThumbprint, false);
        foreach (var cert in found)
        {
            matching.Add(X509CertificateLoader.LoadCertificate(cert.RawData));
        }
    }
    else
    {
        // Prefix match for partial thumbprint
        foreach (var cert in store.Certificates)
        {
            if (cert.Thumbprint.StartsWith(normalizedThumbprint, StringComparison.OrdinalIgnoreCase))
            {
                matching.Add(X509CertificateLoader.LoadCertificate(cert.RawData));
            }
        }
    }
}
```

---

### Step 2: Add Validation for Minimum Length

**Modify:** `Commands/Trust/TrustCommand.cs`

Add validation before calling FindMatchingCertificates:

```csharp
// Validate thumbprint length (minimum 8 characters if partial)
if (!string.IsNullOrEmpty(thumbprint))
{
    var normalized = thumbprint.Replace(" ", "");
    if (normalized.Length < 8)
    {
        throw new InvalidOperationException(
            "Thumbprint must be at least 8 characters for partial matching, or 40 characters for exact match.");
    }
    if (normalized.Length > 0 && normalized.Length < 40 && !normalized.All(c => char.IsAsciiHexDigit(c)))
    {
        throw new InvalidOperationException(
            "Thumbprint must contain only hexadecimal characters (0-9, A-F).");
    }
}
```

---

### Step 3: Update Command Help Text

**Modify:** `Commands/Trust/TrustCommand.cs`

Update thumbprint argument description:

```csharp
var thumbprintArgument = new Argument<string?>("thumbprint")
{
    Description = "Certificate thumbprint to remove (full 40-char or partial 8+ char prefix)"
};
```

---

### Step 4: Add Tests

**Create:** `test/test-trust-remove.ps1` or add to existing test file

```powershell
# Test: Partial thumbprint matching (8 chars)
# Test: Partial thumbprint matching (16 chars)
# Test: Partial thumbprint too short (< 8 chars) - error
# Test: Partial thumbprint matches multiple - requires --force
# Test: Full thumbprint exact match
```

---

### Step 5: Update Documentation

**Modify:** `README.md`

Add to trust remove section:

```markdown
### Partial Thumbprint Matching

You can specify a partial thumbprint (minimum 8 characters) instead of the full 40-character thumbprint:

```bash
# Full thumbprint
certz trust remove ABC123DEF456789012345678901234567890ABCD

# Partial thumbprint (prefix match)
certz trust remove ABC123DE

# If multiple certificates match, use --force to remove all
certz trust remove ABC1 --force
```
```

---

## Verification Checklist

- [x] `dotnet build` succeeds
- [x] Partial thumbprint (8 chars) removes single matching cert
- [x] Partial thumbprint (16 chars) removes single matching cert
- [x] Partial thumbprint < 8 chars shows error message
- [x] Multiple matches without --force shows warning and lists certs
- [x] Multiple matches with --force removes all matching certs
- [x] Full thumbprint (40 chars) works as before
- [x] JSON output works correctly with partial thumbprint
- [x] Tests pass

---

## Notes & Adjustments

*Changes made during implementation:*

1. **TrustHandler.FindMatchingCertificates** (Services/TrustHandler.cs:73-98):
   - Added conditional logic: if thumbprint.Length == 40, use X509FindType.FindByThumbprint for exact match
   - Otherwise, iterate over all certificates and use StartsWith for prefix matching

2. **TrustCommand.BuildRemoveCommand** (Commands/Trust/TrustCommand.cs:162-181):
   - Added validation after checking thumbprint/subject is provided
   - Validates minimum 8 characters for partial thumbprint
   - Validates all characters are hexadecimal

3. **Updated thumbprint argument description** to clarify partial match support

4. **Added 4 new tests** in test-trust.ps1:
   - trm-2.1: Remove by 8-char partial thumbprint
   - trm-2.2: Remove by 16-char partial thumbprint
   - trm-2.3: Reject thumbprint < 8 chars
   - trm-2.4: Multiple matches require --force

5. **Updated README.md** with partial thumbprint documentation*
