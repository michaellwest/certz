# Phase 5: Enhanced Chain Visualization

**Status:** Complete
**Created:** 2026-02-08
**Completed:** 2026-02-08

## Overview

Enhance the existing `certz inspect --chain` functionality with richer visualization options, detailed certificate information in tree nodes, and improved output formatting. The current implementation provides basic chain tree rendering; this phase adds a `--tree` flag for enhanced ASCII tree output with comprehensive certificate details.

## Current State Analysis

### Existing Infrastructure

| Component | File | Status |
|-----------|------|--------|
| Chain validation | `src/certz/Services/Validation/ChainValidator.cs` | ✅ Complete |
| Basic tree rendering | `src/certz/Services/Validation/ChainVisualizer.cs` | ✅ Complete |
| Chain element model | `src/certz/Models/ChainElementInfo.cs` | ✅ Complete |
| Inspector integration | `src/certz/Services/CertificateInspector.cs` | ✅ Complete |
| Inspect command | `src/certz/Commands/Inspect/InspectCommand.cs` | ✅ Has `--chain` |

### Current `--chain` Output

The current implementation shows:
- Certificate type (Root CA, Intermediate CA, End Entity)
- Subject name
- Expiration status (EXPIRED, NOT YET VALID, days remaining)
- Thumbprint (abbreviated)
- Expiration date
- Validation errors

### Gaps to Address

1. **Missing certificate details in tree nodes:**
   - Key algorithm and size
   - Subject Alternative Names (for end-entity)
   - Signature algorithm
   - Serial number

2. **No compact/detailed toggle:**
   - Current output is one-size-fits-all
   - Need `--tree` for detailed view vs basic `--chain`

3. **Missing revocation status per element:**
   - Chain shows overall status but not per-certificate

4. **No JSON chain output with full details:**
   - JSON format exists but could be enhanced

## Design Decisions

| Area | Decision | Rationale |
|------|----------|-----------|
| **Flag structure** | `--chain` (basic) vs `--chain --tree` (detailed) | Backwards compatible, opt-in detail |
| **Tree rendering** | Enhance existing `ChainVisualizer` | Reuse proven Spectre.Console Tree |
| **Detail level** | Add node detail properties | Configurable output |
| **JSON output** | Include all detail in JSON regardless of `--tree` | Automation always gets full data |

## Progress Tracker

| # | Step | Status | Notes |
|---|------|--------|-------|
| 1 | Add `--tree` option to InspectCommand | [x] | Added --tree/-t option, updated InspectOptions and CertificateInspectResult |
| 2 | Extend ChainElementInfo model | [x] | Added KeyAlgorithm, KeySize, SignatureAlgorithm, SANs, DaysRemaining, RevocationStatus, CRL/OCSP |
| 3 | Update CertificateInspector | [x] | Added GetRevocationInfo, DetermineRevocationStatus, populate chain element fields |
| 4 | Enhance ChainVisualizer | [x] | Added RenderDetailedChain, BuildDetailedNodeText, ExtractCN methods |
| 5 | Update TextFormatter chain output | [x] | Conditional rendering based on DetailedTree flag |
| 6 | Update JsonFormatter chain output | [x] | Extended ChainElementDto with all new fields |
| 7 | Add tests to test-inspect.ps1 | [x] | Added chn-1.3 (detailed tree) and chn-1.4 (JSON fields) tests |
| 8 | Update documentation | [x] | Updated README.md and TESTING.md with --tree option |

---

## Implementation Steps

### Step 1: Add `--tree` Option to InspectCommand

**Modify:** `src/certz/Commands/Inspect/InspectCommand.cs`

```csharp
// Add new option after --chain
var treeOption = new Option<bool>("--tree", "-t")
{
    Description = "Show detailed certificate chain tree with key info, SANs, and signatures",
    DefaultValueFactory = _ => false
};

// Update options in InspectOptions
var options = new InspectOptions
{
    // ... existing fields ...
    ShowChain = showChain,
    DetailedTree = showTree,  // New field
    // ...
};
```

**Status:** [ ] Not Started

---

### Step 2: Extend ChainElementInfo Model

**Modify:** `src/certz/Models/ChainElementInfo.cs`

```csharp
internal record ChainElementInfo
{
    // ... existing properties ...

    /// <summary>
    /// Key algorithm (e.g., "ECDSA P-256", "RSA").
    /// </summary>
    public string? KeyAlgorithm { get; init; }

    /// <summary>
    /// Key size in bits.
    /// </summary>
    public int KeySize { get; init; }

    /// <summary>
    /// Signature algorithm (e.g., "sha256RSA").
    /// </summary>
    public string? SignatureAlgorithm { get; init; }

    /// <summary>
    /// Subject Alternative Names (for end-entity certificates).
    /// </summary>
    public List<string> SubjectAlternativeNames { get; init; } = [];

    /// <summary>
    /// Days until certificate expires.
    /// </summary>
    public int DaysRemaining { get; init; }

    /// <summary>
    /// Revocation status if checked.
    /// </summary>
    public string? RevocationStatus { get; init; }

    /// <summary>
    /// CRL Distribution Point URLs.
    /// </summary>
    public List<string> CrlDistributionPoints { get; init; } = [];

    /// <summary>
    /// OCSP responder URL.
    /// </summary>
    public string? OcspResponder { get; init; }
}
```

**Status:** [ ] Not Started

---

### Step 3: Update CertificateInspector

**Modify:** `src/certz/Services/CertificateInspector.cs`

Add helper method to extract additional info:

```csharp
private static ChainElementInfo BuildChainElementInfo(
    X509Certificate2 cert,
    List<X509ChainStatus> status,
    bool isEndEntity)
{
    var basicConstraints = cert.Extensions["2.5.29.19"] as X509BasicConstraintsExtension;
    var isCa = basicConstraints?.CertificateAuthority ?? false;
    var now = DateTime.Now;
    var daysRemaining = (cert.NotAfter - now).Days;

    // Get key info
    var (keyAlgorithm, keySize) = GetKeyInfo(cert);

    // Get SANs for end-entity
    var sans = isEndEntity ? GetSubjectAlternativeNames(cert) : [];

    // Get CRL/OCSP info
    var (crlPoints, ocspUrl) = GetRevocationInfo(cert);

    // Determine revocation status from chain status
    var revocationStatus = DetermineRevocationStatus(status);

    return new ChainElementInfo
    {
        Subject = cert.Subject,
        Issuer = cert.Issuer,
        Thumbprint = cert.Thumbprint,
        SerialNumber = cert.SerialNumber,
        NotBefore = cert.NotBefore,
        NotAfter = cert.NotAfter,
        IsCa = isCa,
        IsSelfSigned = cert.Subject == cert.Issuer,
        KeyAlgorithm = keyAlgorithm,
        KeySize = keySize,
        SignatureAlgorithm = cert.SignatureAlgorithm.FriendlyName,
        SubjectAlternativeNames = sans,
        DaysRemaining = daysRemaining,
        RevocationStatus = revocationStatus,
        CrlDistributionPoints = crlPoints,
        OcspResponder = ocspUrl,
        ValidationErrors = status
            .Where(s => s.Status != X509ChainStatusFlags.NoError)
            .Select(s => s.StatusInformation)
            .ToList()
    };
}

private static (List<string> CrlPoints, string? OcspUrl) GetRevocationInfo(X509Certificate2 cert)
{
    var crlPoints = new List<string>();
    string? ocspUrl = null;

    // CRL Distribution Points (OID 2.5.29.31)
    var crlExt = cert.Extensions["2.5.29.31"];
    if (crlExt != null)
    {
        // Parse CRL distribution points from extension
        // ... implementation
    }

    // Authority Information Access (OID 1.3.6.1.5.5.7.1.1) for OCSP
    var aiaExt = cert.Extensions["1.3.6.1.5.5.7.1.1"];
    if (aiaExt != null)
    {
        // Parse OCSP URL from AIA extension
        // ... implementation
    }

    return (crlPoints, ocspUrl);
}

private static string? DetermineRevocationStatus(List<X509ChainStatus> status)
{
    if (status.Any(s => s.Status == X509ChainStatusFlags.Revoked))
        return "Revoked";
    if (status.Any(s => s.Status == X509ChainStatusFlags.RevocationStatusUnknown))
        return "Unknown";
    if (status.Any(s => s.Status == X509ChainStatusFlags.OfflineRevocation))
        return "Offline";
    return "OK";
}
```

**Status:** [ ] Not Started

---

### Step 4: Enhance ChainVisualizer

**Modify:** `src/certz/Services/Validation/ChainVisualizer.cs`

Add detailed tree rendering mode:

```csharp
internal interface IChainVisualizer
{
    void RenderChain(ChainValidationResult result, IAnsiConsole console);
    void RenderDetailedChain(List<ChainElementInfo> chain, bool isValid, IAnsiConsole console);
}

internal class ChainVisualizer : IChainVisualizer
{
    public void RenderDetailedChain(List<ChainElementInfo> chain, bool isValid, IAnsiConsole console)
    {
        var root = new Tree("[bold]Certificate Chain[/]");

        if (chain.Count == 0)
        {
            root.AddNode("[red]No chain elements found[/]");
            console.Write(root);
            return;
        }

        // Build tree from root CA down to end entity
        TreeNode? currentNode = null;
        for (int i = chain.Count - 1; i >= 0; i--)
        {
            var element = chain[i];
            var isEndEntity = (i == 0);
            var nodeText = BuildDetailedNodeText(element, isEndEntity);

            if (currentNode == null)
            {
                currentNode = root.AddNode(nodeText);
            }
            else
            {
                currentNode = currentNode.AddNode(nodeText);
            }
        }

        console.Write(root);

        // Show overall chain status
        if (!isValid)
        {
            console.MarkupLine("");
            console.MarkupLine("[red]Chain validation failed[/]");
        }
        else
        {
            console.MarkupLine("");
            console.MarkupLine("[green]Chain validation successful[/]");
        }
    }

    private static string BuildDetailedNodeText(ChainElementInfo element, bool isEndEntity)
    {
        var sb = new StringBuilder();

        // Certificate type indicator
        string typeLabel;
        if (isEndEntity)
        {
            typeLabel = "[blue]End Entity[/]";
        }
        else if (element.IsSelfSigned)
        {
            typeLabel = "[green]Root CA[/]";
        }
        else if (element.IsCa)
        {
            typeLabel = "[cyan]Intermediate CA[/]";
        }
        else
        {
            typeLabel = "[grey]Certificate[/]";
        }

        // Subject name (extract CN)
        var cn = ExtractCN(element.Subject) ?? element.Subject;
        sb.Append($"{typeLabel}: [bold]{Markup.Escape(cn)}[/]");

        // Validity status
        if (element.NotAfter < DateTime.Now)
        {
            sb.Append(" [red](EXPIRED)[/]");
        }
        else if (element.NotBefore > DateTime.Now)
        {
            sb.Append(" [yellow](NOT YET VALID)[/]");
        }
        else if (element.DaysRemaining < 30)
        {
            sb.Append($" [yellow]({element.DaysRemaining} days remaining)[/]");
        }

        // Key info
        sb.Append($"\n  [dim]Key:[/] {element.KeyAlgorithm ?? "Unknown"}");
        if (element.KeySize > 0)
        {
            sb.Append($" ({element.KeySize}-bit)");
        }

        // Signature algorithm
        if (!string.IsNullOrEmpty(element.SignatureAlgorithm))
        {
            sb.Append($"\n  [dim]Signature:[/] {element.SignatureAlgorithm}");
        }

        // Validity period
        sb.Append($"\n  [dim]Valid:[/] {element.NotBefore:yyyy-MM-dd} to {element.NotAfter:yyyy-MM-dd}");

        // SANs for end-entity
        if (isEndEntity && element.SubjectAlternativeNames.Count > 0)
        {
            var sansDisplay = string.Join(", ", element.SubjectAlternativeNames.Take(5));
            if (element.SubjectAlternativeNames.Count > 5)
            {
                sansDisplay += $" (+{element.SubjectAlternativeNames.Count - 5} more)";
            }
            sb.Append($"\n  [dim]SANs:[/] {Markup.Escape(sansDisplay)}");
        }

        // Thumbprint (abbreviated)
        sb.Append($"\n  [dim]Thumbprint:[/] {element.Thumbprint[..16]}...");

        // Revocation status (if checked)
        if (!string.IsNullOrEmpty(element.RevocationStatus))
        {
            var statusColor = element.RevocationStatus switch
            {
                "OK" => "green",
                "Revoked" => "red",
                "Unknown" or "Offline" => "yellow",
                _ => "dim"
            };
            sb.Append($"\n  [dim]Revocation:[/] [{statusColor}]{element.RevocationStatus}[/]");
        }

        // Validation errors
        foreach (var error in element.ValidationErrors)
        {
            sb.Append($"\n  [red]- {Markup.Escape(error)}[/]");
        }

        return sb.ToString();
    }

    private static string? ExtractCN(string subject)
    {
        var match = Regex.Match(subject, @"CN=([^,]+)");
        return match.Success ? match.Groups[1].Value : null;
    }
}
```

**Expected Output:**
```
Certificate Chain
└─ Root CA: Development Root CA
   │  Key: ECDSA P-256 (256-bit)
   │  Signature: sha256ECDSA
   │  Valid: 2026-01-01 to 2036-01-01
   │  Thumbprint: A1B2C3D4E5F6...
   └─ Intermediate CA: Development Intermediate CA
      │  Key: ECDSA P-256 (256-bit)
      │  Signature: sha256ECDSA
      │  Valid: 2026-01-15 to 2031-01-15
      │  Thumbprint: B2C3D4E5F6A7...
      └─ End Entity: myapp.local
         │  Key: ECDSA P-256 (256-bit)
         │  Signature: sha256ECDSA
         │  Valid: 2026-02-08 to 2026-05-09
         │  SANs: myapp.local, localhost, 127.0.0.1
         │  Thumbprint: C3D4E5F6A7B8...
         │  Revocation: OK

Chain validation successful
```

**Status:** [ ] Not Started

---

### Step 5: Update TextFormatter Chain Output

**Modify:** `src/certz/Formatters/TextFormatter.cs`

```csharp
public void WriteCertificateInspected(CertificateInspectResult result)
{
    // ... existing certificate info display ...

    // Show chain if present
    if (result.Chain != null && result.Chain.Count > 0)
    {
        _console.WriteLine();
        if (result.DetailedTree)
        {
            var visualizer = new ChainVisualizer();
            visualizer.RenderDetailedChain(result.Chain, result.ChainIsValid, _console);
        }
        else
        {
            RenderChainFromInfo(result.Chain, result.ChainIsValid);
        }
    }
}
```

**Status:** [ ] Not Started

---

### Step 6: Update JsonFormatter Chain Output

**Modify:** `src/certz/Formatters/JsonFormatter.cs`

Ensure all new `ChainElementInfo` fields are included in JSON output:

```csharp
private record ChainElementDto(
    string Subject,
    string Issuer,
    string Thumbprint,
    string SerialNumber,
    DateTime NotBefore,
    DateTime NotAfter,
    bool IsCa,
    bool IsSelfSigned,
    string? KeyAlgorithm,      // New
    int KeySize,               // New
    string? SignatureAlgorithm, // New
    string[]? SubjectAlternativeNames, // New
    int DaysRemaining,         // New
    string? RevocationStatus,  // New
    string[]? CrlDistributionPoints, // New
    string? OcspResponder,     // New
    string[]? ValidationErrors
);
```

**Status:** [ ] Not Started

---

### Step 7: Add Tests to test-inspect.ps1

**Modify:** `test/test-inspect.ps1`

Add chain visualization test cases:

```powershell
# Chain visualization tests
$script:TestCategories["chain"] = @("ins-5.1", "ins-5.2", "ins-5.3", "ins-5.4")

# ins-5.1: Inspect with basic chain
# ins-5.2: Inspect with detailed tree (--chain --tree)
# ins-5.3: Inspect chain with revocation check (--chain --crl)
# ins-5.4: Inspect chain JSON output
```

**Status:** [ ] Not Started

---

### Step 8: Update Documentation

**Modify:** `README.md`, `TESTING.md`

Add documentation for `--tree` option:

```markdown
### Chain Visualization

View the full certificate chain from root to end-entity:

```bash
# Basic chain view
certz inspect https://github.com --chain

# Detailed tree with key info, SANs, and signatures
certz inspect https://github.com --chain --tree

# Chain with revocation check
certz inspect https://github.com --chain --crl

# Chain with detailed tree and revocation
certz inspect https://github.com --chain --tree --crl
```
```

**Status:** [ ] Not Started

---

## Command Specification Update

### `certz inspect <source>` (Updated)

```
certz inspect <source> [options]

Arguments:
  source              File path, URL, or certificate thumbprint

Options:
  --password, -p      Password for PFX/P12 files
  --chain, -c         Show certificate chain
  --tree, -t          Show detailed tree with key info, SANs, signatures (requires --chain)
  --crl               Check certificate revocation status
  --warn, -w <days>   Warn if certificate expires within N days
  --save <file>       Save certificate to file
  --save-key <file>   Save private key to file
  --save-format       Export format: pem (default) or der
  --store, -s         Certificate store name (My, Root, CA)
  --location, -l      Store location (CurrentUser or LocalMachine)
  --format            Output format: text (default) or json

Examples:
  certz inspect server.pfx --password secret --chain
  certz inspect https://example.com --chain --tree
  certz inspect https://example.com --chain --tree --crl
  certz inspect ABC123... --store Root --chain --format json
```

---

## Verification Checklist

- [ ] `dotnet build` succeeds
- [ ] `certz inspect --help` shows `--tree` option
- [ ] `certz inspect cert.pfx --chain` shows basic chain (unchanged)
- [ ] `certz inspect cert.pfx --chain --tree` shows detailed tree
- [ ] `certz inspect https://example.com --chain --tree` works for URLs
- [ ] `certz inspect https://example.com --chain --crl` shows revocation status
- [ ] `certz inspect cert.pfx --chain --format json` includes all new fields
- [ ] Tree shows key algorithm, signature, validity for each element
- [ ] End-entity shows SANs in detailed tree
- [ ] Revocation status displayed when `--crl` used
- [ ] Tests pass in `test-inspect.ps1`

---

## Future Enhancements (After Phase 5)

### Phase 6: Expiration Monitoring
```
certz monitor <directory|url> [options]
  --warn              Warning threshold (days)
  --format            Output format (text, json)
  --recursive         Scan subdirectories
```

### Phase 7: Certificate Renewal
```
certz renew <source> [options]
  --issuer            Issuing CA certificate (for re-signing)
  --days              New validity period
  --keep-key          Preserve existing private key
```

---

## Notes & Adjustments

*Record any changes to the plan during implementation:*

1. Implementation completed successfully on 2026-02-08
2. Added `--tree` option to InspectCommand that implies `--chain` if not specified
3. Extended ChainElementInfo with: KeyAlgorithm, KeySize, SignatureAlgorithm, SubjectAlternativeNames, DaysRemaining, RevocationStatus, CrlDistributionPoints, OcspResponder
4. Added helper methods GetRevocationInfo and DetermineRevocationStatus to CertificateInspector
5. Added RenderDetailedChain method to ChainVisualizer with detailed node text including key info, signatures, validity, SANs, and revocation status
6. Updated JsonFormatter ChainElementDto to include all new fields
7. Added tests chn-1.3 (detailed tree view) and chn-1.4 (JSON fields verification)
8. Updated README.md and TESTING.md with --tree option documentation
