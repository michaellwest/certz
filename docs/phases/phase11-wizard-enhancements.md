# Phase 11: Wizard UX Enhancements

**Status:** Complete
**Created:** 2026-02-16

## Objective

Enhance the `--guided` wizard mode with three UX improvements identified via TODO comments in `CertificateWizard.cs`:

1. **Smart URL input** — Auto-prefix `https://` so users don't need to type the protocol
2. **Store browser for Inspect** — Browse and pick certificates from the Windows store instead of manually entering thumbprints
3. **Store browser for Trust Remove** — Same browsing capability for the removal workflow, with export-to-file support

These enhancements reduce friction for users who don't already know their certificate thumbprints or exact URLs.

## Project Context

This is a .NET 10 CLI tool using:

- **System.CommandLine** for command parsing
- **Spectre.Console** for display formatting
- **Record types** for options and results

### Established Patterns

**Wizard Structure:** `src/certz/Services/CertificateWizard.cs`

- Static partial class with `Run<Feature>Wizard()` methods
- Returns options records consumed by existing service layer
- Uses `WriteWelcome()`, `WriteHelp()`, `WriteEquivalentCommand()` helpers
- `WizardRunner` provides step-based loops with breadcrumb trail, keyboard tips, and back navigation
- Spectre.Console `SelectionPrompt`, `TextPrompt`, and `Confirm` for user input

**Store Infrastructure (already exists):**

- `StoreListHandler.ListCertificates(options)` — returns `StoreListResult` with `List<StoreCertificateInfo>`
- `TrustHandler.FindMatchingCertificates(thumbprint, subject, storeName, storeLocation)` — returns `List<X509Certificate2>`
- `StoreCertificateInfo` record — Subject, Issuer, Thumbprint, NotBefore, NotAfter, DaysRemaining, IsExpired, HasPrivateKey, IsCa

---

## Current State Analysis

### TODO #1: URL Auto-Prefix (Lines 697, 784)

**Current behavior:** Both the Inspect and Lint wizards require the user to type the full `https://` prefix. The validator rejects anything without it.

**Locations:**
- `RunInspectWizard()` line 697–702 — URL source for inspect
- `RunLintWizard()` line 783–788 — URL source for lint

### TODO #2: Store Browser for Inspect (Line 707)

**Current behavior:** The Inspect wizard's "Windows Store (thumbprint)" path requires the user to type a thumbprint manually. If the user doesn't know the thumbprint, they must first run `certz store list` separately.

**Location:** `RunInspectWizard()` line 707–728

### TODO #3: Store Browser for Trust Remove (Line 876)

**Current behavior:** The Trust Remove wizard also requires a manually-typed thumbprint. There is an additional typo on line 878: "orl" should be "or".

**Location:** `RunTrustRemoveWizard()` line 876–898

---

## Enhancement Specifications

### Enhancement A: Smart URL Input

**Goal:** Accept URLs with or without the `https://` prefix. Auto-correct and warn as appropriate.

#### Behavior Rules

| User Input | Action |
|---|---|
| `https://example.com` | Accept as-is |
| `example.com` | Auto-prefix to `https://example.com`, no warning |
| `example.com:8443` | Auto-prefix to `https://example.com:8443`, no warning |
| `https://example.com/path/` | Accept as-is, keep trailing slash and path |
| `example.com/api` | Auto-prefix to `https://example.com/api` |
| `http://example.com` | Warn: "[yellow]Non-secure URL detected. Upgrading to HTTPS.[/]", replace with `https://example.com` |
| `http://crl.example.com/root.crl` | Warn: "[yellow]CRL endpoint uses non-secure HTTP. Proceeding with caution.[/]", keep `http://` |

#### CRL Detection

A URL is considered a CRL endpoint if:
- The path ends with `.crl`, OR
- The hostname contains `crl.` as a subdomain

For CRL URLs using `http://`, warn but do not upgrade — CRL distribution points commonly use HTTP by design.

#### Affected Methods

1. `RunInspectWizard()` — URL source branch
2. `RunLintWizard()` — URL source branch

Both should use a shared helper: `NormalizeUrl(string input)` that returns `(string normalizedUrl, string? warning)`.

#### Implementation: `NormalizeUrl` Helper

```csharp
private static (string Url, string? Warning) NormalizeUrl(string input)
{
    input = input.Trim();

    // Already has https://
    if (input.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        return (input, null);

    // Has http:// — check if CRL
    if (input.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
    {
        var uri = new Uri(input);
        var isCrl = uri.AbsolutePath.EndsWith(".crl", StringComparison.OrdinalIgnoreCase)
                    || uri.Host.StartsWith("crl.", StringComparison.OrdinalIgnoreCase);

        if (isCrl)
            return (input, "CRL endpoint uses non-secure HTTP. Proceeding with caution.");

        // Non-CRL http:// — upgrade to https://
        var upgraded = "https://" + input[7..];
        return (upgraded, "Non-secure URL detected. Upgrading to HTTPS.");
    }

    // No protocol at all — prepend https://
    return ("https://" + input, null);
}
```

#### Updated URL Prompt (shared by Inspect and Lint)

```csharp
private static string PromptUrl(string title = "[green]?[/] URL (e.g. example.com or https://example.com):")
{
    var raw = AnsiConsole.Prompt(
        new TextPrompt<string>(title)
            .Validate(u => !string.IsNullOrWhiteSpace(u)
                ? ValidationResult.Success()
                : ValidationResult.Error("[red]URL cannot be empty[/]")));

    var (url, warning) = NormalizeUrl(raw);

    if (warning != null)
        AnsiConsole.MarkupLine($"[yellow]  {warning}[/]");

    if (url != raw)
        AnsiConsole.MarkupLine($"[grey]  Using: {Markup.Escape(url)}[/]");

    return url;
}
```

---

### Enhancement B: Store Browser for Inspect and Lint

**Goal:** Let users browse certificates in the store instead of typing thumbprints manually.

#### User Flow

```
? Certificate source:
  > File (PFX, PEM, DER, CRT)
    URL (HTTPS endpoint)
    Windows Store (browse or enter thumbprint)     ← updated label

? Store location:
  > CurrentUser
    LocalMachine

? Certificate store:
  > My (Personal)
    Root (Trusted Root CAs)
    CA (Intermediate CAs)
    TrustedPeople

? How would you like to find the certificate?
  > Browse certificates in store
    Search by subject (supports wildcards)
    Enter thumbprint manually

--- If "Browse certificates in store" ---

? Filter certificates:
  > Show all (*)
    Expiring within N days
    Expired only
    Not expired only

[Table showing Subject | Thumbprint | Expires | Status]

? Select a certificate:
  > CN=localhost  AB12CD34...  2026-05-01  [green]Valid[/]
    CN=myapp.dev  EF56GH78...  2026-01-15  [red]Expired[/]
    CN=api.local  IJ90KL12...  2026-04-20  [yellow]Expiring[/]

--- If "Search by subject" ---

? Subject filter (use * for wildcard):  *.local

[Shows filtered results, same selection prompt]

--- If "Enter thumbprint manually" ---

? Certificate thumbprint (full 40-char or partial 8+):
```

#### Display Format

Certificates in the `SelectionPrompt` display as:
```
{SubjectCN}  {Thumbprint:first8}...  {NotAfter:yyyy-MM-dd}  {StatusTag}
```

Where `StatusTag` is:
- `[red]Expired[/]` if `IsExpired`
- `[yellow]Expiring[/]` if `DaysRemaining <= 30`
- `[green]Valid[/]` otherwise

After selection, the full thumbprint is displayed for easy copying:
```
  Selected: CN=localhost
  Thumbprint: AB12CD34EF56GH78IJ90KL12MN34OP56QR78ST90
```

#### Implementation: Shared Store Browser

Both the Inspect and Lint wizards (and later Trust Remove) need this capability. Create a shared helper:

```csharp
private record StoreCertificateChoice(string Display, string Thumbprint, string Subject);

private static string BrowseOrEnterThumbprint(string storeName, string storeLocation)
{
    var findMethod = AnsiConsole.Prompt(
        new SelectionPrompt<string>()
            .Title("[green]?[/] How would you like to find the certificate?")
            .AddChoices(
                "Browse certificates in store",
                "Search by subject (supports wildcards)",
                "Enter thumbprint manually")
            .HighlightStyle(HighlightStyle));

    return findMethod switch
    {
        "Browse certificates in store" => BrowseStore(storeName, storeLocation, subjectFilter: null),
        "Search by subject (supports wildcards)" => SearchBySubject(storeName, storeLocation),
        _ => PromptThumbprintManually()
    };
}
```

```csharp
private static string BrowseStore(string storeName, string storeLocation, string? subjectFilter)
{
    // Prompt for filter
    string filterLabel;
    StoreListOptions listOptions;

    if (subjectFilter == null)
    {
        var filterChoice = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[green]?[/] Filter certificates:")
                .AddChoices("Show all", "Not expired only", "Expiring soon (within N days)", "Expired only")
                .HighlightStyle(HighlightStyle));

        bool showExpired = false;
        int? expiringDays = null;
        bool validOnly = false;

        switch (filterChoice)
        {
            case "Expired only":
                showExpired = true;
                break;
            case "Expiring soon (within N days)":
                expiringDays = AnsiConsole.Prompt(
                    new TextPrompt<int>("[green]?[/] Expiring within how many days:")
                        .DefaultValue(30)
                        .Validate(d => d > 0));
                break;
            case "Not expired only":
                validOnly = true;
                break;
        }

        listOptions = new StoreListOptions
        {
            StoreName = storeName,
            StoreLocation = storeLocation,
            ShowExpired = showExpired,
            ValidOnly = validOnly,
            ExpiringDays = expiringDays
        };
    }
    else
    {
        listOptions = new StoreListOptions
        {
            StoreName = storeName,
            StoreLocation = storeLocation
        };
    }

    var result = StoreListHandler.ListCertificates(listOptions);

    // Apply subject filter if provided
    var certs = result.Certificates;
    if (!string.IsNullOrEmpty(subjectFilter) && subjectFilter != "*")
    {
        var pattern = "^" + Regex.Escape(subjectFilter)
            .Replace("\\*", ".*")
            .Replace("\\?", ".") + "$";
        var regex = new Regex(pattern, RegexOptions.IgnoreCase);
        certs = certs.Where(c => regex.IsMatch(c.Subject)).ToList();
    }

    if (certs.Count == 0)
    {
        AnsiConsole.MarkupLine("[yellow]  No certificates found matching the filter.[/]");
        // Fall back to manual entry
        return PromptThumbprintManually();
    }

    AnsiConsole.MarkupLine($"[grey]  Found {certs.Count} certificate(s) (of {result.TotalCount} total).[/]");

    var choices = certs.Select(c =>
    {
        var cn = ExtractCN(c.Subject);
        var thumbShort = c.Thumbprint[..8];
        var status = c.IsExpired
            ? "[red]Expired[/]"
            : c.DaysRemaining <= 30
                ? $"[yellow]Expiring ({c.DaysRemaining}d)[/]"
                : "[green]Valid[/]";
        var display = $"{cn}  {thumbShort}...  {c.NotAfter:yyyy-MM-dd}  {status}";
        return new StoreCertificateChoice(display, c.Thumbprint, c.Subject);
    }).ToList();

    var selected = AnsiConsole.Prompt(
        new SelectionPrompt<StoreCertificateChoice>()
            .Title("[green]?[/] Select a certificate:")
            .AddChoices(choices)
            .UseConverter(c => c.Display)
            .HighlightStyle(HighlightStyle));

    // Show full thumbprint for copying
    AnsiConsole.MarkupLine($"[grey]  Selected: {Markup.Escape(selected.Subject)}[/]");
    AnsiConsole.MarkupLine($"[cyan]  Thumbprint: {selected.Thumbprint}[/]");

    return selected.Thumbprint;
}
```

```csharp
private static string SearchBySubject(string storeName, string storeLocation)
{
    var filter = AnsiConsole.Prompt(
        new TextPrompt<string>("[green]?[/] Subject filter (use * for wildcard, e.g. *localhost*):")
            .Validate(f => !string.IsNullOrWhiteSpace(f)));

    return BrowseStore(storeName, storeLocation, subjectFilter: filter);
}

private static string PromptThumbprintManually()
{
    return AnsiConsole.Prompt(
        new TextPrompt<string>("[green]?[/] Certificate thumbprint (full 40-char or partial 8+):")
            .WithConverter(input => AlphaNumericRegex().Replace(input, ""))
            .Validate(t => !string.IsNullOrWhiteSpace(t) && t.Length >= 8
                ? ValidationResult.Success()
                : ValidationResult.Error("[red]Thumbprint must be at least 8 hex characters[/]")));
}

private static string ExtractCN(string subject)
{
    var match = Regex.Match(subject, @"CN=([^,]+)");
    return match.Success ? match.Groups[1].Value.Trim() : subject;
}
```

---

### Enhancement C: Store Browser for Trust Remove with Export

**Goal:** Allow users to discover certificates for removal by browsing the store. Add an option to export the selection summary to a file for offline analysis.

#### User Flow

```
? Certificate thumbprint (full 40-char or partial 8+):
    ← REPLACED WITH ↓

? How would you like to find the certificate to remove?
  > Browse certificates in store
    Search by subject (supports wildcards)
    Enter thumbprint manually

[Same browse/search/manual flow as Enhancement B]

? Certificate found:
  Subject:     CN=old-ca-root
  Thumbprint:  AB12CD34EF56GH78IJ90KL12MN34OP56QR78ST90
  Expires:     2024-01-15 (Expired)
  Issuer:      CN=old-ca-root
  Is CA:       Yes
  Has Key:     No

Remove 1 certificate(s)? [y/N]

? What would you like to do?
  > Confirm removal
    Save details to file for offline analysis
    Cancel

--- If "Save details to file" ---

? Output file path: [removed-certs-2026-02-16.txt]
  Saved certificate details to removed-certs-2026-02-16.txt

? Proceed with removal? [y/N]
```

#### Export File Format

```
Certificate Removal Summary
Generated: 2026-02-16 14:30:00 UTC
Store: CurrentUser\Root

Certificate #1:
  Subject:     CN=old-ca-root
  Issuer:      CN=old-ca-root
  Thumbprint:  AB12CD34EF56GH78IJ90KL12MN34OP56QR78ST90
  Not Before:  2020-01-15
  Not After:   2024-01-15
  Is CA:       Yes
  Has Key:     No
  Status:      Expired
```

#### Trust Status Display

When displaying certificates in the Trust Remove browser, include additional context:

| Field | Source |
|---|---|
| Is CA | `StoreCertificateInfo.IsCa` |
| Has Private Key | `StoreCertificateInfo.HasPrivateKey` |
| Self-Signed | `Subject == Issuer` |
| Status | Expired / Expiring / Valid |

#### Updated `RunTrustRemoveWizard`

The method signature stays the same but the thumbprint acquisition changes to use the shared store browser. After finding matches, the confirmation prompt expands to three choices instead of a simple y/n:

```csharp
var action = AnsiConsole.Prompt(
    new SelectionPrompt<string>()
        .Title($"[yellow]Found {matches.Count} certificate(s). What would you like to do?[/]")
        .AddChoices(
            "Confirm removal",
            "Save details to file for offline analysis",
            "Cancel")
        .HighlightStyle(HighlightStyle));
```

If the user saves to file, re-prompt for removal confirmation afterward.

---

## Design Decisions

| Decision | Rationale |
|---|---|
| Auto-prefix `https://` silently (no warning) for bare domains | Reduces noise; HTTPS is the expected protocol for certificate inspection |
| Warn but keep `http://` for CRL endpoints | CRL distribution points legitimately use HTTP (RFC 5280 Section 4.2.1.13) |
| Warn and upgrade `http://` for non-CRL URLs | Guides users toward secure practice while still completing the task |
| Store/location selection before browse | Permissions differ between CurrentUser and LocalMachine; user should choose scope first |
| Three-way find method (browse / search / manual) | Covers all user scenarios: discovery, partial knowledge, exact thumbprint |
| `*` wildcard shows all in subject search | Explicit user intent to see everything, avoids overwhelming by default |
| Show full thumbprint after selection | Enables copy-paste for documentation or scripting |
| Export-to-file on trust remove | Supports audit trails and offline review before destructive operations |
| Shared helpers for store browsing | Avoids duplication across Inspect, Lint, and Trust Remove wizards |
| Fix "orl" typo on line 878 | Existing bug; fix as part of this phase |

---

## Progress Tracker

| # | Step | Status | Notes |
|---|------|--------|-------|
| 1 | Add `NormalizeUrl()` helper | [x] | Shared URL normalization logic |
| 2 | Add `PromptUrl()` helper | [x] | Replaces inline URL prompts |
| 3 | Update `RunInspectWizard()` URL branch to use `PromptUrl()` | [x] | Remove old validator |
| 4 | Update `RunLintWizard()` URL branch to use `PromptUrl()` | [x] | Remove old validator |
| 5 | Add `StoreCertificateChoice` record | [x] | Display model for store browser |
| 6 | Add `ExtractCN()` helper | [x] | Parse CN from Subject DN |
| 7 | Add `BrowseOrEnterThumbprint()` helper | [x] | Three-way store certificate finder |
| 8 | Add `BrowseStore()` helper | [x] | Store listing with filter + SelectionPrompt |
| 9 | Add `SearchBySubject()` helper | [x] | Wildcard subject search |
| 10 | Add `PromptThumbprintManually()` helper | [x] | Extracted from current inline code |
| 11 | Update `RunInspectWizard()` store branch to use `BrowseOrEnterThumbprint()` | [x] | Replace manual-only thumbprint entry |
| 12 | Update `RunLintWizard()` store branch to use `BrowseOrEnterThumbprint()` | [x] | Replace manual-only thumbprint entry |
| 13 | Update `RunTrustRemoveWizard()` to use `BrowseOrEnterThumbprint()` | [x] | Replace manual-only thumbprint entry |
| 14 | Add trust status display (Is CA, Self-Signed, Has Key) to Trust Remove | [x] | `DisplayMatchedCertificates()` helper |
| 15 | Add three-way confirmation (Confirm / Save to file / Cancel) to Trust Remove | [x] | Replace y/n with expanded choices |
| 16 | Add `SaveRemovalSummary()` helper | [x] | Export cert details to text file |
| 17 | Fix "orl" typo on line 878 | [x] | Removed with Step 13 rewrite |
| 18 | Update `RunStoreListWizard()` label in global menu (if needed) | [x] | Updated source choice + Trust Remove store labels |
| 19 | Update README.md with enhanced wizard behavior | [x] | Added "Guided Wizard Mode" section |
| 20 | Update docs/README.md with Phase 11 entry | [x] | Added row to feature table |

---

## Implementation Steps

### Step 1: Add `NormalizeUrl()` Helper

**File:** `src/certz/Services/CertificateWizard.cs`

Add to the "Shared helpers" section at the bottom of the file.

```csharp
private static (string Url, string? Warning) NormalizeUrl(string input)
{
    input = input.Trim();

    // Already has https://
    if (input.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        return (input, null);

    // Has http:// — check if CRL endpoint
    if (input.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
    {
        if (Uri.TryCreate(input, UriKind.Absolute, out var uri))
        {
            var isCrl = uri.AbsolutePath.EndsWith(".crl", StringComparison.OrdinalIgnoreCase)
                        || uri.Host.StartsWith("crl.", StringComparison.OrdinalIgnoreCase);

            if (isCrl)
                return (input, "CRL endpoint uses non-secure HTTP. Proceeding with caution.");
        }

        // Non-CRL http:// — upgrade to https://
        var upgraded = "https://" + input[7..];
        return (upgraded, "Non-secure URL detected. Upgrading to HTTPS.");
    }

    // No protocol — prepend https://
    return ("https://" + input, null);
}
```

### Step 2: Add `PromptUrl()` Helper

**File:** `src/certz/Services/CertificateWizard.cs`

```csharp
private static string PromptUrl(string title = "[green]?[/] URL (e.g. example.com or https://example.com):")
{
    var raw = AnsiConsole.Prompt(
        new TextPrompt<string>(title)
            .Validate(u => !string.IsNullOrWhiteSpace(u)
                ? ValidationResult.Success()
                : ValidationResult.Error("[red]URL cannot be empty[/]")));

    var (url, warning) = NormalizeUrl(raw);

    if (warning != null)
        AnsiConsole.MarkupLine($"[yellow]  {warning}[/]");

    if (!string.Equals(url, raw, StringComparison.Ordinal))
        AnsiConsole.MarkupLine($"[grey]  Using: {Markup.Escape(url)}[/]");

    return url;
}
```

### Step 3: Update `RunInspectWizard()` URL Branch

**File:** `src/certz/Services/CertificateWizard.cs`

Replace the current URL prompt block (lines 697–702) with a call to `PromptUrl()`.

```csharp
case InspectSourceType.Url:
    source = PromptUrl();
    WriteEquivalentCommand($"certz inspect {source}");
    break;
```

### Step 4: Update `RunLintWizard()` URL Branch

**File:** `src/certz/Services/CertificateWizard.cs`

Replace the current URL prompt block (lines 783–788) with a call to `PromptUrl()`.

```csharp
case InspectSourceType.Url:
    source = PromptUrl();
    break;
```

### Step 5–10: Add Store Browser Helpers

**File:** `src/certz/Services/CertificateWizard.cs`

Add the following to the "Shared helpers" section:

- `StoreCertificateChoice` record (Step 5)
- `ExtractCN()` helper (Step 6)
- `BrowseOrEnterThumbprint()` dispatcher (Step 7)
- `BrowseStore()` with filter + SelectionPrompt (Step 8)
- `SearchBySubject()` with wildcard input (Step 9)
- `PromptThumbprintManually()` extracted from inline code (Step 10)

See the code samples in the Enhancement B specification above.

### Step 11: Update `RunInspectWizard()` Store Branch

**File:** `src/certz/Services/CertificateWizard.cs`

Replace the current store branch (lines 706–728):

```csharp
default: // Store
    storeName = AnsiConsole.Prompt(
        new SelectionPrompt<string>()
            .Title("[green]?[/] Certificate store:")
            .AddChoices("My (Personal)", "Root (Trusted Root CAs)", "CA (Intermediate CAs)", "TrustedPeople")
            .HighlightStyle(HighlightStyle));
    var inspectStoreKey = storeName.Split(' ')[0];

    storeLocation = AnsiConsole.Prompt(
        new SelectionPrompt<string>()
            .Title("[green]?[/] Store location:")
            .AddChoices("CurrentUser", "LocalMachine")
            .HighlightStyle(HighlightStyle));

    source = BrowseOrEnterThumbprint(inspectStoreKey, storeLocation);
    storeName = inspectStoreKey;

    WriteEquivalentCommand($"certz inspect {source} --store {inspectStoreKey} --location {storeLocation}");
    break;
```

### Step 12: Update `RunLintWizard()` Store Branch

Same pattern as Step 11 but for the lint wizard's store branch (lines 791–808).

### Step 13: Update `RunTrustRemoveWizard()` Thumbprint Acquisition

**File:** `src/certz/Services/CertificateWizard.cs`

Replace the current thumbprint prompt (lines 877–882):

```csharp
// Ask for store first (needed for browsing)
var storeName = AnsiConsole.Prompt(
    new SelectionPrompt<string>()
        .Title("[green]?[/] Certificate store:")
        .AddChoices("Root", "My", "CA", "TrustedPeople")
        .HighlightStyle(HighlightStyle));

var storeLocation = AnsiConsole.Prompt(
    new SelectionPrompt<string>()
        .Title("[green]?[/] Store location:")
        .AddChoices("CurrentUser", "LocalMachine")
        .HighlightStyle(HighlightStyle));

var thumbprint = BrowseOrEnterThumbprint(storeName, storeLocation);
```

Note: Store name and location prompts move *before* the thumbprint acquisition since browsing needs them.

### Step 14: Add Trust Status Display

After finding matches in `RunGlobalWizard()` Trust Remove branch, display detailed certificate information:

```csharp
foreach (var cert in matches)
{
    var isSelfSigned = cert.Subject == cert.Issuer;
    var basicConstraints = cert.Extensions["2.5.29.19"] as X509BasicConstraintsExtension;
    var isCa = basicConstraints?.CertificateAuthority ?? false;

    var table = new Table()
        .Border(TableBorder.Rounded)
        .BorderColor(Color.Grey)
        .AddColumn(new TableColumn("[bold]Property[/]").Width(16))
        .AddColumn(new TableColumn("[bold]Value[/]"));

    table.AddRow("Subject", Markup.Escape(cert.Subject));
    table.AddRow("Issuer", Markup.Escape(cert.Issuer));
    table.AddRow("Thumbprint", $"[cyan]{cert.Thumbprint}[/]");
    table.AddRow("Not Before", cert.NotBefore.ToString("yyyy-MM-dd"));
    table.AddRow("Not After", cert.NotAfter.ToString("yyyy-MM-dd"));
    table.AddRow("Is CA", isCa ? "[yellow]Yes[/]" : "No");
    table.AddRow("Self-Signed", isSelfSigned ? "[yellow]Yes[/]" : "No");
    table.AddRow("Has Key", cert.HasPrivateKey ? "Yes" : "No");
    table.AddRow("Status", cert.NotAfter < DateTime.Now
        ? "[red]Expired[/]"
        : "[green]Valid[/]");

    AnsiConsole.Write(table);
}
```

### Step 15: Three-Way Confirmation for Trust Remove

Replace the simple `AnsiConsole.Confirm()` in the global wizard Trust Remove branch:

```csharp
var action = AnsiConsole.Prompt(
    new SelectionPrompt<string>()
        .Title($"[yellow]Found {matches.Count} certificate(s). What would you like to do?[/]")
        .AddChoices(
            "Confirm removal",
            "Save details to file for offline analysis",
            "Cancel")
        .HighlightStyle(HighlightStyle));

switch (action)
{
    case "Confirm removal":
        var result = TrustHandler.RemoveFromStore(matches, storeName, storeLocation);
        formatter.WriteTrustRemoved(result);
        break;

    case "Save details to file for offline analysis":
        SaveRemovalSummary(matches, storeName, storeLocation);
        var proceed = AnsiConsole.Confirm("[green]?[/] Proceed with removal?", defaultValue: false);
        if (proceed)
        {
            var removeResult = TrustHandler.RemoveFromStore(matches, storeName, storeLocation);
            formatter.WriteTrustRemoved(removeResult);
        }
        else
        {
            AnsiConsole.MarkupLine("[yellow]  Operation cancelled.[/]");
            foreach (var c in matches) c.Dispose();
        }
        break;

    default: // Cancel
        AnsiConsole.MarkupLine("[yellow]  Operation cancelled.[/]");
        foreach (var c in matches) c.Dispose();
        break;
}
```

### Step 16: Add `SaveRemovalSummary()` Helper

```csharp
private static void SaveRemovalSummary(List<X509Certificate2> certificates, string storeName, string storeLocation)
{
    var defaultPath = $"removed-certs-{DateTimeOffset.UtcNow:yyyy-MM-dd}.txt";
    var path = AnsiConsole.Prompt(
        new TextPrompt<string>("[green]?[/] Output file path:")
            .DefaultValue(defaultPath));

    var sb = new StringBuilder();
    sb.AppendLine("Certificate Removal Summary");
    sb.AppendLine($"Generated: {DateTimeOffset.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
    sb.AppendLine($"Store: {storeLocation}\\{storeName}");
    sb.AppendLine();

    for (var i = 0; i < certificates.Count; i++)
    {
        var cert = certificates[i];
        var basicConstraints = cert.Extensions["2.5.29.19"] as X509BasicConstraintsExtension;
        var isCa = basicConstraints?.CertificateAuthority ?? false;
        var isSelfSigned = cert.Subject == cert.Issuer;
        var status = cert.NotAfter < DateTime.Now ? "Expired" : "Valid";

        sb.AppendLine($"Certificate #{i + 1}:");
        sb.AppendLine($"  Subject:     {cert.Subject}");
        sb.AppendLine($"  Issuer:      {cert.Issuer}");
        sb.AppendLine($"  Thumbprint:  {cert.Thumbprint}");
        sb.AppendLine($"  Not Before:  {cert.NotBefore:yyyy-MM-dd}");
        sb.AppendLine($"  Not After:   {cert.NotAfter:yyyy-MM-dd}");
        sb.AppendLine($"  Is CA:       {(isCa ? "Yes" : "No")}");
        sb.AppendLine($"  Self-Signed: {(isSelfSigned ? "Yes" : "No")}");
        sb.AppendLine($"  Has Key:     {(cert.HasPrivateKey ? "Yes" : "No")}");
        sb.AppendLine($"  Status:      {status}");
        sb.AppendLine();
    }

    File.WriteAllText(path, sb.ToString());
    AnsiConsole.MarkupLine($"[green]  Saved certificate details to {Markup.Escape(path)}[/]");
}
```

### Step 17: Fix "orl" Typo

**File:** `src/certz/Services/CertificateWizard.cs`, line 878

Change `"orl"` to `"or"` in the thumbprint prompt text. This line will be replaced by the store browser but fix it regardless for completeness.

### Steps 18–20: Documentation Updates

- **Step 18:** Review `RunStoreListWizard()` menu label in global wizard for consistency with enhanced store browser terminology.
- **Step 19:** Update README.md wizard section to document: URL auto-prefix behavior, store browsing capability, export-to-file on trust remove.
- **Step 20:** Add Phase 11 row to `docs/README.md` feature table.

---

## Verification Checklist

### Enhancement A: Smart URL Input

- [ ] Bare domain `example.com` is auto-prefixed to `https://example.com`
- [ ] Domain with port `example.com:8443` auto-prefixes correctly
- [ ] `https://` URLs pass through unchanged
- [ ] `http://` non-CRL URLs are upgraded with a warning
- [ ] `http://crl.example.com/root.crl` keeps `http://` with CRL warning
- [ ] URL with path and trailing slash is preserved
- [ ] Both Inspect and Lint wizards use the shared `PromptUrl()` helper
- [ ] "Using:" echo only appears when the URL was modified

### Enhancement B: Store Browser

- [ ] Store location and store name are prompted before browsing
- [ ] "Browse certificates in store" shows a filtered list from `StoreListHandler`
- [ ] "Search by subject" accepts wildcard patterns (`*localhost*`)
- [ ] `*` wildcard in subject search shows all certificates
- [ ] "Enter thumbprint manually" works as before
- [ ] Empty store shows warning and falls back to manual entry
- [ ] Full thumbprint is displayed after selection for easy copying
- [ ] Inspect wizard store branch uses shared `BrowseOrEnterThumbprint()`
- [ ] Lint wizard store branch uses shared `BrowseOrEnterThumbprint()`

### Enhancement C: Trust Remove Browser + Export

- [ ] Trust Remove wizard uses `BrowseOrEnterThumbprint()` instead of direct thumbprint prompt
- [ ] Store/location prompts are asked before thumbprint acquisition
- [ ] Certificate details table shows Subject, Issuer, Thumbprint, dates, Is CA, Self-Signed, Has Key, Status
- [ ] Three-way confirmation: Confirm removal / Save to file / Cancel
- [ ] Save-to-file generates a properly formatted text summary
- [ ] Save-to-file uses UTC timestamp
- [ ] After saving, user is re-prompted for removal confirmation
- [ ] Cancel disposes all certificate objects

### General

- [ ] "orl" typo on line 878 is fixed
- [ ] Existing wizard flows (dev cert, CA cert, etc.) are not affected
- [ ] `certz --guided` launches without errors
- [ ] README.md updated with enhanced wizard behavior
- [ ] docs/README.md includes Phase 11 row

---

## Security Considerations

- **No credentials in export files:** The removal summary exports only public certificate metadata (subject, thumbprint, dates). No private keys or passwords are included.
- **CRL HTTP warning:** Users are explicitly warned when CRL endpoints use HTTP, but the URL is not blocked since HTTP CRL distribution is a legitimate and common pattern per RFC 5280.
- **Store access permissions:** The store browser respects existing permission boundaries — LocalMachine requires admin, CurrentUser does not.

---

## Key Files Modified

| File | Change |
|------|--------|
| `src/certz/Services/CertificateWizard.cs` | Add `NormalizeUrl()`, `PromptUrl()`, `BrowseOrEnterThumbprint()`, `BrowseStore()`, `SearchBySubject()`, `PromptThumbprintManually()`, `ExtractCN()`, `SaveRemovalSummary()`, `StoreCertificateChoice` record; update Inspect/Lint/TrustRemove wizards |
| `README.md` | Document enhanced wizard behavior (URL auto-prefix, store browsing, export) |
| `docs/README.md` | Add Phase 11 row to feature table |
| `docs/phases/phase11-wizard-enhancements.md` | This file |
