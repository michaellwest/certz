# Wizard Guide -- certz --guided

The certz interactive wizard asks you questions step by step and assembles the command
for you. It is ideal when you are creating a certificate for the first time, or running
an operation you do not do often enough to remember all the flags.

After each operation the wizard prints the equivalent direct CLI command, so you can
see exactly what it built and reuse it in scripts later.

**See also:**
[Quickstart](quickstart.md) |
[certz create](../reference/create.md) |
[certz inspect](../reference/inspect.md) |
[certz trust](../reference/trust.md)

---

## Launching the Wizard

### Global wizard -- main menu

```bash
certz --guided
```

Starts the global wizard at a main menu where you choose what to do. The menu stays
open after each operation so you can run multiple commands in sequence.

### Command-scoped wizard

Add `--guided` to any command to skip the main menu and go straight to the relevant
wizard flow:

```bash
certz create dev --guided
certz create ca --guided
certz inspect --guided
certz lint --guided
certz trust add --guided
certz trust remove --guided
certz convert --guided
certz monitor --guided
certz renew --guided
```

Pre-scoping is useful when you know which operation you want but still want the
guided step-by-step experience.

---

## Main Menu

The global wizard (`certz --guided`) presents a grouped menu:

```
? What would you like to do?

  Create
  > Create a development certificate
    Create a Certificate Authority (CA)

  Inspect & Validate
    Inspect a certificate
    Lint / validate a certificate

  Manage
    List certificates in store
    Add certificate to trust store
    Remove certificate from trust store
    Convert certificate format
    Monitor certificates for expiration
    Renew a certificate

  Exit
```

Use the arrow keys to navigate, Enter to select. The menu reappears after each
operation so you can keep working without relaunching certz.

---

## Navigation Controls

| Key / input | Action |
|-------------|--------|
| `Up` / `Down` arrow | Move through choices in a selection prompt |
| `Left` arrow | Go back to the previous step (selection prompts only) |
| `Enter` | Confirm the current selection or typed value |
| `Esc` | Cancel the current wizard session without making changes |
| `Ctrl+C` | Exit certz entirely |
| Select "Cancel" | Cancel the current operation and return to the main menu |

> **Back navigation in text fields:** Left arrow moves the cursor within a text field
> rather than going back. To go back from a text field, press `Esc` to cancel, or
> complete the field and use `Left` arrow on the next selection prompt.

### Breadcrumb trail

Each step shows a breadcrumb at the top so you know where you are:

```
Certz > Create > Dev Certificate > Step 3/6: Certificate Validity
```

The step counter updates as you move forward and back.

---

## Operations Covered

| Operation | Wizard support |
|-----------|----------------|
| Create dev certificate | Yes |
| Create CA certificate | Yes |
| Inspect certificate (file, URL, or store) | Yes |
| Lint / validate certificate | Yes |
| List certificates in store | Yes |
| Add certificate to trust store | Yes |
| Remove certificate from trust store | Yes |
| Convert certificate format | Yes |
| Monitor certificates for expiration | Yes |
| Renew a certificate | Yes |

---

## Wizard Step Reference

### Create dev certificate (6 steps)

| Step | What it asks |
|------|-------------|
| 1. Domain Name | Primary domain (default: `localhost`) |
| 2. Subject Alternative Names | Add extra SANs beyond the primary domain (one per line) |
| 3. Certificate Validity | Days (default: 90; max 398) |
| 4. Key Algorithm | ECDSA-P256 (recommended), ECDSA-P384, RSA 3072-bit, RSA 4096-bit |
| 5. Trust Store | Install to trust store? CurrentUser or LocalMachine? |
| 6. Output Files | PFX filename, separate .cer/.key export?, password or auto-generate? |

Final step: summary table with all settings → "Create certificate with these settings?" (Y/n) → certificate is created → equivalent command printed.

### Create CA certificate (5 steps)

| Step | What it asks |
|------|-------------|
| 1. CA Identity | Common Name for the CA (default: `Development Root CA`) |
| 2. Certificate Validity | Days (default: 3650 -- ~10 years) |
| 3. Path Length Constraint | No constraint / 0 (leaf CA only) / 1 / 2 |
| 4. Key Algorithm | ECDSA-P384 (recommended for CA), ECDSA-P256, RSA 4096-bit, RSA 3072-bit |
| 5. Trust Store & Output | Trust to Root store? PFX filename? Password? |

Final step: summary table → "Create CA certificate with these settings?" (Y/n) → certificate is created → equivalent command printed.

### Inspect certificate

The wizard offers three source modes:

1. **File** -- enter or browse to a file path; prompted for password if PFX
2. **HTTPS URL** -- type a URL; wizard normalizes input (see [Smart URL Input](#smart-url-input))
3. **Certificate store** -- choose store and location, then browse or search by subject

After source selection: show chain? (yes/no)

### Lint certificate

Same source selection as inspect (file, URL, or store), then: choose validation
policy (cabf / mozilla / dev / all).

**Context shortcut:** After inspecting a certificate, the follow-up menu offers
"Lint this certificate". The wizard skips source re-entry and goes straight to policy
selection, using the same source and password from the previous step.

---

## Smart URL Input

When the wizard prompts for an HTTPS URL, it normalizes your input:

| What you type | What certz uses | Note |
|---------------|----------------|------|
| `example.com` | `https://example.com` | `https://` prefix added automatically |
| `example.com:8443` | `https://example.com:8443` | Port preserved |
| `http://example.com` | `https://example.com` | Upgraded with a warning |
| `https://example.com` | `https://example.com` | Used as-is |

**Exception -- CRL endpoints:** HTTP is legitimate for CRL distribution points
(`.crl` file paths or `crl.*` subdomains). The wizard does not upgrade these to HTTPS.

---

## Store Browsing

When an operation requires a certificate from the Windows store, the wizard offers
three selection modes:

### Browse

Lists all certificates in the selected store with a filter:

- Show all
- Valid only
- Expiring soon (within 30 days)
- Expired only

Certificates are displayed as a selection list with subject, thumbprint prefix, and
expiry date. Arrow keys navigate; Enter selects.

### Search by subject

Type a wildcard pattern (e.g., `*localhost*`, `CN=api*`) to filter the list. Only
matching certificates appear. Useful when the store is large.

### Enter thumbprint manually

Type a full 40-character or partial 8+ character thumbprint. Useful when you already
have the thumbprint from `certz store list` or a previous operation.

After selection, the wizard displays the full thumbprint so you can copy it for use
in scripts.

---

## Trust Removal Workflow

When you select "Remove certificate from trust store", the wizard shows the full
certificate details before any deletion occurs:

```
Certificate to Remove
+-------------------+------------------------------------------+
| Field             | Value                                    |
+-------------------+------------------------------------------+
| Subject           | CN=My Dev Root CA                        |
| Issuer            | CN=My Dev Root CA                        |
| Is CA             | Yes                                      |
| Self-Signed       | Yes                                      |
| Has Private Key   | No                                       |
| Thumbprint        | A1B2C3D4E5F6789012345678901234567890ABCD |
| Expires           | 2035-10-23 (3,527 days remaining)        |
| Status            | Valid                                    |
+-------------------+------------------------------------------+
```

You are then offered three choices:

1. **Confirm removal** -- proceeds with the deletion
2. **Save details to file** -- writes a JSON summary of the certificate before removing,
   useful for offline review or audit logs
3. **Cancel** -- exits without removing

---

## Context Forwarding -- No Re-entry Between Steps

The wizard carries context from one operation to the next so you do not have to
re-enter source paths and passwords:

| After... | Follow-up options |
|----------|-------------------|
| Create cert | "Inspect the created certificate" or "Create another certificate" |
| Inspect cert | "Lint this certificate" or "Inspect another certificate" |
| Inspect from store | + "Inspect another from this store" (keeps store context) |
| Any operation | Main menu or Exit |

When a follow-up is chosen, the wizard reuses the source path and password from the
previous step -- they are not shown on screen again.

---

## Equivalent Command Display

After every operation, the wizard prints the equivalent direct CLI command. This
applies to both the global wizard (`certz --guided`) and command-scoped wizards
(`certz create dev --guided`, `certz create ca --guided`, etc.).

For `create dev` and `create ca`, the command is printed after the certificate is
successfully created:

```
-- Equivalent command -------------------------------------------
  certz create dev "myapp.local" --san "127.0.0.1" --days 90 --key-type ECDSA-P256 --file "myapp-local.pfx"
```

For other operations (inspect, lint, trust, convert, monitor, renew), it is printed
during the wizard step before execution:

```
-- Equivalent command -------------------------------------------
  certz inspect "api-local.pfx" --password <hidden>
```

Copy this command into a script or share it with your team. Passwords are never
included in the output; substitute the actual value when scripting.

---

## When to Use Wizard vs Direct CLI

| Scenario | Recommended |
|----------|-------------|
| First-time certificate creation | Wizard |
| Infrequent or complex operations | Wizard |
| Learning which flags exist | Wizard (shows the equivalent command it builds) |
| CI/CD or scripted pipelines | Direct CLI with `--format json` |
| Familiar repeated operations | Direct CLI |
| Bulk operations across many certs | Direct CLI |

---

## Exiting Cleanly

- **`Esc`** at any step cancels the current operation and returns to the main menu
  (or exits if not in the global wizard loop).
- **`Ctrl+C`** exits certz immediately.
- **Selecting "Cancel"** in any selection prompt cancels the current operation.

If certz has already written files (e.g., a certificate was created before you
cancelled a follow-up step), those files remain on disk. Cancelling does not roll
back completed operations.
