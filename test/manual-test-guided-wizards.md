# Manual Test Plan: Guided Wizards

Covers the wizard work shipped on `main` in commits `a1c99f4` (`#64`/`#65`) and `51e328c` (`#66`):

- `certz inspect --guided` -- newly exposed via per-command flag.
- `certz convert --guided` -- newly exposed via per-command flag.
- `certz renew --guided` -- new "Modify SANs?" branch added to the existing wizard.

These flows are interactive and cannot be exercised by `test-*.ps1`, which is why this is a manual plan. Run from a terminal that supports ANSI rendering (Windows Terminal, VS Code integrated terminal, or `pwsh` directly).

---

## Setup (once per session)

Build the binary and prepare a scratch directory plus a couple of source certificates the wizards can consume.

```powershell
# From repo root
dotnet build src\certz\certz.csproj -nologo -v quiet

$exe = "$PWD\src\certz\bin\Debug\net10.0\win-x64\certz.exe"
$lab = Join-Path $env:TEMP "certz-wizard-lab"
New-Item -ItemType Directory -Path $lab -Force | Out-Null
Set-Location $lab

# Source cert with multiple SANs (used by inspect, renew)
& $exe create dev api.local --san backup.local --san 10.0.0.5 `
    --file leaf.pfx --password TestPass123 --days 30

# A PEM cert (used by convert)
& $exe convert leaf.pfx --to pem --password TestPass123 --output leaf.pem
```

Cleanup at the very end:

```powershell
Set-Location ~
Remove-Item $lab -Recurse -Force
```

---

## Section 1: `certz inspect --guided`

### 1.1 -- File source, no chain

**Run:** `& $exe inspect --guided`

**Walkthrough:**
1. Prompt: `Certificate source` -> select **File (PFX, PEM, DER, CRT)**.
2. Prompt: `Certificate file` -> enter `leaf.pfx`.
3. Prompt: `Password` -> enter `TestPass123`.
4. The wizard prints the equivalent CLI command (should be `certz inspect "leaf.pfx" --password <hidden>`).
5. Prompt: `Show certificate chain?` -> answer **No** (default).

**Expected:**
- [ ] Inspect summary renders with `Subject CN=api.local`, three SANs (`api.local`, `backup.local`, `10.0.0.5`).
- [ ] Exit code is `0` (no warnings).
- [ ] No password prompt appears in the printed equivalent CLI command (it shows `<hidden>`).

### 1.2 -- URL source

**Run:** `& $exe inspect --guided`

**Walkthrough:**
1. Source -> **URL (HTTPS endpoint)**.
2. URL -> `https://github.com`.
3. Show chain -> **Yes**.

**Expected:**
- [ ] Cert summary for github.com renders.
- [ ] Chain section shows the issuer chain up to a root.
- [ ] Equivalent command shown is `certz inspect https://github.com`.

### 1.3 -- Windows store source

**Run:** `& $exe inspect --guided`

**Walkthrough:**
1. Source -> **Windows Store (browse or enter thumbprint)**.
2. Store location -> `CurrentUser`.
3. Certificate store -> `My (Personal)`.
4. The wizard offers a thumbprint selector. Pick any cert (or cancel to back out).

**Expected:**
- [ ] Selected cert's details render.
- [ ] Equivalent command includes `--store My --location CurrentUser`.
- [ ] Cancelling at any prompt exits cleanly with `Operation cancelled.` (exit 0, no stack trace).

### 1.4 -- Cancel at first prompt

**Run:** `& $exe inspect --guided`

**Walkthrough:**
1. At the first source prompt, scroll to the **Cancel** option (or press Esc).

**Expected:**
- [ ] Wizard exits with `Operation cancelled.` and exit code `0`.

---

## Section 2: `certz convert --guided`

### 2.1 -- PFX to PEM

**Run:** `& $exe convert --guided`

**Walkthrough:**
1. Input certificate file -> `leaf.pfx`.
2. Target format -> **PEM (.pem / .crt)**.
3. Output file path -> accept default (`leaf.pem` will already exist; the wizard should suggest a unique name or let you overwrite -- note the actual default it shows).
4. Source PFX password -> `TestPass123`.

**Expected:**
- [ ] Conversion completes with exit 0.
- [ ] Output file exists; opening it shows `-----BEGIN CERTIFICATE-----`.
- [ ] Equivalent command printed is `certz convert "leaf.pfx" --to pem --output "<path>"`.

### 2.2 -- PEM to PFX with auto-generated password

**Run:** `& $exe convert --guided`

**Walkthrough:**
1. Input -> `leaf.pem`.
2. Target -> **PFX / PKCS#12 (.pfx)**.
3. Output path -> `leaf-converted.pfx`.
4. PFX password -> leave blank (triggers auto-generate).
5. Password file prompt -> accept default or supply a path.

**Expected:**
- [ ] Conversion succeeds.
- [ ] PFX file is readable with the auto-generated password printed in the output table.
- [ ] If a password file was specified, it now contains the generated password.

### 2.3 -- DER target

**Run:** `& $exe convert --guided`

**Walkthrough:**
1. Input -> `leaf.pem`.
2. Target -> **DER (.der / .cer)**.
3. Output -> accept default.

**Expected:**
- [ ] DER file written.
- [ ] `Get-Item leaf.der | Format-List Length` shows non-zero binary size.
- [ ] Equivalent command shows `--to der`.

### 2.4 -- Cancel at format prompt

**Run:** `& $exe convert --guided`

**Walkthrough:**
1. Input -> `leaf.pfx`.
2. At target format prompt, choose **Cancel**.

**Expected:**
- [ ] Wizard exits with `Operation cancelled.` and no output file is written.

---

## Section 3: `certz renew --guided` (new SAN modification branch)

### 3.1 -- Renew without modifying SANs (default path)

**Run:** `& $exe renew --guided`

**Walkthrough:**
1. Source certificate -> `leaf.pfx`.
2. Password -> `TestPass123`.
3. New validity period (days) -> `60`.
4. Preserve existing private key? -> **No**.
5. **Modify the certificate's SAN list?** -> **No** (default).
6. Output file path -> accept default (`leaf-renewed.pfx`).

**Expected:**
- [ ] Renewal succeeds.
- [ ] Equivalent command printed has **no** `--add-san` or `--remove-san` flags.
- [ ] `& $exe inspect leaf-renewed.pfx --password <prompt-output-password> --format json | ConvertFrom-Json` shows the same three SANs as the source.

### 3.2 -- Add a SAN

**Run:** `& $exe renew --guided`

**Walkthrough:**
1. Source -> `leaf.pfx`. Password -> `TestPass123`. Days -> `60`. Keep key -> **No**.
2. **Modify SANs?** -> **Yes**.
3. Remove prompt -> leave blank to skip.
4. First add -> `new.local`.
5. Second add -> leave blank to finish.
6. Output -> `leaf-add.pfx`.

**Expected:**
- [ ] Renewal succeeds.
- [ ] Equivalent command shows ` --add-san "new.local"` (no `--remove-san` flags).
- [ ] Inspecting `leaf-add.pfx` shows four SANs: `api.local`, `backup.local`, `10.0.0.5`, `new.local`.

### 3.3 -- Remove a SAN

**Run:** `& $exe renew --guided`

**Walkthrough:**
1. Source -> `leaf.pfx`. Password -> `TestPass123`. Days -> `60`. Keep key -> **No**.
2. Modify SANs? -> **Yes**.
3. First remove -> `backup.local`.
4. Second remove -> leave blank.
5. First add -> leave blank.
6. Output -> `leaf-rem.pfx`.

**Expected:**
- [ ] Equivalent command shows `--remove-san "backup.local"` only.
- [ ] Inspecting `leaf-rem.pfx` shows two SANs: `api.local` and `10.0.0.5` (no `backup.local`).

### 3.4 -- Combined add + remove

**Run:** `& $exe renew --guided`

**Walkthrough:**
1. Source `leaf.pfx`, password, 60 days, no key reuse.
2. Modify SANs? -> Yes.
3. Removes: `backup.local`, then blank.
4. Adds: `api-v2.local`, `192.168.1.50`, then blank.
5. Output -> `leaf-swap.pfx`.

**Expected:**
- [ ] Equivalent command lists removes before adds, both quoted.
- [ ] Inspect shows: dnsName SANs `api.local`, `api-v2.local`; iPAddress SANs `10.0.0.5`, `192.168.1.50`. (`192.168.1.50` should land in the iPAddress entry, not dnsName.)

### 3.5 -- IP literal in add

**Run:** `& $exe renew --guided`

**Walkthrough:**
1. Modify SANs -> Yes. Add `203.0.113.7`. No removes.

**Expected:**
- [ ] Renewed cert has `203.0.113.7` in the iPAddress SAN entry, not the dnsName entry.
- [ ] `certz lint` on the renewed cert produces no BR-022 warning.

### 3.6 -- Validation failure: whitespace add

**Run:** `& $exe renew --guided`

**Walkthrough:**
1. Modify SANs -> Yes. Add `bad space.local`. No removes.

**Expected:**
- [ ] Renewal fails with exit 1 and an error message that includes "whitespace" and "BR-019".
- [ ] No output file is written.

### 3.7 -- Validation failure: invalid LDH

**Run:** `& $exe renew --guided` -> Modify SANs -> Yes -> Add `under_score.local`.

**Expected:**
- [ ] Exit 1, error mentions BR-021 and the underscore character.
- [ ] No output file written.

### 3.8 -- Validation failure: duplicate add

**Run:** `& $exe renew --guided` -> Modify SANs -> Yes -> Add `api.local` (which already exists in the source).

**Expected:**
- [ ] Exit 1, error message contains `already exists in the certificate's SAN list`.
- [ ] No output file written.

### 3.9 -- Cancel inside the SAN modification branch

**Run:** `& $exe renew --guided`

**Walkthrough:**
1. Reach the "Modify SANs?" prompt. Press Esc / select Cancel.

**Expected:**
- [ ] Wizard exits with `Operation cancelled.` and exit 0.
- [ ] No file is written.

---

## Cross-cutting checks

Run these mentally during every wizard scenario:

- [ ] **Breadcrumbs**: the header at the top of each wizard page shows the path (e.g. `Certz > Renew > Modify SANs`).
- [ ] **Defaults are highlighted**: when a prompt has a default value, pressing Enter accepts it.
- [ ] **Equivalent CLI command**: each wizard prints the equivalent flag-form command before running, and copy-pasting that command into a fresh terminal reproduces the same outcome.
- [ ] **No stack traces** on Ctrl+C or Esc -- the wizard reports "Operation cancelled." and exits 0.
- [ ] **Password masking**: all password prompts hide input; the equivalent command shows `<hidden>` rather than the literal password.

---

## Cleanup

```powershell
Set-Location ~
Remove-Item (Join-Path $env:TEMP "certz-wizard-lab") -Recurse -Force
```
