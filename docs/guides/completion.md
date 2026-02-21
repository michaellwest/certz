# Shell Tab Completion

certz supports tab completion for option names and values in PowerShell (Windows). Bash and
Zsh support will be added in a follow-up release when cross-platform builds are available.

---

## PowerShell

### Quick install (one command)

```powershell
certz completion powershell >> $PROFILE
. $PROFILE
```

### What gets installed

Running `certz completion powershell` outputs a `Register-ArgumentCompleter` block that
tells PowerShell to call certz for completions whenever you press Tab after a certz command.

### Manual install (step by step)

1. **Output the script** to verify it looks correct:

   ```powershell
   certz completion powershell
   ```

2. **Append it to your profile** so it loads every session:

   ```powershell
   certz completion powershell >> $PROFILE
   ```

   To find your profile path:

   ```powershell
   $PROFILE
   # e.g. C:\Users\you\Documents\PowerShell\Microsoft.PowerShell_profile.ps1
   ```

3. **Reload your profile** in the current session:

   ```powershell
   . $PROFILE
   ```

4. **Test it** -- type a command and press Tab:

   ```powershell
   certz create dev --key-type <TAB>
   # cycles through: ECDSA-P256  ECDSA-P384  ECDSA-P521  RSA

   certz create dev --eku <TAB>
   # cycles through: clientAuth  codeSigning  emailProtection  serverAuth

   certz --format <TAB>
   # cycles through: json  text
   ```

---

## What completes

### Option names

Subcommand names and all option flags complete automatically. For example:

```
certz <TAB>            -> create  convert  inspect  lint  monitor  renew  store  trust ...
certz create <TAB>     -> dev  ca
certz create dev <TAB> -> --key-type  --eku  --days  --trust  ...
```

### Option values with fixed valid sets

| Option | Completions |
|--------|-------------|
| `--key-type` / `--kt` | ECDSA-P256, ECDSA-P384, ECDSA-P521, RSA |
| `--hash-algorithm` / `--hash` | auto, SHA256, SHA384, SHA512 |
| `--pfx-encryption` / `--pe` | modern, legacy |
| `--format` / `--fmt` | text, json |
| `--pipe-format` | pem, pfx, cert, key |
| `--rsa-padding` / `--rp` | pkcs1, pss *(RSA only -- see below)* |
| `--store` | My, Root, CA, TrustedPeople, TrustedPublisher, AuthRoot, AddressBook, Disallowed |
| `--location` | CurrentUser, LocalMachine |
| `--trust-location` / `--tl` | LocalMachine, CurrentUser |
| `--eku` | serverAuth, clientAuth, codeSigning, emailProtection |
| `--days` | 30, 90, 180, 365, 398 *(presets; any integer is still accepted)* |
| `--subject-c` / `--c` | Full ISO 3166-1 alpha-2 country code list (AD .. ZW) |

### Context-aware completions

Some options only complete when a prerequisite flag has already been typed:

| Option | Condition | Completions |
|--------|-----------|-------------|
| `--key-size` / `--ks` | `--key-type RSA` already typed | 2048, 3072, 4096 |
| `--rsa-padding` / `--rp` | `--key-type RSA` already typed | pkcs1, pss |

Example:

```powershell
# With ECDSA key type -- no completions for --key-size or --rsa-padding
certz create dev --key-type ECDSA-P256 --key-size <TAB>    # (nothing)

# With RSA key type -- completions appear
certz create dev --key-type RSA --key-size <TAB>           # 2048  3072  4096
certz create dev --key-type RSA --rsa-padding <TAB>        # pkcs1  pss
```

### Options with no completion (free-form values)

These options accept values that cannot be predicted, so no completion is registered:

- `--san` (hostnames / IP addresses)
- `--thumbprint` (certificate fingerprints)
- `--cn`, `--name`, `--url`, `--password`
- `--crl-url`, `--ocsp-url`, `--ca-issuers-url`
- `--subject-o`, `--subject-ou`, `--subject-st`, `--subject-l`

---

## Typo correction ("Did you mean?")

When certz does not recognize an option, it searches all known option names and prints a
suggestion to stderr if the edit distance is 3 or fewer characters:

```
$ certz create dev --key-tpe RSA
'--key-tpe' was not matched. Did you mean '--key-type'?
```

This is in addition to System.CommandLine's own built-in error messages.

---

## Troubleshooting

**Tab shows nothing after sourcing the profile**

Make sure certz is on your `$PATH` or use the full path in the registered completer:

```powershell
# Check if certz is found
Get-Command certz

# If not found, add its directory to PATH
$env:PATH += ";C:\path\to\certz"
```

**Profile was updated but completions don't appear yet**

Reload the profile in the current session:

```powershell
. $PROFILE
```

**I want to see the raw completion script**

```powershell
certz completion powershell
```

**I want installation instructions instead of the script**

```powershell
certz completion powershell --explain
```
