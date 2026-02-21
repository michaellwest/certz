# certz convert -- Reference

Convert certificates between PEM, DER, and PFX formats with automatic input format detection.
Certificates are format-agnostic, but platforms are not. This command handles all the common
conversion paths without memorising complex flag combinations.

**See also:** [Certificate Formats](../concepts/certificate-formats.md)

---

## Simplified Syntax

```
certz convert <input> --to <format> [options]
```

| Argument / Option | Description |
|-------------------|-------------|
| `<input>` | Input certificate file. Format is auto-detected. |
| `--to, -t` | Target format: `pem`, `der`, or `pfx` (required). |
| `--output, -o` | Output file path. Default: same directory as input, new extension. |
| `--key` | Private key file. Required when converting to PFX if the input has no embedded key. |
| `--password, -p` | Password for PFX input or output. |
| `--password-file` | Read the PFX password from a file (avoids shell history exposure). |
| `--pfx-encryption` | PFX encryption mode: `modern` (default, AES-256-CBC) or `legacy` (3DES). |
| `--include-key` | Whether to extract the private key alongside the certificate (default: `true`). |
| `--format` | Output format: `text` (default) or `json`. |

---

## Format Auto-Detection

certz determines the input format from the file extension first, then falls back to reading the
file content for ambiguous extensions.

| Extension | Detected format |
|-----------|-----------------|
| `.pfx`, `.p12` | PFX (PKCS#12) |
| `.der` | DER (binary ASN.1) |
| `.pem` | PEM (Base64 text) |
| `.crt`, `.cer` | Auto-detect from file content |
| `.key` | Auto-detect from file content |

Content detection rules:
- File starts with `-----BEGIN` -> PEM
- File is binary and parses as PKCS#12 -> PFX
- File is binary but not PKCS#12 -> DER

---

## Output File Naming

When `--output` is not specified, the output file is placed in the same directory as the input
with a new extension:

| Input | `--to` | Default output |
|-------|--------|----------------|
| `server.pfx` | `pem` | `server.pem` + `server.key` |
| `server.pem` | `pfx` | `server.pfx` |
| `server.pem` | `der` | `server.der` |
| `server.der` | `pem` | `server.pem` |
| `server.der` | `pfx` | `server.pfx` |
| `server.pfx` | `der` | `server.der` |

When converting to PEM and a private key is extracted, the key is written to a separate `.key`
file next to the certificate file.

---

## Conversion Examples

### PFX to PEM

Extracts the certificate and private key into separate files:

```bash
certz convert server.pfx --to pem --password secret
# Creates: server.pem, server.key

certz convert server.pfx --to pem --password secret --output /certs/server.pem
# Creates: /certs/server.pem, /certs/server.key

# Certificate only, no key file
certz convert server.pfx --to pem --password secret --include-key:false
```

### PEM to PFX

```bash
# Auto-discovers server.key in the same directory
certz convert server.pem --to pfx

# Explicit key file
certz convert server.pem --to pfx --key private.key --password MyPass

# Auto-generated password (printed to console)
certz convert server.pem --to pfx --key private.key
```

### PEM to DER

```bash
certz convert server.pem --to der
# Creates: server.der

certz convert server.pem --to der --output /tmp/server-binary.der
```

### DER to PEM

```bash
certz convert server.der --to pem
# Creates: server.pem

certz convert server.der --to pem --output decoded.pem
```

### PFX to DER

```bash
certz convert server.pfx --to der --password secret
# Creates: server.der (certificate only, no key)
```

### DER to PFX

DER files do not contain a private key, so `--key` is required:

```bash
certz convert server.der --to pfx --key server.key --password NewPass
# Creates: server.pfx
```

### Certificate-only extraction

Omit the key from PFX output when you only need the public certificate:

```bash
certz convert server.pfx --to pem --password secret --include-key:false
```

---

## PFX Encryption

When certz produces a PFX file, it encrypts it with AES-256-CBC by default (modern PKCS#12
encryption introduced in RFC 9579). Use `--pfx-encryption legacy` when the target system cannot
read AES-256 PFX files.

| Mode | Algorithm | When to use |
|------|-----------|-------------|
| `modern` (default) | AES-256-CBC, HMAC-SHA256, 100 000 iterations | All modern platforms |
| `legacy` | 3DES (RC2-40 outer, SHA-1 HMAC) | Older Java (pre-JDK 8u301), some legacy Windows APIs |

```bash
# Default: modern encryption
certz convert cert.pem --to pfx --key cert.key

# Legacy 3DES for old Java versions
certz convert cert.pem --to pfx --key cert.key --pfx-encryption legacy
```

> **Why modern?** Java's default `keytool` now reads AES-256 PFX. The legacy flag exists only for
> environments that pre-date that support.

---

## Legacy Syntax

The original flag-based syntax is still supported for backwards compatibility:

```bash
# PEM + KEY -> PFX
certz convert --cert certificate.crt --key private.key --file output.pfx --password MyPass

# PFX -> PEM files
certz convert --file devcert.pfx --password YourPass --out-cert certificate.cer --out-key private.key
```

---

## Platform Deployment Matrix

For each platform, the table shows the required certificate format, the certz command that
produces it, and any steps needed after the conversion.

| Platform | Required format | certz command | Post-certz notes |
|----------|-----------------|---------------|-----------------|
| **IIS** | PFX (`.pfx`) | `certz convert cert.pem --to pfx --key cert.key` | Import via IIS Manager or `certutil -importpfx` |
| **nginx** | PEM cert + PEM key (separate files) | `certz convert cert.pfx --to pem --password pass` | Set `ssl_certificate` and `ssl_certificate_key` in `nginx.conf` |
| **Apache httpd** | PEM cert + PEM key (separate files) | `certz convert cert.pfx --to pem --password pass` | Set `SSLCertificateFile` and `SSLCertificateKeyFile` |
| **Tomcat (Java)** | PFX / PKCS#12 | `certz convert cert.pem --to pfx --key cert.key` | Reference with `certificateKeystoreFile` in `<SSLHostConfig>` |
| **Java keytool / JKS** | PFX first, then keytool | `certz convert cert.pem --to pfx` then `keytool -importkeystore` | See JKS note below |
| **Kubernetes TLS Secret** | PEM cert + PEM key | `certz create dev app.local --pipe \| kubectl create secret tls ...` | Pipe mode avoids intermediate files |
| **macOS Keychain** | PFX (`.p12`) | `certz convert cert.pem --to pfx --key cert.key` | Double-click `.p12` or use `security import cert.p12` |
| **Azure App Service** | PFX | `certz convert cert.pem --to pfx --key cert.key` | Upload via Azure portal or `az webapp config ssl upload` |
| **HAProxy** | PEM cert + key concatenated | `certz convert cert.pfx --to pem` then `cat cert.pem cert.key > combined.pem` | Point HAProxy `bind` directive at `combined.pem` |

### JKS note

Java KeyStore (`.jks`) is not a direct certz output target. Convert to PFX first, then use
`keytool` to import:

```bash
# Step 1: convert to PFX
certz convert cert.pem --to pfx --key cert.key --output cert.pfx --password mypass

# Step 2: import into JKS with keytool (bundled with every JDK)
keytool -importkeystore \
  -srckeystore cert.pfx -srcstoretype PKCS12 -srcstorepass mypass \
  -destkeystore keystore.jks -deststoretype JKS -deststorepass changeit
```

---

## JSON Output Schema

Use `--format json` to get machine-readable output suitable for CI/CD pipelines.

```bash
certz convert server.pem --to pfx --key server.key --format json
```

Example output:

```json
{
  "success": true,
  "subject": "CN=server.local",
  "outputFormat": "PFX",
  "outputFile": "server.pfx",
  "additionalOutputFiles": null,
  "inputCertificate": "/path/to/server.pem",
  "inputKey": "/path/to/server.key",
  "inputPfx": null,
  "generatedPassword": "Xk9!mP2rLq",
  "passwordWasGenerated": true
}
```

Field descriptions:

| Field | Type | Description |
|-------|------|-------------|
| `success` | bool | `true` if conversion succeeded |
| `subject` | string | Subject DN from the converted certificate |
| `outputFormat` | string | `"PEM"`, `"DER"`, or `"PFX"` |
| `outputFile` | string | Path to the primary output file |
| `additionalOutputFiles` | string[] or null | Additional files produced (e.g. `.key` alongside `.pem`) |
| `inputCertificate` | string or null | Source PEM/DER file path, if applicable |
| `inputKey` | string or null | Source key file path, if applicable |
| `inputPfx` | string or null | Source PFX file path, if applicable |
| `generatedPassword` | string or null | Auto-generated PFX password, if no password was supplied |
| `passwordWasGenerated` | bool | `true` if certz generated the password |

---

## Troubleshooting

| Problem | Likely cause | Fix |
|---------|--------------|-----|
| "Wrong password" on PFX input | Incorrect `--password` value | Verify the password with `certz inspect cert.pfx --password ...` first |
| "Private key not found" | PEM to PFX conversion with no key available | Add `--key private.key`; or ensure `<name>.key` is in the same directory |
| "Legacy Java cannot read PFX" | Java version predates AES-256 PKCS#12 support | Add `--pfx-encryption legacy` to produce a 3DES-encrypted PFX |
| "Output file already exists" | Auto-named output collides with an existing file | Use `--output` to specify a distinct path |
| "Unable to detect format" | Ambiguous extension with unexpected content | Rename the file with the correct extension (`.pem`, `.der`, `.pfx`) |
| Input and output format are the same | `--to` value matches the detected input format | No conversion needed; if in doubt, run `certz inspect <file>` to confirm the format |
