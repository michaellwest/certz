# certz create — Reference

Create X.509 certificates for local development or as a Certificate Authority. Defaults to ECDSA P-256 keys and 90-day validity.

**See also:** [RSA vs ECDSA](../concepts/rsa-vs-ecdsa.md) · [Subject Alternative Names](../concepts/subject-alternative-names.md) · [Certificate Lifecycle](../concepts/certificate-lifecycle.md) · [Certificate Chain](../concepts/certificate-chain.md)

---

## Development Certificates

Create certificates for local development with modern defaults (ECDSA P-256, 90 days).

```bash
# Basic: Create certificate for localhost
certz create dev localhost

# With custom domain and auto-trust
certz create dev api.local --trust

# With additional Subject Alternative Names
certz create dev myapp.local --san "*.myapp.local" --san "127.0.0.1"

# Signed by your own CA
certz create dev api.local --issuer-cert ca.pfx --issuer-password CaPassword

# Interactive wizard mode
certz create dev localhost --guided

# Output to specific files
certz create dev localhost --file server.pfx --cert server.cer --key server.key
```

**Options:**

| Option | Description |
|--------|-------------|
| `--trust` | Install to Root trust store after creation |
| `--trust-location` | CurrentUser (default) or LocalMachine |
| `--san <name>` | Additional Subject Alternative Names (repeatable) |
| `--days <n>` | Validity period (default: 90, max: 398) |
| `--key-type` | ECDSA-P256 (default), ECDSA-P384, ECDSA-P521, RSA |
| `--key-size` | RSA key size: 2048, 3072 (default), 4096 |
| `--guided` | Launch interactive wizard |
| `--issuer-cert` | Sign with existing CA (PFX or PEM) |
| `--issuer-key` | CA private key (for PEM issuer) |
| `--issuer-password` | Password for CA PFX |
| `--file` | Output PFX filename |
| `--cert` | Output certificate filename |
| `--key` | Output private key filename |
| `--password` | PFX password (auto-generated if not provided) |
| `--password-file` | File to write the generated password to |
| `--ephemeral, -e` | Generate certificate in memory only |
| `--pipe` | Stream certificate to stdout |
| `--pipe-format` | Pipe output format: pem, pfx, cert, key |
| `--pipe-password` | Password for PFX pipe output |

---

## CA Certificates

Create Certificate Authority certificates for signing other certificates.

```bash
# Create a Root CA
certz create ca --name "Development Root CA"

# Create and trust the CA
certz create ca --name "Dev CA" --trust

# With specific validity and path length
certz create ca --name "My CA" --days 3650 --path-length 1

# With CRL and OCSP URLs
certz create ca --name "My CA" --crl-url http://crl.example.com/ca.crl --ocsp-url http://ocsp.example.com

# Interactive wizard mode
certz create ca --guided
```

**Options:**

| Option | Description |
|--------|-------------|
| `--name` | CA Common Name (required) |
| `--trust` | Install to Root trust store |
| `--days <n>` | Validity period (default: 3650 / ~10 years) |
| `--path-length <n>` | Maximum chain depth (-1 = unlimited) |
| `--crl-url` | CRL Distribution Point URL |
| `--ocsp-url` | OCSP responder URL |
| `--password` | PFX password (auto-generated if not provided) |
| `--password-file` | File to write the generated password to |
| `--guided` | Launch interactive wizard |
| `--ephemeral, -e` | Generate certificate in memory only (no files written) |
| `--pipe` | Stream certificate to stdout (no files written) |
| `--pipe-format` | Pipe output format: pem (default), pfx, cert, key |
| `--pipe-password` | Password for PFX pipe output |

---

## Ephemeral Mode

Generate certificates in memory without writing files to disk:

```bash
# Create ephemeral certificate (displays details, no files)
certz create dev example.com --ephemeral

# Ephemeral with custom options
certz create dev app.local --ephemeral --san "*.app.local" --key-type RSA

# Ephemeral CA certificate
certz create ca --name "Test CA" --ephemeral

# JSON output for scripting
certz create dev test.local --ephemeral --format json
```

**Use cases:**

- Testing certificate settings before committing to files
- CI/CD pipelines without cleanup requirements
- Security-sensitive environments (keys never touch disk)
- Training and demonstrations

---

## Pipe Mode

Stream certificate content to stdout for piping to other tools:

```bash
# Pipe full PEM (cert + key) to stdout
certz create dev example.com --pipe

# Pipe to kubectl to create Kubernetes secret
certz create dev app.local --pipe | kubectl create secret tls my-cert --cert=/dev/stdin --key=/dev/stdin

# Pipe certificate only (no private key)
certz create dev example.com --pipe --pipe-format cert

# Pipe private key only
certz create dev example.com --pipe --pipe-format key

# Pipe as base64 PFX with specified password
certz create dev example.com --pipe --pipe-format pfx --pipe-password "MySecret"

# Pipe PFX with auto-generated password (password written to stderr)
certz create dev example.com --pipe --pipe-format pfx 2>password.txt > cert.b64
```

**Pipe Formats:**

| Format | Output |
|--------|--------|
| `pem` (default) | Certificate + private key in PEM format |
| `pfx` | Base64-encoded PFX (password required or auto-generated to stderr) |
| `cert` | Certificate only (PEM format) |
| `key` | Private key only (PEM format) |

---

## Restrictions

Both `--ephemeral` and `--pipe` are mutually exclusive with:

- `--file`, `--cert`, `--key` (file output options)
- `--trust` (cannot install in-memory certificate)
- `--password-file` (no file to protect)

You cannot use both `--ephemeral` and `--pipe` together.
