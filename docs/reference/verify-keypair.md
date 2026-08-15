# certz verify-keypair -- Reference

Confirm that a private key matches a certificate (or CSR) by comparing their `SubjectPublicKeyInfo`.
Catches "wrong key for this cert" misconfigurations before deployment, in CI, or during rotation.
This is the algorithm-agnostic equivalent of `openssl x509 -modulus -in cert.pem | openssl md5` vs `openssl rsa -modulus -in key.pem | openssl md5` -- but it works uniformly for RSA and ECDSA in a single command.

**See also:**
[convert](convert.md) |
[fingerprint](fingerprint.md) |
[Exit Codes](exit-codes.md)

---

## Usage

```
certz verify-keypair --cert <file> --key <file> [--password <pwd>]
certz verify-keypair --csr  <file> --key <file>
certz verify-keypair --pfx  <file> --password <pwd>
```

Exactly one of these input modes is valid: `--cert + --key`, `--csr + --key`, or `--pfx + --password`.

---

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `--cert <file>` | _(none)_ | Certificate file (PEM, DER, .crt, .cer) |
| `--csr <file>` | _(none)_ | CSR file (PEM) -- alternative to `--cert` |
| `--key <file>` | _(none)_ | Private key file (PEM, PKCS#1 or PKCS#8) |
| `--pfx <file>` | _(none)_ | PFX/PKCS#12 file -- self-checks the embedded cert against its embedded key |
| `--password`, `--pass`, `-p` | _(none)_ | Password for the PFX, or for an encrypted PEM key |
| `--format`, `--fmt` | `text` | Output format: `text` or `json` |

`--cert`, `--csr`, and `--pfx` are mutually exclusive.

---

## Examples

```bash
# Cert + key on disk
certz verify-keypair --cert server.pem --key server.key

# Self-check a PFX bundle
certz verify-keypair --pfx server.pfx --password MyPass

# Confirm a CSR was generated with a particular key
certz verify-keypair --csr request.csr --key server.key

# Encrypted PEM key
certz verify-keypair --cert server.pem --key encrypted.key --password KeyPass

# JSON output for CI / scripting
certz verify-keypair --cert server.pem --key server.key --format json
```

---

## Text output (match)

```
Keypair matches
  Match:                    YES
  Subject:                  CN=api.example.com
  Certificate:              server.pem
  Private key:              server.key
  Algorithm:                ECDSA P-256 (256-bit)
  Cert public key SHA-256:  sha256:7f3a8c...
  Key  public key SHA-256:  sha256:7f3a8c...
```

## Text output (mismatch)

```
Keypair MISMATCH
  Match:                    NO
  ...
  Cert public key SHA-256:  sha256:7f3a8c...
  Key  public key SHA-256:  sha256:9b2d44...

The cert and key do not pair. Do not deploy this combination.
```

## JSON output

```json
{
  "success": true,
  "match": false,
  "certSource": "server.pem",
  "keySource": "server.key",
  "subject": "CN=api.example.com",
  "algorithm": "RSA",
  "keySize": 2048,
  "certPublicKeyHash": "sha256:7f3a8c...",
  "keyPublicKeyHash": "sha256:9b2d44..."
}
```

`success` is `true` whenever the comparison ran cleanly, regardless of the result. Use `match` (or the exit code) to branch in CI.

---

## How the comparison works

certz exports the `SubjectPublicKeyInfo` (SPKI) bytes from each input and compares them as raw bytes. SPKI is the canonical, algorithm-agnostic encoding of a public key, so a single code path covers RSA and ECDSA. The SHA-256 of each SPKI is shown so a human can spot which side is wrong at a glance.

For a PFX self-check, the cert's `SubjectPublicKeyInfo` is compared against the SPKI derived from the embedded private key.

---

## Comparison with OpenSSL

| OpenSSL | certz equivalent |
|---------|-----------------|
| `openssl x509 -modulus -in cert.pem \| openssl md5` + `openssl rsa -modulus -in key.pem \| openssl md5` | `certz verify-keypair --cert cert.pem --key key.pem` |
| `openssl pkcs12 -in bundle.pfx -nodes -passin pass:P` then eyeballing the result | `certz verify-keypair --pfx bundle.pfx --password P` |

`-modulus` only covers RSA. certz handles both RSA and ECDSA without a separate code path.

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Cert and key match |
| `1` | Cert and key do **not** match (the result block is still printed for inspection) |
| `1` | Bad input: missing file, unreadable format, wrong password |

In a CI pipeline, treat any non-zero exit as a failure and surface the JSON `match` field for diagnostics.

---

## Supported algorithms

- RSA (any key size)
- ECDSA on P-256, P-384, P-521

Ed25519 is not currently supported (no future-key change is planned until .NET surfaces stable APIs for it across all the relevant operations).
