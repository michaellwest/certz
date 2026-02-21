# RSA vs ECDSA

Every certificate has a public key, and that key was generated using a specific algorithm. The algorithm you choose determines the certificate's security level, its performance under load, how large the key material is, and which clients can use it. This page explains the two mainstream choices — RSA and ECDSA — so you understand certz's defaults and know when to override them.

## Why your key type matters

The key algorithm is not a cosmetic choice. It affects:

- **Security**: How hard it is to break the key mathematically
- **Performance**: How fast a TLS handshake completes, especially under high concurrency
- **File size**: Smaller keys mean smaller certificates and faster network transfers
- **Compatibility**: Some older clients cannot negotiate ECDSA; most modern ones can

certz defaults to ECDSA P-256 for all new certificates. If you are targeting a legacy environment that cannot handle ECDSA, you can switch to RSA with `--key-type RSA`.

## RSA

RSA security rests on the mathematical difficulty of factoring the product of two large prime numbers. The larger the key, the harder it is to factor — but also the slower every signature and verification operation becomes.

Key sizes in common use:

| Key size | Security level | Status |
|----------|---------------|--------|
| 1024 bits | ~80-bit | Broken — do not use |
| 2048 bits | ~112-bit | Minimum acceptable; legacy use only |
| 3072 bits | ~128-bit | **certz default for RSA** |
| 4096 bits | ~140-bit | Maximum practical; significant performance cost |

The CA/Browser Forum Baseline Requirements prohibit RSA keys smaller than 2048 bits. certz enforces this and will refuse to generate a key below that limit. When you request RSA without specifying a size, certz uses 3072 bits because it matches ECDSA P-256's 128-bit security level without the legacy-breaking behavior of jumping straight to 4096.

## ECDSA

ECDSA (Elliptic Curve Digital Signature Algorithm) derives security from the difficulty of the elliptic curve discrete logarithm problem. The key insight is that equivalent security is achieved with a much smaller key than RSA.

Certz supports three named curves:

| Curve | Key size | Security level | Notes |
|-------|----------|---------------|-------|
| P-256 | 256 bits | ~128-bit | **certz default** — universal browser support |
| P-384 | 384 bits | ~192-bit | Used by some government and high-assurance PKI |
| P-521 | 521 bits | ~256-bit | Maximum NIST curve; rarely needed in practice |

ECDSA signatures are also faster to generate and verify than RSA at equivalent security levels, which matters when a server handles thousands of TLS handshakes per second.

## Comparison at the same security level

| Property | RSA 3072 | ECDSA P-256 |
|----------|----------|-------------|
| Security level | ~128-bit | ~128-bit |
| Key size | 3072 bits | 256 bits |
| Certificate size | Larger | Smaller |
| Handshake time | Slower | Faster |
| Browser compatibility | Universal | 99%+ modern browsers |
| Certz default? | No | Yes |
| Use `--key-type` flag | `RSA` | `ECDSA-P256` (default) |

## Ed25519

Ed25519 is a modern elliptic curve algorithm based on Curve25519. It offers excellent performance and a cleaner implementation than the NIST P-curves, and it is gaining adoption in newer protocols. Certz does not currently support Ed25519 because .NET's X.509 certificate generation pipeline does not fully support it for TLS use cases. Support may be added in a future release.

## Certz flags

```
certz create dev --cn api.local --key-type ECDSA-P256    # default, usually omit
certz create dev --cn api.local --key-type ECDSA-P384    # higher assurance
certz create dev --cn api.local --key-type RSA           # legacy compat; uses 3072-bit
certz create dev --cn api.local --key-type RSA --key-size 4096  # explicit RSA size
```

Valid `--key-type` values: `ECDSA-P256`, `ECDSA-P384`, `ECDSA-P521`, `RSA`

Valid `--key-size` values (RSA only): `2048`, `3072`, `4096`

**When to override the default:**

- Stick with `ECDSA-P256` for all new development and production certificates
- Use `RSA 3072` only if a specific client or tool explicitly cannot negotiate ECDSA (this is rare in 2025 — browsers, nginx, Apache, and IIS all support ECDSA)
- Use `ECDSA-P384` if your organization's security policy requires it (e.g., government PKI, FIPS 140-3 environments)
- Never use `RSA 2048` for new certificates; it meets the minimum but is not future-proof

See [create.md](../reference/create.md) for the full set of `create dev` and `create ca` options.

[← Back to concepts](README.md)
