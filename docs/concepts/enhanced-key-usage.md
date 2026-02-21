# Enhanced Key Usage

A certificate's public key is mathematically capable of being used for many different operations. Enhanced Key Usage (EKU) is an X.509 extension that locks a certificate to specific, declared operations. A certificate issued for HTTPS cannot be used for code signing, even if the key is technically capable of it. This page explains what EKU restricts, what certz sets by default, and what happens when there is a mismatch.

## What EKU restricts

The EKU extension holds a list of Object Identifiers (OIDs), each representing a permitted use. Clients — browsers, TLS stacks, operating systems — check this list before accepting a certificate for a given purpose.

If the certificate's EKU does not include the OID for the intended use, the client rejects it, even if the cryptographic signature is valid. The error message varies by client but typically says something like "certificate is not authorized for this purpose" or "key usage mismatch."

## Common EKU OIDs

| OID | Short name | Use case |
|-----|-----------|---------|
| 1.3.6.1.5.5.7.3.1 | Server Authentication | TLS server certificates (HTTPS) |
| 1.3.6.1.5.5.7.3.2 | Client Authentication | mTLS, VPN clients, smart cards |
| 1.3.6.1.5.5.7.3.3 | Code Signing | Signing executables, scripts, packages |
| 1.3.6.1.5.5.7.3.4 | Email Protection | S/MIME encrypted or signed email |
| 1.3.6.1.5.5.7.3.8 | Time Stamping | RFC 3161 timestamp authority |
| 1.3.6.1.5.5.7.3.9 | OCSP Signing | Online Certificate Status Protocol responders |
| 2.5.29.37.0 | Any Extended Key Usage | No restriction; used mainly by root CAs |

EKU is separate from Key Usage (KU), which covers lower-level operations like `digitalSignature`, `keyEncipherment`, and `keyCertSign`. Both extensions may be present. For TLS, a server certificate typically has:
- Key Usage: `digitalSignature`, `keyEncipherment` (or `keyAgreement` for ECDSA)
- Extended Key Usage: `serverAuth`

## What certz sets by default

`certz create dev` generates leaf certificates with **Server Authentication** EKU. This is the correct setting for all HTTPS development certificates.

`certz create ca` generates CA certificates without leaf EKU extensions. CA certificates use `keyCertSign` and `cRLSign` Key Usage flags instead; they are not meant to be presented directly to TLS clients.

You can verify the EKU on any certificate:

```
certz inspect --file api.local.crt

Enhanced Key Usage:
  Server Authentication (1.3.6.1.5.5.7.3.1)
```

## Why mismatched EKU causes errors

When a certificate has the wrong EKU, the error surface depends on which client encounters it:

**Chrome / Edge:** "Your connection is not private" with error code `ERR_SSL_SERVER_CERT_BAD_FORMAT` or `NET::ERR_CERT_INVALID`

**Firefox:** "SEC_ERROR_INADEQUATE_CERT_TYPE" — usually shown as a broken lock icon with an explanation in the certificate viewer

**curl:** `SSL certificate problem: certificate is not conforming to the requirements`

**Windows Schannel (IIS, .NET):** `The certificate's key usage extensions indicate that it cannot be used to authenticate you to this server`

These errors all mean the certificate's EKU does not match what the client expected. The fix is to regenerate the certificate with the correct EKU.

## EKU and certz

certz sets EKU based on the certificate type and any `--eku` flags you provide:

- `create dev` defaults to Server Authentication. Use `--eku` to change or extend this.
- `create ca` does not set leaf EKU extensions. CA certificates use `keyCertSign` and `cRLSign` Key Usage flags instead.

### Controlling EKU with --eku

The `--eku` option on `certz create dev` accepts friendly names and can be repeated:

```bash
# Client authentication only (mTLS, VPN)
certz create dev client.local --eku clientAuth --file client.pfx

# Dual-purpose: HTTPS server and mTLS client in one cert
certz create dev mtls.local --eku serverAuth --eku clientAuth --file mtls.pfx
```

Accepted values:

| Value | OID | Use case |
|-------|-----|---------|
| `serverAuth` | 1.3.6.1.5.5.7.3.1 | TLS server (default) |
| `clientAuth` | 1.3.6.1.5.5.7.3.2 | mTLS client, VPN |
| `codeSigning` | 1.3.6.1.5.5.7.3.3 | Signing executables or scripts |
| `emailProtection` | 1.3.6.1.5.5.7.3.4 | S/MIME email |

When `--eku` is omitted, `serverAuth` is used automatically, preserving the existing default behaviour.

For cross-referencing certificate purpose against the full inspect output, see [inspect.md](../reference/inspect.md).

[← Back to concepts](README.md)
