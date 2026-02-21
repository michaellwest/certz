# Certificate Lifecycle

Certificates have a built-in expiration date, and managing that expiration is one of the most operationally important aspects of running TLS. This page covers how validity dates work, why there is a hard 398-day limit on public certificates, when to renew vs reissue, and what triggers each choice.

## Validity dates

Every certificate contains two dates:

- **NotBefore** — the earliest moment the certificate is valid
- **NotAfter** — the moment the certificate expires

Both are stored as UTC timestamps. A certificate presented before its NotBefore date or after its NotAfter date is rejected by TLS clients, even if every signature in the chain is valid.

Certz uses `DateTimeOffset.UtcNow` for all validity calculations, not local time. This matters because:

- A certificate generated at 11 PM Eastern Standard Time is generated at 4 AM UTC the following day
- If NotBefore is set to local midnight instead of UTC, the certificate may appear "not yet valid" to clients in other timezones for several hours
- Using UTC throughout eliminates this class of bug entirely

When certz reports expiry, it always reports in UTC. When you see a `certz inspect` output showing `Not After: 2025-06-15 00:00:00 UTC`, that is the actual expiration moment regardless of your local timezone.

## The 398-day limit

In September 2020, Apple announced that Safari would reject TLS certificates with a validity period longer than 398 days. Chrome and Firefox followed. This limit is now enforced by all major browsers and is codified in the CA/Browser Forum Baseline Requirements.

**Why 398 days, not 365?** The extra 33 days allows for certificate renewal overlap — you can renew up to a month before expiry, and the new certificate can cover the same NotBefore date as the old one without immediately expiring. 398 = 365 + 33.

**Why is shorter better?** Shorter-lived certificates limit the blast radius of a compromised private key. If a key is stolen and the certificate expires in 90 days, the attacker's window is at most 90 days. With a 2-year certificate, the window is 2 years. Shorter validity also forces more frequent renewal, which exercises automation and surfaces problems before they become emergencies.

Certz defaults to **90 days** for `create dev` certificates and **3650 days** (10 years) for `create ca` certificates. The CA limit is intentionally generous because CA certificates are managed separately and are not subject to the browser-enforced 398-day limit (that limit applies to leaf/TLS certificates).

`certz lint` fails on any leaf certificate exceeding 398 days:

```
certz lint --file old-cert.crt
[FAIL] Validity period exceeds 398 days (CA/B Forum Baseline Requirements)
       Issued: 2023-01-01, Expires: 2025-01-01, Duration: 730 days
```

Set a custom validity with `--days`:

```
certz create dev --cn api.local --days 90      # 90-day cert (default)
certz create dev --cn api.local --days 30      # 30-day cert for short-lived use
certz create ca  --cn "My Root CA" --days 3650 # 10-year CA (default)
```

## Development vs production validity

| Certificate type | Certz default | Typical range | Notes |
|-----------------|--------------|---------------|-------|
| `create dev` leaf | 90 days | 30-398 days | Subject to 398-day browser limit |
| `create ca` root | 3650 days (10 years) | 1-25 years | Not subject to leaf limit; manage separately |
| Production leaf | -- | 90 days | Let's Encrypt default; matches ACME standard |
| Production intermediate | -- | 1-3 years | Revocable independently of root |

Development certificates are usually set longer than production certificates to reduce friction — you do not want a localhost cert expiring in the middle of a sprint. 90 days is a reasonable balance between security habit and developer ergonomics.

## Renewal vs reissue

**Renewal** means extending the validity period of an existing certificate, typically reusing the same key pair. The certificate gets new NotBefore and NotAfter dates; everything else stays the same.

**Reissue** means generating a completely new key pair and a new certificate. This is a heavier operation but appropriate when the old key may have been compromised or when the algorithm needs to change (e.g., migrating from RSA to ECDSA).

| Situation | Renewal or reissue? |
|-----------|-------------------|
| Certificate is approaching expiry, key is secure | Renewal |
| Private key may have been exposed | Reissue (new key) |
| Moving from RSA to ECDSA | Reissue (new key) |
| Name change (new CN or SAN) | Reissue |
| Compliance change requiring shorter validity | Renewal may suffice |
| Routine rotation per policy | Either; many orgs use renewal for automation |

Certz implements renewal with `certz renew`:

```
certz renew --file api.local.pfx --days 90
```

By default, `certz renew` reuses the existing key pair. To force a new key (reissue):

```
certz renew --file api.local.pfx --days 90 --new-key
```

The `--keep-key` flag is the default and explicit form; `--new-key` forces key rotation.

## What triggers renewal

| Trigger | Action |
|---------|--------|
| Certificate expires soon | Renew before expiry; use `certz monitor` to track |
| Private key compromise | Reissue immediately with a new key |
| Algorithm deprecated (e.g., SHA-1 sunset) | Reissue with new algorithm |
| New SANs needed | Reissue (SANs are part of the certificate content) |
| CA certificate expires | Reissue all certificates signed by that CA after renewing the CA |
| Compliance change | Reissue or renew depending on what changed |

## Private key rotation

Reusing the same key on renewal is convenient but not always appropriate. Security-sensitive environments rotate keys on every renewal — new key, new cert — so that a past key compromise does not create a long-term window.

Trade-offs:

| Approach | Convenience | Security |
|----------|------------|---------|
| `--keep-key` (renewal) | Easier — no re-pinning, no key distribution | Key compromise window lasts until key is rotated |
| `--new-key` (reissue) | Requires updating any pinned certificates | Clean break; old key cannot be reused by attacker |

For development certificates, `--keep-key` is usually fine. For production certificates, follow your organization's key rotation policy; many organizations rotate annually regardless of the validity period.

See [monitor.md](../reference/monitor.md) for setting up expiry tracking and [renew.md](../reference/renew.md) for the full renewal command reference.

[← Back to concepts](README.md)
