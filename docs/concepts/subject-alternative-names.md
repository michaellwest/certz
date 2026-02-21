# Subject Alternative Names

A TLS certificate proves that a server owns a specific domain name or IP address. Until 2017, browsers accepted the Common Name (CN) field for this proof. Today, every major browser requires the proof to be in the Subject Alternative Name (SAN) extension instead. This page explains what SANs are, how certz handles them automatically, and what to do when you need to add more.

## Why the Common Name alone no longer works

The Common Name field was the original way to specify what a certificate covered. A cert for `api.example.com` would have `CN=api.example.com` in its subject, and browsers would match it.

The problem: CN is a free-text field with no standard parsing rules. Different implementations matched it differently, leading to security bugs — a CN value like `evil.com\x00.good.com` could fool some parsers into thinking the cert was for `good.com`.

The Subject Alternative Name extension was designed to replace CN for identity binding. It is a structured list with typed entries: DNS names, IP addresses, email addresses, URIs. The format is unambiguous and machine-parseable.

In 2017, Chrome 58 dropped CN-only validation. Firefox, Safari, and Edge followed. Today, a certificate without a SAN extension is rejected by all major browsers, regardless of what is in the CN.

`certz lint` will report `SAN required` if it finds a certificate without the extension:

```
certz lint --file mycert.crt
[FAIL] SAN required: certificate has no Subject Alternative Name extension
```

## What SANs are

The SAN extension holds a list of identities the certificate is valid for. Each entry has a type:

| Type | Example | Used for |
|------|---------|---------|
| DNS name | `example.com` | Domain name matching |
| IP address | `192.168.1.1` | Numeric IP matching |
| Email address | `admin@example.com` | S/MIME email certificates |
| URI | `https://example.com` | Specific URI-scoped certs |

For TLS server certificates, DNS names and IP addresses are the relevant types. A certificate can have as many SAN entries as needed.

## Wildcard SANs

A wildcard DNS SAN covers all direct subdomains of a domain:

```
DNS:*.example.com
```

This matches `api.example.com`, `www.example.com`, and `auth.example.com` — but **not** `example.com` itself (no root domain coverage) and **not** `deep.api.example.com` (only one subdomain level).

Some clients — notably older Java versions and certain embedded TLS stacks — do not support wildcard certificates. For maximum compatibility, list each subdomain explicitly.

## What certz auto-adds

When you run `certz create dev`, certz automatically adds SANs so the certificate works for local development without any extra flags:

```
certz create dev --cn api.local
```

This generates a certificate with:
- `DNS:api.local` (the CN value, promoted to SAN)
- `DNS:localhost`
- `IP:127.0.0.1`

You can verify this with `certz inspect`:

```
certz inspect --file api.local.crt

Subject Alternative Names:
  DNS: api.local
  DNS: localhost
  IP:  127.0.0.1
```

The automatic additions mean your certificate works whether the browser connects via the hostname, `localhost`, or the loopback IP — which covers the typical development workflow.

## Adding SANs manually

Use `--san` to add extra names. The flag can be repeated and accepts DNS names, IP addresses, and wildcards:

```
# Additional hostnames
certz create dev --cn api.local --san staging.local --san dev.local

# IP addresses
certz create dev --cn api.local --san 10.0.0.5 --san 10.0.0.6

# Wildcard subdomain
certz create dev --cn example.local --san "*.example.local"

# Mixed
certz create dev --cn myapp.local --san "*.myapp.local" --san 192.168.50.10
```

Certz detects the SAN type automatically: values that look like IP addresses (`x.x.x.x` or IPv6) are added as IP SANs; everything else is added as a DNS SAN.

## Lint enforcement

`certz lint` checks SANs against CA/Browser Forum Baseline Requirements:

| Check | Rule |
|-------|------|
| SAN extension present | Required for all TLS certificates |
| CN promoted to SAN | CN value must also appear in SAN |
| No bare IP as CN | IP addresses must be in SAN, not only CN |
| Wildcard covers only one level | `*.example.com` is valid; `*.*.example.com` is not |

Fix a missing SAN by regenerating the certificate with the `--san` flag or by relying on `create dev`'s automatic SAN addition.

See [lint.md](../reference/lint.md) for the full list of lint checks and [create.md](../reference/create.md) for all `--san` flag details.

[← Back to concepts](README.md)
