# Windows Trust Store

When your browser navigates to an HTTPS site, Windows silently checks whether the certificate's issuing CA is in a list of trusted authorities. That list is the Windows Certificate Store. This page explains how the store is structured, what certz reads and writes, and the security risks of adding your own CAs.

## What a trust store is

A trust store is the set of Certificate Authority certificates that your operating system and applications treat as unconditionally trustworthy. If a CA certificate is in the Root store, then any certificate signed by that CA — for any domain, for any purpose — is automatically trusted.

This is powerful and dangerous. A CA in your Root store can issue a certificate for `api.github.com` or `login.microsoftonline.com`, and your browser will accept it without complaint. That is why operating system vendors control which CAs ship in the default trust store, and why adding a CA yourself requires deliberate action.

For local development, adding your own CA to the Root store is the correct approach: it lets you issue `localhost` certificates that your browser trusts exactly like a production certificate.

## Store names

Windows organizes certificates into named logical stores. Each store holds certificates of a specific type and is accessed by applications for specific purposes.

| Store name | Display name | Purpose |
|------------|-------------|---------|
| `Root` | Trusted Root Certification Authorities | Root CAs that are unconditionally trusted |
| `CA` | Intermediate Certification Authorities | Intermediate CAs used to build chains |
| `My` | Personal | Certificates with associated private keys |
| `TrustedPeople` | Trusted People | Self-signed certificates from known individuals |
| `TrustedPublisher` | Trusted Publishers | Certificates for code-signed software |
| `Disallowed` | Untrusted Certificates | Explicitly blocked certificates |

For certz operations, the relevant stores are:

- **Root** — where `certz trust add` places CA certificates and where the `--trust` flag writes during `create dev`
- **My** — where installed certificates with private keys are stored (used by `certz install`)
- **CA** — where intermediate CAs are placed when building multi-level PKI

## CurrentUser vs LocalMachine

Each store exists in two scopes:

| Scope | Registry location | Who can write | Visible to |
|-------|------------------|--------------|-----------|
| `CurrentUser` | `HKCU\SOFTWARE\Microsoft\SystemCertificates` | Any user | Only the current user |
| `LocalMachine` | `HKLM\SOFTWARE\Microsoft\SystemCertificates` | Administrator only | All users on the machine |

**CurrentUser** is safe for developer workflows. Certificates you add here are trusted only by your own Windows session. Other users on the same machine are unaffected, and administrative elevation is not required.

**LocalMachine** is appropriate for team development environments, CI/CD build agents, and server deployments where you need the certificate to be trusted by all users and services running on the machine. Writing to LocalMachine requires an elevated (Administrator) process.

Certz defaults to **CurrentUser** for `trust add` and the `--trust` flag on `create dev`. Pass `--machine` to write to LocalMachine instead (requires elevation):

```
certz trust add --file ca.crt              # CurrentUser Root store
certz trust add --file ca.crt --machine    # LocalMachine Root store (requires admin)
certz create dev --cn dev.local --trust    # CurrentUser Root store
```

## How certz interacts with the store

| Command | What it does | Store | Scope |
|---------|-------------|-------|-------|
| `certz trust add --file ca.crt` | Adds CA certificate to Root | Root | CurrentUser |
| `certz trust add --file ca.crt --machine` | Adds CA certificate to Root | Root | LocalMachine |
| `certz trust remove --thumbprint <hash>` | Removes certificate by thumbprint | Root | CurrentUser |
| `certz trust list` | Lists certificates in Root store | Root | CurrentUser |
| `certz install --file cert.pfx` | Installs cert+key | My | CurrentUser |
| `certz store list` | Lists all personal certificates | My | CurrentUser |
| `certz create dev --trust` | Creates cert and adds issuing CA | Root + My | CurrentUser |

## Security risk of adding a Root CA

When you add a certificate to the Root store, you are making a trust decision with wide consequences. Specifically:

**Any certificate signed by that CA will be trusted — including certificates for any domain.**

This is the correct behavior for a CA you control. It is a significant risk if you add a CA you do not control, or if a CA's private key is ever compromised.

Practical guidelines for certz-generated CAs:

- Generate CA private keys on the machine that will use them. Do not share CA keys across machines.
- Store CA PFX files in a location only you can read. Treat the PFX password as a secret.
- Remove the CA from the trust store with `certz trust remove` when you no longer need it.
- Never use a development CA certificate in a production environment.

## Viewing the store outside certz

If you want to inspect or manage the store without certz:

- **MMC snap-in**: Run `mmc`, add the "Certificates" snap-in, choose user or computer account
- **certmgr.msc**: Opens the Current User certificate manager directly
- **PowerShell**: `Get-ChildItem Cert:\CurrentUser\Root` or `Cert:\LocalMachine\Root`
- **certutil**: `certutil -store Root` for LocalMachine, `certutil -user -store Root` for CurrentUser

For certz-specific trust operations, see [trust.md](../reference/trust.md).

[← Back to concepts](README.md)
