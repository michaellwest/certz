# Compliance Standards

Public TLS certificates are governed by two sets of rules: the CA/Browser Forum Baseline Requirements and the Mozilla Root Store Policy. These are not optional guidelines — major browsers refuse certificates that violate them. This page explains what each standard governs, the key rules you encounter in practice, and how `certz lint` maps to them.

## What the CA/Browser Forum is

The CA/Browser Forum (CA/B Forum) is an industry consortium of Certificate Authorities and browser vendors. Members include Mozilla, Apple, Google, Microsoft, DigiCert, Sectigo, Let's Encrypt, and others.

The Forum publishes the **Baseline Requirements (BR)**, a document that defines the minimum rules all publicly-trusted CAs must follow when issuing certificates. Browser vendors make compliance with the BR a condition for inclusion in their trust stores — if a CA violates the BR, the browser vendor can remove their root, which effectively makes the CA non-functional for public TLS.

The BR is updated regularly. The rules certz lint checks against reflect the requirements in effect as of the certz release date.

## CA/Browser Forum Baseline Requirements — key rules

| Rule | Requirement | Why it exists |
|------|-------------|--------------|
| Max validity | 398 days for leaf certs | Limits the window for compromised keys; forces regular renewal |
| SAN required | Leaf certs must have a Subject Alternative Name extension | CN-only validation was ambiguous and led to spoofing attacks |
| RSA minimum | RSA keys must be at least 2048 bits | 1024-bit RSA is computationally breakable with modern hardware |
| SHA-1 prohibited | Certificates must use SHA-2 or better for signatures | SHA-1 collision attacks were demonstrated in 2017 |
| Basic Constraints required | CA certs must have `CA=true`; leaf certs must have `CA=false` or omit it | Prevents leaf certs from signing other certificates |
| CN in SAN | If a CN is present, it must also appear as a SAN | Prevents CN/SAN mismatch confusion |
| No internal names | Publicly-trusted certs must not use internal hostnames (e.g., `MYSERVER`) | Internal names are not routable; public CAs should not vouch for them |

The 398-day limit and SHA-1 prohibition were controversial when introduced but are now universally enforced. Let's Encrypt's 90-day validity was ahead of its time; it is now considered best practice.

## Mozilla Root Store Policy

Mozilla maintains its own CA trust store policy, separate from but aligned with the CA/B Forum BR. The Mozilla Root Store Policy (MRSP) applies specifically to CAs whose roots are included in Firefox and other Mozilla products.

Key additional constraints from MRSP:

| Rule | Requirement |
|------|-------------|
| Root CA max validity | 25 years |
| Intermediate CA max validity | 10 years |
| Name Constraints recommended | CAs that only serve specific domains should constrain their certs to those domains |
| Annual audits required | CAs must submit to annual WebTrust or ETSI audits |
| Incident reporting | CAs must publicly disclose mis-issuance within 24 hours |

The MRSP applies to publicly-trusted CAs, not to privately-operated CAs like those you generate with `certz create ca`. Your certz-generated CA operates under no external policy; you are the policy authority.

## Development certificate policy

The BR rules apply to certificates issued by publicly-trusted CAs. They do not technically apply to certificates issued by your own local CA (which is not publicly trusted). However, `certz lint` still checks BR rules by default because:

1. **Good habit**: Certificates that comply with BR rules work everywhere, including in future environments where compliance is required.
2. **Browser enforcement**: Browsers enforce some BR rules locally, not just at the CA level. The 398-day limit, for example, is enforced by the browser regardless of whether the issuing CA is public or private.
3. **Portability**: A development certificate built to BR standards can be used as a template when ordering a production certificate from a public CA.

When you know a certificate is for local-only use and the violation is intentional, pass `--policy dev` to relax the BR checks:

```
certz lint --file myca.crt --policy dev
```

With `--policy dev`, the 398-day limit is not enforced, and CA-specific extensions are evaluated under relaxed rules. All other checks (SHA-2, RSA key size, SAN presence) still apply because browsers enforce those locally.

**Warning: never use a dev-policy certificate in production.** Browsers enforce the 398-day limit regardless of the CA's trust status. A 10-year development certificate would be rejected by Safari, Chrome, and Firefox in a production environment.

## How certz lint maps to these rules

`certz lint` runs a battery of checks against a certificate and reports findings. Each finding is labeled with the rule it comes from:

```
certz lint --file api.local.crt

[PASS] Key algorithm: ECDSA P-256 (strong)
[PASS] Signature algorithm: SHA-256 with ECDSA
[PASS] Subject Alternative Name extension present
[PASS] Validity period: 90 days (under 398-day limit)
[PASS] Basic Constraints: CA=false
[FAIL] CN not in SAN: CN=api.local is not listed in Subject Alternative Names
       Rule: CA/B Forum BR section 7.1.4.2
       Fix:  Regenerate with --san api.local or use certz create dev (auto-adds CN)
```

Each `[FAIL]` line includes the specific rule violated and a suggested fix. `[PASS]` lines confirm compliance.

The full set of checks and their rule references is documented in [lint.md](../reference/lint.md).

[← Back to concepts](README.md)
