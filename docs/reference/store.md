# certz store list -- Reference

List and filter certificates in the Windows certificate store. Useful for auditing what
is installed, locating thumbprints for use with other commands, and finding certificates
that are expiring or have already expired.

**See also:**
[Windows Trust Store](../concepts/windows-trust-store.md) |
[certz trust](trust.md) |
[certz monitor](monitor.md) |
[Exit Codes](exit-codes.md)

---

## Examples

### By store name

```bash
# List personal certificates (My store -- default)
certz store list

# List trusted Root CAs
certz store list --store Root

# List intermediate CAs
certz store list --store CA

# List trusted people
certz store list --store TrustedPeople
```

### By location

```bash
# CurrentUser (default)
certz store list --store Root --location CurrentUser

# LocalMachine (requires Administrator for full read access)
certz store list --store Root --location LocalMachine
```

### Filter by expiration

```bash
# Show only certificates that have already expired
certz store list --expired

# Show certificates expiring within 30 days
certz store list --expiring 30

# Expired from a specific store
certz store list --store Root --expired

# Expiring within 90 days, machine-wide
certz store list --store My --location LocalMachine --expiring 90
```

### JSON output for scripting

```bash
certz store list --format json
certz store list --store Root --location LocalMachine --format json
certz store list --expiring 30 --format json
```

---

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `--store, -s` | `My` | Store name: `My`, `Root`, `CA`, `TrustedPeople`, `TrustedPublisher` |
| `--location, -l` | `CurrentUser` | Store location: `CurrentUser` or `LocalMachine` |
| `--expired` | `false` | Show only certificates that have already expired |
| `--expiring <days>` | (none) | Show only certificates expiring within N days |
| `--format` | `text` | Output format: `text` or `json` |

---

## Store Names Reference

| Store | Typical contents |
|-------|-----------------|
| `My` | Personal certificates with private keys (used for TLS, code signing, authentication) |
| `Root` | Trusted Root CA certificates (self-signed) |
| `CA` | Intermediate CA certificates |
| `TrustedPeople` | Certificates trusted on a peer-to-peer basis |
| `TrustedPublisher` | Certificates for software publishers trusted for code signing |

---

## Example Output

**Text format:**

```
Store: CurrentUser\My  (4 certificates)

+------------------------------------------+-----------------+------------+------+
| Thumbprint                               | Subject         | Expires    | Days |
+------------------------------------------+-----------------+------------+------+
| A1B2C3D4E5F678901234567890ABCDEF12345678 | CN=api.local    | 2026-01-23 |   64 |
| B2C3D4E5F6789012345678901234567890ABCDE1 | CN=dev.local    | 2025-11-01 |   -1 |
| C3D4E5F678901234567890ABCDEF1234567890AB | CN=test.local   | 2026-06-15 |  208 |
+------------------------------------------+-----------------+------------+------+
```

Expired certificates are highlighted and shown with negative `Days` values.

Use `--expired` to show only expired rows. Use `--expiring 30` to show only rows where
`Days` is between 0 and 30 (inclusive).

---

## JSON Output Schema

```bash
certz store list --format json
```

Example output:

```json
{
  "storeName": "My",
  "storeLocation": "CurrentUser",
  "totalCount": 4,
  "filteredCount": 3,
  "certificates": [
    {
      "subject": "CN=api.local",
      "issuer": "CN=api.local",
      "thumbprint": "A1B2C3D4E5F678901234567890ABCDEF12345678",
      "notBefore": "2025-10-26T00:00:00",
      "notAfter": "2026-01-23T00:00:00",
      "daysRemaining": 64,
      "isExpired": false,
      "hasPrivateKey": true,
      "isCa": false
    },
    {
      "subject": "CN=dev.local",
      "issuer": "CN=dev.local",
      "thumbprint": "B2C3D4E5F6789012345678901234567890ABCDE1",
      "notBefore": "2024-11-01T00:00:00",
      "notAfter": "2025-11-01T00:00:00",
      "daysRemaining": -81,
      "isExpired": true,
      "hasPrivateKey": true,
      "isCa": false
    }
  ]
}
```

Top-level fields:

| Field | Type | Description |
|-------|------|-------------|
| `storeName` | string | The store name queried (e.g., `"My"`, `"Root"`) |
| `storeLocation` | string | The store location queried (`"CurrentUser"` or `"LocalMachine"`) |
| `totalCount` | int | Total certificates in the store before filtering |
| `filteredCount` | int | Certificates returned after applying `--expired` or `--expiring` filter |
| `certificates` | array | One entry per certificate returned |

Each certificate entry:

| Field | Type | Description |
|-------|------|-------------|
| `subject` | string | Subject Distinguished Name |
| `issuer` | string | Issuer Distinguished Name |
| `thumbprint` | string | SHA-1 thumbprint (hex, uppercase, no colons) |
| `notBefore` | ISO 8601 | Validity start date (UTC) |
| `notAfter` | ISO 8601 | Expiry date (UTC) |
| `daysRemaining` | int | Days until expiry. Negative means already expired. |
| `isExpired` | bool | `true` when `daysRemaining` is negative |
| `hasPrivateKey` | bool | `true` when the store entry includes a private key |
| `isCa` | bool | `true` when the certificate has CA:TRUE in Basic Constraints |

---

## Workflow: Find and Inspect a Certificate

A common workflow is to use `store list` to find a thumbprint, then `inspect` for details:

```bash
# Step 1: find the thumbprint
certz store list --store My

# Step 2: inspect it in full
certz inspect A1B2C3D4E5F678901234567890ABCDEF12345678 --store My

# Step 3: inspect its chain
certz inspect A1B2C3D4E5F678901234567890ABCDEF12345678 --store My --tree
```

---

## Troubleshooting

| Problem | Likely cause | Fix |
|---------|--------------|-----|
| LocalMachine store appears empty or incomplete | Standard user accounts cannot read all LocalMachine certificates | Run the terminal as Administrator to see all machine-wide certificates. |
| Certificate appears in store but `certz inspect <thumbprint>` fails | `--store` mismatch -- the cert is in a different store | Use `certz store list` across all stores (`My`, `Root`, `CA`) to find where the cert is actually installed. |
| `filteredCount` is 0 with `--expiring N` | No certs expire within N days, or store is empty | Try a larger value (e.g., `--expiring 365`) or run without the filter to confirm certs are present. |
| `isExpired: true` for a cert you just renewed | Old certificate not removed after renewal | Remove the expired cert with `certz trust remove <thumbprint> --force` and verify the renewed cert is in the correct store. |
