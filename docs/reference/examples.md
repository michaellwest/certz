# certz examples -- Reference

Show usage examples for certz commands.
With no arguments, displays a summary index of all available command groups.
Pass a command name to see its full examples; partial names expand to all matching subcommands.

**See also:**
[Exit Codes](exit-codes.md)

---

## Usage

```
certz examples [command] [options]
```

### Behavior by argument

| Invocation | Behavior |
|------------|----------|
| `certz examples` | Summary table: one row per command group with count and quick-start example |
| `certz examples <exact>` | Full examples for that command (e.g. `certz examples lint`) |
| `certz examples <prefix>` | Full examples for all matching subcommands (e.g. `certz examples create` shows both `create dev` and `create ca`) |
| `certz examples <unknown>` | Warning and list of available command paths |

---

## Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--format` | `--fmt` | `text` | Output format: `text` or `json` |

---

## Available command paths

These are the command paths registered in the examples index:

| Command path | Quick-start example |
|---|---|
| `convert` | `certz convert server.pfx --to pem --password secret` |
| `create ca` | `certz create ca --name "Development Root CA"` |
| `create dev` | `certz create dev localhost` |
| `diff` | `certz diff old.pem new.pem` |
| `fingerprint` | `certz fingerprint cert.pem` |
| `inspect` | `certz inspect cert.pfx --password MyPassword` |
| `lint` | `certz lint cert.pfx --password MyPassword` |
| `monitor` | `certz monitor ./certs` |
| `renew` | `certz renew server.pfx --password OldPass` |
| `store list` | `certz store list` |
| `trust add` | `certz trust add ca.cer --store Root` |
| `trust remove` | `certz trust remove ABC123DEF456789012345678901234567890ABCD --force` |

Prefix matching is automatic: `certz examples create` returns both `create dev` and `create ca`.
`certz examples trust` returns both `trust add` and `trust remove`.
`certz examples store` returns `store list`.

---

## Examples

```bash
# Show the command index (summary table)
certz examples

# Show examples for a specific command
certz examples lint
certz examples convert
certz examples inspect

# Prefix match -- shows all subcommands
certz examples create    # shows create dev + create ca
certz examples trust     # shows trust add + trust remove
certz examples store     # shows store list

# JSON output
certz examples lint --format json
certz examples --format json
```

---

## JSON output

`certz examples <command> --format json` emits an `ExamplesOutput` object:

```json
{
  "success": true,
  "commandPath": "lint",
  "examples": [
    { "description": "Lint a certificate file", "command": "certz lint cert.pfx --password MyPassword", "notes": null }
  ]
}
```

`certz examples --format json` (no args) emits an `AllExamplesOutput` object:

```json
{
  "success": true,
  "commands": {
    "lint": [
      { "description": "Lint a certificate file", "command": "certz lint cert.pfx --password MyPassword", "notes": null }
    ]
  }
}
```

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Examples displayed (or index shown) |
| `1` | Invalid argument |
