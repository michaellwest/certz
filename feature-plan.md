# Implementation Plan

To evolve certz into a world-class utility, the command structure should move from a flat list of flags to a hierarchical, intent-based system.

The goal is to make the tool "guessable"—where a user can predict the parameters without checking the help menu every time.

## Improved Command & Parameter Specification

Instead of a single generic create, split by intent to reduce flag clutter.

### Create

create (Generation)

- certz create ca: Specifically for Root/Intermediate CAs.
  - --name: (Required) Subject name.
  - --duration: (Default: 10y) Validity period.

- certz create dev: The "Make it work" command for local devs.
  - --domain: (Default: localhost) Primary domain.
  - --trust: (Flag) Automatically install to system trust store.
  - --san: (Repeatable) Add extra names (e.g., --san dev.local --san 127.0.0.1).

- certz create csr: For when you need a signed cert from a 3rd party.
  - --file: Output path for the .csr.
  - --key: Use an existing private key instead of generating a new one.

### Inspect

Replace basic "list" or "verify" with a powerful inspection suite.

inspect (Diagnostics)

- certz inspect <file|thumbprint>: Local inspection.
  - --format: (text, json, yaml) For automation.
  - --parts: (cert, key, chain) Specific view of a bundle.

- certz inspect https://<url>: Remote inspection.
  - --port: (Default: 443).
  - --chain: (Flag) Show the full validation path to the root.

### Manage

Consolidate installation and removal under a management verb.

manage (Trust & Lifecycle)

- certz trust add <file>: Adds a cert to the OS/Browser trust store.
  - --store: (root, intermediate, user).
  - --browser: (chrome, firefox, safari) Target specific browsers.

- certz trust remove <thumbprint>: Clean up old dev certs safely.

## Suggested Syntax Design Pattern

To align with modern CLI standards (like kubectl or docker), use the Global Flag Pattern:

```bash
# General Syntax
certz [verb] [noun] [positional-arg] [flags]

# Example: Creating a local dev cert and trusting it in one line
certz create dev api.local --trust --output json

# Example: Checking why a site has a certificate error
certz inspect https://internal-api:8443 --chain --lint
```

---

## Console Improvements

Refactor CLI. "Update Program.cs to use Spectre.Console.Cli. Map existing commands (create, etc.) to new Command classes."
