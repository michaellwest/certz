# Implementation Prompts for certz v2.0

Use these prompts sequentially to implement the v2.0 migration based on [feature-plan-recommendations.md](feature-plan-recommendations.md).

---

## Phase 1: Infrastructure + Create Commands

```
Implement Phase 1 of the v2.0 migration for certz based on feature-plan-recommendations.md.

## Scope (in order)
1. Add Spectre.Console NuGet package
2. Create IOutputFormatter interface with TextFormatter and JsonFormatter
3. Add --format global option to Program.cs
4. Implement `create dev` command with:
   - New hierarchical structure (Commands/Create/CreateDevCommand.cs)
   - --guided flag with Spectre.Console wizard
   - --trust flag (auto-install to appropriate store)
   - --issuer, --issuer-cert, --issuer-key options
   - JSON output support via formatter
5. Implement `create ca` command following the same pattern
6. Remove old `create` command

## Constraints
- Reuse existing CertificateOperations service methods where possible
- Follow existing code style and patterns
- Update tests to match new command structure
- Do NOT implement other commands yet (inspect, trust, etc.)

## Success Criteria
- `certz create dev api.local` works
- `certz create dev --guided` launches wizard
- `certz create dev api.local --trust` creates and installs cert
- `certz create ca --name "Dev Root"` works
- `certz create dev --format json` outputs JSON
- All existing create functionality preserved
```

---

## Phase 2: Inspect Command

```
Implement Phase 2 of the v2.0 migration for certz based on feature-plan-recommendations.md.

## Scope
1. Implement `inspect` command (Commands/Inspect/InspectCommand.cs) with:
   - Positional argument accepting file path, URL, or thumbprint
   - Auto-detection of input type (file vs URL vs thumbprint)
   - --chain flag for certificate chain visualization (Spectre.Console tree)
   - --crl flag for revocation checking
   - --warn <days> for expiration warnings
   - --save <file> to export certificate
   - --save-key <file> to export private key (if available)
   - --format json support
2. Create ChainVisualizer service using Spectre.Console Tree
3. Migrate functionality from existing info, verify, and export commands
4. Remove old info, verify, and export commands

## Constraints
- Reuse CertificateOperations methods for certificate loading/validation
- Chain visualization should show: Subject, Issuer, Validity, Thumbprint per cert
- Handle errors gracefully (expired certs, revoked certs, network issues)

## Success Criteria
- `certz inspect cert.pem` displays certificate info
- `certz inspect https://example.com` fetches and displays remote cert
- `certz inspect ABC123 --store My` inspects cert from store
- `certz inspect cert.pem --chain` shows visual chain tree
- `certz inspect https://example.com --save server.pem` saves cert to file
- `certz inspect cert.pem --crl` checks revocation status
- `certz inspect cert.pem --warn 30` warns if expiring within 30 days
- `certz inspect cert.pem --format json` outputs JSON
```

---

## Phase 3: Trust Commands

```
Implement Phase 3 of the v2.0 migration for certz based on feature-plan-recommendations.md.

## Scope
1. Implement `trust add` command (Commands/Trust/TrustAddCommand.cs) with:
   - Positional argument for certificate file
   - --browser flag (chrome, firefox, edge) for browser-specific stores
   - --password for PFX files
   - Auto-detection: CA certs → Root store, end-entity → Personal store
2. Implement `trust remove` command (Commands/Trust/TrustRemoveCommand.cs) with:
   - Positional argument for thumbprint
   - --subject option for removal by subject (multiple matches possible)
   - --browser flag for browser-specific stores
3. Create ITrustStore interface with implementations:
   - WindowsTrustStore.cs
   - ChromeTrustStore.cs
   - FirefoxTrustStore.cs
   - EdgeTrustStore.cs
4. Migrate functionality from existing install and remove commands
5. Remove old install and remove commands

## Constraints
- Firefox uses NSS certutil (document requirement in output)
- Chrome/Edge on Windows use Windows certificate store
- Warn user if browser not installed or store not found

## Success Criteria
- `certz trust add cert.pem` installs to Windows store
- `certz trust add ca.pem` installs CA to Trusted Root
- `certz trust add cert.pem --browser firefox` installs to Firefox
- `certz trust remove ABC123` removes by thumbprint
- `certz trust remove --subject "CN=dev.local"` removes by subject
- `certz trust add cert.pem --format json` outputs JSON result
```

---

## Phase 4: Remaining Commands

```
Implement Phase 4 of the v2.0 migration for certz based on feature-plan-recommendations.md.

## Scope
1. Implement `store list` command (Commands/Store/StoreListCommand.cs) with:
   - --store-name option (default: My)
   - --store-location option (default: LocalMachine)
   - --format json support
   - Tabular output using Spectre.Console Table
2. Implement `lint` command (Commands/LintCommand.cs) with:
   - Positional argument for file or URL
   - CA/B Forum Baseline Requirements validation
   - Mozilla NSS Policy validation
   - Severity levels (error, warning, info)
   - --format json support
3. Implement `renew` command (Commands/RenewCommand.cs) with:
   - Positional argument for existing certificate file
   - --days option for new validity period
   - --out option for output file
   - Auto-detect: subject, SANs, key type from existing cert
   - Generate new key pair, preserve extensions
4. Update `convert` command to new structure (Commands/ConvertCommand.cs)
5. Migrate functionality from existing list command
6. Remove old list command

## Constraints
- Lint rules should be extensible (ILintRule interface)
- Renew must work with both PFX and PEM inputs
- Store list should show: Subject, Thumbprint, Expiry, Issuer

## Success Criteria
- `certz store list` shows certificates in table format
- `certz store list --format json` outputs JSON
- `certz lint cert.pem` validates against CA/B + Mozilla rules
- `certz lint https://example.com` validates remote cert
- `certz renew server.pfx --days 90 --out renewed.pfx` renews cert
- `certz convert cert.pfx --out cert.pem` converts formats
```

---

## Phase 5: Documentation + Cleanup

```
Complete Phase 5 of the v2.0 migration for certz based on feature-plan-recommendations.md.

## Scope
1. Write MIGRATION.md documenting all v1.x → v2.0 command changes
2. Update README.md with new command structure and examples
3. Update CLAUDE.md if needed
4. Ensure all commands have --help with clear descriptions
5. Add shell completion support (PowerShell, Bash, Zsh)
6. Clean up any dead code from old commands
7. Update version to 2.0.0 in project file
8. Run all tests and fix any failures

## Migration Guide Structure
- Overview of changes
- Command mapping table (old → new)
- Examples for common workflows
- Breaking changes list

## Success Criteria
- All old command files removed
- No compiler warnings
- All tests pass
- `certz --help` shows new command structure
- `certz <command> --help` shows command-specific help
- MIGRATION.md is complete and accurate
```

---

## Quick Reference: Implementation Order

| Phase | Commands | Key Dependencies |
|-------|----------|------------------|
| 1 | `create dev`, `create ca` | Spectre.Console, IOutputFormatter |
| 2 | `inspect` | ChainVisualizer, existing verify/info/export logic |
| 3 | `trust add`, `trust remove` | ITrustStore, browser detection |
| 4 | `store list`, `lint`, `renew`, `convert` | ILintRule, existing list/convert logic |
| 5 | Documentation | All commands complete |

---

## Notes

- Each phase builds on the previous - complete in order
- Run tests after each phase before proceeding
- Commit after each phase for easy rollback
- Reference [feature-plan-recommendations.md](feature-plan-recommendations.md) for detailed requirements
