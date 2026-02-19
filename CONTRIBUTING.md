# Contributing to certz

This document describes the expected workflow for developers, testers, and project managers contributing to certz.

---

## Workflow Overview

```
Open Issue → Branch → Implement → Test → PR → Merge → Issue closes
```

All work starts with a GitHub Issue. Do not open a PR for a feature or bug fix that lacks a corresponding issue.

---

## For Everyone: Issue-First Workflow

1. **Check existing issues** before opening a new one — search labels and milestones at https://github.com/michaellwest/certz/issues
2. **Open an issue** with a clear title, description, and acceptance criteria
3. Assign labels (`feature`, `bug`, `enhancement`, `deferred`) and a milestone (`v0.4`, `v1.0`) at the time of creation
4. For complex features, attach or link a `docs/phases/phase<N>-<feature>.md` spec doc from the issue body — the spec doc is the design artifact; the issue is the work item
5. Move the issue card on the project board as work progresses: **Backlog → Ready → In Progress → Done**

### Labels

| Label | Use for |
|-------|---------|
| `feature` | New capability |
| `bug` | Defect in existing behavior |
| `enhancement` | Improvement to an existing feature |
| `deferred` | Intentionally parked with no timeline |
| `cross-platform` | Linux/macOS scope |
| `wizard` | Guided mode or UX changes |
| `breaking-change` | Requires a version bump |

### Milestones

| Milestone | Scope |
|-----------|-------|
| `v0.4` | Next planned release |
| `v1.0` | GA quality — cross-platform, stable API |

---

## For Developers: Code Workflow

### Branching and commits

- Branch from `main`: `git checkout -b feat/short-description`
- Reference the issue in every commit: `feat: add --foo option (closes #42)`
- PRs that close issues must include `closes #N` in the PR body so GitHub auto-closes the issue on merge

### Adding a new command

Follow the established pattern exactly — do not invent new structures:

```
src/certz/
├── Commands/<Feature>/<Feature>Command.cs   ← CLI entry point, SetAction handler
├── Services/<Feature>Service.cs             ← business logic, returns result record
├── Models/<Feature>Options.cs               ← input parameters
└── Models/<Feature>Result.cs                ← structured output
```

- Register new CLI options in `src/certz/Options/OptionBuilders.cs`
- Use `FormatterFactory.Create(format)` for all output — never write directly to `Console`
- Use `throw new ArgumentException("message")` for validation errors in async handlers — never `Environment.ExitCode = 1` (see [CLAUDE.md](CLAUDE.md) for why)

### Cryptography defaults

| Setting | Default | Override |
|---------|---------|----------|
| Key algorithm | ECDSA P-256 | `--key-type rsa` |
| RSA key size | 3072-bit | `--key-size` |
| Max leaf validity | 398 days | — (enforced, not overridable) |
| PFX encryption | AES-256-CBC | — |
| Time source | `DateTimeOffset.UtcNow` | — (never `DateTime.Now`) |

### Spec docs (`docs/phases/`)

- Existing phase docs (`phase1–12`) are **read-only** after implementation. Do not edit them to reflect current status.
- For a new complex feature, create `docs/phases/phase<N>-<feature>.md` containing: Overview, Design Decisions, Implementation Steps, Tests, Verification Checklist.
- Do **not** include a Status field or Progress Tracker in spec docs — status lives on the GitHub Issue.

### Building

```powershell
# Debug build (fast iteration)
dotnet build

# Release build (single-file exe, use this for manual testing)
.\build-release.ps1
```

The release executable at `release/certz.exe` must be a single self-contained file with no runtime dependencies. Do not change `PublishSingleFile`, `SelfContained`, or `PublishTrimmed` in `certz.csproj` without team discussion.

---

## For Testers: Testing Workflow

Tests live in `test/` and run with PowerShell 7.5+.

```powershell
# Run all tests
pwsh -File test/test-all.ps1

# Run a specific suite
pwsh -File test/test-create.ps1
pwsh -File test/test-lint.ps1
```

### Test isolation rules (non-negotiable)

Each test must follow this exact structure:

1. **Preconditions** — PowerShell only (`New-SelfSignedCertificate`, `Copy-Item`, etc.)
2. **Action** — invoke `certz.exe` exactly **once**
3. **Assertions** — PowerShell only (check filesystem state, certificate store, exit code)
4. **Cleanup** — PowerShell only

**Never** use `certz.exe` for setup or teardown. **Never** invoke `certz.exe` more than once per test case. See [test/isolation-plan.md](test/isolation-plan.md) for the full rationale and examples.

### When writing a new test

- Add it to the relevant `test/test-<feature>.ps1` file
- Reference the issue number in the test name or comment
- Assert against system state (file exists, cert in store, exit code), not console output text

---

## For Project Managers: Tracking Workflow

- **GitHub Issues** is the single source of truth for what is planned, in progress, or deferred
- **Milestones** represent target releases — assign every actionable issue to a milestone
- **The project board** (Backlog → Ready → In Progress → Done) reflects current sprint state
- **Spec docs** in `docs/phases/` are design artifacts for complex features — they describe the "how", not the current status
- **`prompts/future-work.md`** is a historical completed-work log, not a live tracker — do not update it
- When a feature is deferred, add the `deferred` label and remove it from its milestone; leave the issue open

---

## Pull Request Checklist

Before opening a PR:

- [ ] A GitHub Issue exists and is linked (`closes #N` in the PR body)
- [ ] `dotnet build` succeeds with no new warnings
- [ ] `.\build-release.ps1` produces a working `release/certz.exe`
- [ ] New behavior is covered by a test in `test/test-<feature>.ps1`
- [ ] Tests pass: `pwsh -File test/test-all.ps1`
- [ ] New options are added to `OptionBuilders.cs`, not defined inline in commands
- [ ] Output goes through a formatter, not `Console.Write*`
- [ ] Async handlers use `throw new ArgumentException()` for validation errors
- [ ] No `DateTime.Now` or `DateTime.Today` in certificate validity logic

---

## Reference

| Resource | Purpose |
|----------|---------|
| [CLAUDE.md](CLAUDE.md) | AI assistant constraints, code patterns, constraint checklist |
| [docs/architecture.md](docs/architecture.md) | Service architecture and options pattern |
| [README.md](README.md) | Full CLI reference — authoritative command syntax |
| [test/isolation-plan.md](test/isolation-plan.md) | Test isolation principles and examples |
| [docs/certz-spec.md](docs/certz-spec.md) | CLI specification |
| https://github.com/michaellwest/certz/issues | Active work tracking |
