# Documentation Migration Plan

**Status:** Draft
**Created:** 2026-02-09
**Purpose:** Restructure documentation for improved organization and discoverability

---

## Overview

This plan migrates from a flat root structure (17 markdown files) to a categorized hierarchy that separates user documentation, developer guidance, implementation details, and AI prompts.

---

## Target Structure

```
certz/
├── README.md                         # User-facing (keep, streamline)
├── CLAUDE.md                         # AI context (keep, refactor)
├── CONTRIBUTING.md                   # NEW: Development patterns
├── CHANGELOG.md                      # NEW: Optional, human-readable history
│
├── docs/
│   ├── README.md                     # Documentation index (replaces CERTZ_REGISTRY.md)
│   ├── certz-spec.md                 # CLI specification (keep)
│   ├── testing.md                    # Moved from /TESTING.md
│   ├── docker-testing.md             # Moved from /DOCKER-TESTING.md
│   ├── docker-files-explained.md     # Moved from /DOCKER-FILES-EXPLAINED.md
│   ├── architecture.md               # Merged from refactoring-plan.md + feature-plan.md
│   ├── feature-recommendations.md    # Moved from /feature-plan-recommendations.md
│   │
│   └── phases/
│       ├── README.md                 # Phase overview and status
│       ├── phase1-create.md          # Renamed from phase1-implementation-plan.md
│       ├── phase2-inspect.md
│       ├── phase3-trust.md
│       ├── phase4-lint.md
│       ├── phase5-chain.md
│       ├── phase6-monitor.md
│       ├── phase7-renew.md
│       ├── phase8-ephemeral.md
│       └── phase9-convert.md
│
├── prompts/                          # Consolidate all AI prompts
│   ├── README.md                     # Prompt index
│   ├── create-test-convert.md        # Keep
│   ├── future-work.md                # Moved from /claude-prompt-future-work.md
│   ├── feature-plan.md               # Moved from /feature-plan-prompt.md
│   └── maintenance.md                # Moved from /maintenance-prompt.md
│
├── test/
│   ├── README.md                     # NEW: Test documentation index
│   ├── isolation-plan.md             # Renamed from test-isolation-plan.md
│   ├── coverage-analysis.md          # Renamed from test-coverage-analysis.md
│   ├── isolation-analysis-request.md # Renamed
│   └── isolation-analysis-result.md  # Renamed
│
├── release/
│   └── RELEASE_NOTES.md              # Keep
│
└── scripts/
    └── Update-DocsIndex.ps1          # Renamed from Update-CertzRegistry.ps1
```

---

## Migration Steps

### Phase 1: Create New Directories

```powershell
# Create new directory structure
New-Item -ItemType Directory -Path "docs/phases" -Force
```

### Phase 2: Move Phase Implementation Plans

| Source | Destination |
|--------|-------------|
| `phase1-implementation-plan.md` | `docs/phases/phase1-create.md` |
| `phase2-implementation-plan.md` | `docs/phases/phase2-inspect.md` |
| `phase3-implementation-plan.md` | `docs/phases/phase3-trust.md` |
| `phase4-implementation-plan.md` | `docs/phases/phase4-lint.md` |
| `phase5-implementation-plan.md` | `docs/phases/phase5-chain.md` |
| `phase6-implementation-plan.md` | `docs/phases/phase6-monitor.md` |
| `phase7-implementation-plan.md` | `docs/phases/phase7-renew.md` |
| `phase8-implementation-plan.md` | `docs/phases/phase8-ephemeral.md` |
| `phase9-implementation-plan.md` | `docs/phases/phase9-convert.md` |

```powershell
# Move phase plans
$phases = @{
    "phase1-implementation-plan.md" = "docs/phases/phase1-create.md"
    "phase2-implementation-plan.md" = "docs/phases/phase2-inspect.md"
    "phase3-implementation-plan.md" = "docs/phases/phase3-trust.md"
    "phase4-implementation-plan.md" = "docs/phases/phase4-lint.md"
    "phase5-implementation-plan.md" = "docs/phases/phase5-chain.md"
    "phase6-implementation-plan.md" = "docs/phases/phase6-monitor.md"
    "phase7-implementation-plan.md" = "docs/phases/phase7-renew.md"
    "phase8-implementation-plan.md" = "docs/phases/phase8-ephemeral.md"
    "phase9-implementation-plan.md" = "docs/phases/phase9-convert.md"
}
foreach ($src in $phases.Keys) {
    git mv $src $phases[$src]
}
```

### Phase 3: Move General Documentation

| Source | Destination |
|--------|-------------|
| `TESTING.md` | `docs/testing.md` |
| `DOCKER-TESTING.md` | `docs/docker-testing.md` |
| `DOCKER-FILES-EXPLAINED.md` | `docs/docker-files-explained.md` |
| `feature-plan-recommendations.md` | `docs/feature-recommendations.md` |
| `partial-thumbprint-plan.md` | `docs/partial-thumbprint-plan.md` |

```powershell
git mv TESTING.md docs/testing.md
git mv DOCKER-TESTING.md docs/docker-testing.md
git mv DOCKER-FILES-EXPLAINED.md docs/docker-files-explained.md
git mv feature-plan-recommendations.md docs/feature-recommendations.md
git mv partial-thumbprint-plan.md docs/partial-thumbprint-plan.md
```

### Phase 4: Consolidate Prompts

| Source | Destination |
|--------|-------------|
| `claude-prompt-future-work.md` | `prompts/future-work.md` |
| `feature-plan-prompt.md` | `prompts/feature-plan.md` |
| `maintenance-prompt.md` | `prompts/maintenance.md` |

```powershell
git mv claude-prompt-future-work.md prompts/future-work.md
git mv feature-plan-prompt.md prompts/feature-plan.md
git mv maintenance-prompt.md prompts/maintenance.md
```

### Phase 5: Merge Architecture Documents

Merge `refactoring-plan.md` and `feature-plan.md` into `docs/architecture.md`:

```powershell
# Manual merge required - combine content from both files
# Then remove originals
git rm refactoring-plan.md
git rm feature-plan.md
```

### Phase 6: Rename Test Documentation

```powershell
git mv test/test-isolation-plan.md test/isolation-plan.md
git mv test/test-coverage-analysis.md test/coverage-analysis.md
git mv test/test-isolation-plan-analysis-request.md test/isolation-analysis-request.md
git mv test/test-isolation-plan-analysis-result.md test/isolation-analysis-result.md
```

### Phase 7: Create Index Files

#### docs/README.md (New Documentation Index)

```markdown
# Certz Documentation

## Quick Links

- [CLI Specification](certz-spec.md) - Authoritative command reference
- [Testing Guide](testing.md) - How to test certz
- [Architecture](architecture.md) - Design patterns and structure

## Feature Implementation

| Phase | Feature | Status | Documentation |
|-------|---------|--------|---------------|
| 1 | Create Commands | ✅ Complete | [Phase 1](phases/phase1-create.md) |
| 2 | Inspect Commands | ✅ Complete | [Phase 2](phases/phase2-inspect.md) |
| 3 | Trust Store | ✅ Complete | [Phase 3](phases/phase3-trust.md) |
| 4 | Linting | ✅ Complete | [Phase 4](phases/phase4-lint.md) |
| 5 | Chain Visualization | ✅ Complete | [Phase 5](phases/phase5-chain.md) |
| 6 | Expiration Monitoring | ✅ Complete | [Phase 6](phases/phase6-monitor.md) |
| 7 | Renewal | ✅ Complete | [Phase 7](phases/phase7-renew.md) |
| 8 | Ephemeral Mode | ✅ Complete | [Phase 8](phases/phase8-ephemeral.md) |
| 9 | Format Conversion | ✅ Complete | [Phase 9](phases/phase9-convert.md) |

## Docker & Deployment

- [Docker Testing](docker-testing.md)
- [Docker Files Explained](docker-files-explained.md)

## Future Work

- [Feature Recommendations](feature-recommendations.md)
```

#### prompts/README.md

```markdown
# AI Prompts

Prompts for AI assistants working on certz.

| Prompt | Purpose |
|--------|---------|
| [future-work.md](future-work.md) | Completed modernization work |
| [feature-plan.md](feature-plan.md) | Feature implementation prompts |
| [maintenance.md](maintenance.md) | Maintenance guidance |
| [create-test-convert.md](create-test-convert.md) | Test creation prompt |
```

#### test/README.md

```markdown
# Test Documentation

- [Testing Guide](../docs/testing.md) - Main testing procedures
- [Isolation Plan](isolation-plan.md) - Single-call test principle
- [Coverage Analysis](coverage-analysis.md) - Test coverage gaps
```

### Phase 8: Update CLAUDE.md

Update the Certz Knowledge Index to reference new paths:

```markdown
## Certz Knowledge Index

### Command Implementation & Usage

| Task | Source File |
|------|-------------|
| Full CLI reference | [README.md](README.md) |
| Create dev/CA certificates | [docs/phases/phase1-create.md](docs/phases/phase1-create.md) |
| Inspect certificates | [docs/phases/phase2-inspect.md](docs/phases/phase2-inspect.md) |
| Trust store operations | [docs/phases/phase3-trust.md](docs/phases/phase3-trust.md) |
| Certificate linting | [docs/phases/phase4-lint.md](docs/phases/phase4-lint.md) |
| Chain visualization | [docs/phases/phase5-chain.md](docs/phases/phase5-chain.md) |
| Expiration monitoring | [docs/phases/phase6-monitor.md](docs/phases/phase6-monitor.md) |
| Certificate renewal | [docs/phases/phase7-renew.md](docs/phases/phase7-renew.md) |
| Ephemeral mode | [docs/phases/phase8-ephemeral.md](docs/phases/phase8-ephemeral.md) |
| Format conversion | [docs/phases/phase9-convert.md](docs/phases/phase9-convert.md) |

### Architecture & Patterns

| Task | Source File |
|------|-------------|
| Service architecture | [docs/architecture.md](docs/architecture.md) |
| Future recommendations | [docs/feature-recommendations.md](docs/feature-recommendations.md) |
| Completed work | [prompts/future-work.md](prompts/future-work.md) |

### Testing

| Task | Source File |
|------|-------------|
| Testing guide | [docs/testing.md](docs/testing.md) |
| Test isolation | [test/isolation-plan.md](test/isolation-plan.md) |
| Coverage analysis | [test/coverage-analysis.md](test/coverage-analysis.md) |
| Docker testing | [docs/docker-testing.md](docs/docker-testing.md) |
```

### Phase 9: Update Registry Script

Rename and update `scripts/Update-CertzRegistry.ps1` to `scripts/Update-DocsIndex.ps1`:

```powershell
$IndexFile = "docs/README.md"

# Generate categorized index instead of flat list
# ... (enhanced script that groups by directory)
```

### Phase 10: Delete Obsolete Files

```powershell
git rm CERTZ_REGISTRY.md  # Replaced by docs/README.md
```

---

## Cross-Reference Updates

After moving files, update internal links in:

1. **CLAUDE.md** - Knowledge Index table (Phase 8)
2. **README.md** - Any links to phase plans or testing docs
3. **Each phase plan** - Links to other phases or docs
4. **Test files** - Links to testing.md

Use this command to find broken links:

```powershell
# Find all markdown links and check if targets exist
Get-ChildItem -Recurse -Filter *.md | ForEach-Object {
    $content = Get-Content $_.FullName -Raw
    [regex]::Matches($content, '\[.*?\]\((.*?\.md.*?)\)') | ForEach-Object {
        $link = $_.Groups[1].Value -replace '#.*$', ''
        $basePath = Split-Path $_.FullName -Parent
        $targetPath = Join-Path $basePath $link
        if (-not (Test-Path $targetPath)) {
            [PSCustomObject]@{
                File = $_.FullName
                BrokenLink = $link
            }
        }
    }
}
```

---

## Verification Checklist

- [ ] All phase plans moved to `docs/phases/`
- [ ] All prompts consolidated in `prompts/`
- [ ] Testing docs moved to `docs/`
- [ ] `docs/README.md` created with categorized index
- [ ] `prompts/README.md` created
- [ ] `test/README.md` created
- [ ] CLAUDE.md Knowledge Index updated with new paths
- [ ] All internal links verified and updated
- [ ] `CERTZ_REGISTRY.md` deleted
- [ ] Registry script renamed and updated
- [ ] Git commit with clear message

---

## Rollback Plan

If issues arise, use git to restore:

```powershell
git checkout HEAD~1 -- .
```

---

## Commit Message

```
docs: restructure documentation hierarchy

- Move phase implementation plans to docs/phases/
- Consolidate AI prompts in prompts/
- Move testing docs to docs/
- Create categorized index files (docs/README.md, prompts/README.md)
- Update CLAUDE.md knowledge index with new paths
- Remove flat CERTZ_REGISTRY.md in favor of categorized docs/README.md

This reduces root-level clutter from 17 to 4 markdown files and
improves discoverability through logical grouping.
```
