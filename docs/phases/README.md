# Phase Implementation Plans

This directory contains detailed implementation plans for each major certz feature.

## Overview

Certz was developed in phases, each adding a major capability:

| Phase | Feature | Key Commands |
|-------|---------|--------------|
| [Phase 1](phase1-create.md) | Certificate Creation | `create dev`, `create ca` |
| [Phase 2](phase2-inspect.md) | Certificate Inspection | `inspect` (file, URL, store) |
| [Phase 3](phase3-trust.md) | Trust Store Operations | `trust add`, `trust remove`, `store list` |
| [Phase 4](phase4-lint.md) | Certificate Linting | `lint` (CA/B Forum, Mozilla NSS) |
| [Phase 5](phase5-chain.md) | Chain Visualization | `inspect --chain --tree` |
| [Phase 6](phase6-monitor.md) | Expiration Monitoring | `monitor` |
| [Phase 7](phase7-renew.md) | Certificate Renewal | `renew` |
| [Phase 8](phase8-ephemeral.md) | Ephemeral Mode | `--ephemeral`, `--pipe` |
| [Phase 9](phase9-convert.md) | Format Conversion | `convert` (PEM, DER, PFX) |
| [Phase 10](phase10-crossplatform.md) | Cross-Platform Support | Linux builds, platform guards |

## Document Structure

Each phase document includes:

1. **Status** - Implementation state
2. **Overview** - Feature summary
3. **Design Decisions** - Architectural choices
4. **Progress Tracker** - Step-by-step completion
5. **Implementation Steps** - Code samples and patterns
6. **Tests** - Test scenarios and scripts
7. **Verification Checklist** - Quality gates
