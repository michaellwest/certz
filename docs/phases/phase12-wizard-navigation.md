# Phase 12: Wizard Navigation Improvements

**Status:** In Progress
**Created:** 2026-02-16

## Objective

Improve the `--guided` wizard navigation flow so users can perform related follow-up actions without restarting from the top-level menu. The current hub-and-spoke pattern (main menu → sub-wizard → result → yes/no → main menu) creates friction for common multi-step workflows.

## Project Context

This is a .NET 10 CLI tool using:

- **System.CommandLine** for command parsing
- **Spectre.Console** for display formatting
- **Record types** for options and results

### Established Patterns

**Wizard Structure:** `src/certz/Services/CertificateWizard.cs`

- Static partial class with `Run<Feature>Wizard()` methods
- Returns options records consumed by existing service layer
- Uses `WriteWelcome()`, `WriteStepHeader()`, `WriteHelp()`, `WriteEquivalentCommand()` helpers
- Spectre.Console `SelectionPrompt`, `TextPrompt`, and `Confirm` for user input

---

## Current State Analysis

### Problem: Post-Operation Dead End

After every wizard operation, the user sees:

```
? Do another operation? [y/n] (n):
```

This forces a full restart to the top-level menu for any follow-up. Common workflows that suffer:

- **Inspect → Lint**: Inspect a cert, want to lint the same cert — must re-select source
- **Store browse → Inspect A → Inspect B**: Must re-navigate store/location/filter each time
- **Create → Trust**: Create a cert, want to add it to trust — must re-enter file path

### Problem: Store Browser One-Shot

`BrowseStore()` returns a single thumbprint and exits. After using it (inspect, lint, trust remove), the store/location/filter context is discarded.

### Problem: No Context Forwarding

Each wizard method collects its own inputs from scratch. When a follow-up action operates on the same certificate, the user must re-enter the source path, password, store name, and location.

### Problem: No Edit-at-Summary for Linear Wizards

The 5–6 step creation wizards are strictly linear. Changing an earlier step requires cancelling and restarting from step 1.

---

## Improvement 1: Contextual Post-Operation Menus

**Priority:** Highest — replaces the binary yes/no at line 682 of `CertificateWizard.cs`

### Design

After each operation completes, show a `SelectionPrompt` with context-aware follow-up actions instead of a yes/no confirm.

**After Inspect:**
| Choice | Action |
|--------|--------|
| Lint this certificate | Re-use same source/password, run lint |
| Inspect another certificate | Re-enter inspect wizard |
| Back to main menu | Return to top-level selection |
| Exit | Quit wizard |

**After Lint:**
| Choice | Action |
|--------|--------|
| Inspect this certificate (full details) | Re-use same source/password |
| Lint another certificate | Re-enter lint wizard |
| Back to main menu | Return to top-level selection |
| Exit | Quit wizard |

**After Create (dev or CA):**
| Choice | Action |
|--------|--------|
| Inspect the created certificate | Use output PFX path + password |
| Create another certificate | Re-enter create wizard |
| Back to main menu | Return to top-level selection |
| Exit | Quit wizard |

**After Store List:**
| Choice | Action |
|--------|--------|
| Inspect a certificate from this store | Browse same store |
| Remove a certificate from this store | Browse same store |
| List with different filter | Re-run store list with same store/location |
| Back to main menu | Return to top-level selection |
| Exit | Quit wizard |

**After Trust Add:**
| Choice | Action |
|--------|--------|
| Inspect the trusted certificate | Use same file/password |
| Back to main menu | Return to top-level selection |
| Exit | Quit wizard |

**After Trust Remove:**
| Choice | Action |
|--------|--------|
| Remove another certificate | Stay in same store |
| Back to main menu | Return to top-level selection |
| Exit | Quit wizard |

**After Convert:**
| Choice | Action |
|--------|--------|
| Inspect the converted file | Use output path |
| Convert another certificate | Re-enter convert wizard |
| Back to main menu | Return to top-level selection |
| Exit | Quit wizard |

**After Monitor:**
| Choice | Action |
|--------|--------|
| Back to main menu | Return to top-level selection |
| Exit | Quit wizard |

**After Renew:**
| Choice | Action |
|--------|--------|
| Inspect the renewed certificate | Use output path |
| Renew another certificate | Re-enter renew wizard |
| Back to main menu | Return to top-level selection |
| Exit | Quit wizard |

### Implementation

Replace the `doAnother` confirm at the end of the `while (true)` loop in `RunGlobalWizard()` with a per-case follow-up prompt. Each case returns a `WizardFollowUp` enum value that controls the outer loop.

---

## Improvement 2: Store Browser Loop

**Priority:** High — avoids re-navigating store/location/filter when browsing multiple certs

### Design

When the store browser is used for inspect or lint, after displaying results, offer to return to the same cert list. This applies specifically to the inspect and lint flows when the source is a Windows store.

The `BrowseStore()` method itself remains unchanged. Instead, the inspect/lint cases in `RunGlobalWizard()` gain a loop when operating on store sources: after showing results, the contextual menu includes "Inspect another certificate from this store" which re-invokes `BrowseStore()` with the same store name, location, and filter parameters.

### Implementation

- Extract store parameters (storeName, storeLocation) from the inspect/lint wizard results
- In the post-operation menu for store-sourced operations, add a "pick another from same store" option
- Call `BrowseStore()` again with preserved parameters, build new options, and re-run the operation

---

## Improvement 3: Context Forwarding Between Operations

**Priority:** Medium — eliminates redundant re-entry of source/password for follow-up actions

### Design

Introduce a `WizardContext` record that captures the last operation's key parameters:

```csharp
private record WizardContext
{
    public string? LastSource { get; init; }
    public string? LastPassword { get; init; }
    public string? LastStoreName { get; init; }
    public string? LastStoreLocation { get; init; }
    public InspectSourceType? LastSourceType { get; init; }
    public string? LastOutputFile { get; init; }
    public string? LastOutputPassword { get; init; }
}
```

After each operation, update the context. When a follow-up action uses the context (e.g., "Lint this certificate" after inspect), pass the stored values directly to the service layer without re-prompting.

### Implementation

- Define `WizardContext` as a private record in `CertificateWizard`
- Initialize at the start of `RunGlobalWizard()`
- Update after each operation completes
- Use when contextual follow-up actions reference "this certificate" or "the created file"

---

## Improvement 4: Summary-and-Edit for Linear Wizards (Documentation Only)

**Priority:** Low — nice-to-have, not implemented in this phase

### Design

At the summary screen of `RunDevCertificateWizard()` and `RunCACertificateWizard()`, instead of only "Create certificate? (y/n)", offer three choices:

1. **Create certificate with these settings** — proceed
2. **Edit a setting** — show selection of steps, jump to selected step, re-run from there forward
3. **Cancel** — abort

### Implementation Notes

This requires restructuring the linear wizard into a step-function pattern where each step is a callable unit. Spectre.Console prompts are inherently blocking, so "going back" means re-executing the step's prompt.

A reasonable approach:

```csharp
// Each step is a Func that modifies a builder
var steps = new (string Name, Action<OptionsBuilder> Run)[]
{
    ("Domain Name", b => b.Domain = PromptDomain()),
    ("SANs", b => b.SANs = PromptSANs()),
    // ...
};

// Run all steps forward, then at summary:
// "Edit a setting" → pick step index → re-run steps[index..] → re-display summary
```

**Deferred to a future phase** because:
- The current summary + cancel flow is functional
- The contextual menus (improvement 1) address the bigger pain point
- The step-function refactor is invasive and should be tested thoroughly

---

## Progress Tracker

| # | Improvement | Status | Commit |
|---|------------|--------|--------|
| 1 | Contextual post-operation menus | Planned | — |
| 2 | Store browser loop | Planned | — |
| 3 | Context forwarding | Planned | — |
| 4 | Summary-and-edit (docs only) | Complete | — |

---

## Verification Checklist

- [ ] `dotnet build` succeeds with no warnings
- [ ] `certz --guided` launches and displays main menu
- [ ] After inspect: contextual menu appears with lint/inspect-another/back/exit options
- [ ] After lint: contextual menu appears with inspect/lint-another/back/exit options
- [ ] After create: contextual menu offers inspect/create-another/back/exit
- [ ] After store list: can inspect or remove a cert from the same store
- [ ] "Lint this certificate" after inspect re-uses the same source without re-prompting
- [ ] "Inspect the created certificate" after create uses the output PFX path
- [ ] Store browser loop works: inspect cert A → inspect another from same store → works
- [ ] "Back to main menu" returns to the top-level "What would you like to do?" prompt
- [ ] "Exit" cleanly exits the wizard
- [ ] Ctrl+C still cancels at any point
