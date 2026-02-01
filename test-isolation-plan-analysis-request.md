# Instructions

## Context

You are reviewing the certz test suite.
certz.exe is the system under test.
PowerShell is responsible for all setup, teardown, and assertions.
No external test frameworks (e.g., Pester) may be introduced.

You must follow the rules defined in the attached document:
test-isolation-plan.md

## Task

Review the existing PowerShell test script:

`test-all.ps1`

Your goal is not to modify code yet.

Instead, produce a recommendation report that explains how the tests should be improved to comply with the isolation plan.

## Constraints

- Do not change or rewrite any code
- Do not introduce new dependencies
- Do not suggest mocking frameworks or Pester
- Assume certz.exe must remain the only executable under test
- Assume tests must remain runnable as a standalone PowerShell script

## What to Produce

Provide a structured recommendation with the following sections:

1. Overall Assessment

- Is the current test suite mostly unit, integration, or hybrid?
- Where does certz currently test itself implicitly?

2. Rule Violations

For each violation, include:

- Test name (e.g., ins-2.1)
- Which rule from test-isolation-plan.md is violated
- Why this is a problem (briefly)

3. Test-by-Test Recommendations

For each problematic test:

- What certz verb the test should focus on
- What setup should move to PowerShell
- What cleanup should move to PowerShell
- Whether the test should be split

Example format:

```
Test: ins-2.1
Current certz usage: install + gen + rm
Recommended certz usage: install only
PowerShell setup needed: certificate creation
PowerShell cleanup needed: certificate removal
```

4. Risk Analysis

- What bugs could currently be hidden by certz-based setup/cleanup?
- Which tests are most likely to mask regressions?

5. Suggested Order of Refactoring

- Which tests should be fixed first and why
- Which changes provide the highest confidence gain

## Output Style

- Use Markdown
- Be precise and opinionated
- Assume the reader is a maintainer of certz
- Do not include speculative improvements beyond the isolation plan

## Final Instruction

Do not propose code changes yet.
Only provide analysis and recommendations.
