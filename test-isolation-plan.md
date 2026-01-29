# Plan: Correct Unit Test Isolation While Keeping `certz.exe` as the SUT

## Core Principle

**Each test must invoke `certz.exe` exactly once for the behavior it is validating.**  
All prerequisite state and all cleanup **must be performed using PowerShell only**.

---

## 1. Define an Explicit Test Contract

Each test must follow this structure:

1. **Preconditions (PowerShell only)**
2. **Action (certz.exe exactly once)**
3. **Assertions (PowerShell only)**
4. **Cleanup (PowerShell only)**

---

## 2. Restrict `certz.exe` Usage by Test Type

### Allowed

- `certz.exe install` → install tests
- `certz.exe create` → create tests
- `certz.exe remove` → removal tests
- `certz.exe list` → listing tests
- `certz.exe export` → exporting tests
- `certz.exe convert` → converting tests
- `certz.exe info` → info tests
- `certz.exe verify` → verification tests
- and any other command supported

### Forbidden

- Using certz for setup or teardown outside the action under test
- Multiple certz invocations in a single test

---

## 3. PowerShell-Only Setup

Use PowerShell to prepare required state.

```powershell
$testId = "ins-2.1"
$uniqueTestRunId = [guid]::NewGuid().ToString()
$subject = "CN=certz-test-$testId-$uniqueTestRunId"

$cert = New-SelfSignedCertificate `
  -Subject $subject `
  -CertStoreLocation "Cert:\CurrentUser\My"
```

---

## 4. PowerShell-Only Cleanup

Cleanup must never rely on certz.

```powershell
Get-ChildItem Cert:\CurrentUser\My |
  Where-Object Subject -eq $subject |
  Remove-Item -Force
```

---

## 5. Single-Action Enforcement

Each test must contain **exactly one** `certz.exe` invocation.

Invalid examples:

- `create` + `install` in the same test
- `install` + `remove` in the same test

Split tests instead.

---

## 6. Assert State, Not Output

Do not assert against certz console output.  
Assert against system state instead.

```powershell
if (-not (Test-Path $expectedPath)) {
  throw "Expected file not found: $expectedPath"
}
```

---

## 7. Minimal Internal Test Helpers (No Pester)

```powershell
function Assert-True($condition, $message) {
  if (-not $condition) { throw $message }
}

function Run-Certz($args) {
  & $global:CertzPath @args
  if ($LASTEXITCODE -ne 0) {
    throw "certz failed with exit code $LASTEXITCODE"
  }
}
```

---

## 8. Align Test Names with certz Verbs

| Test Name | certz Verb | Purpose                       |
| --------- | ---------- | ----------------------------- |
| ins-2.1   | install    | Validate install behavior     |
| cre-1.3   | create     | Validate certificate creation |
| rem-3.2   | rem        | Validate certificate removal  |

---

## 9. Ensure Idempotency

- Tests must be safe to rerun
- Cleanup must run in `finally` blocks
- No shared artifacts between tests

---

## 10. Documentation Rule

> **certz.exe performs the action under test**  
> **PowerShell controls the environment**

This rule should be documented and enforced consistently.


