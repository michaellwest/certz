#requires -version 7

<#
.SYNOPSIS
    Tests for the examples command feature.

.DESCRIPTION
    Tests the 'certz examples' command which displays usage examples for certz commands.
    Follows the single-call test principle from test/isolation-plan.md.

.PARAMETER TestId
    Run specific test(s) by ID.

.PARAMETER Category
    Run tests in specific category(ies).

.EXAMPLE
    .\test-examples.ps1
    Runs all examples tests.

.EXAMPLE
    .\test-examples.ps1 -TestId "ex-1.1"
    Runs only the specified test.

.EXAMPLE
    .\test-examples.ps1 -Category "json-output"
    Runs only JSON output tests.
#>

param(
    [string[]]$TestId,
    [string[]]$Category
)

. "$PSScriptRoot\test-helper.ps1"

$TestCategories = @{
    "examples-command" = @("ex-1.1", "ex-1.2", "ex-1.3", "ex-1.4", "ex-1.5", "ex-1.6")
    "json-output"      = @("ex-2.1", "ex-2.2")
    "errors"           = @("ex-3.1")
}

Initialize-TestEnvironment -TestId $TestId -Category $Category -TestCategories $TestCategories
Build-Certz

# Change to tools directory (syncs both PowerShell and .NET current directories)
Enter-ToolsDirectory

Write-TestHeader "Examples Command Tests"

# ============================================================================
# EXAMPLES COMMAND TESTS
# ============================================================================

Write-TestHeader "Examples Command - All Examples"

# ex-1.1: Show all examples
Invoke-Test -TestId "ex-1.1" -TestName "Show all examples (no arguments)" -TestScript {
    $output = & .\certz.exe examples 2>&1
    $outputText = $output -join "`n"

    if ($outputText -match "create dev" -and $outputText -match "trust add" -and $outputText -match "inspect") {
        return [PSCustomObject]@{ Success = $true; Details = "All command categories shown" }
    }
    return [PSCustomObject]@{ Success = $false; Details = "Missing expected command categories" }
}

# ex-1.2: Show examples for specific command
Invoke-Test -TestId "ex-1.2" -TestName "Show examples for 'create dev'" -TestScript {
    $output = & .\certz.exe examples create dev 2>&1
    $outputText = $output -join "`n"

    if ($outputText -match "certz create dev" -and $outputText -match "localhost") {
        return [PSCustomObject]@{ Success = $true; Details = "Create dev examples shown" }
    }
    return [PSCustomObject]@{ Success = $false; Details = "Missing create dev examples" }
}

# ex-1.3: Show examples for nested command (trust add)
Invoke-Test -TestId "ex-1.3" -TestName "Show examples for 'trust add'" -TestScript {
    $output = & .\certz.exe examples trust add 2>&1
    $outputText = $output -join "`n"

    if ($outputText -match "certz trust add" -and $outputText -match "Root") {
        return [PSCustomObject]@{ Success = $true; Details = "Trust add examples shown" }
    }
    return [PSCustomObject]@{ Success = $false; Details = "Missing trust add examples" }
}

# ex-1.4: Show examples for convert
Invoke-Test -TestId "ex-1.4" -TestName "Show examples for 'convert'" -TestScript {
    $output = & .\certz.exe examples convert 2>&1
    $outputText = $output -join "`n"

    if ($outputText -match "certz convert" -and $outputText -match "--to pem") {
        return [PSCustomObject]@{ Success = $true; Details = "Convert examples shown" }
    }
    return [PSCustomObject]@{ Success = $false; Details = "Missing convert examples" }
}

# ex-1.5: Show examples for lint
Invoke-Test -TestId "ex-1.5" -TestName "Show examples for 'lint'" -TestScript {
    $output = & .\certz.exe examples lint 2>&1
    $outputText = $output -join "`n"

    if ($outputText -match "certz lint" -and $outputText -match "--policy") {
        return [PSCustomObject]@{ Success = $true; Details = "Lint examples shown" }
    }
    return [PSCustomObject]@{ Success = $false; Details = "Missing lint examples" }
}

# ex-1.6: Show examples for store list
Invoke-Test -TestId "ex-1.6" -TestName "Show examples for 'store list'" -TestScript {
    $output = & .\certz.exe examples store list 2>&1
    $outputText = $output -join "`n"

    if ($outputText -match "certz store list" -and $outputText -match "--store Root") {
        return [PSCustomObject]@{ Success = $true; Details = "Store list examples shown" }
    }
    return [PSCustomObject]@{ Success = $false; Details = "Missing store list examples" }
}

# ============================================================================
# JSON OUTPUT TESTS
# ============================================================================

Write-TestHeader "JSON Output"

# ex-2.1: Examples command with JSON format for specific command
Invoke-Test -TestId "ex-2.1" -TestName "Examples command with --format json (specific)" -TestScript {
    $output = & .\certz.exe examples create dev --format json 2>&1

    try {
        $json = $output | ConvertFrom-Json
        if ($json.success -and $json.examples.Count -gt 0 -and $json.commandPath -eq "create dev") {
            return [PSCustomObject]@{ Success = $true; Details = "JSON output valid with $($json.examples.Count) examples" }
        }
        return [PSCustomObject]@{ Success = $false; Details = "JSON missing expected fields" }
    }
    catch {
        return [PSCustomObject]@{ Success = $false; Details = "Invalid JSON: $_" }
    }
}

# ex-2.2: All examples with JSON format
Invoke-Test -TestId "ex-2.2" -TestName "All examples with --format json" -TestScript {
    $output = & .\certz.exe examples --format json 2>&1

    try {
        $json = $output | ConvertFrom-Json
        if ($json.success -and $json.commands) {
            $commandCount = ($json.commands | Get-Member -MemberType NoteProperty).Count
            return [PSCustomObject]@{ Success = $true; Details = "JSON output valid with $commandCount command groups" }
        }
        return [PSCustomObject]@{ Success = $false; Details = "JSON missing expected fields" }
    }
    catch {
        return [PSCustomObject]@{ Success = $false; Details = "Invalid JSON: $_" }
    }
}

# ============================================================================
# ERROR HANDLING TESTS
# ============================================================================

Write-TestHeader "Error Handling"

# ex-3.1: Unknown command shows suggestions
Invoke-Test -TestId "ex-3.1" -TestName "Unknown command shows available commands" -TestScript {
    $output = & .\certz.exe examples unknown-command 2>&1
    $outputText = $output -join "`n"

    if ($outputText -match "No examples found" -and $outputText -match "Available") {
        return [PSCustomObject]@{ Success = $true; Details = "Helpful message for unknown command" }
    }
    return [PSCustomObject]@{ Success = $false; Details = "Expected helpful error message. Got: $outputText" }
}

# ============================================================================
# SUMMARY
# ============================================================================

$exitCode = Write-TestSummary
exit $exitCode
