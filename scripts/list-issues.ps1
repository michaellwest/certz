<#
.SYNOPSIS
    List GitHub issues with optional filters.

.PARAMETER Repo
    GitHub repository in owner/name format. Defaults to michaellwest/certz.

.PARAMETER State
    Filter by state: open, closed, or all. Defaults to open.

.PARAMETER Label
    Filter by label (comma-separated). Optional.

.PARAMETER Limit
    Maximum number of issues to return. Defaults to 30.

.EXAMPLE
    .\list-issues.ps1
    .\list-issues.ps1 -State closed -Limit 10
    .\list-issues.ps1 -Label documentation
#>
param(
    [string]$Repo = 'michaellwest/certz',

    [ValidateSet('open', 'closed', 'all')]
    [string]$State = 'open',

    [string]$Label,

    [int]$Limit = 30
)

$gh = 'C:\Program Files\GitHub CLI\gh.exe'

$args = @(
    'issue', 'list',
    '--repo', $Repo,
    '--state', $State,
    '--limit', $Limit
)

if ($Label) {
    $args += @('--label', $Label)
}

& $gh @args
