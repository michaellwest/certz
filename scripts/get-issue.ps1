<#
.SYNOPSIS
    Fetch a GitHub issue and display its title, labels, and body.

.PARAMETER Issue
    The issue number to fetch.

.PARAMETER Repo
    GitHub repository in owner/name format. Defaults to michaellwest/certz.

.PARAMETER Raw
    If set, output only the raw body text (useful for piping into other scripts).

.EXAMPLE
    .\get-issue.ps1 -Issue 16
    .\get-issue.ps1 -Issue 16 -Raw
#>
param(
    [Parameter(Mandatory)]
    [int]$Issue,

    [string]$Repo = 'michaellwest/certz',

    [switch]$Raw
)

$gh = 'C:\Program Files\GitHub CLI\gh.exe'

$result = & $gh api "repos/$Repo/issues/$Issue" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to fetch issue #$Issue from $Repo"
    exit 1
}

$data = $result | ConvertFrom-Json

if ($Raw) {
    Write-Output $data.body
    exit 0
}

$labels = ($data.labels | ForEach-Object { $_.name }) -join ', '
Write-Host ""
Write-Host "Issue #$($data.number): $($data.title)" -ForegroundColor Cyan
Write-Host "State : $($data.state)  |  Labels: $labels" -ForegroundColor DarkGray
Write-Host "URL   : $($data.html_url)" -ForegroundColor DarkGray
Write-Host ""
Write-Host $data.body
