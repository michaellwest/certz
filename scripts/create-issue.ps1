<#
.SYNOPSIS
    Create a new GitHub issue and return its number.

.PARAMETER Title
    Issue title.

.PARAMETER BodyFile
    Path to a Markdown file whose contents become the issue body.

.PARAMETER Labels
    Comma-separated list of labels to apply. Optional.

.PARAMETER Milestone
    Milestone title or number to assign. Optional.

.PARAMETER Repo
    GitHub repository in owner/name format. Defaults to michaellwest/certz.

.EXAMPLE
    .\create-issue.ps1 -Title "feat: add X" -BodyFile scripts\body.md
    .\create-issue.ps1 -Title "docs: convert.md" -BodyFile scripts\body.md -Labels "documentation"
#>
param(
    [Parameter(Mandatory)]
    [string]$Title,

    [Parameter(Mandatory)]
    [string]$BodyFile,

    [string]$Labels,

    [string]$Milestone,

    [string]$Repo = 'michaellwest/certz'
)

$gh = 'C:\Program Files\GitHub CLI\gh.exe'

$resolved = Resolve-Path $BodyFile -ErrorAction Stop

$args = @(
    'issue', 'create',
    '--repo', $Repo,
    '--title', $Title,
    '--body-file', $resolved
)

if ($Labels) {
    $args += @('--label', $Labels)
}

if ($Milestone) {
    $args += @('--milestone', $Milestone)
}

$url = & $gh @args 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to create issue: $url"
    exit 1
}

$num = ($url -split '/')[-1]
Write-Host "Created #$num : $url"
return [int]$num
