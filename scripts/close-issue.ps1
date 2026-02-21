<#
.SYNOPSIS
    Post a closing comment on a GitHub issue and close it.

.PARAMETER Issue
    The issue number to close.

.PARAMETER BodyFile
    Path to a plain-text or Markdown file whose contents become the closing comment.
    Omit to close the issue without a comment.

.PARAMETER Repo
    GitHub repository in owner/name format. Defaults to michaellwest/certz.

.EXAMPLE
    .\close-issue.ps1 -Issue 14 -BodyFile scripts\close-14.md
    .\close-issue.ps1 -Issue 42 -BodyFile C:\tmp\summary.md -Repo myorg/myrepo
#>
param(
    [Parameter(Mandatory)]
    [int]$Issue,

    [string]$BodyFile,

    [string]$Repo = 'michaellwest/certz'
)

$gh = 'C:\Program Files\GitHub CLI\gh.exe'

if ($BodyFile) {
    $resolved = Resolve-Path $BodyFile -ErrorAction Stop
    $body = [System.IO.File]::ReadAllText($resolved)
    $payload = [pscustomobject]@{ body = $body }
    $payload | ConvertTo-Json -Compress |
        & $gh api --method POST "repos/$Repo/issues/$Issue/comments" --input -
    Write-Host "Posted comment on issue #$Issue"
}

$close = [pscustomobject]@{ state = 'closed'; state_reason = 'completed' }
$close | ConvertTo-Json -Compress |
    & $gh api --method PATCH "repos/$Repo/issues/$Issue" --input -
Write-Host "Closed issue #$Issue"
