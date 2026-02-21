<#
.SYNOPSIS
    Post a comment on a GitHub issue.

.PARAMETER Issue
    The issue number to comment on.

.PARAMETER BodyFile
    Path to a plain-text or Markdown file whose contents become the comment.

.PARAMETER Body
    Inline comment text. Use BodyFile for multi-line content with backticks.

.PARAMETER Repo
    GitHub repository in owner/name format. Defaults to michaellwest/certz.

.EXAMPLE
    .\comment-issue.ps1 -Issue 16 -BodyFile scripts\comment-16.md
    .\comment-issue.ps1 -Issue 16 -Body "Done — see commit abc1234."
#>
param(
    [Parameter(Mandatory)]
    [int]$Issue,

    [string]$BodyFile,

    [string]$Body,

    [string]$Repo = 'michaellwest/certz'
)

$gh = 'C:\Program Files\GitHub CLI\gh.exe'

if ($BodyFile -and $Body) {
    Write-Error 'Specify either -BodyFile or -Body, not both.'
    exit 1
}

if (-not $BodyFile -and -not $Body) {
    Write-Error 'Either -BodyFile or -Body is required.'
    exit 1
}

if ($BodyFile) {
    $resolved = Resolve-Path $BodyFile -ErrorAction Stop
    $text = [System.IO.File]::ReadAllText($resolved)
} else {
    $text = $Body
}

$payload = [pscustomobject]@{ body = $text }
$payload | ConvertTo-Json -Compress |
    & $gh api --method POST "repos/$Repo/issues/$Issue/comments" --input -

Write-Host "Posted comment on issue #$Issue"
