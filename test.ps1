Clear-Host

Push-Location -Path (Join-Path -Path $PSScriptRoot -ChildPath "docker\tools")

function Remove-TestData {
    Get-ChildItem -Path . | Where-Object { $_.Name.StartsWith("devcert") } | Remove-Item
}

Remove-TestData
Write-Host "Create with defaults" -ForegroundColor Green
.\certz.exe create

Remove-TestData
Write-Host "Create with all options" -ForegroundColor Green
.\certz.exe create --f devcert.pfx --san *.dev.local localhost 127.0.0.1 --p changeit --c devcert.cer --k devcert.key --days 1825

Write-Host "Install certificate" -ForegroundColor Green
.\certz.exe install --f devcert.pfx --p changeit --sl localmachine --sn root

Write-Host "Remove certificate" -ForegroundColor Green
.\certz.exe remove --subject *.dev.local --sl localmachine --sn root

Remove-TestData
Write-Host "Create only PEM" -ForegroundColor Green
.\certz.exe create --c devcert.cer --k devcert.key

Write-Host "List certificates" -ForegroundColor Green
.\certz.exe list --sl localmachine --sn root

Pop-Location