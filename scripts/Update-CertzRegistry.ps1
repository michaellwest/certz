$RegistryFile = "CERTZ_REGISTRY.md"

# 1. Generate the Header
$Content = @(
    "# Certz Knowledge Registry",
    "> This file is auto-generated. Do not edit manually.",
    "Last Updated: $(Get-Date)",
    ""
)

# 2. Scan for .md files containing "certz"
# Excludes the registry itself and the .git folder
$Files = Get-ChildItem -Recurse -Filter *.md | 
         Where-Object { $_.Name -ne $RegistryFile -and $_.FullName -notlike "*\.git\*" }

foreach ($File in $Files) {
    if (Select-String -Path $File.FullName -Pattern "certz" -Quiet) {
        # Extract the first heading for the title
        $TitleMatch = Select-String -Path $File.FullName -Pattern '^#{1,2}\s+(.*)' | Select-Object -First 1
        $Title = if ($TitleMatch) { $TitleMatch.Matches.Groups[1].Value.Trim() } else { $File.Name }
        
        # Calculate relative path
        $RelativePath = Resolve-Path -Path $File.FullName -Relative
        $Content += "* [$Title]($RelativePath)"
    }
}

# 3. Write the file (Overwrite mode)
$Content | Out-File -FilePath $RegistryFile -Encoding utf8
Write-Host "✅ Created $RegistryFile with latest certz references." -ForegroundColor Green