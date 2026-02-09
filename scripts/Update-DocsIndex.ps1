$IndexFile = "docs/README.md"

# This script is deprecated since docs/README.md is now manually maintained.
# The previous auto-generated CERTZ_REGISTRY.md has been replaced with a
# categorized documentation index at docs/README.md.

Write-Host "Note: docs/README.md is now manually maintained." -ForegroundColor Yellow
Write-Host "The auto-generated registry has been replaced with a categorized index." -ForegroundColor Yellow
Write-Host ""
Write-Host "Documentation structure:" -ForegroundColor Cyan
Write-Host "  docs/           - Main documentation"
Write-Host "  docs/phases/    - Phase implementation plans"
Write-Host "  prompts/        - AI prompts"
Write-Host "  test/           - Test documentation"
Write-Host "  release/        - Release notes"
