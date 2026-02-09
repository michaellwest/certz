Task: Sync docs/certz-spec.md with the current state of the codebase.

Instructions:

Diff Analysis: Review the recent changes in the repository (especially command definitions and logic in Program.cs).

Update Specs: If any new flags, commands, or logic constraints have been added, update the corresponding sections in docs/certz-spec.md.

Prune Outdated Info: Remove any parameters or behaviors that have been deprecated or removed from the code.

Self-Correction: Ensure the "Usage Examples" still reflect the valid CLI syntax.

Finally: Once the file is updated, run the PowerShell script .\scripts\Update-CertzIndex.ps1 to refresh the index in CLAUDE.md.
