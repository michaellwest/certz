# certz Release Notes

**Version:** 0.3.0.0
**Release Date:** 2026-02-10
**Previous Version:** 0.2

## Changes Since 0.2
- test: add test/test-all.ps1 runner that invokes individual test suites
- test: restore -UseDocker and -DockerVerbose parameters for Docker container testing
- docker: copy all test scripts into container, update ENTRYPOINT to test/test-all.ps1
- test: add container detection to test-helper.ps1 (Build-Certz, Enter/Exit-ToolsDirectory)
- Merge branch 'feature/efficiency' into upgrade
- test: add export/verify/install test suites, fix renew isolation, remove legacy test-all.ps1
- feat: add examples command to display usage examples
- docs: mark medium priority test gaps as complete
- docs: update test coverage analysis to reflect current state
- refactor: move source code to src/certz directory
- docs: add workflow prompts for commands, tests, and releases
- chore: remove obsolete prompts and deprecated script
- docs: add passive context index to CLAUDE.md
- Merge branch 'feature/longterm' into upgrade
- docs: add phase 10 cross-platform support plan
- docs: add single-file distribution requirement
- docs: defer YAML output format
- docs: defer browser trust store integration
- chore: remove temporary migration plan
- docs: restructure documentation hierarchy
- docs: implement retrieval-led reasoning for certz tasks
- Add Certz Knowledge Index and Reasoning Protocol to CLAUDE.md
- Fix test scripts to sync .NET current directory with PowerShell location
- Phase 9 step 9: Update documentation for enhanced convert command
- Phase 9 step 8: Add tests for simplified convert interface
- Phase 9 step 7: Update JsonFormatter with format info fields
- Phase 9 step 6: Update TextFormatter for enhanced conversion output
- Phase 9 step 5: Update ConvertCommand with simplified interface
- Phase 9 step 4: Add DER conversion methods
- Phase 9 step 3: Add format detection service
- Phase 9 step 2: Add ConvertOptions model
- Phase 9 step 1: Add FormatType enum
- Add phase 9 plan for enhanced certificate format conversion
- Mark phase 8 (ephemeral/pipe modes) as completed
- Fix ephemeral test failures and exit code handling
- Add tests and documentation for ephemeral and pipe modes
- Update formatters for ephemeral mode display
- Update CreateService to handle ephemeral and pipe modes
- Add ephemeral and pipe support to create ca command
- Add ephemeral and pipe support to create dev command
- Add PipeOutputService for streaming certificate output
- Add option builders for ephemeral and pipe flags
- Add ephemeral and pipe properties to certificate options models
- Add phase 8 implementation plan for ephemeral and pipe modes.
- Implement phase 7: Certificate renewal command with certz renew
- Add phase 7 implementation plan.
- Make allowed command execution less risky.
- Implement phase 6: Certificate expiration monitoring with certz monitor command
- Added phase 6 implementation plan for certificate expiration monitoring.
- Add partial thumbprint matching for trust remove command
- Implement phase 5: Enhanced chain visualization with --tree option
- Added phase 5 implementation plan.
- Merge branch 'feature/longterm' into upgrade
- Completed documentation for phase 4.
- Created a set of lint tests.
- Added phase 4 plan.
- Fixed tests for convert : cnv-1.3 and cnv-2.3.
- Organized tests.
- Created new tests for convert.
- Analysis and prompts.
- Removed legacy code.
- Update documentation to reflect completed MEDIUM TERM work
- Merge branch 'feature/mediumterm' into upgrade
- Enhance guided wizard with beautiful Spectre.Console UI
- Create specialized service classes for certificate operations
- Merge branch 'feature/refactorlegacy' into feature/phase3
- Migrate VerifyCertificate to options pattern
- Migrate ShowCertificateInfo to options pattern
- Migrate RemoveCertificate to options pattern
- Migrate ListCertificates to options pattern
- Migrate ExportCertificate (store overload) to options pattern
- Migrate ExportCertificate (URI overload) to options pattern
- Migrate ConvertFromPfx to options pattern
- Migrate ConvertToPfx to options pattern
- docs: Add comprehensive Claude prompt for future modernization work
- docs: Update refactoring plan with completion status
- Refactor: Move WriteCertificateToFile and InstallCertificate to CertificateUtilities
- Refactor: Extract utility methods to CertificateUtilities
- Completed phase 3 planning.
- Merge branch 'feature/phase2' into upgrade
- Completed phase 2.
- Fixed trm-1.4 when multiple matches exist.
- Added prefix of "certz" to certificates.
- Some of the tests were fixed by AI.
- Minor improvements to test result output and cleaning up certs.
- Fixed test output to console.
- Completed phase 2 steps 11-13.
- Completed phase 2 steps 1-10.
- Completed phase 2 planning.
- Merge branch 'feature/phase1' into upgrade
- Completed phase 1.
- Updated implementation plan.
- Let's not lose all this hard work.
- Minor improvements to documentation and defaults.
- Updated cre-2.2 to follow updated guidelines for tests.
- Fixed issue with failing tests.
- Use a strong password with less complicated code.
- Added TestId to the test output.
- Added build script for release notes.
- Added new defaults and parameters.
- Fixed filtering for categories.
- Improved error handling of tests.
- Fixed failing tests.
- Added option to export password to a text file.
- Updated to support more modern security standards and improved tests.
- Refactored codebase to better fit dotnet 10 styles.
- Added support for additional features.
- Fixed tests for the uri.
- Cleaned up files and migrated to newer command line api.
- All tests are passing now.
- First pass to add conversion command.
- Added support for exporting certificates from a url.

---

## File Verification

**File:** certz.exe
**SHA256 Hash:** `B2C6C7505B9ED816D0F3C0F3CB7ACA4F8439E1BA5480D82D9AC88885494B342E`
