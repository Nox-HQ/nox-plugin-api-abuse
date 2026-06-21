# Changelog

All notable changes to this project will be documented in this file.

## [0.3.0] - Unreleased

### Added
- API-ABUSE-006 BFLA (privileged/admin route without role check, CWE-285) + role-check mitigation.
- Negative fixtures (testdata/safe/) + FP guard (TestSafeHandlersNoFindings).

### Fixed
- API-ABUSE-001 no longer flags role-checked admin routes (e.g. , requireRole) as missing-auth (a role check implies authentication).


- chore: add CI/CD, lint config, pre-commit hooks, and fix lint issues
- chore: add LICENSE, .gitignore, and tidy go.mod

