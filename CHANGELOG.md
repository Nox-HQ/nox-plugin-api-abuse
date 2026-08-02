# Changelog

All notable changes to this project will be documented in this file.

## [0.2.3] - 2026-08-02

### Fixed
- API-ABUSE-001 now requires the handler body to perform a **sensitive
  operation** before reporting a missing auth check. Matching any handler at
  all meant every route on a router — health checks, static file serving,
  redirects — was reported as unauthenticated, which is where most of this
  rule's false positives came from.

### Changed
- nox SDK and the CI action pin both move to v1.26.0. `go.mod` had sat on
  v1.17.0 while the action pin advanced independently; they are now bumped
  together so the plugin builds against the same nox that scans it.
- Picks up `golang.org/x/net` 0.57.0, `x/sys` 0.47.0 and `x/text` 0.40.0.

## [0.2.2] - 2026-07-20

### Changed
- nox SDK v1.13.0 (loopback bind + gRPC token auth).

## [0.2.1] - 2026-07-05

### Added
- API-ABUSE-006 BFLA (privileged/admin route without role check, CWE-285) + role-check mitigation.
- Negative fixtures (testdata/safe/) + FP guard (TestSafeHandlersNoFindings).

### Fixed
- API-ABUSE-001 no longer flags role-checked admin routes (e.g. `requireRole`) as missing-auth (a role check implies authentication).

## [0.2.0]

- chore: add CI/CD, lint config, pre-commit hooks, and fix lint issues
- chore: add LICENSE, .gitignore, and tidy go.mod

