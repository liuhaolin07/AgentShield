# Changelog

All notable changes to AgentShield are documented in this file.

## v1.6.1 — 2026-10-01

### Fixed

- **URL-field coverage**: outbound `http` / `model` calls now scan the `url`
  field for sensitive data. Previously only `data` was scanned, so a secret
  placed in a query string or path could bypass the check.

### Added

- Regression tests for the URL-field fix: a secret-in-URL attack case and a
  benign-URL-with-query control case.
- GitHub Actions CI (`.github/workflows/ci.yml`) running the offline test
  suite on Python 3.10, 3.11 and 3.12.
- MIT license (`LICENSE`).

### Changed

- Added packaged `__init__.py` files for `agent/`, `model/`, `security/`
  and `tools/`.
- README: CI and license badges, version bumped to V1.6.1, test count
  updated (eighteen).
