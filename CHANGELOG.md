# Changelog

All notable changes to AgentShield are documented in this file.

## Unreleased — V1.7 evaluation foundations

### Added

- Complete source review, severity-ordered risk register and staged research plan.
- Independent synthetic evaluation for five principles, with HELD/FAILED/UNRUN,
  actual file/model/HTTP execution evidence, blocker attribution, clean-copy
  execution, fixed seeds, repeat runs, source hashes and JSON/CSV exports.
- Optional pinned IPv4-loopback transport and a controlled receiver. Default
  sends remain simulated; no DNS, proxy, redirect or third-party traffic is used
  by the experimental transport.
- Measurement tests that reject fabricated receipts, inconsistent logs and
  environment restrictions as proof of AgentShield success.

### Fixed

- Reject malformed destinations and non-string outbound arguments before tool
  execution; invalid policy encoding fails closed.
- Check lexical and resolved file names, carry the approved canonical path to
  file executors, and audit path-resolution failures.
- Stop the LLM tool flow cleanly on file decoding or local transport errors.

### Known limitations

- The independent baseline deliberately reports encoded/RSA detection misses,
  benign-marker false positives and unsupported model completion claims.
- Taint tracking, audit integrity protection and the four-arm research benchmark
  are not implemented in this first iteration. No release or safety certification.

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
