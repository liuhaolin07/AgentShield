# Changelog

All notable changes to AgentShield are documented in this file.

## Unreleased

### Fixed

- **Scanner false positives**: the `sk-` key pattern had no word boundary or
  minimum length, so ordinary words like `task-123` or `risk-2026` matched and
  were blocked as `sensitive_data` — killing LLM-loop model calls whose
  serialized payload contains the user task text. The pattern now mirrors the
  redaction patterns in `model/dots_client.py` (`\bsk-[a-zA-Z0-9_-]{8,}\b`).
- **Symlink dodge of `blocked_files`**: blocked-name matching only saw the
  caller-supplied path, so a benign-named symlink (e.g. `notes.txt` → `.env`)
  could reach a blocked target. The middleware now checks the resolved path
  against the blocked-name list too.

### Changed

- `load_policy` caches parsed policies per path, revalidated against the
  file's `(st_mtime_ns, st_size)` fingerprint — ~5.5x faster on hot
  middleware loops with identical on-disk-change semantics; errors are never
  cached.
- The deterministic demo (`python main.py` without `--llm`) now exits with
  code 2 when a call is blocked, matching the `--llm` mode.

### Added

- Regression tests for the scanner fix (unit and model-payload level), the
  symlink dodge (skipped where the platform cannot create symlinks), and the
  policy cache (change detection, object reuse).

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
