# Changelog

All notable changes to AgentShield are documented in this file.

## Unreleased — V1.7 evaluation foundations

### Added

- Frozen `v1.7-synthetic-2` dataset: 43 explicit cases, including multilayer
  encoding, nested/escaped JSON, token/key headers, encoded tool output, normal
  encoded documents/API parameters and resource-budget controls. Expanded
  baseline committed and executed before defense changes.
- `inspect_sensitive` with sanitized transformation findings and configurable
  positive resource limits; compatible `scan_sensitive` boolean guard retained.
- Structured `AgentRunResult` and `ToolEvidence`, explicit required-tool and
  real-HTTP completion contracts; simulations are labeled separately.
- JSON/CSV before/after comparison that rejects changed expectations, inputs,
  policies, limitations or oracle versions and retains every case/run.
- Scanner resource/false-positive tests, evidence/protocol regression tests,
  a dishonest-completion measurement mutation test and CI evaluation gate.
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

- Decode bounded layers of URL/Base64 and structured JSON before outbound HTTP
  or model requests; recognize RSA/DSA/EC/OpenSSH/encrypted/PKCS#8 private keys.
  Duplicate JSON keys and escaped credential keys cannot hide earlier values.
- Ordinary PASSWORD documentation, public-key text, schema objects, redaction
  placeholders and unrelated API/cursor parameters no longer trigger the
  tested false positives. Recognizable credential assignments still block.
- Model final messages alone no longer return successful tool-work completion.
  Failed tools and simulated sends cannot prove real delivery. Existing CLI
  options and boolean API remain; incomplete LLM runs return exit code 2.
- Reject malformed tool batches before execution, cap batch size/argument
  length, and audit unsupported agent tool names with fixed safe metadata.
- Reject malformed destinations and non-string outbound arguments before tool
  execution; invalid policy encoding fails closed.
- Check lexical and resolved file names, carry the approved canonical path to
  file executors, and audit path-resolution failures.
- Stop the LLM tool flow cleanly on file decoding or local transport errors.

### Known limitations

- Historical raw baselines are preserved. Actual Linux/Python 3.12 validation:
  92 tests pass; expanded seed=17/repeat=2 evaluation improves from
  HELD 40 / FAILED 42 / UNRUN 4 to HELD 82 / FAILED 0 / UNRUN 4. See
  `docs/ITERATION2.md`; synthetic counts are not population metrics.
- Scanning is heuristic, with explicit fail-closed resource rejections;
  arbitrary transforms, split calls, generic token identifiers and semantic
  task satisfaction are not reliably tracked. No complete information-flow claim.
- Taint tracking, audit integrity protection and the four-arm research benchmark
  are not implemented. No release or safety certification.

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
