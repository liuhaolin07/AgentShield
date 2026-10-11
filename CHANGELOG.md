# Changelog

All notable changes to AgentShield are documented in this file.

## Unreleased — V1.10 precision evaluation

- Immutable bounded field/element/character dependencies, exact JSON/Base64/URL
  witnesses, replayed narrowing and scoped trusted original-source releases.
- Authenticated explicit source classification/uncertainty, independent source/
  payload/sink attack oracle, multi-round guarded model tool loop and bounded
  opt-in provider budget using existing DeepSeek/Qwen adapters.
- New frozen 43-development / 20-reserved contracts, six baselines/six ablations
  (11 unique arms), actual local HTTP evidence, unique-task uncertainty,
  complete JSON/CSV/SVG, separate cost/measurement controls and independent gate.
- Actual Full development ASR 9/63, TCR 42/51, FPR 9/51; first untouched reserved
  ASR 6/24, TCR 21/24, FPR 3/24. Coarse FPR 39/51 and 21/24 decreases, but wrong
  public granular labels add real leaks (reserved Coarse ASR 3/24). Failures remain.
- Genuine model study: 36 UNRUN, missing credentials, zero API calls, no invented
  usage/cost. Paid calls stay off by default even when credentials exist.
- 271 tests pass; 49 historical artifact and 61 old Python source hashes unchanged.
  V1.7/V1.8/V1.9 compatibility validated. Candidate 196bedc preceded first new
  reserved observation; no implementation tuning after it. CI uploads failures.
- Updated source/precision/threat/research/experiment documentation and bilingual
  README. Mature taint/declassification techniques are not claimed as novel;
  correct-label mechanism benefit does not establish unconditional security.

## V1.9 research hardening — historical development

- Session-issued immutable handles, keyed source hashes/HMAC and replayed
  transform-chain verification; bounded data-only AgentPort rejects manual
  wrappers, label stripping, fake literals, cross-session/source mismatch.
  Trusted runtime boundary only, not unrestricted Python isolation.
- Opt-in stdlib DeepSeek/Qwen real-model tool loop, fixed official endpoints,
  bounded tool schemas/budgets and model-payload checks; user-selected
  deepseek-flash. Missing credentials: nine live assessments UNRUN, no fabricated
  model/token evidence. Legacy Dots/CLI and V1.8 API remain compatible.
- Frozen 120-development / 40-reserved authored benchmark, independent authoring
  oracle, pinned hashes and preserved initial revision/authoring failure.
- Five baselines, four ablations (seven unique arms), real local receivers,
  separate detection/enforcement attribution, actual fractions/exclusions,
  paired instrumented latency/Python allocation measurements and JSON/CSV/charts.
- Independent stdlib evidence gate and mutation tests, CI evidence artifacts,
  threat/boundary/benchmark/experiment and research-positioning documentation.
- Actual development: 2,520 assessments; Full ASR 6/246, TCR 48/54, FPR 6/54;
  misclassification and coarse-taint failures retained. Exploratory mechanism
  evidence, not general prompt-injection security or submission-ready results.
- Local validation: 199 tests pass, zero failures/skips; V1.7/V1.8 states unchanged.
  First reserved run after candidate c8eebca: Full ASR 3/81, TCR 6/12, FPR 6/12;
  Scanner ASR 54/81. All implementation hashes match development and candidate;
  no tuning on reserved outcomes. Full false positives remain a material limit.

## V1.8 explicit source-aware taint MVP — historical development

### Added

- Immutable bounded TaintedValue, TaintLabel, SourceRecord, ProvenanceRecord,
  SinkTarget, TaintPolicy and TaintDecision with stable lineage IDs and scoped
  output constraints, independent of string-pattern recognition.
- Explicit concat/slice, list/dict composition/access, JSON/Base64/URL roundtrips,
  conservative source unions, sticky lost/unsupported states and strict raw-sink
  handling. No arbitrary Python or implicit-flow tracking claim.
- Optional TaintContext source classification, `--taint-config`, guarded runtime
  and deterministic explicit-flow agent. Confidential readable files and tool
  outputs are checked before HTTP or next model request; known read denials remain.
- Separate sanitized scanner/taint audit observations with source categories and
  provenance explanations; bounded tracked file/config reads.
- Frozen 23-case development and 11-case authored holdout datasets, pinned SHA-256,
  common four-arm executors/contracts, actual loopback observations, exploratory
  ASR/TCR/FPR/precision/recall and paired gate latency with numerator/denominator
  and exclusion reporting. Candidate committed before first holdout execution.
- Complete JSON/CSV exports, optional matplotlib research figures, durable
  payload-free result summaries and CI evidence gates/artifacts on three Python
  versions. Runtime/evaluation remain standard-library only.
- Core/propagation, real sink, source-scoping, CLI compatibility, measurement
  mutation and negative-control tests. Actual local validation: **143 tests pass**;
  V1.7 remains HELD 82 / FAILED 0 / UNRUN 4 with unchanged contracts.

### Observed experiments and limits

- Three repeats: development Scanner ASR 36/42 versus Scanner+Taint 0/42,
  both TCR 18/18; first untouched holdout Scanner 12/15 versus Taint 0/15,
  both TCR 12/12. Other arms' real failures and unsupported UNRUN remain visible.
  See `docs/EXPERIMENT_V1.8.md` for all metrics, statuses and artifacts.
- Explicit enforcement depends on accurate trusted source classification.
  Misclassified sources and privileged relabeling demonstrably allow delivery.
  Coarse labels can overtaint projections; declassification, arbitrary transforms,
  implicit flows, real agent reasoning, live-provider confinement, filesystem
  races and audit integrity remain open. No release or broad safety certification.

## V1.7 evaluation foundations — historical development baseline

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
