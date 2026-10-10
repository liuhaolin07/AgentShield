# V1.8 baseline review and frozen experiment contracts

Base: `codex/v1.7-independent-evaluation`, `d1e0552949570a657955420c7b294e728a52866d`.
V1.8 changes are isolated on `codex/v1.8-taint-tracking`; historical V1.7 docs,
datasets and recorded results are retained unchanged.

Verified 2026-10-10 on Linux/Python 3.12.14: **92 tests passed**; V1.7 independent
evaluation seed=17/repeat=2 produced **HELD 82 / FAILED 0 / UNRUN 4**, exit 2.
Raw output, JSON/CSV and invocation metadata are in `logs/v1.8/baseline/`.

Reviewed the agents, CLI, policy, capability registry, middleware, scanner,
audit writer, file/HTTP/model executors, independent cases/runner/comparator,
receiver, existing tests, CI and V1.7 boundary documents. Actual V1.7 behavior:

| Capability | Confirmed implementation | Remaining gap |
| --- | --- | --- |
| Policy/middleware | Checks supplied agents' file/HTTP/model operations; canonical path and malformed inputs fail closed | Direct Python tool calls are unmediated; check/open race persists |
| Scanner | Bounded JSON/URL/Base64 views with separate `scan_limit` | No source state; arbitrary opaque confidential strings are not necessarily recognized |
| Real experiments | Pinned numeric 127.0.0.1 transport and actual arrival records | Not a production HTTP client; provider redirects remain outside this boundary |
| Evaluation | Explicit contracts, reachability controls, HELD/FAILED/UNRUN, JSON/CSV, source hashes | No four-arm dataset/metrics or implicit flow coverage yet |
| Completion | Separate model termination and successful executor evidence | Default tool-work completion does not establish arbitrary task semantics |
| Audit | Decisions omit arguments/payloads and are checked against independent effects | Unsigned mutable logs; no cryptographic execution proof |

V1.8 must add an explicit tracking domain, not replace these components. Values
and lineage are immutable, source identities derive from logical references
rather than content, and operations retain all parent labels. Coarse aggregate
labels intentionally overapproximate slices/projections. Strict tracked sinks
reject missing/unsupported metadata, but a trusted caller can reclassify or forge
metadata; this is not enforcement against malicious Python in the process.

The frozen `evaluation/datasets/` contracts are authored independently of the
taint/scanner code. The development split includes opaque confidential values,
known scanner fixtures, public controls, loss of wrappers and unsupported flows.
The additional holdout is frozen with SHA-256 before integration. It must not be
executed for debugging. Freeze/commit the complete candidate harness and run
holdout only afterward; repairs following that result invalidate the split's
independent status. Authored holdout is not an external blind benchmark.

Stages: (1) core/operation tests and commit, (2) guarded file/tool/HTTP/model
integration and cross-step tests/commit, (3) unified four-arm measurements,
metrics/charts and candidate freeze before holdout, (4) full V1.7 regression,
documentation, CI and final commits. Each component's tests precede its commit.
Unsupported flows stay UNRUN, never counted as successful taint defense.
