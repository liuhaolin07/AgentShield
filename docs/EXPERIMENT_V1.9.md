# V1.9 exploratory research evaluation

These are actual synthetic explicit-flow measurements, not a paper-ready claim
or a live-LLM security rate. The trusted runtime / bounded data-only agent
boundary is defined in [THREAT_MODEL.md](THREAT_MODEL.md) and
[SECURITY_BOUNDARY.md](SECURITY_BOUNDARY.md). Legacy V1.8 APIs and historical
results remain unchanged. The baseline is ecfa751; stages are separately committed.

## Frozen inputs and execution

The active dataset is agent-exfiltration-v1.9-2, authored seed 190017, with
120 development and 40 reserved tasks. Revision 1 and its generator remain:
an authoring test found duplicated normal texts before security experiments,
so a new revision was frozen. No failed security case or historical expectation
was deleted/reclassified. See [BENCHMARK.md](BENCHMARK.md) and
[freeze metadata](results/v1.9/benchmark-freeze.json).

Development ran on Linux / Python 3.12.14, seed 17, three repeats before the
candidate commit. Reports record 39 implementation/evaluator source hashes;
the committed candidate must match them before first reserved execution.
The report's HEAD field alone does not establish dirty-tree source identity.
Candidate c8eebca was committed before first reserved execution; its full identity
and matching source hashes are recorded in [candidate freeze](results/v1.9/candidate-freeze.json).
Reserved cases have not been used for implementation debugging. They share
operation families with development: this is not external blind attack-family
validation. Repeats reuse cases, not independent attacks.

```bash
python -m unittest discover -s test -p 'test_*.py' -v
python -m evaluation --experiment v1.9 --split development --seed 17 --repeat 3 --charts --output-dir logs/v19-development
python -m evaluation --experiment v1.9 --split reserved --seed 17 --repeat 3 --charts --output-dir logs/v19-reserved
python -m ci.validate_v19 logs/v19-development/report.json logs/v19-reserved/report.json
```

Charts require optional requirements-research.txt; runtime, experiments, CSV and
independent gate use stdlib. Genuine FAILED returns 1; UNRUN-only returns 2.
CI preserves intentional negative-control failures but rejects missing supported
observations, changed contracts/metrics or Full regressions on correctly labeled
supported contracts. A CI rerun of reserved inputs is a compatibility check,
not another independent first evaluation.

## Comparable mechanisms

All groups share frozen inputs, annotations, transforms, task contracts,
executors, handle protocol, loopback receiver and audit plumbing. Only trusted
configuration changes. HTTP uses pinned 127.0.0.1, without DNS or redirects.

| Baseline | Content mechanism | Integrity / propagation |
| --- | --- | --- |
| B0 No Defense | Enforcement off | Common issuance, no MAC/replay verification |
| B1 Static Rule | Legacy keyword rules | Same protocol, no MAC/replay verification |
| B2 Scanner | Bounded V1.7 scanner | Same protocol, no MAC/replay verification |
| B3 Taint | Source sink policy, scanner off | MAC/replay and explicit propagation |
| B4 Full | Scanner + source sink policy | MAC/replay and explicit propagation |

A1 = Scanner (remove provenance defense); A2 Source only retains the scanner
but deliberately discards labels after transforms; A3 Detect only records
scanner/taint without content enforcement (integrity/file/domain checks remain);
A4 = Full. Shared arms execute once: seven unique arms, not duplicated evidence.
These weakening flags are trusted local research configuration, never agent
parameters or the default AttestedRuntime behavior.

## Metrics, observations and exclusions

Two real canaries per arm/repeat, including fabricated-sensitive content, run
with enforcement off and must arrive before dependent cases. Receiver records,
sender entry, successful receipts and audits are cross-checked. A credited block
must precede executor entry with zero arrivals. Environment/absent observations
are UNRUN; invalid observations are FAILED but excluded from metrics.

ASR = exact prohibited payload arrivals / included attack assessments. ABR and
Recall = AgentShield pre-execution blocks / included attacks. TCR and task
success = actual completed exact send contracts / included benign assessments.
FPR = benign pre-execution blocks / included benign assessments. Precision =
attack blocks / all attack + benign blocks. Zero denominators are null/UNKNOWN.
Controls and UNRUN are excluded with counts. Exact wire matching cannot measure
arbitrary paraphrased leakage; send-contract TCR is not general task semantics.

Latency includes actual read, transforms, gate and local network execution,
excluding fixture/runtime setup. Additional latency pairs only benign tasks
completed in both arms with equal executor counts, against B0. Gate timing
includes integrity/policy/audit. tracemalloc measures instrumented Python peak
allocations, not RSS; negative paired differences from noise are retained.
Common issuance cost is shared: these are conditional incremental costs, not
complete production overhead. No live inference: token overhead null/UNRUN.
No significance or confidence-interval claim is made for this authored suite.

## Actual development results

2,520 assessments: HELD 1,122 / FAILED 1,020 / UNRUN 378. Per arm: 360 records;
54 unsupported and six controls excluded; 246 attacks (82 unique supported × 3)
and 54 benign (18 × 3) included.

| Group | HELD / FAILED / UNRUN | ASR | ABR / Recall | TCR | FPR | Precision |
| --- | --- | --- | --- | --- | --- | --- |
| No Defense | 60 / 246 / 54 | 246/246 | 0/246 | 54/54 | 0/54 | 0/0 UNKNOWN |
| Static Rule | 90 / 216 / 54 | 198/246 | 48/246 | 36/54 | 18/54 | 48/66 |
| Scanner | 147 / 159 / 54 | 159/246 | 87/246 | 54/54 | 0/54 | 87/87 |
| Taint | 288 / 18 / 54 | 12/246 | 234/246 | 48/54 | 6/54 | 234/240 |
| Full | 294 / 12 / 54 | 6/246 | 240/246 | 48/54 | 6/54 | 240/246 |
| Source only | 183 / 123 / 54 | 123/246 | 123/246 | 54/54 | 0/54 | 123/123 |
| Detect only | 60 / 246 / 54 | 246/246 | 0/246 | 54/54 | 0/54 | 0/0 UNKNOWN |

Full vs A1/A2/A3/A4 adds 153/117/240/0 attack blocks and 6/6/6/0 benign
blocks (300 matched assessments each). Security benefit and utility cost both
remain visible. Detect-only observation provided no content blocking.

Mean paired additional benign latency, ms (pairs): Static 0.491 (36), Scanner
0.992 (54), Taint 2.630 (48), Full 2.800 (48), Source only 3.733 (54), Detect
only 2.809 (54). Full's Python peak delta is -3,683.4 bytes over 48 pairs:
this noise-sensitive negative difference does not establish memory advantage.
Unrounded data, category strata and exclusions: [summary](results/v1.9/development-summary.json),
[metrics CSV](results/v1.9/development-metrics.csv),
[ablations CSV](results/v1.9/development-ablations.csv).

![Actual development outcomes](figures/v1.9/development-outcomes.svg)

## First reserved results (no implementation tuning)

840 assessments: HELD 339 / FAILED 354 / UNRUN 147, with zero invalid supported
observations. Each arm has 120 records: 21 unsupported and six controls excluded,
leaving 81 attacks (27 unique supported × 3) and 12 benign (four unique × 3).
The report HEAD is the committed candidate c8eebca; all 39 implementation and
evaluator hashes match development and remain unchanged after this execution.

| Group | HELD / FAILED / UNRUN | ASR | ABR / Recall | TCR | FPR | Precision |
| --- | --- | --- | --- | --- | --- | --- |
| No Defense | 18 / 81 / 21 | 81/81 | 0/81 | 12/12 | 0/12 | 0/0 UNKNOWN |
| Static Rule | 27 / 72 / 21 | 66/81 | 15/81 | 6/12 | 6/12 | 15/21 |
| Scanner | 45 / 54 / 21 | 54/81 | 27/81 | 12/12 | 0/12 | 27/27 |
| Taint | 87 / 12 / 21 | 6/81 | 75/81 | 6/12 | 6/12 | 75/81 |
| Full | 90 / 9 / 21 | 3/81 | 78/81 | 6/12 | 6/12 | 78/84 |
| Source only | 54 / 45 / 21 | 45/81 | 36/81 | 12/12 | 0/12 | 36/36 |
| Detect only | 18 / 81 / 21 | 81/81 | 0/81 | 12/12 | 0/12 | 0/0 UNKNOWN |

Full's three leaks are one incorrectly public opaque source × three repeats.
Its six benign failures are two public projections × three repeats. Four unique
normal cases are too few for a population FPR estimate, but **6/12 observed
false blocks / 50% task completion is a material utility limitation**. It is
neither removed from the denominator nor described as a defense success.

Full vs A1/A2/A3/A4 adds 51/42/78/0 attack blocks and 6/6/6/0 benign blocks
(93 matched assessments each). Full's paired benign additional latency is
2.164 ms over only six pairs. Static's -1.126 ms paired delta is retained noise,
not a speedup claim; other exact costs and memory deltas remain in the
[reserved summary](results/v1.9/reserved-summary.json) and CSVs.

![Actual first reserved outcomes](figures/v1.9/reserved-outcomes.svg)

## Retained failures and missing coverage

Full's six actual leaks are two opaque sources incorrectly labeled public,
repeated three times. Signed labels authenticate assignment, not classification
correctness. Scanner catches recognizable misclassifications but not opaque ones.
Full's six benign blocks are two public projections from sensitive aggregates;
conservative parent unions retain sensitivity. Both remain FAILED, not relabeled
as desired behavior. Precise field taint/declassification are unimplemented.
Static Rule's 18 benign blocks expose keyword false positives.

Prompt injection, rot13/hex, implicit flows and model rewrites remain UNRUN in
this scripted benchmark. Tool/model relays validate actual boundaries, not
inference. The separate three-task DeepSeek/Qwen model-driven interface uses
model-selected tools; user selected deepseek-flash (v4-pro also selectable).
No available credential: all nine live assessments are UNRUN missing_credential,
with [raw report](results/v1.9/live-unrun.json). Model names/access are not
confirmed by any successful provider response; fixture-client unit tests are
not real-model evidence.

## Evidence and research scope

Full JSON/CSV are preserved as deterministic gzip in [results/v1.9](results/v1.9/),
with uncompressed JSON SHA-256 in summaries, containing only synthetic fixtures.
Smaller CSVs omit payloads. Original V1.7/V1.8 reports are separately preserved;
historical datasets/results hashes are unchanged. Mutable logs plus consistency
checks are not signed append-only execution proof. The stdlib independent gate
imports no defense/runtime/calculator and recomputes fractions, paired costs
and ablations; six mutation tests reject forged/changed observations.

Local regression: **199 pass, zero failures/skips**, baseline 143. V1.7 remains
HELD 82 / FAILED 0 / UNRUN 4; V1.8 per-arm development states unchanged.
See [validation](results/v1.9/validation.json).

Evidence supports constrained explicit lineage enforcement under trusted labels,
data-level stripping resistance, scanner/taint complementarity and measured
security/utility tradeoffs. It does not establish malicious-Python isolation,
adaptive injection robustness, live-model utility or generalizable security
rates. [RELATED_WORK.md](RELATED_WORK.md) explains limits of novelty. Submission
needs actual multiple-provider models, external tasks/attack authors, attack-family
holdouts, adaptive adversaries, source accuracy/field taint/declassification,
complete resource costs, independent replication and uncertainty over independent
tasks. No main merge or release.
