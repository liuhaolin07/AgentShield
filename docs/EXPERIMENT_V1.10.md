# V1.10 frozen research protocol

The V1.9 baseline is commit `5cd84705b2ebfef3b142c75ff7826250e769bd3f`.
`docs/results/v1.10/baseline-freeze.json` records all historical artifact and
source hashes, environment and actual baseline re-execution. V1.7/V1.8/V1.9
contracts/results are immutable. New authored contracts are frozen before new
benchmark executions in `benchmark/datasets/v1.10/precision-manifest.json`:
43 development and 20 reserved tasks, seed 110017 for authoring metadata;
execution seed 17, three repeats. These are distinct semantic mechanism tasks,
not a population sample or external blind benchmark. No model sampling is used.

Six primary arms share source declarations, operations, policy, handles, actual
file/tool executor and pinned HTTP receiver. No Defense disables content policy,
not common metadata integrity or the transport safety harness. Static Rule is
frozen V1.7 raw matching. Scanner is the bounded V1.7 scanner. Coarse applies the
V1.9-style union-of-container/parent labels in the V1.10 authenticated runtime
with the same source registry; it is **not** historical V1.9 absolute performance.
Precision disables the scanner, and Full enables scanner plus precision.
Coarse disables scoped releases; precision/full enable the same frozen trusted
release rule only for the designated public projection. All arms attempt the
same release call; disabling it retains the original handle and audit evidence.

Six ablations remove source labels AND uncertainty enforcement (`no_source`),
transform propagation, field precision, scoped releases, scanner (identical to
Precision, not separately re-executed), or enforcement (Detection Only). Trusted
local-only research switches are inaccessible to AgentPort; their values are
MAC-bound. Identical public and private measurement canaries bypass content
enforcement in **every** arm, establishing receiver reachability without claiming
defense. Their results are excluded from attack/utility denominators.

The independent plaintext contract builder imports no scanner/taint/runtime.
Frozen expected wire strings, source identity, classification ground truth,
operation list and sink kind never enter defense decisions. Source execution,
pre-send candidate equality, authentic transform chain, separate scanner/taint/
classification decisions, actual executor entry, independent receiver arrival,
response receipt and audit/decision equality are recorded per assessment.
Model sinks here are real loopback transport probes for the model boundary,
**not** genuine model inference. Actual inference uses the separate opt-in
`evaluation.live_precision` study; scripted clients appear only in unit tests.

HELD requires the frozen contract and verified observations. FAILED retains real
leaks, false blocks and evaluation errors. UNRUN excludes unsupported third-party
operations, implicit flows, semantic rewrites and missing execution observations;
none receive defense credit. `ci.validate_v110` independently checks frozen
cohorts, sources/operations, arrivals, audits, module attribution, numerators,
denominators, task intervals and instrumented cost. It rejects missing supported
observations; matching a report is not third-party signed authenticity.

ASR = attacks delivered / observed supported attacks. ABR/recall = verified
pre-execution blocks / observed supported attacks. TCR and normal execution
success = correctly delivered legitimate outputs / observed supported benign
tasks. FPR = verified benign blocks / observed supported benign tasks. Precision
= attack blocks / (attack blocks + benign blocks). Controls, UNRUN and invalid
evidence are excluded and listed explicitly. An unblocked attack is not a
successful benign task. Classification profiles retain wrong-public, wrong-field,
missing, unknown, conflict, correct and conservative annotations independently.

Assessment fractions describe all repeats. Uncertainty uses **unique task**
clusters: ASR/FPR mean any observed repeat leaked/blocked; TCR/ABR mean all
observed repeats completed/blocked. Wilson 95% intervals use unique task counts,
never repeat counts. Zero leaks yield a nonzero upper bound. These intervals
are descriptive and rely on an IID approximation that authored dependent tasks
do not justify as a generalization guarantee. No significance claim is made.

Cost includes actual end-to-end time (fixture setup + execution + evidence
verification), gate time (integrity + classification + policy/audit), explicit
transform issuance/replay time, and per-case Python `tracemalloc` peak (not RSS,
not a peak across process lifetime). All arms run with tracing. Matched extra
cost uses only benign tasks completed by both arms with equal executor counts,
so skipped network execution is not claimed as a speedup. Noise can give
negative deltas. Peak/duration include observer overhead; they are exploratory
instrumented costs, not production overhead. Live-model tokens/billing are null
unless actually reported by a provider; current paid calls are zero.

```bash
python -m unittest discover -s test -p 'test_*.py' -v
python -m evaluation.precision_experiment --split development --seed 17 --repeat 3 --charts --output-dir logs/v110-development
python -m ci.validate_v110 logs/v110-development/report.json
# Only after candidate implementation is committed: first reserved evaluation.
python -m evaluation.precision_experiment --split reserved --seed 17 --repeat 3 --charts --output-dir logs/v110-reserved
python -m ci.validate_v110 logs/v110-reserved/report.json
python -m evaluation.live_precision --output-dir logs/v110-live-disabled
```

Experiment commands intentionally exit 1 when any FAILED survives, or 2 for
UNRUN only. Independent evidence gates validate observations without hiding
failures. Optional figures use `requirements-research.txt`; core needs stdlib only.
Raw JSON/CSV, computed metrics/ablations/failure CSV and SVG are saved completely.
Compressed committed artifacts are exact raw outputs; manifest hashes permit
verification after decompression. Original failed development smoke/tests are
retained; fixing observer tuple/list normalization and a copied trace list did
not change contracts, runtime decisions or expected outputs.

The reserved split must first run after a committed implementation candidate.
Unit tests execute development only. Record candidate SHA and source hashes
before the first reserved run; then freeze implementation. If reserved results
are used to change code/policy, relabel that cohort development evidence. Later
CI executions are compatibility checks, not new independent blind tests.
