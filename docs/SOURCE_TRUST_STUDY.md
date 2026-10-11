# V1.10 follow-up: source trust before another version

V1.10 commit `f7c706f40e52a76c7fa9977dc2a72a9fe71ca359`, including its
implementation, datasets, documentation, CI and observed results, is frozen.
`results/source-trust/v1/frozen-v110.json` hashes the entire tracked baseline.
This branch adds files; it does not change any V1.10 artifact or re-score the
historical dataset. It is not V2.0 or a production-default change.

Research order is source-classification trust → measured security/utility
tradeoffs → genuine agents when usable credentials and opt-in are available →
independent authorship/external benchmarks and adaptive attacks. Current 36 live
UNRUN observations cannot estimate model adoption or defense effectiveness.

The first follow-up uses frozen new synthetic contracts and the existing
PrecisionRuntime, guarded file executor, scanner and independent loopback
receiver. All three strategies have scanner ON, identical operations and source
declarations. Coarse unions dependencies; current precision uses the unchanged
V1.10 defaults; conservative precision changes only MIXED's otherwise-undeclared
value sensitivity to True. Explicit PUBLIC fields still override, including a
PUBLIC container's inherited classification. Structure/implicit-flow labels are
not made sensitive merely to force blocking. No trusted release is used here.
The treatment and effective registry are recorded separately from frozen input.

Evaluate omitted private labels, incorrect field labels in both directions,
incorrect whole-source PUBLIC, incomplete nested/list schemas, missing and
unknown sources, plus correctly classified public/private paired tasks. Include
unannotated genuinely public values to measure conservative-default cost, and
PUBLIC-parent schema extension to expose an adaptive boundary. Classification
truth is independently authored, never inferred from the scanner or HMAC.

No zero-leak premise or acceptance gate is imposed. Attack delivery, pre-execution
blocking, legitimate completion and false blocks are measured against frozen
source/selector/payload/sink contracts and actual arrivals. Measurement controls
send both public and private synthetic canaries with content enforcement OFF in
every strategy; all primary cases traverse the middleware. Missing observations
are UNRUN and input/evaluation errors receive no defense credit. Repeats describe
stability, not independent attacks; profile rates and Wilson intervals use unique
tasks. The dataset is author-constructed development evidence, not independent
research validation, and has no holdout/official external score claim.

The third stage requires existing credentials, explicit live opt-in and verified
provider prices/budgets, using evaluation.live_precision. Fourth-stage external
samples require a pinned upstream revision, actual license/provenance, unchanged
attack objectives, separate adaptation records and independent authors. Reading
AgentDojo or authoring adaptive examples does not satisfy that requirement.
Neither stage is represented by scripted-model numbers.
