# V1.10 source-classification experiments

Four independent questions are recorded: metadata integrity, initial declaration
correctness, dependency propagation and pre-execution sink enforcement. A valid
HMAC proves consistent issuance, not truth of a PUBLIC label. Deliberately public
opaque private fixtures actually arrive; this failure remains measured.

SourceRegistry is immutable trusted configuration, separate from read permissions.
PUBLIC/SENSITIVE/MIXED plans declare full/field/range layouts. UNKNOWN, MISSING
and conflicting declarations do not guess from strings. Default uncertainty
policy BLOCK denies at sinks before sender entry; REQUIRE_REVIEW denies with a
distinct review-required reason (no automatic human approval); ALLOW explicitly
trades safety for utility. A valid narrowly authorized trusted release can satisfy
review for that particular projection and target. All statuses and active source
IDs are authenticated, propagate with relevant dependencies, and are audited
without raw values/references. Unused uncertain elements do not pollute a known
projection under precise propagation. Coarse propagation intentionally preserves
broader dependence for comparison.

File/tool wildcard declarations are rejected; dynamic model references may use
an explicit model-only plan. Wrong paths become MISSING. Invalid configuration,
nonfinite/duplicate-key structured inputs and malformed/oversized tool values
reject. The runtime never infers public sensitivity from harmless output. Trusted
model adapters conservatively use one whole-result label and inherit request
dependencies: field-precise semantic model output is not claimed.

Unknown-public normal controls quantify false blocking; registered-public normal
controls must actually arrive. Correct private, wrong PUBLIC, missing, conflicting,
unknown, wrong-path config and malformed tool controls are separately tested.
No Defense/Scanner do not gain source-policy enforcement; detect-only records
would-block decisions without blocking. Runtime flags/registry are inaccessible
to the data-only agent. Unknown handling reduces unclassified-source exposure
but cannot repair an explicitly wrong trusted public declaration. Root/runtime
mutation, arbitrary Python and semantic model inference remain out of scope.
