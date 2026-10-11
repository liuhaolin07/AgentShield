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

## Actual V1.10 source-policy sensitivity

Full development: correct classification ASR 0/42; incorrect PUBLIC 3/6;
incorrect field 3/3; unknown-source ALLOW leaks 3/3 while unknown-source BLOCK
leaks 0/3. Missing/conflicting private declarations each leak 0/3. Normal unknown
BLOCK and REQUIRE_REVIEW each falsely block 3/3 public tasks; the reason is
explicit and independently measured. Full reserved: correctly classified ASR
0/15; missing 0/3; wrong PUBLIC 3/3; wrong element 3/3; conflicting normal data
is blocked 3/3. Repeats are not independent classification samples.

Coarse accidentally protects the wrong-field/element fixtures through another
field's private annotation. Fine projection removes that unrelated dependence,
exposing the annotation mistake. This is not forged metadata or a sink execution
bypass, and HMAC is functioning correctly. It is a genuine safety/utility
tradeoff under erroneous trusted classification. No source-accuracy oracle or
automatic trustworthy PUBLIC inference is claimed. The scanner recovers one
known-key misclassification in development; it cannot repair unknown-format
public labels. Removing source policy/labels raises ASR from 9/63 to 60/63 in
development and from 6/24 to 24/24 in reserved. All groups keep legitimate public
traffic and the same local receiver; success is not manufactured by banning HTTP.
