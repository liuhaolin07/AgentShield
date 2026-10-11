# V1.10 precision-aware explicit provenance

This opt-in runtime extends the existing guarded executor; V1.7/V1.8/V1.9
interfaces and historical contracts stay unchanged. SourceLayout is trusted
configuration: it describes field/element sensitivity, character ranges, JSON
format and container structure. Public fields/ranges must be declared at ingress;
no scanner match or harmless-looking substring removes sensitivity.

PrecisionValue is an immutable bounded dependency tree with character spans and
container ambient/shape dependencies. Dictionary/list projections and list/string
slices select relevant dependencies plus ancestor shape dependencies. Concat and
composition union only participating pieces. JSON serialization maps encoded
characters to source dependencies. Exact unchanged JSON/Base64/URL roundtrips
restore a verified metadata witness; unrelated decoding conservatively unions
all dependencies. Base64 groups conservatively union their three input bytes,
including Unicode contributions. Unsupported operations raise, never return public.

ValueHandle is session-issued. A separate precision attestation binds data,
field/range dependencies, witnesses, trusted settings and release grants. The
runtime verifies HMAC, issuance, parents and replayed narrowing semantics before
the existing scanner/taint middleware and shared executor. Bounds include old
64 Ki-character / depth-16 value limits, 128 direct node/child limits, 512 spans,
32 source labels/parents, 512 attestation snapshots, 128 chain nodes and the
old 512-entry / 8 MiB charged registry. Oversized operations reject; budgets do
not prove constant CPU time or protect against unrestricted trusted Python.

Trusted declassification is a narrowly scoped release, not untaint(). A frozen
DeclassificationRule binds original source/category, immediate projection/slice
operation and exact parameters, and one sink kind/origin. Only trusted runtime
code can apply it; AgentPort has no release/mint/literal tool. Grants are sealed,
audited without raw content, apply only at the declared sink and are revoked
by later transforms. Scanner decisions still apply. Wildcard targets and projections of recomposed/derived containers are rejected; original labels remain in provenance and unrelated sources,
selectors, operations or destinations are denied.

Metadata authenticity, source classification correctness, propagation correctness
and sink execution are distinct. HMAC cannot correct bad source policy. Unknown
JSON and transforms stay conservative, shape/selection/length implicit flows and
model semantics are not tracked. Same-process Python introspection/root/runtime
mutation remain outside the data-only boundary. The legacy API has not become
a sandbox. Public parameter literals have no inferred protected origin; external
unwrapped data and model-generated semantic reconstruction remain limitations.

## Supported precision contracts and verified benefit

| Operation | Dependency behavior | Conservative boundary |
| --- | --- | --- |
| dictionary/list access | selected leaf + ancestor structure labels | secret selection/index information is an implicit flow |
| string/list slice | selected declared character/element labels | empty secret slices retain labels; no length-channel guarantee |
| concat/list/dict | participating pieces, independently projectable | unwrapped Python/library composition is not tracked |
| JSON encode/decode | character escaping + exact unchanged witness | independently produced JSON strings union all dependencies |
| Base64 encode/decode | three UTF-8 bytes per quartet + verified inverse witness | arbitrary decode conservatively unions labels |
| URL encode/decode | per-character percent encoding + verified inverse witness | altered encoded text cannot reuse a narrowing witness |
| scoped release | original source, immediate projection, exact operation/parameters/sink | recomposed containers, wildcard sinks and agent release requests denied |

The same frozen V1.10 tasks show Coarse → Full FPR 39/51 → 9/51 development
and 21/24 → 3/24 reserved. Ten development and six reserved unique benign tasks
regain actual delivery. These include public fields/elements, public character
ranges, exact codec/JSON roundtrips, reprojected public composition and trusted
release. This is a mechanism comparison, not a re-score of historical V1.9.

**Precision depends more strongly on correct granular annotations.** An opaque
private username/list element declared public while another public field/element
is declared private leaks in Precision/Full and is blocked by Coarse. This real
regression remains FAILED: reserved ASR rises 3/24 → 6/24. Correctly classified
supported explicit attacks have no observed Full leaks (0/42 development, 0/15
reserved assessments; only 14/5 independent authored tasks). This conditional
observation is not a proof of general confidentiality or classification accuracy.

The default runtime preserves enforcement. `security.precision_research` is a
trusted, pinned-loopback-only study constructor; research switches intentionally
weaken source labeling, propagation, precision, scanner or enforcement. They are
never tools available to the agent. Session attestation binds these settings;
changing a flag after issuing a handle causes verification failure.
