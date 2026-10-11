# V1.9 runtime security boundary

Agent logic submits data requests to AgentPort. A trusted file adapter, approved
tool adapter or model adapter issues an opaque ValueHandle inside AttestedRuntime.
The agent receives no raw confidential read result and has no literal, mint,
reveal or callback tool. Supported transforms execute inside the runtime and
keep parent sources. The runtime checks handle integrity before the existing
middleware checks HTTP/model policy and content, then invokes the executor.

Every handle has a session ID, value ID, provenance ID, keyed source hash and
HMAC seal. Immutable entries contain the bounded value/metadata and parents.
Verification binds data, labels, permissions, transform parameters and session;
checks issuance and parent handles; replays the supported transform chain; and
defaults to BLOCK on mismatch or tracking loss. Keyed hashes avoid publishing
guessable content hashes in integrity audit records. IDs/seals are session-local,
not independently verifiable public proofs. Audit files themselves remain mutable.

V1.8 source/provenance IDs stay stable for logical references/operations; V1.9
attestations add session integrity. Raw source values and paths are not recorded
in integrity logs. Access policy and content scanner remain separate judgments.
Successful permission is not execution or task-completion evidence.

The default new runtime accepts only issued handles at sinks. A manually created
TaintedValue, reclassified literal, malformed or cross-session handle is rejected
before sender entry. Legitimate public handles can actually reach the controlled
receiver. Registry size is bounded to 512 entries / 8 MiB charged canonical
snapshots; chain verification is bounded to 128 nodes, parents to 32, in addition
to the V1.8 character/structure/label/provenance budgets.

This protection is conditional on a trusted runtime and data-only agent port.
Unrestricted malicious Python, private-object introspection, runtime mutation,
wrong source classification, implicit flows, arbitrary third-party computation,
model rewrites and information encoded in tool choice/timing are outside proven
coverage. No OS isolation, signed append-only audit or complete information-flow
security is claimed. Legacy V1.8 APIs are unchanged and do not gain attestation
protection automatically.

ResearchRuntime requires a local target. Trusted configuration may omit MAC
verification (B0–B2), disable scanning (Taint), drop transformed labels (Source
only), or observe content without enforcing (Detect only). These flags are absent
from AgentPort and are not default AttestedRuntime behavior. Detector findings
and enforcing modules are separate: detection in an ALLOW decision is not a block.
The model adapter allows only fixed official DeepSeek/Qwen endpoints after opt-in
and credential reuse; attack sinks stay local. Missing keys, non-attempted attacks
and unsupported conversions are UNRUN without credit. Model paraphrase is not tracked.

## V1.10 extension

PrecisionAuthority additionally authenticates per-field/element/character
metadata, encoder witnesses, active classification references, study flags and
scoped release stamps. Narrowing is replayed; literal/wrapper replacement and
cross-session handles are rejected. Source-layout declarations remain trusted
and fallible. Coarse/precise comparisons share metadata integrity and the same
transport path. Uncertain sources BLOCK or REQUIRE_REVIEW before execution,
unless a trusted scoped grant resolves that output or policy explicitly ALLOWs.

A release never erases provenance globally. Only an immediate original-source
projection/slice with exact authorized parameters may be released to the exact
sink kind/origin. Later transforms revoke the grant; the scanner still applies.
Independent tests include wildcard, wrong source/sink/selector, recomposed-field
substitution, metadata tampering, downgraded labels and raw wrappers.

Audit metadata omit raw source values/paths, but audit files and public result
files are not signed append-only proofs. Benchmark receiver bodies and fixture
inputs are intentionally synthetic, retained as independent execution evidence;
never use personal data/real credentials with these research exporters. The
independent gate verifies report consistency, not authenticity against a
malicious experiment operator. Same-process Python is still not an isolation
boundary, and metadata/decoding bounds are not a universal denial-of-service proof.
