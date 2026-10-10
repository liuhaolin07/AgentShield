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
