# V1.9 threat model

The attacker controls user prompts, injected tool text, tool arguments and the
choice/order of supported agent operations. The attacker can submit malformed
handles, replay handles from another session, replace source/provenance hashes,
request label stripping, or construct a V1.8 Python wrapper. They do not control
runtime code, the source classifier, approved adapters, the per-session issuer
key/registry, access policy, or the receiver/evaluator. Root and malicious runtime
modification are excluded.

The untrusted interface is **bounded data requests through AgentPort**, not
arbitrary Python execution. A Python object with private attributes is not a
sandbox: Python capable of inspecting trusted runtime objects, invoking private
issuers or importing senders has crossed this boundary. Process separation is
not implemented. Partial untrusted agent logic means tool selection and explicit
transforms through the port, never exec/eval, callbacks or unrestricted imports.

File sensitivity and approved-tool classifications are trusted configuration.
Wrong classification can still leak an opaque value. Live model paraphrase,
implicit flows and arbitrary computation have no proven explicit lineage.
Experiments must distinguish mechanism validation under trusted labels from
source detection accuracy and natural-language task success.

Confidential information is fabricated in experiments. HTTP attack sinks are
pinned to 127.0.0.1. The optional live model endpoint is a separately configured
official provider, receives only synthetic experiment content, and requires an
explicit credential decision. Transport restrictions are never defense credit.

V1.8 APIs and evidence are preserved. Their publicly constructed TaintedValue
is a legacy trusted-caller value, **not** an attestation accepted by the V1.9
runtime. Existing V1.8 negative controls remain valid for that interface.

The five baselines / A1–A4 ablations are selected by trusted evaluation code.
No AgentPort request can disable integrity, discard labels, or select detect-only.
B0–B2 omit MAC/replay checks while sharing bounded issuance; source-only and
observe-only are intentional research weakening modes. The receiver/executor
is infrastructure, never a defense credited for blocking. Misclassification and
benign-projection contracts remain in every group and metric denominator.

## V1.10 precision additions (historical V1.9 text above)

PrecisionRuntime/PrecisionAgent use the same data-only trust boundary. The
attacker can choose bounded operations, arguments, handle aliases and injected
public tool content; cannot edit trusted SourceLayout, SourceRegistry, release
rules, callback registration, study arm, issuer storage or receiver/oracle.
Fine labels describe dictionary fields, list elements and Unicode character
ranges. Projection is allowed to narrow only according to authenticated source
granularity and replayed supported semantics. This does not establish secrecy
of shape, length, key selection, branch/timing or other implicit channels.

Granular classification errors are included in experiments even though classifier
modification is outside the runtime attacker model: they model configuration
failures, not HMAC forgery. Incorrect public fields can leak where coarse union
would incidentally protect them. Correct-label mechanism evidence and
classification accuracy are reported separately. Authorized releases are trusted
policy actions scoped to one original source/projection/sink; ordinary agent
interfaces have no untaint, release, literal issuer or raw-value mint operation.

The new genuine-model study distinguishes adoption, matching attack attempts,
specific protected sources, matching canaries, pre-execution blocks and observed
sink delivery. Indirect injection occurs in PUBLIC tool/file content while the
user asks for a benign summary; direct malicious user tasks remain separate.
Opaque private reads need not enter model context merely to name a handle, but
inspect/transform materialization is checked before the next actual model call.
Model-generated values conservatively inherit request dependencies. Semantic
reconstruction from external/raw information is unproved and not credited.

The V1.10 No Defense arm keeps common handle verification unlike historical
V1.9 B0; comparison is about content defenses inside a common guarded protocol,
not unrestricted malicious Python. Detection Only findings do not count as
blocks. All paid calls default off; provider endpoints are fixed and distinct
from the loopback attack receiver. Missing credentials, provider failure or
unobserved adoption are UNRUN. Model-boundary transport probes are not inference.
