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
