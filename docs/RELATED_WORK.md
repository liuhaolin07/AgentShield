# Research positioning: checked public papers and code

Reviewed on 2026-10-11. The lookup ledger in
[results/v1.10/reference-verification.json](results/v1.10/reference-verification.json)
records actual URLs/statuses/content hashes, including unsuccessful lookups.
References were read for mechanisms and scope; no head-to-head evaluation was
run, and published numbers are not compared to AgentShield's authored contracts.

| Work and inspected sources | Mechanism and boundary | Relationship to V1.10 |
| --- | --- | --- |
| [CaMeL: Defeating Prompt Injections by Design](https://arxiv.org/abs/2503.18813), [v2 full HTML](https://arxiv.org/html/2503.18813v2), [official code](https://github.com/google-research/camel-prompt-injection) | Privileged LLM creates program control flow from trusted user intent; quarantined LLM parses untrusted data. Interpreter carries capability/source/dependency objects and checks tool policy. Paper discusses declassification/user fatigue, side channels, ambiguous queries and explicit non-goals. Code is an Apache-2.0 research artifact whose README warns about security/implementation bugs. | AgentShield does not implement trusted program synthesis/control-flow separation or a CaMeL interpreter. Its bounded handle API and replayed field/range narrowing are an integration choice, not a new information-flow principle. |
| [AgentDojo](https://arxiv.org/abs/2406.13352), [official code](https://github.com/ethz-spylab/agentdojo) | Extensible dynamic agent tasks, injected tool data and attacks; `BaseUserTask.utility` and `BaseInjectionTask.security` distinguish task completion from attack goals; `FunctionsRuntime` performs structured tool execution/environment updates. | V1.10 adopts objective-specific source/payload/sink contracts and independently observed effects. It has not run AgentDojo suites and has no official AgentDojo score. |
| [TaintDroid, OSDI 2010](https://www.usenix.org/legacy/events/osdi10/tech/full_papers/Enck.pdf) | System-wide dynamic taint tracking on Android, multiple source labels and variable/method/message/file granularity; tracks transitive data flow to network, with native/implicit-flow limitations discussed. Full PDF inspected. | Source labels, propagation, sink observation and granularity/utility tradeoffs are mature techniques. AgentShield tracks a small explicit operation set in trusted Python, not system-wide program execution. |
| [Jif/JFlow implementation](https://github.com/apl-cornell/jif), `README.in`, `LabeledTypeNode.java`, `DeclassifyExpr_c.java` | Information-flow language/compiler with labels and explicit declassification/downgrade syntax. README identifies Myers's POPL 1999 JFlow work. | Fine labels and authorized declassification are not novel. AgentShield's release scope and transformation witnesses target a constrained tool interface; it does not offer language-level noninterference. |
| [W3C PROV overview](https://www.w3.org/TR/prov-overview/) | Entities, activities, agents and derivation describe provenance; provenance is not inherently confidentiality enforcement. | A lineage record alone is not an enforcement or authenticity proof. AgentShield adds conditional runtime checks and empirical receiver evidence. |
| [Spotlighting](https://arxiv.org/abs/2403.14720) | Prompt transformations signal untrusted input provenance to the LLM; abstract describes indirect prompt injection and task efficacy. Abstract inspected, not a reproduced defense implementation. | Model instruction-following defenses differ from an explicit-flow sink gate. AgentShield does not claim to prevent injection adoption or semantic misinformation. |

CaMeL code inspection included `security_policy.py`, `interpreter/value.py`,
`capabilities/capabilities.py` and `quarantined_llm.py`. For example, sequence and
mapping projections retain receiver/index dependencies and container traversal
collects element dependencies. Thus structured values/provenance are already
present in related implementations; it would be false to claim V1.10 first
introduces field tracking for agents or declassification. Our exact-codec
witnesses and declared character ranges differ operationally, but superiority,
novel theory and empirical improvement over CaMeL have not been established.

AgentDojo's inspected LICENSE is MIT, with copyright/permission notice retention
required if code/tasks are redistributed. We copied no task/code/dataset here.
Its benchmark suites include actions beyond file-to-local-HTTP confidentiality;
a future adapter must preserve suite utility/security contracts, inject via tool
data, replace real side effects with controlled state/receivers, verify license
and dependencies at a pinned commit, and report adapted—not official—scores.
Installing a suite and generating model responses remain unperformed. AgentDojo
would supply external task structure, not automatically a blind adaptive attacker.

Potential contributions are: a bounded, precision-controllable tool-chain
integration; joint security/legitimate-task evidence; objective-specific
pre-execution versus received-data attribution; and a reproducible analysis of
classification errors, overtaint and unsupported operations. These are prototype
systems/evaluation contributions, not demonstrated standalone algorithmic novelty.
The central **unconditional** hypothesis is not supported: precision eliminates
unnecessary blocking but worsens leakage on wrong granular annotations in the
untouched reserved set. A testable narrower hypothesis is that authenticated
projection/witness narrowing improves legitimate completion under independently
validated accurate source schemas while preserving supported explicit-flow
confidentiality. Another hypothesis is that calibrated uncertain-field review can
recover the new regression at lower cost than full-container taint; no experiment
or implementation of that future mechanism is claimed.

A submission needs actual multi-provider/model runs, external independently
constructed attacks and source annotations, adaptive metadata/codec/semantic
attacks, CaMeL/AgentDojo-compatible matched tasks and budgets, classifier-error
sweeps, independent task-family uncertainty, process-boundary evaluation,
production-like latency/RSS/token/billing measurements and third-party replication.
