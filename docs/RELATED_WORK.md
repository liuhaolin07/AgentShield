# Research positioning

The following public abstracts/readmes were read on 2026-10-10. These are
architectural references, not measured head-to-head comparisons.

- [CaMeL — Defeating Prompt Injections by Design](https://arxiv.org/abs/2503.18813)
  extracts control/data flow from a trusted query and uses capabilities to
  constrain untrusted data and private-data exfiltration. Explicit taint and
  capabilities are not novel by themselves. AgentShield does not implement
  CaMeL's trusted program generation/control-flow isolation.
- [AgentDojo](https://arxiv.org/abs/2406.13352),
  [official implementation](https://github.com/ethz-spylab/agentdojo), evaluates
  real agent tasks, prompt injection and defenses in a dynamic environment.
  AgentShield's authored explicit-flow cases are mechanism tests; UNRUN injection
  tasks cannot substitute for AgentDojo-style real-model evidence.

Potential contribution is an inspectable bounded middleware integration with
session-issued handles, transform-chain checks, independent pre-execution
attribution and retained misclassification/utility failures plus ablations.
Current status is a reproducible prototype, not an established novel security
proof or validated superior defense. Same-process Python privacy is a boundary,
not isolation. Trusted classification and explicit-only tracking limit coverage.

Research requires external benchmark integration/attack authors, multi-provider
actual model tool selection, adaptive flow/metadata attacks, source accuracy,
precise projection/declassification, complete costs including issuance and RSS,
independent replication and uncertainty over independent families/tasks.
Published numbers must not be directly compared: tasks, models, objectives and
denominators differ. No relative performance claim was measured here.
