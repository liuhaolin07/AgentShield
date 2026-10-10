# Security Policy

AgentShield is a security tool — it exists to stop sensitive-data leakage
through LLM agent tool calls. Findings about its own defenses are taken
seriously.

## Runtime and evaluation boundary

The Python process, policy author and local filesystem owner are trusted.
Middleware protects calls integrated through it; direct tool/client calls are
not process-wide mediated. Audit records are decisions, not signed execution
receipts. Canonical path checks do not provide atomic-open guarantees.

The V1.7 development evaluator uses fabricated fixtures and an opt-in receiver
on 127.0.0.1 only. Its transport is separately confined and is not evidence of
AgentShield blocking an action. The live Dots client is not covered by this
experimental transport guarantee. Do not replace fixtures with real credentials.
See [evaluation conditions and known failures](docs/EVALUATION.md) and the
[source review](docs/REVIEW-v1.7.md) before interpreting results.

## Supported versions

Only the latest release line (`v1.6.x`) is supported. Fixes land on `main`
and ship as patch releases; see [CHANGELOG.md](CHANGELOG.md).

## Reporting a vulnerability

Use **GitHub's private vulnerability reporting**:

> Repository **Security** tab → **Report a vulnerability**
> (direct link: https://github.com/liuhaolin07/AgentShield/security/advisories/new)

Please do not open a public issue for a vulnerability.

Include:

- the version / commit you tested,
- a minimal reproduction (tool call, payload, policy),
- the expected vs. observed decision (blocked vs. allowed).

## Scope

In scope:

- a secret reaching a tool call without being flagged (scanner bypass),
- fail-open behavior under malformed input where fail-closed is promised,
- audit-log integrity issues (see the audit notes in the README).

Out of scope:

- false positives on benign content — report those as a normal issue,
- the simulated `send_http` tool making no real network request (by design).

## Expectations

Best-effort response, typically within a week. This is a small project with no
bug bounty; reporters are credited in release notes unless they prefer
otherwise. Please allow time for a fix before any public write-up.
