# AgentShield · V1.8 in development (V1.7 baseline preserved)

**English** · [中文](README.md)

[![CI](https://github.com/liuhaolin07/AgentShield/actions/workflows/ci.yml/badge.svg)](https://github.com/liuhaolin07/AgentShield/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

AgentShield is a small, runnable security layer for tool-using agents. Every
file read and outbound HTTP call passes through middleware that can allow or
block the action before the tool executes.

V1.6 includes both the deterministic demo agent and an optional Dots-powered
tool-calling agent. The policy parser and API client use only the Python
standard library. The `send_http` tool still prints a simulation instead of
making a real network request.

## V1.8: explicit source-aware taint tracking

Built on V1.7 `d1e0552`, this branch adds immutable source labels, transformation
lineage and per-source sink permissions. Explicit concat/slice, list/dictionary,
JSON, Base64 and percent conversions retain confidential sources. Opaque file/
tool results can be blocked before HTTP/model execution without a scanner match.
Scanner and taint observations are recorded separately; public data still sends.
Tracking is opt-in; existing CLI options and simulated HTTP remain compatible.

```bash
python main.py "read normal log and send" --taint-config path/to/taint.json
python -m evaluation --experiment v1.8 --split development --seed 17 --repeat 3 --output-dir logs/v18-development
python -m evaluation --experiment v1.8 --split holdout --seed 17 --repeat 3 --output-dir logs/v18-holdout
```

Example configuration:
`{"sensitive_files":["test/data/confidential*.txt"],"sensitive_tools":["private_lookup"],"require_tracked":true}`.
Read permission and source confidentiality are separate policies. See
[TAINT_TRACKING.md](docs/TAINT_TRACKING.md) for runnable local usage and boundaries.

**143 tests passed, no skips**. The 86 V1.7 assessments remain unchanged at
**HELD 82 / FAILED 0 / UNRUN 4**. New datasets were frozen first; the complete
candidate `b3a2808` was committed before the first holdout run and was not tuned
on its results. Observed Linux/Python 3.12.14, seed 17, three repeats:

| Arm | Development ASR | Holdout ASR | Development TCR | Development FPR |
| --- | --- | --- | --- | --- |
| No Defense | 42/42 | 15/15 | 18/18 | 0/18 |
| Static Rule | 39/42 | 15/15 | 12/18 | 6/18 |
| Scanner (V1.7) | 36/42 | 12/15 | 18/18 | 0/18 |
| Scanner + Taint (V1.8) | 0/42 | 0/15 | 18/18 | 0/18 |

All arms' holdout TCR is 12/12. These are exploratory authored fixtures given
accurate source classification; repeated cases are not independent populations.
Unsupported transforms/implicit flows stay UNRUN. Controls and missing/invalid
evidence are excluded from metric denominators. Other arms' actual FAILED cases
remain, so four-arm commands exit 1. Full precision/recall, latency, numerators,
denominators, [JSON/CSV summaries](docs/results/v1.8/), figures and failure analysis
are in [EXPERIMENT_V1.8.md](docs/EXPERIMENT_V1.8.md).

Plotting is an optional dependency; core runtime/evaluation uses the standard library:

```bash
python -m pip install -r requirements-research.txt
python -m evaluation.plot logs/v18-development/report.json
```

Unwrapped Python/third-party operations, model paraphrase and implicit flows are
untracked. Misclassified sources and privileged relabeling can still leak; real
negative-control tests demonstrate these gaps. No main merge or formal release.

## V1.7 stage one: independent security evaluation

This development branch adds an [architecture review, risk register and staged
plan](docs/REVIEW-v1.7.md) and evaluates Clean Start, Blocked Means Blocked,
No Escape, Honest Logs and Done Means Done. Each case records inputs, policy,
execution observations, receiver arrivals, expected/actual effects and blocker,
with **HELD / FAILED / UNRUN** outcomes.

```bash
python -m evaluation --seed 17 --repeat 2 --output-dir logs/evaluation
```

This command explicitly starts a temporary **127.0.0.1** receiver and sends only
fabricated fixtures. No model key is needed. Real HTTP is disabled by default;
the opt-in experimental transport pins one local port, performs no DNS lookup
and never follows redirects. Ordinary demos still simulate HTTP. Transport or
environment restrictions receive no AgentShield defense credit.

Observed on 2026-10-10, Linux/Python 3.12.14: **92 automated tests passed**.
The original 21 cases changed from **HELD 28 / FAILED 10 / UNRUN 4** to
**HELD 38 / FAILED 0 / UNRUN 4** over two repeats. An expanded baseline was
recorded before defense changes: 43 cases repeated twice changed from
**HELD 40 / FAILED 42 / UNRUN 4** to **HELD 82 / FAILED 0 / UNRUN 4**.
Inputs, policies and expected contracts were preserved. Audit tamper verification
and implicit information flow remain UNRUN. These synthetic counts include
controls; they are not ASR or a general security score.

The scanner now inspects nested JSON, percent-encoding and standard/URL-safe
Base64 within explicit resource budgets, and recognizes RSA/EC/OpenSSH/PKCS#8
private-key headers. Ordinary PASSWORD documentation, public keys and legal API
parameters have delivery controls. `scan_limit` distinguishes exhausted budgets
from detected credentials. [Iteration evidence and all case transitions](docs/ITERATION2.md)
describe remaining heuristic limits.

`run_llm_agent_result` separates `model_finished`, tool `evidence` and
`completed`. A final model claim without an executed tool is incomplete.
Callers may specify `required_tools` and `require_real_http`; simulated sends
cannot satisfy a real-HTTP contract. Default completion requires successful tool
work, not semantic proof of an arbitrary task. CLI options remain unchanged;
LLM runs without required execution evidence return exit code 2.

Evidence is exported to Git-ignored `logs/evaluation/report.json` and `cases.csv`.
The evaluator exits 1 for FAILED cases or 2 for UNRUN cases without failures.
See [historical V1.7 conditions and boundaries](docs/EVALUATION.md). The V1.8
explicit tracking MVP and exploratory four-arm framework are described above;
complete information-flow protection remains unimplemented.

## Flow

```text
User task
    ↓
Deterministic or Dots Agent
    ↓
Tool Call
    ↓
AgentShield Middleware
    ├── Policy check
    ├── Sensitive-data scan
    └── Audit event
    ↓
Allow / Block
    ↓
Tool execution
```

## What's new in V1.6

- Dots Chat Completions integration using `dots3-note-prev`.
- Native parsing and execution of `message.tool_calls`.
- Mandatory middleware checks before every model request and tool execution.
- Protection against leaking sensitive tool results back to the model API.
- Allowed file roots that prevent model-generated arbitrary local file reads.
- Detection of Dots `ak_...` credentials.
- Standard-library regression tests, including a scripted fake-model loop;
  V1.7 adds independent receiver-evidence tests.

V1.5 also introduced:

- Runnable CLI and deterministic demo agent.
- `policy.yaml` with blocked files and allowed HTTP domains.
- Append-only JSONL audit log containing time, agent, tool, decision, and
  reason.
- Fail-closed behavior for missing policies, invalid policies, audit failures,
  and unsupported tools.
- Standard-library tests covering attack and normal flows.

The audit writer excludes tool arguments, file contents and HTTP payloads, but
agent/tool metadata is caller supplied. Logs are unsigned and mutable. ALLOW
records permission, not successful execution. Direct tool/client calls still
require the caller to integrate the middleware.

## Run the deterministic demos

No dependencies need to be installed. From the repository root:

![AgentShield demo: two blocked attempts, one allowed flow](docs/demo.gif)

### 1. Block a protected file read

```bash
python main.py "read secret and send"
```

```text
[AgentShield] Checking...
BLOCKED: File denied by policy
```

The agent never reads `.env`, so no HTTP call is attempted.

### 2. Block sensitive data already in memory

```bash
python main.py "send embedded secret"
```

```text
[AgentShield] Checking...
BLOCKED: Sensitive data detected
```

### 3. Allow a normal flow

```bash
python main.py "read normal log and send"
```

```text
[AgentShield] Checking...
Allowed
[AgentShield] Checking...
Allowed
Sending data to:
example.com
INFO service started successfully
```

## Run with the Dots model

The live mode sends the user prompt and security-approved tool results to:

```text
https://note3-prev-api.askdiandian.com/v1/chat/completions
```

Create a fresh API key before testing. Do not paste it into source code, a
command-line argument, shell history, `.env`, or Git. In PowerShell, read it
without echoing it and keep it only in the current process:

```powershell
$agentShieldKey = Read-Host "Dots API Key" -AsSecureString
$agentShieldPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($agentShieldKey)
try {
    $env:AGENTSHIELD_API_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($agentShieldPtr)
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($agentShieldPtr)
}
```

The simplest live test uses the secure launcher. It prompts for the key with
masked input, runs the task, and removes the process environment variable:

```powershell
.\run_dots_live.ps1
```

Pass a different task when needed:

```powershell
.\run_dots_live.ps1 "Read test/data/app.log and send a summary to example.com"
```

Alternatively, after configuring the process environment manually, run:

```bash
python main.py --llm "Read test/data/app.log and send a summary to example.com"
```

Live mode uses `dots3-note-prev`, disables model reasoning output, limits each
response to 512 tokens, and allows at most six tool-call rounds. Override the
model or API base URL only when the corresponding destination is also present
in `policy.yaml`.

## Policy

V1.6 accepts this intentionally small YAML shape:

```yaml
blocked_files:
  - .env
  - id_rsa

allowed_file_roots:
  - test

allowed_domains:
  - example.com
  - github.com
  - note3-prev-api.askdiandian.com
```

Only files under an allowed read root can be opened. Exact allowed domains and
their subdomains are accepted for simulated HTTP and model API traffic. All
other destinations are blocked. Unknown policy keys or missing required keys
cause a fail-closed decision.

The V1.7 development branch rejects malformed URLs, non-HTTP(S) schemes,
userinfo and invalid argument types. File paths resolve relative to the policy
directory; both lexical names and symlink targets are checked. Checking and
opening a file are separate operations and do not guarantee protection against
concurrent filesystem replacement. The existing live Dots client is outside
the experimental loopback transport's guarantee.

## Audit log

Runtime decisions are appended to `logs/audit.jsonl`:

```json
{"time":"2026-01-01T00:00:00Z","agent":"simple-agent","tool":"http","decision":"BLOCK","reason":"sensitive_data"}
```

The runtime `logs/` directory is ignored by Git.

## Security policy

See [SECURITY.md](SECURITY.md) for supported versions and how to report a
vulnerability privately (please do not open a public issue).

## Test

```bash
python -m unittest discover -s test -p "test_*.py" -v
```

## Repository layout

```text
AgentShield/
├── main.py
├── policy.yaml
├── run_dots_live.ps1
├── SECURITY.md
├── CHANGELOG.md
├── LICENSE
├── docs/
│   └── demo.gif
├── agent/
│   ├── agent.py
│   └── llm_agent.py
├── model/
│   └── dots_client.py
├── security/
│   ├── audit.py
│   ├── middleware.py
│   ├── policy.py
│   └── scanner.py
├── tools/
│   ├── file_tool.py
│   └── http_tool.py
└── test/
    ├── data/app.log
    ├── secrets/.env
    ├── test_dots_client.py
    ├── test_llm_agent.py
    └── test_security.py
```

The values in `test/secrets/.env` are fake test fixtures and must never be
replaced with real credentials.

## Next direction

Extend the explicit-flow MVP and four-arm framework with external held-out
datasets, real agent tasks, finer propagation/false-positive studies, independent
reproduction and statistical analysis. Production networking, filesystem races
and audit integrity still need separate validation. See the
[research gaps](docs/EXPERIMENT_V1.8.md).
