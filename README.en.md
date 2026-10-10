# AgentShield V1.6.1 · V1.7 in development

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
See [evaluation conditions and boundaries](docs/EVALUATION.md). Taint tracking
and the four-arm research benchmark remain subsequent stages.

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

Follow the [staged plan](docs/REVIEW-v1.7.md): extend held-out scanner controls,
explicit provenance-aware taint tracking, then No Defense, Static Rule, Scanner
and Scanner + Taint experiments. Derive metrics and plots from actual execution
evidence, including false positives, failures and missing observations.
